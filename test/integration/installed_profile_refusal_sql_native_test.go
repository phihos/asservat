package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Observe the two independently approved manual captures after public terminal
// delivery. This reads retained accounting; it grants no collection authority
// and makes no physical allocation/refund claim from aggregate byte counters.
func installedProfileRefusalSQLCheck(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string) func(captureID, grantID, reason string) time.Time {
	t.Helper()
	return func(captureID, grantID, reason string) time.Time {
		t.Helper()
		phase := ""
		switch reason {
		case "ProfilerBusy":
			phase = "profilerBusy"
		case "ProfileUnavailable":
			phase = "profileUnavailable"
		default:
			t.Fatal("unexpected profile refusal SQL check reason", reason)
		}
		bounded, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		var exact bool
		var started time.Time
		var timeoutMillis int64
		if err := admin.QueryRow(bounded, `SELECT
 c.state='intent_audited' AND c.preview_id=g.preview_id AND c.scope_digest=g.execution_digest AND c.scope_json=g.scope
 AND g.kind='adHocCapture' AND g.data_class='raw' AND g.decision='approved'
 AND x.phase=$4 AND x.object_uid IS NOT NULL AND x.started_at IS NOT NULL AND x.completed_at>=x.started_at
 AND x.acquired_at IS NULL AND x.copies_json IS NULL AND x.copies_digest IS NULL
 AND (convert_from(x.binding_json,'UTF8')::jsonb->>'NativeType')='pprof'
 AND (convert_from(x.binding_json,'UTF8')::jsonb->>'NativeBytes')::bigint=a.native_limit
 AND (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Profile,MaxBytes}')::bigint=a.native_limit
 AND (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Profile,Type}')='cpu'
 AND (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Profile,Mode}')='interval'
 AND (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Profile,DurationMillis}')::bigint=10000
 AND (SELECT count(*) FROM context_capture WHERE root_id=c.root_id AND preview_id=g.preview_id)=1
 AND (SELECT count(*) FROM context_execution WHERE root_id=c.root_id AND capture_id=c.id)=1
 AND (SELECT count(*) FROM context_control_charge WHERE root_id=c.root_id AND capture_id=c.id AND allocation_id=a.allocation_id)=1
 AND NOT EXISTS(SELECT 1 FROM context_verification WHERE root_id=c.root_id AND capture_id=c.id)
 AND NOT EXISTS(SELECT 1 FROM context_catalog WHERE root_id=c.root_id AND capture_id=c.id)
 AND NOT EXISTS(SELECT 1 FROM context_writer_completion WHERE root_id=c.root_id AND capture_id=c.id)
 AND NOT EXISTS(SELECT 1 FROM custody_copy WHERE attempt_id=a.id AND ciphertext_bytes IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM policy_observation_session WHERE root_id=c.root_id AND capture_id=c.id)
 AND NOT EXISTS(SELECT 1 FROM adhoc_observation_spend WHERE root_id=c.root_id AND grant_id=g.id),
 x.started_at,(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Profile,TimeoutMillis}')::bigint
 FROM context_capture c
 JOIN context_execution x ON x.root_id=c.root_id AND x.capture_id=c.id AND x.attempt_id=c.attempt_id
 JOIN custody_attempt a ON a.id=c.attempt_id
 JOIN access_grant g ON g.root_id=c.root_id AND g.capture_id=c.id
 WHERE c.root_id=$1 AND c.id=$2 AND g.id=$3`, root, captureID, grantID, phase).Scan(&exact, &started, &timeoutMillis); err != nil || !exact || started.IsZero() || timeoutMillis != 15000 {
			t.Fatal("installed profile refusal lost exact terminal, empty evidence, original grant or retained admission/control debit", reason, exact, err)
		}
		t.Logf("%s SQL: one immutable approved capture/execution/control debit; no stored evidence, observation session or same-preview retry; physical capacity/refund unclaimed", reason)
		// This is the regional holder's original slot cutoff, not a new lease.
		// Terminal refusal does not shorten a start that may have reached HTTP.
		return started.Add(time.Duration(timeoutMillis) * time.Millisecond)
	}
}
