package integration

import (
	"context"
	"crypto/tls"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	app "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type liveManualFixtureKey struct{}
type liveManualStartedFixture struct {
	run     func(*testing.T, *capacitySQLFixture, captureAdmissionScenario, capture.Accepted, *postgres.APIContextExecutions, value.APIExecution, func() app.APIExecutionCheck)
	handled bool
}

func liveManualFixtureHook(ctx context.Context) *liveManualStartedFixture {
	hook, _ := ctx.Value(liveManualFixtureKey{}).(*liveManualStartedFixture)
	return hook
}

// Separate pristine campaigns reuse one admitted recording and actual compiled
// hub SQL role. They end before publication: no saved artifact/query is invented
// to make a live source. Target/region/node/process/authority facts are controlled
// component inputs; this proves SQL provenance/closure, not running node reads.
func TestLiveManualMetadataSourceWithRealServices(t *testing.T) {
	withLiveManualSourceFixture(t, "metadata")
}
func TestLiveManualRawPacketSourceWithRealServices(t *testing.T) {
	withLiveManualSourceFixture(t, "raw")
}
func TestLiveManualArgumentsSourceWithRealServices(t *testing.T) {
	withLiveManualSourceFixture(t, "arguments")
}

func withLiveManualSourceFixture(t *testing.T, mode string) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		hook := &liveManualStartedFixture{run: qualifyLiveManualStartedSource}
		ctx = context.WithValue(ctx, liveManualFixtureKey{}, hook)
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(t *testing.T, _ *queryLedgerFixture) {
			t.Fatal("manual-only fixture unexpectedly reached saved query qualification")
		}, false, false, false, mode != "arguments", mode == "raw", mode == "arguments")
		if !hook.handled {
			t.Fatal("original started source callback was not exercised")
		}
	})
}

func qualifyLiveManualStartedSource(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, accepted capture.Accepted, executions *postgres.APIContextExecutions, original value.APIExecution, refresh func() app.APIExecutionCheck) {
	t.Helper()
	if executions == nil || refresh == nil || original.Phase != "started" || accepted.Expectation.Recording == nil {
		t.Fatal("missing original finite execution")
	}
	ctx, root, id := f.ctx, s.a.RootID, accepted.CaptureID
	check := refresh()
	snapshot := func() string {
		var result string
		if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object(
 'capture',(SELECT to_jsonb(c) FROM context_capture c WHERE root_id=$1 AND id=$2),
 'execution',(SELECT to_jsonb(e) FROM context_execution e WHERE root_id=$1 AND capture_id=$2),
 'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM access_grant g WHERE root_id=$1 AND capture_id=$2),
 'observation',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM policy_observation_session o WHERE root_id=$1 AND capture_id=$2),
 'queries',(SELECT count(*) FROM context_query WHERE root_id=$1),
 'catalog',(SELECT count(*) FROM context_catalog WHERE root_id=$1))::text`, root, id).Scan(&result); err != nil {
			t.Fatal("original finite acquisition snapshot", err)
		}
		return result
	}
	before := snapshot()
	prepaid := func() string {
		var result string
		if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object(
 'sessions',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM policy_observation_session o WHERE root_id=$1 AND capture_id=$2),
 'observedSpend',(SELECT jsonb_agg(to_jsonb(o) ORDER BY grant_id) FROM adhoc_observation_spend o WHERE root_id=$1 AND grant_id IN (SELECT id FROM access_grant WHERE root_id=$1 AND capture_id=$2)),
 'disclosureSpend',(SELECT jsonb_agg(jsonb_build_array(id,artifacts_spent,bytes_spent,operations_spent) ORDER BY id) FROM access_grant WHERE root_id=$1 AND capture_id=$2))::text`, root, id).Scan(&result); err != nil {
			t.Fatal("original prepaid source/disclosure snapshot", err)
		}
		return result
	}
	originalPrepaid := prepaid()
	target := s.a.Plan.Input.Target.Target()
	gotTarget, err := executions.LiveManualTarget(ctx, id)
	if err != nil || gotTarget != target {
		t.Fatal("exact minimal manual target", err)
	}
	if _, err = executions.LiveManualTarget(ctx, custodyID()); err == nil {
		t.Fatal("unrelated capture acquired a target")
	}
	rows, err := executions.ReadLiveManualWork(ctx, []string{id}, check.Recovery)
	if err != nil || len(rows) != 1 || !reflect.DeepEqual(rows[0].Execution, original) || !reflect.DeepEqual(rows[0].Work.Accepted, check.Work.Accepted) || rows[0].Work.Actor != check.Work.Actor || !time.Now().Before(rows[0].FreshUntil) || rows[0].FreshUntil.After(check.Recovery.FreshUntil) {
		t.Fatal("current original finite execution/authority", len(rows), err)
	}
	rec := accepted.Expectation.Recording
	if rec.Arguments != nil {
		if rows[0].Arguments == nil || rows[0].Observation != nil || rows[0].Arguments.CaptureID != id || rows[0].Arguments.ExpectationDigest != [32]byte(original.ExpectationDigest) {
			t.Fatal("actual original argument permit omitted or relabeled")
		}
	} else if rec.Profile == "rawPackets" || rec.Profile == "httpHeaders" {
		if rows[0].Observation == nil || rows[0].Arguments != nil || rows[0].Observation.CaptureID != id || rows[0].Observation.ExpectationDigest != [32]byte(original.ExpectationDigest) {
			t.Fatal("actual original packet permit omitted or relabeled")
		}
	} else if rows[0].Observation != nil || rows[0].Arguments != nil {
		t.Fatal("metadata source invented a sensitive session")
	}
	workload := authorization.WorkloadTarget{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID}
	listed, next, err := executions.ListLiveManualWork(ctx, workload, "", 100, check.Recovery)
	if err != nil || next != "" || len(listed) != 1 || listed[0].Work.Accepted.CaptureID != id {
		t.Fatal("bounded exact manual workload inventory", len(listed), err)
	}
	if after, cursor, err := executions.ListLiveManualWork(ctx, workload, id, 100, check.Recovery); err != nil || len(after) != 0 || cursor != "" {
		t.Fatal("original capture cursor replayed source", err)
	}
	workload.WorkloadUID = "unrelated-workload"
	if other, _, err := executions.ListLiveManualWork(ctx, workload, "", 100, check.Recovery); err != nil || len(other) != 0 {
		t.Fatal("manual inventory crossed workload", err)
	}
	if missing, err := executions.ReadLiveManualWork(ctx, []string{custodyID()}, check.Recovery); err != nil || len(missing) != 0 {
		t.Fatal("unknown manual source manufactured an execution", err)
	}
	if snapshot() != before {
		t.Fatal("live routing/provenance read changed original acquisition, grant, publication or spend")
	}
	// Each negative uses the real existing product operation, then proves the
	// live read refuses immediately. No holder or source is restarted/replaced.
	check = refresh()
	switch {
	case rec.Arguments != nil:
		var revision int64
		if err := f.admin.QueryRow(ctx, `SELECT progress_revision FROM context_capture WHERE root_id=$1 AND id=$2`, root, id).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		stop := capture.CancellationCheck{RootID: root, Identity: check.Eligibility.VerifiedIdentity, Recovery: check.Recovery, CheckedAt: now, ValidUntil: identity.Earlier(check.ValidUntil, now.Add(5*time.Second)), Request: capture.CancellationRequest{CaptureID: id, ExpectedRevision: revision, IdempotencyKey: "stop-original-manual-live"}}
		result, err := executions.RequestCaptureCancellation(ctx, stop)
		if err != nil || !result.Decision.Requested || result.Recording == nil || result.Recording.CaptureID != id || result.Recording.AttemptID != original.Binding.AttemptID {
			t.Fatal("actual original finite Stop request", err)
		}
		// Requested Stop is not a synthetic joined/terminal node proof.
	case rec.Profile == "rawPackets" || rec.Profile == "httpHeaders":
		store, err := postgres.NewAccessGrants(ctx, f.roles["hub-runtime"], root, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		var grantID string
		if err = f.admin.QueryRow(ctx, `SELECT id::text FROM access_grant WHERE root_id=$1 AND capture_id=$2 AND kind='adHocCapture'`, root, id).Scan(&grantID); err != nil {
			t.Fatal("original observation approval", err)
		}
		g, err := store.Grant(ctx, grantID)
		if err != nil {
			t.Fatal(err)
		}
		g, _, err = store.RevokeGrant(ctx, authapp.GrantRevocationInput{GrantID: g.ID, Revoker: check.Work.Actor, ExpectedRevision: g.Revision, IdempotencyKey: "revoke-original-manual-source"}, check.Recovery)
		if err != nil || g.RevokedAt.IsZero() {
			t.Fatal("actual original source grant revocation", err)
		}
	default:
		ended := original
		ended.Phase = "captureFailed"
		ended.CompletedAt = time.Now().UTC().Truncate(time.Microsecond)
		if _, err := executions.RecordAPIOutcome(ctx, ended, check.Process); err != nil {
			t.Fatal("actual terminal finite execution row", err)
		}
	}
	if ended, err := executions.ReadLiveManualWork(ctx, []string{id}, check.Recovery); err != nil || len(ended) != 0 {
		t.Fatal("ended, Stop-requested or revoked original remained a live source", len(ended), err)
	}
	if prepaid() != originalPrepaid {
		t.Fatal("live closure refunded, renewed or consumed original observation/disclosure credit")
	}
	var queries, published int64
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM context_query WHERE root_id=$1),(SELECT count(*) FROM context_catalog WHERE root_id=$1)`, root).Scan(&queries, &published); err != nil || queries != 0 || published != 0 {
		t.Fatal("manual live fixture created a saved/query outcome", queries, published, err)
	}
	t.Log("actual compiled-role original finite execution/permit/target/inventory and read-only control; actual SQL closure/refusal; no node-holder delivery, collection join, publication or installed qualification")
}
