package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func checkInstalledErasureReadAudit(t *testing.T, ctx context.Context, run installedProcessingRun, id, name string, responseBytes int64) {
	t.Helper()
	if !authorization.UUID(id) {
		t.Fatal("installed erasure: missing read audit ID", name)
	}
	installedJourneyReadOnly(t, ctx, run.SQL, func(tx pgx.Tx) error {
		var acknowledged bool
		err := tx.QueryRow(ctx, `
SELECT o.lane='normal' AND o.intent->>'Name'=$3 AND o.intent->>'InputFormat'='context-input/v1'
 AND o.outcome->>'Status'='success' AND o.outcome->>'Effect'='none' AND o.outcome->'ArtifactIDs'=jsonb_build_array($4::uuid)
 AND o.intent_receipt IS NOT NULL AND o.outcome_receipt IS NOT NULL AND h.binding=o.intent->'Lifecycle'
 AND h.intent_completion->'Receipt'=o.intent_receipt AND h.outcome_completion->'Receipt'=o.outcome_receipt
 AND ($5::bigint=0 OR (o.outcome->>'OutputBytes')::bigint=$5)
FROM operation_audit o JOIN operation_audit_lifecycle h ON h.root_id=o.root_id AND h.operation_id=o.id AND h.lane=o.lane
WHERE o.root_id=$1 AND o.id=$2`, run.RootID, id, name, run.ArtifactID, responseBytes).Scan(&acknowledged)
		if err != nil || !acknowledged {
			t.Fatal("installed erasure: read was not exactly acknowledged in the normal audit lane", name, err)
		}
		return nil
	})
}

func awaitInstalledEarlyErasure(t *testing.T, ctx context.Context, run installedProcessingRun, requestID string, loc artifact.Location, applied, anchor time.Time) (time.Time, value.LifecycleDecision, audit.Receipt, audit.Receipt) {
	t.Helper()
	for {
		var raw, lifecycleRaw, deletionRaw []byte
		var deleted, purged, acknowledged pgtype.Timestamptz
		var finalized, lifecycleCurrent bool
		installedJourneyReadOnly(t, ctx, run.SQL, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `
SELECT d.decision_json, d.audit_receipt_json, c.audit_receipt_json, a.deleted_at, c.purged_at, c.audit_acknowledged_at,
 c.finalization_xid IS NOT NULL AND a.state='deleted',
 coalesce(public.retention_lifecycle_receipt_current(d.root_id,d.id,d.audit_receipt_json),false) AND d.audit_acknowledged_at IS NOT NULL
FROM retention_decision d JOIN custody_attempt a ON a.id=d.attempt_id
LEFT JOIN context_deletion_checkpoint c ON c.attempt_id=a.id AND c.root_id=d.root_id
WHERE d.root_id=$1 AND d.id=$2 AND a.id=$3`, run.RootID, requestID, loc.AttemptID).
				Scan(&raw, &lifecycleRaw, &deletionRaw, &deleted, &purged, &acknowledged, &finalized, &lifecycleCurrent)
		})
		if finalized && lifecycleCurrent {
			var decision value.LifecycleDecision
			var lifecycle, deletion audit.Receipt
			if json.Unmarshal(raw, &decision) != nil || !decision.Valid() || decision.ID != requestID || decision.Location != loc ||
				!decision.Effective.ExpiresAt.Equal(anchor) || !decision.Previous.ExpiresAt.Equal(run.ExpiresAt) ||
				json.Unmarshal(lifecycleRaw, &lifecycle) != nil || !lifecycle.ValidLifecycle(run.RootID, requestID) ||
				json.Unmarshal(deletionRaw, &deletion) != nil || !deletion.ValidContextDeletion(run.RootID, loc.AttemptID) || deletion.Version == "" || deletion.Version == "null" ||
				!deleted.Valid || !purged.Valid || !acknowledged.Valid || purged.Time.Before(applied) ||
				acknowledged.Time.Before(purged.Time) || deleted.Time.Before(acknowledged.Time) || !deleted.Time.Before(run.ExpiresAt) {
				t.Fatal("installed erasure: signed lifecycle or audited managed deletion proof invalid")
			}
			return deleted.Time, decision, lifecycle, deletion
		}
		if err := installedJourneyPause(ctx, time.Second); err != nil {
			t.Fatalf("installed erasure: before original expiry, finalized=%t lifecycle acknowledged=%t: %v", finalized, lifecycleCurrent, err)
		}
	}
}
