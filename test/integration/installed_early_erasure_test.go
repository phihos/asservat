package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"k8s.io/client-go/kubernetes"
)

type installedEarlyErasure struct {
	hub                                     kubernetes.Interface
	providers                               *initialRuntimeNativeProviders
	installation, namespace, evidenceBucket string
}

type installedErasureEvent struct {
	installedProcessingEvent
	Status      value.ProcessingErasureStatus `json:"status"`
	OperationID string                        `json:"operationID"`
}

// The installed React operator supplies the exact destructive request. The
// bounded fixture fault only delays the cleaner's evidence inventory so the
// browser can observe a real pending state before installed cleanup resumes.
func (s installedEarlyErasure) qualify(t *testing.T, parent context.Context, cluster string, run installedProcessingRun) {
	t.Helper()
	ctx, cancel := context.WithDeadline(parent, run.ExpiresAt)
	defer cancel()
	defer func() {
		if t.Failed() {
			run.Diagnose()
		}
	}()
	loc := artifact.Location{ClusterID: cluster, ArtifactID: run.ArtifactID}
	var captureID string
	var anchor time.Time
	installedJourneyReadOnly(t, ctx, run.SQL, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
SELECT l.capture_id::text, a.id::text, a.anchor_at
FROM context_case_locator l JOIN custody_attempt a ON a.artifact_id=l.artifact_id AND a.cluster_id=l.cluster_id
WHERE l.root_id=$1 AND l.case_id=$2 AND l.artifact_id=$3 AND l.cluster_id=$4
 AND a.state='stored_unpublished' AND a.retention_sequence=0 AND a.expires_at=a.effective_expires_at AND a.delete_by=a.effective_delete_by`,
			run.RootID, run.CaseID, loc.ArtifactID, loc.ClusterID).Scan(&captureID, &loc.AttemptID, &anchor)
	})
	original, err := readInstalledDeletionState(ctx, run.SQL, run.RootID, loc)
	if err != nil || loc.Validate() != nil || !authorization.UUID(captureID) || !original.Now.Before(run.ExpiresAt) ||
		!original.ExpiresAt.Equal(run.ExpiresAt) || !run.ExpiresAt.Before(original.DeleteBy) || original.Copies != 4 ||
		original.Objects != 4 || original.Bytes < 1 || original.Full < 1 || original.Replay < 1 ||
		original.Deleted || original.Checkpoint || original.Lease.Valid || len(original.Writer) != 32 {
		t.Fatal("installed erasure: original published writer and charges unavailable", err)
	}
	p := s.providers
	client := func(key, secret string) *s3.Client {
		return s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: &p.desired.AuditStore.Endpoint, UsePathStyle: true,
			Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: p.client, RetryMaxAttempts: 1})
	}
	store := client("synthetic-only", "synthetic-only-secret")
	cleaner := client("evidence-delete-continuation", "evidence-delete-continuation-secret")
	prefix := loc.Prefix()
	fault := installedDeletionFault{store: store, bucket: s.evidenceBucket}
	fault.original, err = fault.read(ctx)
	if err != nil {
		t.Fatal("installed erasure: original evidence policy unavailable", err)
	}
	if unexpected, ok := installedDeletionInstalledPolicy(fault.original, installerEvidenceBucketPolicy(s.evidenceBucket)); !ok {
		t.Fatal("installed erasure: unexpected original fixture policy", unexpected)
	}
	fault.denied, err = installedDeletionFaultPolicy(fault.original, s.evidenceBucket, loc)
	if err != nil {
		t.Fatal("installed erasure: exact cleaner fault unavailable", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := fault.restore(cleanup); err != nil {
			t.Error("installed erasure: original evidence policy restoration", err)
		}
	})
	if ok, err := installedDeletionInventoryAccess(ctx, cleaner, s.evidenceBucket, prefix, false); err != nil || !ok {
		t.Fatal("installed erasure: original cleaner inventory unavailable", err)
	}
	if err = fault.arm(ctx); err != nil {
		t.Fatal("installed erasure: arm scoped inventory fault", err)
	}
	if err = installedDeletionWaitAccess(ctx, cleaner, s.evidenceBucket, prefix, true); err != nil {
		t.Fatal("installed erasure: scoped inventory denial not established", err)
	}
	session := run.Identity.consoleSession(t, ctx, run.PublicRoot, run.Address, run.Origin)
	driver := startInstalledProcessingBrowser(t, ctx, session, run.Address, loc.ArtifactID, run.CaseID, "installed-erasure-browser.mjs")
	next := func(want string) installedErasureEvent {
		t.Helper()
		var event installedErasureEvent
		driver.read(&event)
		if event.Kind == "failed" {
			t.Fatalf("installed erasure browser stage=%s reason=%s check=%s", event.Stage, event.Reason, event.Check)
		}
		if event.Kind != want {
			t.Fatalf("installed erasure expected %s, received %s", want, event.Kind)
		}
		return event
	}
	accepted := next("accepted")
	d := accepted.Discovery
	candidate := d.Candidate
	if !candidate.Valid() || candidate.ArtifactID != loc.ArtifactID || candidate.ClusterID != loc.ClusterID || candidate.CaseID != run.CaseID || candidate.CaptureID != captureID ||
		candidate.Origin != "capture" || len(candidate.Parents) != 0 || !candidate.AnchorAt.Equal(anchor) ||
		!candidate.ExpiresAt.Equal(original.ExpiresAt) || !candidate.DeleteBy.Equal(original.DeleteBy) || d.ResponseBytes < 1 || d.ResponseBytes > audit.OperationOutputLimit {
		t.Fatal("installed erasure: browser discovery returned a different candidate")
	}
	checkInstalledErasureReadAudit(t, ctx, run, d.RequestID, "search_processing_evidence", d.ResponseBytes)
	requestID := accepted.Receipt.RequestID
	if !authorization.UUID(requestID) || accepted.Key != requestID || accepted.Receipt.OperationID != requestID || accepted.Receipt.RootID != run.RootID ||
		accepted.Receipt.State != "erasureRequested" || accepted.Receipt.RuleID != "" || accepted.Receipt.Revision != 0 ||
		!authorization.UUID(accepted.Receipt.Epoch) || accepted.Receipt.Sequence < 1 {
		t.Fatal("installed erasure: invalid accepted exact request receipt")
	}
	var applied time.Time
	installedJourneyReadOnly(t, ctx, run.SQL, func(tx pgx.Tx) error {
		var exact bool
		err := tx.QueryRow(ctx, `
SELECT p.applied_at, p.action='request_early_erasure' AND p.rule_id IS NULL AND p.result_revision=0
 AND p.result_sequence=$4 AND pr.epoch=$5 AND d.decision_json=p.erasure_decision
 AND a.anchor_at=$6 AND a.expires_at=$7 AND a.delete_by=$8 AND a.effective_expires_at=$6 AND a.effective_delete_by=$8
 AND d.previous_expires_at=$7 AND d.previous_delete_by=$8 AND d.expires_at=$6 AND d.delete_by=$8
 AND a.retention_sequence=1 AND d.sequence=1 AND o.lane='normal' AND o.intent->>'Name'='request_early_erasure'
 AND o.intent_receipt IS NOT NULL AND o.outcome_receipt IS NOT NULL AND p.audit_digest=sha256(convert_to(o.outcome_receipt::text,'UTF8'))
 AND h.binding=o.intent->'Lifecycle' AND h.intent_completion->'Receipt'=o.intent_receipt AND h.outcome_completion->'Receipt'=o.outcome_receipt
FROM processing_decision p
JOIN processing_root pr ON pr.root_id=p.root_id
JOIN retention_decision d ON d.id=p.id AND d.root_id=p.root_id
JOIN custody_attempt a ON a.id=d.attempt_id
JOIN operation_audit o ON o.id=p.id AND o.root_id=p.root_id
JOIN operation_audit_lifecycle h ON h.operation_id=o.id AND h.root_id=o.root_id AND h.lane=o.lane
WHERE p.root_id=$1 AND p.id=$2 AND a.id=$3`,
			run.RootID, requestID, loc.AttemptID, accepted.Receipt.Sequence, accepted.Receipt.Epoch, anchor, original.ExpiresAt, original.DeleteBy).Scan(&applied, &exact)
		if err != nil || !exact || !applied.Before(run.ExpiresAt) {
			t.Fatal("installed erasure: accepted receipt lacks exact cutoff or normal audit", err)
		}
		return nil
	})
	out, err := run.Call(ctx, "get_case", map[string]string{"case_id": run.CaseID})
	var refusal struct {
		Code string `json:"code"`
	}
	if err != nil || out.Status != "error" || json.Unmarshal(out.Data, &refusal) != nil || refusal.Code != "NotAvailable" || !time.Now().Before(run.ExpiresAt) {
		t.Fatal("installed erasure: new ordinary read lacked expected refusal before original expiry", err, out.Status, refusal.Code)
	}
	driver.send(map[string]bool{"continue": true})
	pending := next("pending")
	checkStatus := func(event installedErasureEvent, state value.ProcessingErasureDeletionState) {
		t.Helper()
		status := event.Status
		if status.RequestID != requestID || status.ArtifactID != loc.ArtifactID || !status.AcceptedAt.Equal(applied) ||
			!status.AccessUntil.Equal(anchor) || !status.DeleteBy.Equal(original.DeleteBy) || !status.EffectiveDeleteBy.Equal(original.DeleteBy) ||
			status.DeletionState != state || event.OperationID == requestID || event.OperationID == d.RequestID {
			t.Fatal("installed erasure: browser status changed original identity, cutoff or state")
		}
		checkInstalledErasureReadAudit(t, ctx, run, event.OperationID, "get_processing_erasure", 0)
	}
	checkStatus(pending, value.ProcessingErasureDeletionPending)
	current, err := readInstalledDeletionState(ctx, run.SQL, run.RootID, loc)
	if err != nil || pending.Status.DeletedAt != nil || current.Deleted || current.Checkpoint || current.Copies != 4 ||
		!current.ExpiresAt.Equal(anchor) || !current.DeleteBy.Equal(original.DeleteBy) || !bytes.Equal(current.Writer, original.Writer) ||
		!bytes.Equal(current.Receipts, original.Receipts) || current.Objects != original.Objects || current.Bytes != original.Bytes {
		t.Fatal("installed erasure: pending state did not retain exact copies and charges", err)
	}
	if err = fault.restore(ctx); err != nil {
		t.Fatal("installed erasure: restore original evidence policy", err)
	}
	if err = installedDeletionWaitAccess(ctx, cleaner, s.evidenceBucket, prefix, false); err != nil {
		t.Fatal("installed erasure: cleaner inventory did not recover", err)
	}
	terminal, decision, lifecycleReceipt, deletionReceipt := awaitInstalledEarlyErasure(t, ctx, run, requestID, loc, applied, anchor)
	verifyInstalledRetentionLifecycle(t, ctx, s.hub, p, s.namespace, s.installation, run.RootID, decision, lifecycleReceipt)
	readInstalledAuditObject(t, ctx, store, p.desired.AuditStore.Bucket, deletionReceipt)
	assertErasedInventory(t, ctx, store, s.evidenceBucket, prefix)
	current, err = readInstalledDeletionState(ctx, run.SQL, run.RootID, loc)
	if err != nil || !current.Deleted || !current.Checkpoint || current.Copies != 0 || current.Objects != 0 || current.Bytes != 0 ||
		current.Full != original.Full || current.Replay != original.Replay || !current.ExpiresAt.Equal(anchor) || !current.DeleteBy.Equal(original.DeleteBy) {
		t.Fatal("installed erasure: finalization changed exact scope or released control charges", err)
	}
	driver.send(map[string]bool{"continue": true})
	verified := next("verified")
	checkStatus(verified, value.ProcessingErasureDeleted)
	if verified.Status.AuditState != value.ProcessingErasureAuditAcknowledged || verified.Status.DeletedAt == nil ||
		!verified.Status.DeletedAt.Equal(terminal) || verified.OperationID == pending.OperationID || !time.Now().Before(run.ExpiresAt) {
		t.Fatal("installed erasure: reloaded browser did not report acknowledged verified deletion before original expiry")
	}
	next("complete")
	awaitInstalledProcessingBrowser(t, driver)
	t.Log("installed erasure: ordinary access stopped before original expiry after the operator discovered and confirmed one artifact. Pending status retained the original copies. Reloaded status reported verified managed deletion and the signed lifecycle record.")
}

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
