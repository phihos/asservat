package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/postgres"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type processingErasureAuditFence struct {
	*postgres.ProcessingDecisions
	beforeAudit func(context.Context, value.ProcessingAuthority, privacyapp.ProcessingDecision)
}

func (s processingErasureAuditFence) PrepareProcessing(ctx context.Context, a value.ProcessingAuthority, d privacyapp.ProcessingDecision) (privacyapp.ProcessingPrepared, error) {
	out, err := s.ProcessingDecisions.PrepareProcessing(ctx, a, d)
	if err == nil && out.Receipt == nil {
		s.beforeAudit(ctx, a, out.Decision)
	}
	return out, err
}

// Starts with an independently verified, published, closed-writer attempt
// and uses the compiled hub login for erasure and status. Identity, protected
// privacy policy and signing keys are synthetic inputs in this service fixture.
func qualifyProcessingEarlyErasure(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, bound *objectstore.CustodyStore, keys authorityTestKeys, s3admin *s3.Client, bucket string, s captureAdmissionScenario, processing *processingTestFixture, published artifact.PublishedContext) {
	t.Helper()
	root, installation := s.a.RootID, s.recovery.installation
	reg := published.Expectation.Registration
	loc := reg.Location
	decisions, err := postgres.NewProcessingDecisions(ctx, hub, root, s.recovery.guard)
	if err != nil {
		t.Fatal("erasure decision through the compiled hub login", err)
	}
	scopes, err := postgres.NewProcessingInventory(ctx, hub, root, s.recovery.guard)
	if err != nil {
		t.Fatal("erasure artifact scope through the compiled hub login", err)
	}
	catalog, err := postgres.NewContextPublications(ctx, hub, root)
	if err != nil {
		t.Fatal("erasure catalog read", err)
	}
	before, err := catalog.RetainedAudience(ctx, loc.ArtifactID)
	if err != nil || !before.ExpiresAt.Equal(reg.ExpiresAt) {
		t.Fatal("erasure target was not readable before the request", err)
	}
	request := value.ProcessingChange{Action: value.RequestEarlyErasure, RequestID: custodyID(), RequestedArtifactID: loc.ArtifactID}
	statusReader := privacyapp.ProcessingErasureStatus{RootID: root, InstallationID: installation, Policies: processing.policy, Recovery: s.recovery.reader, Status: decisions, Now: time.Now}
	if _, err := statusReader.Get(ctx, processing.actor, request.RequestID); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("unknown erasure request acquired a status", err)
	}
	unaudited := 0
	service := processing.service
	service.ArtifactScopes = scopes
	service.Decisions = processingErasureAuditFence{decisions, func(call context.Context, a value.ProcessingAuthority, d privacyapp.ProcessingDecision) {
		unaudited++
		if d.Change.RequestID != request.RequestID || d.Change.Scope.Location != loc || d.Intent.Lifecycle == nil || d.Intent.Lifecycle.Policy.Lane != "normal" {
			t.Fatal("prepared erasure changed its exact target or normal audit lane")
		}
		if _, err := decisions.ApplyProcessing(call, a, d); err == nil {
			t.Fatal("erasure applied without the independent operation audit")
		}
		installedJourneyReadOnly(t, call, admin, func(tx pgx.Tx) error {
			var unchanged bool
			err := tx.QueryRow(call, `SELECT effective_expires_at=expires_at AND effective_delete_by=delete_by AND retention_sequence=0
 AND NOT EXISTS(SELECT 1 FROM retention_decision WHERE attempt_id=custody_attempt.id)
 AND NOT EXISTS(SELECT 1 FROM operation_audit WHERE root_id=$1 AND id=$2)
 FROM custody_attempt WHERE id=$3`, root, request.RequestID, loc.AttemptID).Scan(&unchanged)
			if err != nil || !unchanged {
				t.Fatal("unaudited erasure altered custody or recorded an audit", err)
			}
			return nil
		})
	}}
	accepted, err := service.Change(ctx, processing.actor, request)
	if err != nil || accepted.State != "erasureRequested" || accepted.RequestID != request.RequestID || accepted.OperationID != request.RequestID || unaudited != 1 {
		t.Fatal("exact erasure was not accepted after normal audit", accepted, err, unaudited)
	}
	var raw []byte
	installedJourneyReadOnly(t, ctx, admin, func(tx pgx.Tx) error {
		var effect, audited bool
		err := tx.QueryRow(ctx, `
SELECT d.decision_json, a.anchor_at=$4 AND a.expires_at=$5 AND a.delete_by=$6
  AND a.effective_expires_at=$4 AND a.effective_delete_by=$6 AND a.retention_sequence=1
  AND d.previous_expires_at=$5 AND d.previous_delete_by=$6 AND d.expires_at=$4 AND d.delete_by=$6
  AND d.audit_acknowledged_at IS NULL,
 o.lane='normal' AND o.intent->>'Name'='request_early_erasure'
  AND o.intent_receipt IS NOT NULL AND o.outcome_receipt IS NOT NULL
  AND p.audit_digest=sha256(convert_to(o.outcome_receipt::text,'UTF8'))
  AND h.binding=o.intent->'Lifecycle'
  AND h.intent_completion->'Receipt'=o.intent_receipt AND h.outcome_completion->'Receipt'=o.outcome_receipt
FROM processing_decision p
JOIN retention_decision d ON d.id=p.id AND d.root_id=p.root_id
JOIN custody_attempt a ON a.id=d.attempt_id
JOIN operation_audit o ON o.id=p.id AND o.root_id=p.root_id
JOIN operation_audit_lifecycle h ON h.operation_id=o.id AND h.root_id=o.root_id AND h.lane=o.lane
WHERE p.root_id=$1 AND p.id=$2 AND p.applied_at IS NOT NULL AND a.id=$3`, root, request.RequestID, loc.AttemptID, reg.AnchorAt, reg.ExpiresAt, reg.DeleteBy).Scan(&raw, &effect, &audited)
		if err != nil || !effect || !audited {
			t.Fatal("erasure lacked the exact retained cutoff or independently acknowledged audit", err)
		}
		return nil
	})
	var lifecycle value.LifecycleDecision
	if json.Unmarshal(raw, &lifecycle) != nil || !lifecycle.Valid() || lifecycle.ID != request.RequestID || lifecycle.Location != loc {
		t.Fatal("exact erasure lifecycle decision did not validate")
	}
	if _, err := catalog.RetainedAudience(ctx, loc.ArtifactID); !errors.Is(err, value.ErrUnavailable) || !time.Now().Before(reg.ExpiresAt) {
		t.Fatal("new reads did not stop at erasure before original expiry", err)
	}
	readStatus := func(auditState value.ProcessingErasureAuditState, deletionState value.ProcessingErasureDeletionState) value.ProcessingErasureStatus {
		t.Helper()
		got, err := statusReader.Get(ctx, processing.actor, request.RequestID)
		if err != nil || got.ArtifactID != loc.ArtifactID || !got.AccessUntil.Equal(reg.AnchorAt) ||
			!got.DeleteBy.Equal(reg.DeleteBy) || !got.EffectiveDeleteBy.Equal(reg.DeleteBy) ||
			got.AuditState != auditState || got.DeletionState != deletionState {
			t.Fatal("unexpected exact erasure status", got, err)
		}
		return got
	}
	pending := readStatus(value.ProcessingErasureAuditPending, value.ProcessingErasureDeletionPending)
	replay, err := service.Change(ctx, processing.actor, request)
	if err != nil || replay.RequestID != accepted.RequestID || replay.OperationID != accepted.OperationID ||
		replay.Sequence != accepted.Sequence || replay.Revision != accepted.Revision || replay.State != accepted.State || unaudited != 1 {
		t.Fatal("same-key erasure replay changed the original effect", replay, err)
	}
	replayed := readStatus(value.ProcessingErasureAuditPending, value.ProcessingErasureDeletionPending)
	if !replayed.AcceptedAt.Equal(pending.AcceptedAt) {
		t.Fatal("same-key erasure replay changed the original acceptance")
	}

	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	const key = "synthetic-privacy-worker"
	pins := map[string]ed25519.PublicKey{key: pub}
	signer, err := jose.NewLifecycleSignatures(root, key, private, pins)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jose.NewLifecycleSignatures(root, "", nil, pins)
	if err != nil {
		t.Fatal(err)
	}
	retentionPool := poolFor("retention_audit_runtime", "synthetic-retention-audit")
	defer retentionPool.Close()
	journal, err := postgres.NewRetention(ctx, retentionPool, root)
	if err != nil {
		t.Fatal("erasure lifecycle ledger", err)
	}
	publisher := privacyapp.LifecyclePublisher{Ledger: journal, Objects: &objectstore.LifecycleObjects{Store: store, Seal: keys, Open: keys, Signer: signer, Verifier: verifier}}
	if attempted, err := publisher.PublishOne(ctx); err != nil || !attempted {
		t.Fatal("publish exact signed erasure lifecycle record", attempted, err)
	}
	if attempted, err := publisher.PublishOne(ctx); err != nil || attempted {
		t.Fatal("erasure lifecycle record was not durably acknowledged exactly once", attempted, err)
	}
	readStatus(value.ProcessingErasureAuditAcknowledged, value.ProcessingErasureDeletionPending)
	verifyProcessingErasureReceipt(t, ctx, admin, s3admin, bucket, keys, verifier, lifecycle)

	deletion := qualifyProcessingErasureCleanup(t, ctx, admin, poolFor, store, bound, keys, s, reg, key, private, pins)
	terminal := readStatus(value.ProcessingErasureAuditAcknowledged, value.ProcessingErasureDeleted)
	if terminal.DeletedAt == nil || !terminal.DeletedAt.Equal(deletion) || !terminal.AcceptedAt.Equal(pending.AcceptedAt) {
		t.Fatal("verified managed deletion did not match the exact original request", terminal)
	}
	assertErasedInventory(t, ctx, s3admin, bucket, loc.Prefix())
}

func verifyProcessingErasureReceipt(t *testing.T, ctx context.Context, admin *pgxpool.Pool, s3admin *s3.Client, bucket string, keys authorityTestKeys, verifier privacyapp.LifecycleVerifier, decision value.LifecycleDecision) {
	t.Helper()
	var raw []byte
	installedJourneyReadOnly(t, ctx, admin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT audit_receipt_json FROM retention_decision WHERE root_id=$1 AND id=$2 AND audit_acknowledged_at IS NOT NULL`, decision.RootID, decision.ID).Scan(&raw)
	})
	var receipt audit.Receipt
	if json.Unmarshal(raw, &receipt) != nil || !receipt.ValidLifecycle(decision.RootID, decision.ID) {
		t.Fatal("acknowledged erasure lifecycle version unavailable")
	}
	object, err := s3admin.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &receipt.Key, VersionId: &receipt.Version, IfMatch: &receipt.ETag})
	if err != nil {
		t.Fatal("read exact erasure lifecycle version", err)
	}
	defer object.Body.Close()
	body, err := io.ReadAll(io.LimitReader(object.Body, receipt.Bytes+1))
	if err != nil || int64(len(body)) != receipt.Bytes || sha256.Sum256(body) != receipt.SHA256 ||
		aws.ToString(object.VersionId) != receipt.Version || aws.ToString(object.ETag) != receipt.ETag {
		t.Fatal("erasure lifecycle ciphertext differs from its exact receipt", err)
	}
	if err = framed.VerifyLifecycle(ctx, keys, verifier, decision, body); err != nil {
		t.Fatal("verify signed encrypted erasure decision", err)
	}
}

func qualifyProcessingErasureCleanup(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, bound *objectstore.CustodyStore, keys authorityTestKeys, s captureAdmissionScenario, reg artifact.Registration, key string, private ed25519.PrivateKey, pins map[string]ed25519.PublicKey) time.Time {
	t.Helper()
	root, installation := s.a.RootID, s.recovery.installation
	facet := func(role, password string) *postgres.ContextDeletions {
		p := poolFor(role, password)
		t.Cleanup(p.Close)
		v, err := postgres.NewContextDeletions(ctx, p, root, installation)
		if err != nil {
			t.Fatal("erasure cleanup facet", role, err)
		}
		return v
	}
	cleanup := facet("context_cleanup_runtime", "synthetic-context-cleanup")
	due, err := cleanup.DueContextDeletions(ctx)
	if err != nil || !slices.Contains(due, reg.Location) || !time.Now().Before(reg.ExpiresAt) {
		t.Fatal("exact attempt was not due for cleanup before original expiry", err)
	}
	ack := facet("context_cleanup_audit_runtime", "synthetic-context-cleanup-audit")
	finalize := facet("context_cleanup_finalize_runtime", "synthetic-context-cleanup-finalize")
	signatures, err := jose.NewContextDeletionSignatures(root, key, private, pins)
	if err != nil {
		t.Fatal(err)
	}
	cleaner := privacyapp.ContextCleaner{Ledger: cleanup, Audit: ack, Finalize: finalize, Purger: bound,
		Objects:  &objectstore.ContextDeletionObjects{Store: store, Seal: keys, Open: keys, Signer: signatures, Verifier: signatures},
		Recovery: s.recovery.reader, Now: time.Now}
	if err = cleaner.Clean(ctx, reg.Location); err != nil {
		t.Fatal("erase exact closed writer through actual purge, audit and finalization", err)
	}
	var deleted, purged, acknowledged time.Time
	var objects, bytes, full, replay int64
	installedJourneyReadOnly(t, ctx, admin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
SELECT a.deleted_at, d.purged_at, d.audit_acknowledged_at, ca.charged_objects, ca.charged_bytes, cc.charged_full, cc.charged_replay
FROM custody_attempt a
JOIN context_deletion_checkpoint d ON d.attempt_id=a.id AND d.root_id=$1
JOIN custody_allocation ca ON ca.id=a.allocation_id
JOIN context_control_account cc ON cc.allocation_id=ca.id
WHERE a.id=$2 AND a.state='deleted' AND d.finalization_xid IS NOT NULL`, root, reg.Location.AttemptID).
			Scan(&deleted, &purged, &acknowledged, &objects, &bytes, &full, &replay)
	})
	if purged.Before(reg.AnchorAt) || acknowledged.Before(purged) || deleted.Before(acknowledged) ||
		!deleted.Before(reg.ExpiresAt) || objects != 0 || bytes != 0 || full != 1 || replay != 1 {
		t.Fatal("erasure changed cleanup ordering or released the wrong charge", deleted, purged, acknowledged, objects, bytes, full, replay)
	}
	return deleted
}

func assertErasedInventory(t *testing.T, ctx context.Context, s3admin *s3.Client, bucket, prefix string) {
	t.Helper()
	keys, err := s3admin.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix, MaxKeys: aws.Int32(4)})
	if err != nil || keys.IsTruncated == nil || aws.ToBool(keys.IsTruncated) || len(keys.Contents) != 0 {
		t.Fatal("erasure left current evidence objects or incomplete inventory", err)
	}
	versions, err := s3admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &prefix, MaxKeys: aws.Int32(4)})
	if err != nil || versions.IsTruncated == nil || aws.ToBool(versions.IsTruncated) || len(versions.Versions) != 0 || len(versions.DeleteMarkers) != 0 {
		t.Fatal("erasure left evidence versions, markers or incomplete inventory", err)
	}
	uploads, err := s3admin.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket, Prefix: &prefix, MaxUploads: aws.Int32(4)})
	if err != nil || uploads.IsTruncated == nil || aws.ToBool(uploads.IsTruncated) || len(uploads.Uploads) != 0 {
		t.Fatal("erasure left evidence uploads or incomplete inventory", err)
	}
}
