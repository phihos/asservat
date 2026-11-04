package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Each entry owns the existing pristine protected SQL/S3 fixture. Human,
// endpoint and process observations remain explicit synthetic component facts.
func TestVerifiedProfileAcquisitionWithRealPostgres(t *testing.T) {
	qualifyProfileAcquisitionFixture(t, false)
}

func TestLegacyProfileAcquisitionWithRealPostgres(t *testing.T) {
	qualifyProfileAcquisitionFixture(t, true)
}

func qualifyProfileAcquisitionFixture(t *testing.T, legacy bool) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		t.Run("profile-acquisition-publication", func(t *testing.T) {
			withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(t *testing.T, f *queryLedgerFixture) {
				if !legacy {
					refuseRetainedProfileSummaryDowngrade(t, f)
				}
			}, true, false, legacy)
		})
	})
}

type profileAcquisitionPublicationProbe struct {
	verified artifact.ContextVerificationResult
	record   audit.ContextVerification
	legacy   bool
}

func qualifyProfileAcquisitionBeforePublication(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, publisher evidence.ContextPublisher, check *postgres.ContextPublications, e artifact.ContextExpectation, copies artifact.Copies, expected artifact.AcquisitionWindow, legacy bool) profileAcquisitionPublicationProbe {
	t.Helper()
	ctx := f.ctx
	var purposeColumns bool
	if err := f.admin.QueryRow(ctx, `SELECT bool_and(
 has_column_privilege(purpose,'context_verification',col,'INSERT')=(purpose='context_verify_runtime')
 AND NOT has_column_privilege(purpose,'context_verification',col,'UPDATE'))
 FROM unnest(ARRAY['context_verify_runtime','context_verification_audit_runtime','context_publish_runtime','context_catalog_read_runtime','context_progress_read_runtime']) purpose
 CROSS JOIN unnest(ARRAY['acquisition_started_at','acquisition_completed_at']) col`).Scan(&purposeColumns); err != nil || !purposeColumns {
		t.Fatal("timing columns require verifier INSERT only, never audit/publish/catalog/progress writes", purposeColumns, err)
	}
	a, err := publisher.Authority.CheckContextPublication(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := check.RecordContextVerification(ctx, e, copies, a, artifact.ContextVerificationResult{NativeBytes: 1}); err == nil {
		t.Fatal("new profile verification accepted without authenticated timing")
	}
	var records int
	if err := f.admin.QueryRow(ctx, "SELECT count(*) FROM context_verification WHERE capture_id=$1", e.CaptureUID).Scan(&records); err != nil || records != 0 {
		t.Fatal("missing timing left a verification row", records, err)
	}
	verified, err := publisher.Verifier.VerifyContext(ctx, e, copies)
	if err != nil || verified.Acquisition == nil || !verified.Acquisition.Equal(expected) {
		t.Fatal("verified timing differs from actual synthetic producer window", verified.Acquisition, expected, err)
	}
	record, err := check.RecordContextVerification(ctx, e, copies, a, verified)
	if err != nil || record.Acquisition == nil || !record.Acquisition.Equal(expected) {
		t.Fatal("new profile verification lost authenticated window", record.Acquisition, err)
	}
	qualifyProfileAcquisitionSQLPair(t, f, e.CaptureUID)
	changed := verified.Clone()
	changed.Acquisition.CompletedAt = changed.Acquisition.CompletedAt.Add(time.Microsecond)
	if _, err := check.RecordContextVerification(ctx, e, copies, a, changed); err == nil {
		t.Fatal("verification replay replaced authenticated window")
	}
	if _, err := f.admin.Exec(ctx, "UPDATE context_verification SET acquisition_completed_at=acquisition_completed_at+interval '1 microsecond' WHERE capture_id=$1", e.CaptureUID); err == nil {
		t.Fatal("unaudited acquisition window mutable")
	}
	if legacy {
		// Explicit administrator-only historical fixture, before any audit is
		// written. Runtime cannot erase or backfill a verification verdict.
		tx, err := f.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		for _, statement := range []string{"ALTER TABLE context_verification DISABLE TRIGGER context_verification_immutable", "UPDATE context_verification SET acquisition_started_at=NULL,acquisition_completed_at=NULL WHERE capture_id=$1", "ALTER TABLE context_verification ENABLE TRIGGER context_verification_immutable"} {
			var args []any
			if bytes.Contains([]byte(statement), []byte("$1")) {
				args = []any{e.CaptureUID}
			}
			if _, err := tx.Exec(ctx, statement, args...); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		record.Acquisition = nil
	}
	return profileAcquisitionPublicationProbe{verified: verified, record: record, legacy: legacy}
}

func qualifyProfileAcquisitionSQLPair(t *testing.T, f *capacitySQLFixture, captureID string) {
	t.Helper()
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	// Reuse the real134 CHECK contract on a temporary copy, without the
	// immutable-row trigger masking partial/reversed/range constraint failures.
	if _, err := tx.Exec(f.ctx, "CREATE TEMP TABLE acquisition_pair_probe (LIKE context_verification INCLUDING CONSTRAINTS) ON COMMIT DROP"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, "INSERT INTO acquisition_pair_probe SELECT * FROM context_verification WHERE capture_id=$1", captureID); err != nil {
		t.Fatal(err)
	}
	for _, set := range []string{"acquisition_started_at=NULL", "acquisition_completed_at=NULL", "acquisition_completed_at=acquisition_started_at-interval '1 microsecond'", "acquisition_started_at='infinity'", "acquisition_completed_at='infinity'", "acquisition_started_at='0001-01-01T00:00:00Z'"} {
		if _, err := tx.Exec(f.ctx, "SAVEPOINT invalid_pair"); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(f.ctx, "UPDATE acquisition_pair_probe SET "+set)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Fatal("acquisition SQL pair CHECK did not reject", set, err)
		}
		if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT invalid_pair"); err != nil {
			t.Fatal(err)
		}
	}
}

func qualifyProfileAcquisitionAfterPublication(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, publisher evidence.ContextPublisher, check *postgres.ContextPublications, e artifact.ContextExpectation, copies artifact.Copies, probe profileAcquisitionPublicationProbe) {
	t.Helper()
	ctx := f.ctx
	a, err := publisher.Authority.CheckContextPublication(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := check.RecordContextVerification(ctx, e, copies, a, probe.verified)
	before, _ := json.Marshal(probe.record)
	after, _ := json.Marshal(replay)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("publication replay changed timing or historical audit bytes", err)
	}
	var storedDigest []byte
	var originalReceipt audit.Receipt
	var objectHash []byte
	if err := f.admin.QueryRow(ctx, "SELECT audit_digest,audit_object_key,audit_object_version,audit_object_etag,audit_object_bytes,audit_object_sha256 FROM context_verification WHERE capture_id=$1", e.CaptureUID).Scan(&storedDigest, &originalReceipt.Key, &originalReceipt.Version, &originalReceipt.ETag, &originalReceipt.Bytes, &objectHash); err != nil {
		t.Fatal(err)
	}
	copy(originalReceipt.SHA256[:], objectHash)
	digest := sha256.Sum256(after)
	if !bytes.Equal(storedDigest, digest[:]) {
		t.Fatal("stored audit does not bind the same acquisition metadata")
	}
	receipt, err := publisher.Audit.WriteContextVerification(ctx, replay)
	if err != nil || receipt != originalReceipt || !receipt.ValidContextVerification(s.a.RootID, e.CaptureUID) {
		t.Fatal("same immutable timing audit did not replay", err)
	}
	pool := f.fixturePool("context_catalog_read_runtime", "synthetic-context-read")
	defer pool.Close()
	catalog, err := postgres.NewContextPublications(ctx, pool, s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := catalog.ContextDownloadEvidence(ctx, e.Registration.Location.ArtifactID)
	if err != nil || metadata.ProfileAcquisition == nil {
		t.Fatal("joined catalog lost profile acquisition metadata", err)
	}
	p := metadata.ProfileAcquisition
	if p.Type != e.Profile.Type || p.Mode != e.Profile.Mode || p.DurationMillis != e.Profile.DurationMillis || p.ForceGC != e.Profile.ForceGC || (p.Acquisition == nil) != probe.legacy || p.Acquisition != nil && !p.Acquisition.Equal(*probe.verified.Acquisition) {
		t.Fatal("joined catalog changed accepted parameters or verified window", p)
	}
	progressPool := f.fixturePool("context_progress_read_runtime", "synthetic-context-progress-read")
	defer progressPool.Close()
	progress, err := postgres.NewContextProgressReads(ctx, progressPool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	request := progressQuery(t, ctx, s)
	result, err := progress.ReadContextProgress(ctx, request)
	if err != nil || result.Phase != "Succeeded" {
		t.Fatal("progress failed acquisition audit reconstruction", result, err)
	}
	target := s.a.Plan.Input.Target.Target()
	history, err := progress.ListCaptureHistory(ctx, capture.HistoryQuery{RootID: s.a.RootID, Target: authorization.WorkloadScope(target.ClusterID, target.NamespaceUID, target.WorkloadUID), Origins: []capture.HistoryOrigin{capture.HistoryManual}, Limit: 20, Identity: request.Identity, Recovery: request.Recovery})
	if err != nil || len(history.Entries) != 1 || history.Entries[0].CaptureID != e.CaptureUID || history.Entries[0].Phase != "Succeeded" {
		t.Fatal("history failed acquisition audit reconstruction", history, err)
	}
	if _, err := f.admin.Exec(ctx, "UPDATE context_verification SET acquisition_started_at=NULL,acquisition_completed_at=NULL WHERE capture_id=$1", e.CaptureUID); err == nil && !probe.legacy {
		t.Fatal("acknowledged acquisition window mutable")
	}
	t.Logf("actual verified profile acquisition: new/replay/immutable/catalog/progress/history; legacy unknown=%t; no native endpoint or process-attribution qualification", probe.legacy)
}
