package integration

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real SQL/publication/S3/audit and native context worker. Human identity,
// placement/allocation and installation acceptance remain explicit fixture inputs.
// No public native-work channel, regional cache or download endpoint is faked.
func qualifyDownloadStop(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) (captureAdmissionScenario, artifact.PublishedContext)) {
	t.Helper()
	t.Run("prepaid-download-stop-no-read-and-original-replay", func(t *testing.T) {
		scenario, published := create(t)
		e := published.Expectation
		root := scenario.a.RootID
		// These are the only additional reads used by this private source/locator
		// facet. There is no new write/owner/schema permission.
		if _, err := admin.Exec(ctx, "GRANT SELECT ON context_case_locator,custody_copy TO download_runtime"); err != nil {
			t.Fatal(err)
		}
		runtimePool := poolFor("download_runtime", "synthetic-download")
		defer runtimePool.Close()
		configPool := poolFor("download_config_runtime", "synthetic-download-config")
		defer configPool.Close()
		catalogPool := poolFor("context_catalog_read_runtime", "synthetic-context-read")
		defer catalogPool.Close()
		guards := postgres.EffectTransactionGuards{Retention: scenario.retention.guard, Recovery: scenario.recovery.guard}
		ledger, err := postgres.NewDownloads(ctx, runtimePool, root, guards)
		if err != nil {
			t.Fatal(err)
		}
		config, err := postgres.NewDownloads(ctx, configPool, root, guards)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := postgres.NewContextPublications(ctx, catalogPool, root, guards)
		if err != nil {
			t.Fatal(err)
		}
		gate := authorizationapp.ContextDownloadAuthority{RootID: root, Permissions: scenario.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: scenario.retention, Now: time.Now}, Environment: newDownloadTestEnvironment(t, ctx, catalogPool, scenario, e.Registration), Now: time.Now}
		scope := artifact.DownloadScope{RootID: root, ArtifactID: e.Registration.Location.ArtifactID, CaptureID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(published.Copies), Principal: scenario.a.Plan.Input.Executor}
		current := func() artifact.DownloadAuthority {
			t.Helper()
			now := time.Now().UTC().Truncate(time.Microsecond)
			batch := scenario.batch
			batch.Initial = nil
			batch.ObservedAt = now
			batch.FreshUntil = now.Add(5 * time.Second)
			if err := scenario.p.RefreshPermissions(ctx, batch); err != nil {
				t.Fatal(err)
			}
			actor := scenario.a.Eligibility.VerifiedIdentity
			actor.Scopes = []string{"evidence:read", "evidence:download"}
			actor.VerifiedAt = now
			actor.ValidUntil = now.Add(5 * time.Second)
			gate.Identities = downloadTestIdentity{actor}
			a, err := gate.CheckDownload(ctx, "synthetic-reference", scope)
			if err != nil {
				t.Fatal(err)
			}
			return a
		}
		a := current()
		allocation := artifact.DownloadAllocation{ID: custodyID(), RootID: root, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, OutputLimit: 1 << 20, ReadLimit: 128 << 20, SessionLimit: 4, ValidUntil: time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)}
		if err = config.BindDownloadAllocation(ctx, allocation); err != nil {
			t.Fatal(err)
		}
		request := evidence.DownloadReservation{Authority: a, IdempotencyDigest: evidence.ContextDownloadKeyDigest("stop-fixture"), Session: artifact.DownloadSession{ID: custodyID(), AllocationID: allocation.ID, Scope: scope, RequestDigest: evidence.ContextDownloadRequestDigest(scope.ArtifactID), State: artifact.DownloadPreparing, StopProtocol: artifact.DownloadStopProtocol, CreatedAt: time.Now().UTC(), Deadline: time.Now().UTC().Add(20 * time.Second).Truncate(time.Microsecond), OutputLimit: 8192, ReadLimit: 16 << 20, RequestLimit: 4}}
		if _, err = ledger.ReserveDownload(ctx, request); err == nil {
			t.Fatal("admitted without prepaid stop backing")
		}
		var sessions, charged int64
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM artifact_download WHERE allocation_id=$1", allocation.ID).Scan(&sessions); err != nil || sessions != 0 {
			t.Fatal("failed admission left session", sessions, err)
		}
		if err = admin.QueryRow(ctx, "SELECT reserved_sessions FROM download_allocation WHERE id=$1", allocation.ID).Scan(&charged); err != nil || charged != 0 {
			t.Fatal("failed admission charged allocation", charged, err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		backing := artifact.DownloadStopBacking{AllocationID: allocation.ID, RootID: root, InstallationID: scenario.recovery.installation, StoreID: e.Registration.StoreID, PolicyID: custodyID(), BackupProfileID: custodyID(), PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, Slots: 4, AllocationSlots: 4, CipherBytes: 4 * artifact.DownloadStopCipherLimit, KeyAttempts: 24, BackupBytes: 4 * 131072, WALBytes: 4 * 1048576, RetainedSeconds: 3600, BackupHorizonSeconds: 60, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
		// Synthetic accepted policy/backing; physical backup/retirement qualification
		// is deliberately outside this SQL/S3 admission and restriction fixture.
		if err = config.BindDownloadStopBacking(ctx, backing); err != nil {
			t.Fatal("stop backing", err)
		}
		request.Authority = current()
		session, err := ledger.ReserveDownload(ctx, request)
		if err != nil || session.StopProtocol != artifact.DownloadStopProtocol {
			t.Fatal("backed admission", err)
		}
		// An admitted but not yet audited acquisition is uncertain work. Stop
		// must fence it without refunding its read charge or replacing its ID.
		batchIntent, err := ledger.BeginDownloadBatch(ctx, session.ID, current(), artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadMetadata, ReadBytes: 2 << 20})
		if err != nil {
			t.Fatal("prepaid acquisition", err)
		}
		session, err = ledger.LookupDownload(ctx, session.ID, scope.Principal)
		if err != nil || session.Active == nil || session.Active.ID != batchIntent.Batch.ID || session.ChargedRead != 2<<20 {
			t.Fatal("acquisition charge missing", err)
		}
		stopPool := poolFor("download_stop_runtime", "synthetic-download-stop")
		defer stopPool.Close()
		writerPool := poolFor("download_stop_writer_runtime", "synthetic-download-stop-writer")
		defer writerPool.Close()
		ackPool := poolFor("download_stop_ack_runtime", "synthetic-download-stop-ack")
		defer ackPool.Close()
		stops, err := postgres.NewDownloadStops(ctx, stopPool, root)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := postgres.NewDownloadStops(ctx, writerPool, root, scenario.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		stopAck, err := postgres.NewDownloadStops(ctx, ackPool, root, scenario.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		// Exhaust the real normal audit account before stopping. No new normal
		// operation admission can succeed, while prepaid Stop stays available.
		auditConfigPool := poolFor("operation_audit_config_runtime", "synthetic-operation-config")
		auditJournalPool := poolFor("operation_audit_runtime", "synthetic-operation-journal")
		func() {
			defer auditConfigPool.Close()
			defer auditJournalPool.Close()
			auditConfig, err := postgres.New(ctx, auditConfigPool)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			// Processing initialization already consumed one actual normal audit
			// record. Keep that history and accept a bounded pool revision whose
			// single remaining account/record is fully occupied by it.
			var revision int64
			var validUntil time.Time
			var occupied []byte
			if err = admin.QueryRow(ctx, "SELECT revision,valid_until FROM operation_audit_pool WHERE root_id=$1 AND lane='normal'", root).Scan(&revision, &validUntil); err != nil {
				t.Fatal(err)
			}
			if err = admin.QueryRow(ctx, "SELECT principal_digest FROM operation_audit_account WHERE root_id=$1 AND lane='normal' AND charged=1", root).Scan(&occupied); err != nil || len(occupied) != 32 {
				t.Fatal("missing charged initialization", err)
			}
			if err = auditConfig.ProvisionOperationAuditPool(ctx, auditapp.OperationAuditPool{RootID: root, Lane: "normal", AccountVersion: "accounts-v1", ExpectedRevision: revision, Accounts: 1, RecordsPerAccount: 1, RetainedSeconds: 3600, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: validUntil}); err != nil {
				t.Fatal(err)
			}
			journal, err := postgres.NewOperationJournal(ctx, auditJournalPool, root, "normal", scenario.recovery.guard)
			if err != nil {
				t.Fatal(err)
			}
			id := custodyID()
			intent := audit.OperationIntent{ID: id, TraceID: id, RootID: root, Name: "get_artifact_download", InputFormat: "context-input/v1", MACVersion: "stop-test", AccountVersion: "accounts-v1", Actor: scope.Principal, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: now, RequestUntil: now.Add(5 * time.Second), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
			copy(intent.PrincipalDigest[:], occupied)
			if _, err = journal.ReserveOperation(ctx, intent); err == nil {
				t.Fatal("normal audit pool did not exhaust")
			}
		}()
		actor := scenario.a.Eligibility.VerifiedIdentity
		actor.Scopes = []string{"openid"}
		actor.VerifiedAt = time.Now()
		actor.ValidUntil = actor.VerifiedAt.Add(5 * time.Second)
		currentActor := stopNativeIdentity{actor}
		service := evidence.ContextDownloadStopCoordinator{Ledger: stopNativeLedger{stops, writer}, Acknowledgements: stopAck, Objects: &objectstore.DownloadStopObjects{Store: store, Seal: keys, Open: keys, StoreID: e.Registration.StoreID}, Now: time.Now}
		requestID := custodyID()
		receipt, err := service.CancelContextDownload(ctx, currentActor, session.ID, "original-stop", requestID)
		if err != nil || receipt.State != "Cancelled" || receipt.AuditState != "recorded" {
			t.Fatal("scope-independent audited stop", receipt, err)
		}
		again, err := service.CancelContextDownload(ctx, currentActor, session.ID, "original-stop", custodyID())
		if err != nil || again.RequestID != requestID {
			t.Fatal("same-key stop replay", err)
		}
		if _, err = service.CancelContextDownload(ctx, currentActor, session.ID, "other-stop", custodyID()); err == nil {
			t.Fatal("new key replaced stop")
		}
		foreign := currentActor
		foreign.i.Principal.ClientID = "foreign-client"
		if _, err = service.CancelContextDownload(ctx, foreign, session.ID, "original-stop", custodyID()); err == nil {
			t.Fatal("foreign stop disclosed")
		}
		stored, err := ledger.LookupDownload(ctx, session.ID, scope.Principal)
		if err != nil || stored.State != artifact.DownloadCancelled || stored.ChargedRead != session.ChargedRead || stored.ChargedOutput != session.ChargedOutput || stored.Active == nil || stored.Active.ID != batchIntent.Batch.ID || stored.Generation != session.Generation {
			t.Fatal("stop changed spend", err)
		}
		if err = ledger.PermitDownloadBatch(ctx, session.ID, current(), batchIntent.Batch.ID, batchIntent.Batch.Generation); err == nil {
			t.Fatal("cancelled acquisition retained authority")
		}
		if _, err = ledger.FinishDownloadBatch(ctx, session.ID, batchIntent.Batch.ID, batchIntent.Batch.Generation, 0, false, false); err != nil {
			t.Fatal("historical joined acquisition outcome blocked", err)
		}
		var writes, lookups int64
		if err = admin.QueryRow(ctx, "SELECT write_started::int,lookup_attempts FROM download_stop WHERE download_id=$1", session.ID).Scan(&writes, &lookups); err != nil || writes != 1 || lookups != 0 {
			t.Fatal("replay repeated audit", writes, lookups, err)
		}
		for _, q := range []string{"SELECT * FROM context_catalog", "UPDATE download_stop SET receipt=receipt", "DELETE FROM download_stop"} {
			_, err = stopPool.Exec(ctx, q)
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != "42501" {
				t.Fatal("stop role did not produce exact privilege denial", q, err)
			}
		}
		// An actual incarnation mismatch blocks new audit provider attempts while
		// the restrictive Stop transaction remains available to its current actor.
		request.Session.ID = custodyID()
		request.Session.CreatedAt = time.Now().UTC()
		request.Session.Deadline = time.Now().UTC().Add(20 * time.Second).Truncate(time.Microsecond)
		request.IdempotencyDigest = evidence.ContextDownloadKeyDigest("fenced-stop")
		request.Authority = current()
		fenced, err := ledger.ReserveDownload(ctx, request)
		if err != nil {
			t.Fatal("fenced-stop reservation", err)
		}
		if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET activated_postmaster_at=activated_postmaster_at-interval '1 microsecond' WHERE installation_id=$1", scenario.recovery.installation); err != nil {
			t.Fatal(err)
		}
		currentActor.i.VerifiedAt = time.Now()
		currentActor.i.ValidUntil = currentActor.i.VerifiedAt.Add(5 * time.Second)
		pending, err := service.CancelContextDownload(ctx, currentActor, fenced.ID, "fenced-stop", custodyID())
		if err != nil || pending.State != "Cancelled" || pending.AuditState != "pending" {
			t.Fatal("recovery must fence audit, not Stop", pending, err)
		}
		if err = admin.QueryRow(ctx, "SELECT write_started::int,lookup_attempts FROM download_stop WHERE download_id=$1", fenced.ID).Scan(&writes, &lookups); err != nil || writes != 0 || lookups != 0 {
			t.Fatal("recovery allowed audit spend", writes, lookups, err)
		}
		// A public restriction and its audit must never alter the source artifact.
		var state string
		if err = admin.QueryRow(ctx, "SELECT state FROM custody_attempt WHERE id=$1", e.Registration.Location.AttemptID).Scan(&state); err != nil || strings.Contains(strings.ToLower(state), "delet") {
			t.Fatal("source changed", state, err)
		}
	})
}

type stopNativeIdentity struct{ i identity.Identity }

func (s stopNativeIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return s.i, ctx.Err()
}

type stopNativeLedger struct{ stop, writer *postgres.DownloadStops }

func (s stopNativeLedger) StopDownload(ctx context.Context, i identity.Identity, id string, key artifact.Digest, request string) (evidence.DownloadStopSnapshot, error) {
	return s.stop.StopDownload(ctx, i, id, key, request)
}
func (s stopNativeLedger) ClaimDownloadStopWrite(ctx context.Context, d artifact.DownloadStopDecision) (bool, error) {
	return s.writer.ClaimDownloadStopWrite(ctx, d)
}
