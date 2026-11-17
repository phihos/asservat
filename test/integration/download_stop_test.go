package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real SQL/publication/S3/audit and native context worker. Human identity,
// placement/allocation and installation acceptance remain explicit fixture inputs.
// No public native-work channel, regional cache or download endpoint is faked.
func qualifyDownloadStop(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) (captureAdmissionScenario, publishedContext)) {
	t.Helper()
	t.Run("download-stop-audit-row-and-original-replay", func(t *testing.T) {
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
		ledger, err := postgres.NewDownloads(ctx, runtimePool, root)
		if err != nil {
			t.Fatal(err)
		}
		config, err := postgres.NewDownloads(ctx, configPool, root)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := postgres.NewContextPublications(ctx, catalogPool, root)
		if err != nil {
			t.Fatal(err)
		}
		gate := authorizationapp.ContextDownloadAuthority{RootID: root, Permissions: scenario.p, Catalog: catalog, Environment: newDownloadTestEnvironment(t, ctx, catalogPool, scenario, e.Registration), Now: time.Now}
		scope := artifact.DownloadScope{RootID: root, ArtifactID: e.Registration.Location.ArtifactID, CaptureID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(published.Copies), Principal: scenario.a.Plan.Input.Executor}
		current := func() artifact.DownloadAuthority {
			t.Helper()
			now := time.Now().UTC().Truncate(time.Microsecond)
			batch := scenario.batch
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
		allocation := artifact.DownloadAllocation{ID: custodyID(), RootID: root, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, OutputLimit: 1 << 20, ReadLimit: 128 << 20, ValidUntil: time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)}
		if err = config.BindDownloadAllocation(ctx, allocation); err != nil {
			t.Fatal(err)
		}
		request := evidence.DownloadReservation{Authority: a, IdempotencyDigest: evidence.ContextDownloadKeyDigest("stop-fixture"), Session: artifact.DownloadSession{ID: custodyID(), AllocationID: allocation.ID, Scope: scope, RequestDigest: evidence.ContextDownloadRequestDigest(scope.ArtifactID), State: artifact.DownloadPreparing, CreatedAt: time.Now().UTC(), Deadline: time.Now().UTC().Add(20 * time.Second).Truncate(time.Microsecond), OutputLimit: 8192, ReadLimit: 16 << 20}}
		request.Authority = current()
		session, err := ledger.ReserveDownload(ctx, request)
		if err != nil {
			t.Fatal("admission", err)
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
		stops, err := postgres.NewDownloadStops(ctx, stopPool, root)
		if err != nil {
			t.Fatal(err)
		}
		actor := scenario.a.Eligibility.VerifiedIdentity
		actor.Scopes = []string{"openid"}
		actor.VerifiedAt = time.Now()
		actor.ValidUntil = actor.VerifiedAt.Add(5 * time.Second)
		currentActor := stopNativeIdentity{actor}
		service := evidence.ContextDownloadStopCoordinator{Ledger: stops, Now: time.Now}
		requestID := custodyID()
		receipt, err := service.CancelContextDownload(ctx, currentActor, session.ID, "original-stop", requestID)
		if err != nil || receipt.State != "Cancelled" {
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
		// ADR-330 D6: one audit row, written with the stop; replays add none.
		var rows int64
		var kind, operation string
		if err = admin.QueryRow(ctx, "SELECT count(*),min(kind),min(operation) FROM audit_event WHERE operation_id=$1", requestID).Scan(&rows, &kind, &operation); err != nil || rows != 1 || kind != "download.stop" || operation != "cancel_artifact_download" {
			t.Fatal("stop audit row", rows, kind, operation, err)
		}
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM audit_event WHERE kind='download.stop' AND $1=ANY(artifact_ids)", scope.ArtifactID).Scan(&rows); err != nil || rows != 1 {
			t.Fatal("replay repeated the stop audit row", rows, err)
		}
		for _, q := range []string{"SELECT * FROM context_catalog", "UPDATE artifact_download_stop SET state=state", "DELETE FROM artifact_download_stop", "DELETE FROM audit_event"} {
			_, err = stopPool.Exec(ctx, q)
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != "42501" {
				t.Fatal("stop role did not produce exact privilege denial", q, err)
			}
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
