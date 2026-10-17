package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real SQL/publication/S3/audit and native context worker. Human identity,
// placement/allocation and installation acceptance remain explicit fixture inputs.
// No public native-work channel, regional cache or download endpoint is faked.
func qualifyDownloadControl(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) (captureAdmissionScenario, artifact.PublishedContext)) {
	t.Helper()
	t.Run("download-control-original-replay-and-current-metadata", func(t *testing.T) {
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
		auditPool := poolFor("download_audit_runtime", "synthetic-download-audit")
		defer auditPool.Close()
		configPool := poolFor("download_config_runtime", "synthetic-download-config")
		defer configPool.Close()
		catalogPool := poolFor("context_catalog_read_runtime", "synthetic-context-read")
		defer catalogPool.Close()
		guards := postgres.EffectTransactionGuards{Retention: scenario.retention.guard, Recovery: scenario.recovery.guard}
		ledger, err := postgres.NewDownloads(ctx, runtimePool, root, guards)
		if err != nil {
			t.Fatal(err)
		}
		ack, err := postgres.NewDownloads(ctx, auditPool, root, guards)
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
		actor, _ := gate.Identities.Resolve(ctx, "synthetic-reference")
		route, err := ledger.ResolveContextDownload(ctx, artifact.DownloadRouteQuery{ArtifactID: scope.ArtifactID, Identity: actor, Recovery: a.Environment.Recovery()})
		if err != nil || route.Scope != scope || !route.Valid(time.Now()) {
			t.Fatal("private exact route", route, err)
		}
		source, err := ledger.ReadContextDownloadSource(ctx, a)
		if err != nil || !source.Valid(time.Now()) || source.Scope != scope || source.Copies != published.Copies || source.Expectation.Registration != e.Registration {
			t.Fatal("verified exact source", err)
		}
		if _, err = ledger.ResolveContextDownload(ctx, artifact.DownloadRouteQuery{ArtifactID: custodyID(), Identity: actor, Recovery: a.Environment.Recovery()}); err == nil {
			t.Fatal("unknown artifact acquired a route")
		}
		for _, q := range []string{"UPDATE context_case_locator SET pod_uid=pod_uid", "UPDATE custody_copy SET etag=etag", "UPDATE context_catalog SET published_at=published_at"} {
			if _, err = runtimePool.Exec(ctx, q); err == nil {
				t.Fatal("source reader gained writes", q)
			}
		}
		allocation := artifact.DownloadAllocation{ID: custodyID(), RootID: root, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, OutputLimit: 1 << 20, ReadLimit: 128 << 20, SessionLimit: 16, ValidUntil: time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)}
		if err = config.BindDownloadAllocation(ctx, allocation); err != nil {
			t.Fatal(err)
		}
		key := evidence.ContextDownloadKeyDigest("original-control-key")
		// A finite requested transfer lifetime shorter than the independent
		// thirty-second fixture source observations lets status outlive the
		// transfer without fabricating renewed evidence/recovery authority.
		request := evidence.DownloadReservation{Authority: a, IdempotencyDigest: key, Session: artifact.DownloadSession{ID: custodyID(), AllocationID: allocation.ID, Scope: scope, RequestDigest: evidence.ContextDownloadRequestDigest(scope.ArtifactID), State: artifact.DownloadPreparing, CreatedAt: time.Now().UTC(), Deadline: time.Now().UTC().Add(15 * time.Second).Truncate(time.Microsecond), OutputLimit: 8192, ReadLimit: 16 << 20, RequestLimit: 4}}
		query := artifact.DownloadKeyQuery{Identity: actor, Recovery: a.Environment.Recovery(), Key: key}
		absent, err := ledger.LookupDownloadKey(ctx, query)
		if err != nil || absent.Found || !absent.Valid(time.Now()) {
			t.Fatal("absent observation", err)
		}
		session, err := ledger.ReserveDownload(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		// Model a caller whose first reply was lost and whose current plan has rotated.
		// A nonexistent proposed allocation must not hide the original committed key.
		changed := request
		changed.Session.ID = custodyID()
		changed.Session.AllocationID = custodyID()
		changed.Session.OutputLimit = 16384
		changed.Session.Deadline = changed.Session.Deadline.Add(time.Second)
		replay, err := ledger.ReserveDownload(ctx, changed)
		if err != nil || replay.ID != session.ID || replay.AllocationID != allocation.ID || replay.OutputLimit != session.OutputLimit || !replay.Deadline.Equal(session.Deadline) {
			t.Fatal("original key replaced by current plan", replay, err)
		}
		looked, err := ledger.LookupDownloadKey(ctx, query)
		if err != nil || !looked.Found || looked.Session.ID != session.ID {
			t.Fatal("original key lookup", err)
		}
		different := query
		different.Identity.Principal.ClientID = "other-client"
		if out, err := ledger.LookupDownloadKey(ctx, different); err != nil || out.Found {
			t.Fatal("cross-client key exposed", err)
		}
		differentRequest := request
		differentRequest.Session.RequestDigest = artifact.Digest{99}
		if _, err = ledger.ReserveDownload(ctx, differentRequest); err == nil {
			t.Fatal("same key changed request")
		}
		// Independent overlapping replays must recover one original immutable row.
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for range 4 {
			wg.Go(func() {
				v, e := ledger.ReserveDownload(ctx, changed)
				if e == nil && v.ID != session.ID {
					e = artifact.ErrIntegrity
				}
				errs <- e
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal("parallel replay", err)
			}
		}
		a = current()
		bound, err := store.ForCustody(e.Registration.StoreID)
		if err != nil {
			t.Fatal(err)
		}
		native, err := objectstore.NewContextNativeReader(bound, keys)
		if err != nil {
			t.Fatal(err)
		}
		objects := &objectstore.DownloadAuditObjects{Store: store, Seal: keys, Open: keys}
		worker := evidence.ContextDownloadWorker{Sessions: ledger, AuditAcknowledgements: ack, Audit: objects, Authority: gate, Native: native, Now: time.Now, NewID: custodyID}
		req := evidence.ContextDownloadRequest{SessionID: session.ID, Scope: scope, Expectation: e, Copies: published.Copies}
		metadata, err := worker.Prepare(ctx, "synthetic-reference", req)
		if err != nil {
			t.Fatal("actual native preparation", err)
		}
		var prep artifact.DownloadPreparation
		var lease time.Time
		prep.SessionID = session.ID
		if err = admin.QueryRow(ctx, "SELECT id,generation,lease_until FROM download_batch WHERE session_id=$1 ORDER BY generation LIMIT 1", session.ID).Scan(&prep.BatchID, &prep.Generation, &lease); err != nil {
			t.Fatal(err)
		}
		wait := time.Until(lease) + 20*time.Millisecond
		if wait > 0 {
			time.Sleep(wait)
		}
		a = current()
		if err = ledger.PermitDownloadMetadata(ctx, session.ID, a, prep.BatchID, prep.Generation); err == nil {
			t.Fatal("old preparation lease renewed")
		}
		view, err := ledger.ObserveDownload(ctx, session.ID, a, &prep)
		if err != nil || !view.Valid(time.Now()) || view.Session.State != artifact.DownloadReady {
			t.Fatal("fresh status over immutable verified facts", err)
		}
		before := view.Session
		for range 3 {
			if _, err = ledger.ObserveDownload(ctx, session.ID, a, &prep); err != nil {
				t.Fatal(err)
			}
		}
		after, err := ledger.LookupDownload(ctx, session.ID, scope.Principal)
		if err != nil || before.Requests != after.Requests || before.ChargedRead != after.ChargedRead || before.Generation != after.Generation {
			t.Fatal("metadata polling spent another preparation", err)
		}
		content, err := ledger.BeginDownloadBatch(ctx, session.ID, a, artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadContent, OutputBytes: metadata.Size, ReadBytes: evidence.ContextDownloadReadWork})
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := objects.WriteDownloadIntent(ctx, content)
		if err != nil {
			t.Fatal(err)
		}
		if err = ack.AcknowledgeDownloadIntent(ctx, content, receipt); err != nil {
			t.Fatal(err)
		}
		if v, err := ledger.ObserveDownload(ctx, session.ID, a, &prep); err != nil || v.Session.State != artifact.DownloadStreaming {
			t.Fatal("later generation invalidated native facts", err)
		}
		// This accounting outcome is explicitly synthetic; the earlier preparation
		// used the actual reader. It tests metadata after terminal accounting only.
		outcome, err := ledger.FinishDownloadBatch(ctx, session.ID, content.Batch.ID, content.Batch.Generation, metadata.Size, true, true)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err = objects.WriteDownloadOutcome(ctx, outcome)
		if err != nil {
			t.Fatal(err)
		}
		if err = ack.AcknowledgeDownloadOutcome(ctx, outcome, receipt); err != nil {
			t.Fatal(err)
		}
		if v, err := ledger.ObserveDownload(ctx, session.ID, a, &prep); err != nil || v.Session.State != artifact.DownloadCompleted {
			t.Fatal("completed metadata observation", err)
		}
		bad := prep
		bad.Generation++
		if _, err = ledger.ObserveDownload(ctx, session.ID, a, &bad); err == nil {
			t.Fatal("wrong historical generation authorized metadata")
		}
		// Keep terminal status usable after the original transfer deadline.
		// These sessions use normal runtime reservations/cancellation; no test
		// administrator rewrites their deadlines, state or accounting.
		statusIDs := map[string]artifact.DownloadState{session.ID: artifact.DownloadCompleted}
		for _, state := range []artifact.DownloadState{artifact.DownloadExpired, artifact.DownloadCancelled} {
			a = current()
			now := time.Now().UTC().Truncate(time.Microsecond)
			r := request
			r.Authority = a
			r.Session.ID = custodyID()
			r.IdempotencyDigest = evidence.ContextDownloadKeyDigest("terminal-status-" + string(state))
			r.Session.CreatedAt = now
			r.Session.Deadline = now.Add(time.Second)
			made, err := ledger.ReserveDownload(ctx, r)
			if err != nil {
				t.Fatal("short status session", err)
			}
			if state == artifact.DownloadCancelled {
				if _, err = ledger.CancelDownload(ctx, made.ID, scope.Principal); err != nil {
					t.Fatal(err)
				}
			}
			statusIDs[made.ID] = state
		}
		// At most the existing original fifteen-second session lifetime remains.
		// This wait never renews preparation/byte authority or modifies SQL.
		statusAfter := session.Deadline.Add(20 * time.Millisecond)
		if minimum := time.Now().Add(1100 * time.Millisecond); minimum.After(statusAfter) {
			statusAfter = minimum
		}
		if delay := time.Until(statusAfter); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				t.Fatal(ctx.Err())
			case <-timer.C:
			}
		}
		for id, expected := range statusIDs {
			a = current()
			storedBefore, err := ledger.LookupDownload(ctx, id, scope.Principal)
			if err != nil {
				t.Fatal(err)
			}
			v, err := ledger.ObserveDownload(ctx, id, a, nil)
			if err != nil || !v.Valid(time.Now()) || v.Session.State != expected || !v.ValidUntil.After(v.Session.Deadline) {
				t.Fatal("terminal status after transfer expiry", expected, v, err)
			}
			storedAfter, err := ledger.LookupDownload(ctx, id, scope.Principal)
			if err != nil || storedAfter.State != storedBefore.State || storedAfter.Generation != storedBefore.Generation || storedAfter.Requests != storedBefore.Requests || storedAfter.ChargedRead != storedBefore.ChargedRead || storedAfter.ChargedOutput != storedBefore.ChargedOutput || !storedAfter.Deadline.Equal(storedBefore.Deadline) {
				t.Fatal("status mutated durable session", err)
			}
			if expected == artifact.DownloadExpired && storedAfter.State != artifact.DownloadPreparing {
				t.Fatal("read-only expiry persisted a state transition")
			}
			if _, err = ledger.BeginDownloadBatch(ctx, id, a, artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadMetadata, ReadBytes: evidence.ContextDownloadReadWork}); err == nil {
				t.Fatal("status revived transfer preparation")
			}
		}
		a = current()
		if err = ledger.PermitDownloadMetadata(ctx, session.ID, a, prep.BatchID, prep.Generation); err == nil {
			t.Fatal("status renewed old metadata effect permit")
		}
		// Wait behind a real row lock past the original current authority interval.
		a = current()
		a.ValidUntil = time.Now().UTC().Add(120 * time.Millisecond)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, "SELECT id FROM artifact_download WHERE id=$1 FOR UPDATE", session.ID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, e := ledger.ObserveDownload(ctx, session.ID, a, &prep); done <- e }()
		time.Sleep(170 * time.Millisecond)
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil {
			t.Fatal("blocking status read renewed authority")
		}
		a = current()
		if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", scenario.recovery.installation); err != nil {
			t.Fatal(err)
		}
		if _, err = ledger.ObserveDownload(ctx, session.ID, a, &prep); err == nil {
			t.Fatal("restored/suspended root disclosed metadata")
		}
	})
}
