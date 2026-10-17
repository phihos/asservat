package integration

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

// Called by the owned custody suite. Actual PostgreSQL/S3/encrypted paired
// records and original published context authority; large response size and
// emitted byte counts below are explicitly synthetic accounting observations.
// This does not qualify a large native decoder, I-13 relay or public download.
func qualifyDownloadResponses(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) (captureAdmissionScenario, artifact.PublishedContext)) {
	t.Helper()
	t.Run("download-response-window-accounting", func(t *testing.T) {
		scenario, published := create(t)
		e := published.Expectation
		root := scenario.a.RootID
		// These are the only additional reads used by this private source/locator
		// facet. There is no new write/owner/schema permission.
		for _, sql := range []string{
			"GRANT SELECT ON download_response,download_window,download_control_allocation TO download_runtime,download_audit_runtime,download_config_runtime",
			"GRANT INSERT ON download_response,download_window TO download_runtime",
			"GRANT UPDATE(lease_sequence,lease_until,closed) ON download_response TO download_runtime",
			"GRANT UPDATE(outcome_json) ON download_window TO download_runtime",
			"GRANT UPDATE(intent_receipt,intent_completion,outcome_receipt,outcome_completion) ON download_window TO download_audit_runtime",
			// SELECT FOR UPDATE requires an UPDATE privilege. The immutable ID
			// provides the lock-only column; this grants no lease/counter writes.
			"GRANT UPDATE(id) ON download_response TO download_audit_runtime",
			"GRANT INSERT ON download_control_allocation TO download_config_runtime",
		} {
			if _, err := admin.Exec(ctx, sql); err != nil {
				t.Fatal(err)
			}
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
		allocation := artifact.DownloadAllocation{ID: custodyID(), RootID: root, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, OutputLimit: 1 << 30, ReadLimit: 2 << 30, SessionLimit: 4, ValidUntil: time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)}
		if err := config.BindDownloadAllocation(ctx, allocation); err != nil {
			t.Fatal(err)
		}
		control := artifact.DownloadControlAllocation{ID: allocation.ID, RootID: root, AuditStoreID: e.Registration.StoreID, ResponseLimit: 2, WindowLimit: 2, AuditByteLimit: 4 * artifact.DownloadWindowAuditBytes, ValidUntil: allocation.ValidUntil, AuditWriteUntil: allocation.ValidUntil.Add(time.Minute)}
		if err := config.BindDownloadControlAllocation(ctx, control); err != nil {
			t.Fatal("backing", err)
		}
		if err := config.BindDownloadControlAllocation(ctx, control); err != nil {
			t.Fatal("backing replay", err)
		}
		bad := control
		bad.WindowLimit++
		if err := config.BindDownloadControlAllocation(ctx, bad); err == nil {
			t.Fatal("backing changed")
		}
		reservation := evidence.DownloadReservation{Authority: a, IdempotencyDigest: artifact.Digest{71}, Session: artifact.DownloadSession{ID: custodyID(), AllocationID: allocation.ID, Scope: scope, RequestDigest: artifact.Digest{72}, State: artifact.DownloadPreparing, CreatedAt: time.Now().UTC(), Deadline: time.Now().UTC().Add(20 * time.Second), OutputLimit: 1 << 29, ReadLimit: 1 << 30, RequestLimit: 4}}
		session, err := ledger.ReserveDownload(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		bound, err := store.ForCustody(e.Registration.StoreID)
		if err != nil {
			t.Fatal(err)
		}
		native, err := objectstore.NewContextNativeReader(bound, keys)
		if err != nil {
			t.Fatal(err)
		}
		worker := evidence.ContextDownloadWorker{Sessions: ledger, AuditAcknowledgements: ack, Audit: &objectstore.DownloadAuditObjects{Store: store, Seal: keys, Open: keys}, Authority: gate, Native: native, Now: time.Now, NewID: custodyID}
		if _, err = worker.Prepare(ctx, "synthetic-reference", evidence.ContextDownloadRequest{SessionID: session.ID, Scope: scope, Expectation: e, Copies: published.Copies}); err != nil {
			t.Fatal("native metadata preparation", err)
		}
		a = current()
		request := artifact.DownloadResponse{ID: custodyID(), SessionID: session.ID, OwnerID: custodyID(), Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: artifact.DownloadWindowBytes + 17}, WholeFile: true, WindowReadLimit: artifact.DownloadWindowBytes}, Until: session.Deadline}
		type responseAttempt struct {
			response artifact.DownloadResponse
			err      error
		}
		attempts := make(chan responseAttempt, 2)
		for range 2 {
			candidate := request
			candidate.ID = custodyID()
			candidate.OwnerID = custodyID()
			go func() {
				r, e := ledger.BeginDownloadResponse(ctx, session.ID, a, candidate)
				attempts <- responseAttempt{r, e}
			}()
		}
		var response artifact.DownloadResponse
		accepted := 0
		for range 2 {
			result := <-attempts
			if result.err == nil {
				accepted++
				response = result.response
			}
		}
		if accepted != 1 {
			t.Fatal("overlapping response admission", accepted)
		}
		request.ID = response.ID
		request.OwnerID = response.OwnerID
		if _, err = ledger.BeginDownloadResponse(ctx, session.ID, a, request); err == nil {
			t.Fatal("replayed response became second writer")
		}
		objects, err := objectstore.NewDownloadWindowAuditObjects(store, control.AuditStoreID, keys, keys)
		if err != nil {
			t.Fatal(err)
		}
		var finalGeneration int64
		for ordinal := int64(1); ordinal <= 2; ordinal++ {
			a = current()
			intent, err := ledger.BeginDownloadWindow(ctx, session.ID, response.ID, response.OwnerID, custodyID(), a)
			if err != nil {
				t.Fatal("window", ordinal, err)
			}
			if _, err = ledger.LeaseDownloadResponse(ctx, session.ID, response.ID, response.OwnerID, intent.Window.ID, a); err == nil {
				t.Fatal("unaudited byte lease")
			}
			receipt, err := objects.CreateDownloadWindowIntent(ctx, intent)
			if err != nil || receipt.Completion == nil {
				t.Fatal("intent write", err)
			}
			if err = ack.AcknowledgeDownloadWindowIntent(ctx, intent, receipt); err != nil {
				t.Fatal("intent acknowledgement", err)
			}
			for _, version := range []string{"", "null"} {
				label := version
				if label == "" {
					label = "empty"
				}
				t.Run("retained-window-intent-"+label, func(t *testing.T) {
					authority := current()
					withHistoricalAuditReceipt(t, ctx, admin, "SELECT intent_receipt FROM download_window WHERE id=$1", "UPDATE download_window SET intent_receipt=$2 WHERE id=$1", []any{intent.Window.ID}, func(r *audit.Receipt) { r.Version = version }, func() {
						if _, err := ledger.LeaseDownloadResponse(ctx, session.ID, response.ID, response.OwnerID, intent.Window.ID, authority); err == nil {
							t.Fatal("historical window receipt authorized bytes")
						}
						if !authority.Valid(time.Now()) {
							t.Fatal("denial crossed original window authority")
						}
					})
				})
			}
			lease, err := ledger.LeaseDownloadResponse(ctx, session.ID, response.ID, response.OwnerID, intent.Window.ID, current())
			if err != nil || !lease.Valid(time.Now()) {
				t.Fatal("current byte lease", err)
			}
			finalGeneration = lease.Generation
			if _, err = ledger.BeginDownloadBatch(ctx, session.ID, current(), artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadContent, OutputBytes: 1, ReadBytes: 1}); err == nil {
				t.Fatal("legacy writer overlapped response")
			}
			var outcome audit.DownloadWindowAuditOutcome
			withHistoricalAuditReceipt(t, ctx, admin, "SELECT intent_receipt FROM download_window WHERE id=$1", "UPDATE download_window SET intent_receipt=$2 WHERE id=$1", []any{intent.Window.ID}, func(r *audit.Receipt) { r.Version = "null" }, func() {
				// Preserve the already-performed synthetic byte accounting
				// after the original positive lease; no new bytes are sent.
				outcome, err = ledger.FinishDownloadWindow(ctx, intent, artifact.DownloadWindowOutcome{EmittedBytes: intent.Window.Length, Success: true, VerifiedFinal: ordinal == 2})
				if err != nil {
					t.Fatal("historical window outcome", err)
				}
			})
			observed, err := ledger.LookupDownload(ctx, session.ID, scope.Principal)
			if err != nil || observed.State == artifact.DownloadCompleted {
				t.Fatal("unaudited completion", err)
			}
			receipt, err = objects.CreateDownloadWindowOutcome(ctx, outcome)
			if err != nil {
				t.Fatal(err)
			}
			if err = ack.AcknowledgeDownloadWindowOutcome(ctx, outcome, receipt); err != nil {
				t.Fatal("outcome acknowledgement", err)
			}
		}
		got, err := ledger.LookupDownload(ctx, session.ID, scope.Principal)
		if err != nil || got.State != artifact.DownloadCompleted || got.EmittedBytes != request.Plan.Selection.Length || got.ChargedOutput != request.Plan.Selection.Length || got.Requests != 1 || got.Generation != finalGeneration {
			t.Fatal("cumulative completion", got, err)
		}
		var responses, windows, auditBytes int64
		if err = admin.QueryRow(ctx, "SELECT reserved_responses,reserved_windows,reserved_audit_bytes FROM download_control_allocation WHERE id=$1", control.ID).Scan(&responses, &windows, &auditBytes); err != nil || responses != 1 || windows != 2 || auditBytes != 4*artifact.DownloadWindowAuditBytes {
			t.Fatal("finite control accounting", responses, windows, auditBytes, err)
		}
		// An independent second session cannot consume a first response's fully
		// reserved pair slots. SQL/S3 uncertainty never makes those slots free.
		reservation.Authority = current()
		reservation.IdempotencyDigest = artifact.Digest{73}
		reservation.Session.ID = custodyID()
		reservation.Session.CreatedAt = time.Now().UTC()
		reservation.Session.Deadline = time.Now().UTC().Add(15 * time.Second)
		second, err := ledger.ReserveDownload(ctx, reservation)
		if err != nil {
			t.Fatal("second session", err)
		}
		worker.Authority = gate
		if _, err = worker.Prepare(ctx, "synthetic-reference", evidence.ContextDownloadRequest{SessionID: second.ID, Scope: scope, Expectation: e, Copies: published.Copies}); err != nil {
			t.Fatal("second metadata", err)
		}
		other := artifact.DownloadResponse{ID: custodyID(), SessionID: second.ID, OwnerID: custodyID(), Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: 1}, WholeFile: true, WindowReadLimit: 1}, Until: second.Deadline}
		if _, err = ledger.BeginDownloadResponse(ctx, second.ID, current(), other); err == nil {
			t.Fatal("second session exceeded paired backing")
		}
		for _, check := range []struct {
			pool *pgxpool.Pool
			sql  string
		}{{runtimePool, "UPDATE download_window SET intent_receipt='{}'"}, {auditPool, "UPDATE download_window SET outcome_json='{}'"}, {auditPool, "UPDATE download_response SET lease_until=clock_timestamp()"}, {configPool, "UPDATE download_control_allocation SET reserved_windows=0"}, {runtimePool, "DELETE FROM download_response"}} {
			_, err = check.pool.Exec(ctx, check.sql)
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != "42501" {
				t.Fatal("expected privilege denial", check.sql, err)
			}
		}
		// The sole UPDATE(id) privilege needed for the audit row lock cannot
		// change response identity, even though the statement passes ACL checks.
		_, err = auditPool.Exec(ctx, "UPDATE download_response SET id=$1 WHERE id=$2", custodyID(), response.ID)
		var immutable *pgconn.PgError
		if !errors.As(err, &immutable) || immutable.Code != "23514" {
			t.Fatal("audit lock column changed immutable response identity", err)
		}
	})
}
