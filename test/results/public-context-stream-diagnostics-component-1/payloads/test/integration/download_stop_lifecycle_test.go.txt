package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sort"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual SQL/S3/codec/signature and role boundaries. Installation policy and
// backup footprint/H are explicitly synthetic accepted inputs; this is not a
// pgBackRest or physical storage qualification. All dates run on actual clocks.
func qualifyDownloadStopLifecycle(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) (captureAdmissionScenario, artifact.PublishedContext)) {
	t.Helper()
	t.Run("prepaid-stop-positive-retirement-backup-history-and-unknown-writers", func(t *testing.T) {
		type record struct {
			session artifact.DownloadSession
			mode    string
			state   audit.DownloadStopLifecycleSnapshot
		}
		type group struct {
			scenario                             captureAdmissionScenario
			allocation                           artifact.DownloadAllocation
			records                              []record
			cleanup, verifier, finalizer, writer *postgres.DownloadStopLifecycles
			objects                              *objectstore.DownloadStopCleanupObjects
			verifyObjects                        *objectstore.DownloadStopCleanupVerifier
			cleanupPool, verifyPool, finalPool   *pgxpool.Pool
			pending                              *postgres.DownloadStops
			horizon                              int64
		}
		var groups []*group
		// Both histories share the same actual end, so the fixture waits once through
		// the longest original schedule rather than adding a minute per case.
		deadline := time.Now().UTC().Add(12 * time.Second).Truncate(time.Microsecond)
		for _, h := range []int64{2, 0} {
			scenario, published := create(t)
			expect := published.Expectation
			root := scenario.a.RootID
			roles := func(name, pass string) *pgxpool.Pool { p := poolFor(name, pass); t.Cleanup(p.Close); return p }
			runtimePool := roles("download_runtime", "synthetic-download")
			defer runtimePool.Close()
			configPool := roles("download_config_runtime", "synthetic-download-config")
			defer configPool.Close()
			catalogPool := roles("context_catalog_read_runtime", "synthetic-context-read")
			defer catalogPool.Close()
			stopPool := roles("download_stop_runtime", "synthetic-download-stop")
			defer stopPool.Close()
			producerPool := roles("download_stop_writer_runtime", "synthetic-download-stop-writer")
			defer producerPool.Close()
			ackPool := roles("download_stop_ack_runtime", "synthetic-download-stop-ack")
			defer ackPool.Close()
			lifecycleConfigPool := roles("download_stop_lifecycle_config_runtime", "synthetic-stop-lifecycle-config")
			defer lifecycleConfigPool.Close()
			cleanupPool := roles("download_stop_cleanup_runtime", "synthetic-stop-cleanup")
			defer cleanupPool.Close()
			verifyPool := roles("download_stop_verify_runtime", "synthetic-stop-verify")
			defer verifyPool.Close()
			finalPool := roles("download_stop_retire_runtime", "synthetic-stop-retire")
			defer finalPool.Close()
			guards := postgres.EffectTransactionGuards{Retention: scenario.retention.guard, Recovery: scenario.recovery.guard}
			ledger, e := postgres.NewDownloads(ctx, runtimePool, root, guards)
			if e != nil {
				t.Fatal(e)
			}
			config, e := postgres.NewDownloads(ctx, configPool, root, guards)
			if e != nil {
				t.Fatal(e)
			}
			catalog, e := postgres.NewContextPublications(ctx, catalogPool, root, guards)
			if e != nil {
				t.Fatal(e)
			}
			scope := artifact.DownloadScope{RootID: root, ArtifactID: expect.Registration.Location.ArtifactID, CaptureID: expect.CaptureUID, ClusterID: expect.Registration.Location.ClusterID, NamespaceUID: expect.NamespaceUID, WorkloadUID: expect.WorkloadUID, PodUID: expect.PodUID, Version: evidence.ContextCopiesDigest(published.Copies), Principal: scenario.a.Plan.Input.Executor}
			gate := authorizationapp.ContextDownloadAuthority{RootID: root, Permissions: scenario.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: scenario.retention, Now: time.Now}, Environment: newDownloadTestEnvironment(t, ctx, catalogPool, scenario, expect.Registration), Now: time.Now}
			current := func() artifact.DownloadAuthority {
				t.Helper()
				now := time.Now().UTC().Truncate(time.Microsecond)
				batch := scenario.batch
				batch.Initial = nil
				batch.ObservedAt = now
				batch.FreshUntil = now.Add(5 * time.Second)
				if e := scenario.p.RefreshPermissions(ctx, batch); e != nil {
					t.Fatal(e)
				}
				actor := scenario.a.Eligibility.VerifiedIdentity
				actor.Scopes = []string{"evidence:read", "evidence:download"}
				actor.VerifiedAt = now
				actor.ValidUntil = now.Add(5 * time.Second)
				gate.Identities = downloadTestIdentity{actor}
				a, e := gate.CheckDownload(ctx, "synthetic-reference", scope)
				if e != nil {
					t.Fatal(e)
				}
				return a
			}
			allocation := artifact.DownloadAllocation{ID: custodyID(), RootID: root, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, OutputLimit: 1 << 20, ReadLimit: 128 << 20, SessionLimit: 4, ValidUntil: deadline.Add(2 * time.Minute)}
			if e = config.BindDownloadAllocation(ctx, allocation); e != nil {
				t.Fatal(e)
			}
			p := audit.DownloadStopLifecyclePolicy{RootID: root, InstallationID: scenario.recovery.installation, StoreID: expect.Registration.StoreID, PolicyID: custodyID(), BackupProfileID: custodyID(), QualificationID: custodyID(), PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, QualificationDigest: artifact.Digest{3}, Layout: audit.DownloadStopHistoryLayout, BackupHorizonSeconds: h, CleanupBudgetSeconds: 6, ProofWindowSeconds: 3, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1, MaxPurgeLeases: 8}
			c, k, backup, wal := p.SlotBacking()
			now := time.Now().UTC().Truncate(time.Microsecond)
			backing := artifact.DownloadStopBacking{AllocationID: allocation.ID, RootID: root, InstallationID: p.InstallationID, StoreID: p.StoreID, PolicyID: p.PolicyID, BackupProfileID: p.BackupProfileID, PolicyDigest: p.PolicyDigest, BackupProfileDigest: p.BackupProfileDigest, Slots: 4, AllocationSlots: 4, CipherBytes: c * 4, KeyAttempts: k * 4, BackupBytes: backup * 4, WALBytes: wal * 4, RetainedSeconds: 60, BackupHorizonSeconds: h, ObservedAt: now, ValidUntil: deadline.Add(2 * time.Minute)}
			if e = config.BindDownloadStopBacking(ctx, backing); e != nil {
				t.Fatal("backed lifecycle", e)
			}
			facet := func(pool *pgxpool.Pool) *postgres.DownloadStopLifecycles {
				x, e := postgres.NewDownloadStopLifecycles(ctx, pool, root, scenario.recovery.guard)
				if e != nil {
					t.Fatal(e)
				}
				return x
			}
			cfg := facet(lifecycleConfigPool)
			now = time.Now().UTC().Truncate(time.Microsecond)
			if e = cfg.Configure(ctx, p, now, now.Add(5*time.Second)); e != nil {
				t.Fatal("lifecycle config", e)
			}
			if h == 2 {
				qualifyStopBackingExpiryAfterLock(t, ctx, admin, ledger, config, current(), backing, scope, deadline)
			}
			g := &group{scenario: scenario, allocation: allocation, writer: facet(producerPool), cleanup: facet(cleanupPool), verifier: facet(verifyPool), finalizer: facet(finalPool), cleanupPool: cleanupPool, verifyPool: verifyPool, finalPool: finalPool, horizon: h}
			stops, e := postgres.NewDownloadStops(ctx, stopPool, root)
			if e != nil {
				t.Fatal(e)
			}
			writer, e := postgres.NewDownloadStops(ctx, producerPool, root, scenario.recovery.guard)
			if e != nil {
				t.Fatal(e)
			}
			g.pending = writer
			ack, e := postgres.NewDownloadStops(ctx, ackPool, root, scenario.recovery.guard)
			if e != nil {
				t.Fatal(e)
			}
			closed, e := objectstore.NewClosedDownloadStopObjects(store, p.StoreID, keys, keys)
			if e != nil {
				t.Fatal(e)
			}
			legacy := &objectstore.DownloadStopObjects{Store: store, Seal: keys, Open: keys, StoreID: p.StoreID}
			healthy, e := evidence.NewHealthyDownloadStopObjects(legacy, closed, g.writer)
			if e != nil {
				t.Fatal(e)
			}
			service := evidence.ContextDownloadStopCoordinator{Ledger: stopNativeLedger{stops, writer}, Acknowledgements: ack, Objects: healthy, Now: time.Now}
			public, private, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			signer, e := jose.NewDownloadStopRetirementSignatures(root, "synthetic-stop", private, map[string]ed25519.PublicKey{"synthetic-stop": public})
			if e != nil {
				t.Fatal(e)
			}
			verifier, e := jose.NewDownloadStopRetirementSignatures(root, "", nil, map[string]ed25519.PublicKey{"synthetic-stop": public})
			if e != nil {
				t.Fatal(e)
			}
			g.objects, e = objectstore.NewDownloadStopCleanupObjects(store, p.StoreID, keys, keys, signer, verifier)
			if e != nil {
				t.Fatal(e)
			}
			g.verifyObjects, e = objectstore.NewDownloadStopCleanupVerifier(store, p.StoreID, keys, verifier)
			if e != nil {
				t.Fatal(e)
			}
			for _, mode := range []string{"written", "unused", "unwritten", "unknown"} {
				a := current()
				session, e := ledger.ReserveDownload(ctx, evidence.DownloadReservation{Authority: a, IdempotencyDigest: evidence.ContextDownloadKeyDigest("lifecycle-" + mode), Session: artifact.DownloadSession{ID: custodyID(), AllocationID: allocation.ID, Scope: scope, RequestDigest: evidence.ContextDownloadRequestDigest(scope.ArtifactID), State: artifact.DownloadPreparing, StopProtocol: artifact.DownloadStopProtocol, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Deadline: deadline, OutputLimit: 8192, ReadLimit: 16 << 20, RequestLimit: 4}})
				if e != nil {
					t.Fatal("reserve lifecycle", mode, e)
				}
				actor := scenario.a.Eligibility.VerifiedIdentity
				actor.Scopes = []string{"openid"}
				actor.VerifiedAt = time.Now()
				actor.ValidUntil = actor.VerifiedAt.Add(5 * time.Second)
				if mode == "written" {
					receipt, e := service.CancelContextDownload(ctx, stopNativeIdentity{actor}, session.ID, "stop-lifecycle", custodyID())
					if e != nil || receipt.AuditState != "recorded" {
						t.Fatal("closed Stop", receipt, e)
					}
				} else if mode != "unused" {
					decision, e := stops.StopDownload(ctx, actor, session.ID, evidence.DownloadStopKeyDigest("stop-lifecycle"), custodyID())
					if e != nil {
						t.Fatal(e)
					}
					if mode == "unknown" {
						fresh, e := writer.ClaimDownloadStopWrite(ctx, decision.Decision)
						if e != nil || !fresh {
							t.Fatal(e)
						}
						binding, e := g.writer.ReadDownloadStopBinding(ctx, decision.Decision)
						if e != nil {
							t.Fatal(e)
						}
						if _, e = closed.CreateClosedDownloadStop(ctx, binding, decision.Decision); e != nil {
							t.Fatal(e)
						}
						// Provider completed, but its completion reply is lost. Existence may
						// recover audit bytes; it cannot qualify SQL writer closure.
						if _, e = healthy.FindDownloadStop(ctx, decision.Decision); e == nil {
							t.Fatal("Find recovered lost completion")
						}
						for attempt := 0; attempt < 4; attempt++ {
							fresh, e := writer.ClaimDownloadStopWrite(ctx, decision.Decision)
							if e != nil || fresh {
								t.Fatal("bounded lookup accounting", attempt, e)
							}
						}
						pending, e := writer.PendingDownloadStops(ctx)
						if e != nil {
							t.Fatal(e)
						}
						for _, item := range pending {
							if item.Decision.DownloadID == session.ID {
								t.Fatal("exhausted lookup occupies pending slot")
							}
						}

					}
				}
				state, e := g.cleanup.ReadDownloadStopLifecycle(ctx, session.ID)
				if e != nil {
					t.Fatal("initial state", e)
				}
				if e = g.finalizer.RetireDownloadStop(ctx, session.ID); e == nil {
					t.Fatal("retired without absence acknowledgement")
				}
				g.records = append(g.records, record{session, mode, state})
			}
			groups = append(groups, g)
		}
		wait := func(until time.Time) {
			t.Helper()
			timer := time.NewTimer(max(0, time.Until(until)+20*time.Millisecond))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		sort.Slice(groups, func(i, j int) bool {
			return groups[i].records[0].state.Binding.OriginalPurgeAt.Before(groups[j].records[0].state.Binding.OriginalPurgeAt)
		})
		for _, g := range groups {
			wait(g.records[0].state.Binding.OriginalPurgeAt)
			refreshAuditFixtureRecovery(t, ctx, admin, g.scenario.recovery.observation, 30*time.Second)
			pending, e := g.pending.PendingDownloadStops(ctx)
			if e != nil || len(pending) != 0 {
				t.Fatal("expired/unclaimed/exhausted rows still consume active pending slots", len(pending), e)
			}
			for i := range g.records {
				r := &g.records[i]
				if r.mode == "unknown" {
					if _, e := g.cleanup.BeginDownloadStopPurge(ctx, r.session.ID, "original"); e == nil {
						t.Fatal("unknown claimed writer was purged")
					}
					continue
				}
				lease, e := g.cleanup.BeginDownloadStopPurge(ctx, r.session.ID, "original")
				if e != nil {
					t.Fatal("original lease", r.mode, e)
				}
				if r.mode == "unwritten" {
					if r.state.Decision == nil {
						t.Fatal("unwritten decision missing")
					}
					if _, e = g.pending.ClaimDownloadStopWrite(ctx, *r.state.Decision); e == nil {
						t.Fatal("closed unclaimed writer regained a provider attempt")
					}
				}
				if e = g.objects.PurgeDownloadStopObjects(ctx, lease); e != nil {
					t.Fatal("original purge", e)
				}
				retirement, e := g.cleanup.RecordOriginalDownloadStopPurge(ctx, lease)
				if e != nil || retirement.Mode != r.mode {
					t.Fatal("retirement mode", retirement.Mode, r.mode, e)
				}
				fresh, e := g.cleanup.ClaimDownloadStopCertificate(ctx, retirement)
				if e != nil || !fresh {
					t.Fatal("certificate claim", e)
				}
				completion, e := g.objects.CreateDownloadStopCertificate(ctx, r.state.Binding, retirement)
				if e != nil {
					t.Fatal("certificate", e)
				}
				if e = g.cleanup.RecordDownloadStopCertificateCompletion(ctx, retirement, completion); e != nil {
					t.Fatal("certificate completion", e)
				}
				if fresh, e = g.verifier.ClaimDownloadStopCertificateVerification(ctx, retirement); e != nil || !fresh {
					t.Fatal("verification claim", e)
				}
				if r.mode == "written" { // First independent verification reply was lost: one prepaid retry remains.
					if fresh, e = g.verifier.ClaimDownloadStopCertificateVerification(ctx, retirement); e != nil || !fresh {
						t.Fatal("verification retry", e)
					}
					if _, e = g.verifier.ClaimDownloadStopCertificateVerification(ctx, retirement); e == nil {
						t.Fatal("unbounded certificate verification attempts")
					}
				}

				if e = g.verifyObjects.VerifyDownloadStopCertificate(ctx, retirement, completion.Receipt); e != nil {
					t.Fatal("independent verify", e)
				}
				if e = g.verifier.AcknowledgeDownloadStopCertificate(ctx, retirement, completion.Receipt); e != nil {
					t.Fatal("certificate ack", e)
				}
				r.state, e = g.cleanup.ReadDownloadStopLifecycle(ctx, r.session.ID)
				if e != nil {
					t.Fatal(e)
				}
			}
		}
		for _, g := range groups {
			wait(g.records[0].state.Binding.CertificatePurgeAt)
			refreshAuditFixtureRecovery(t, ctx, admin, g.scenario.recovery.observation, 30*time.Second)
			for _, r := range g.records {
				if r.mode == "unknown" {
					continue
				}
				lease, e := g.cleanup.BeginDownloadStopPurge(ctx, r.session.ID, "terminal")
				if e != nil {
					t.Fatal("terminal lease", e)
				}
				if e = g.objects.PurgeDownloadStopObjects(ctx, lease); e != nil {
					t.Fatal(e)
				}
				purged, e := g.cleanup.RecordTerminalDownloadStopPurge(ctx, lease)
				if e != nil {
					t.Fatal(e)
				}
				if e = g.verifyObjects.VerifyDownloadStopAbsence(ctx, lease); e != nil {
					t.Fatal(e)
				}
				if e = g.verifier.AcknowledgeDownloadStopAbsence(ctx, lease, purged); e != nil {
					t.Fatal(e)
				}
				// The positive finalization transition remains rollback-safe together
				// with its charge/history transfer; no separate best-effort refund.
				tx, e := g.finalPool.Begin(ctx)
				if e != nil {
					t.Fatal(e)
				}
				var retired bool
				if e = tx.QueryRow(ctx, "SELECT finish_download_stop_retirement($1,$2,$3)", g.allocation.RootID, r.session.ID, g.scenario.recovery.installation).Scan(&retired); e != nil || !retired {
					_ = tx.Rollback(ctx)
					t.Fatal("staged finalization", e)
				}
				var count int
				if e = tx.QueryRow(ctx, "SELECT count(*) FROM download_stop WHERE download_id=$1", r.session.ID).Scan(&count); e != nil || count != 0 {
					_ = tx.Rollback(ctx)
					t.Fatal("did not retire inside transaction", count, e)
				}
				if e = tx.Rollback(ctx); e != nil {
					t.Fatal(e)
				}
				if e = admin.QueryRow(ctx, "SELECT count(*) FROM download_stop WHERE download_id=$1", r.session.ID).Scan(&count); e != nil || count != 1 {
					t.Fatal("rollback lost original Stop", count, e)
				}
				if e = g.finalizer.RetireDownloadStop(ctx, r.session.ID); e != nil {
					t.Fatal("retire", e)
				}
			}
			var charged, reserved int64
			if e := admin.QueryRow(ctx, "SELECT charged FROM download_stop_backing WHERE allocation_id=$1", g.allocation.ID).Scan(&charged); e != nil || g.horizon == 0 && charged != 1 || g.horizon > 0 && charged != 4 {
				t.Fatal("history prematurely refunded", charged, e)
			}
			if e := admin.QueryRow(ctx, "SELECT reserved_sessions FROM download_allocation WHERE id=$1", g.allocation.ID).Scan(&reserved); e != nil || reserved != 4 {
				t.Fatal("retirement changed parent download accounting", reserved, e)
			}
			for _, denial := range []struct {
				p   *pgxpool.Pool
				sql string
			}{{g.cleanupPool, "UPDATE download_stop_lifecycle SET terminal_acknowledged_at=clock_timestamp()"}, {g.verifyPool, "UPDATE download_stop_lifecycle SET lease_fence=lease_fence+1"}, {g.finalPool, "DELETE FROM download_stop"}, {g.finalPool, "UPDATE download_stop_backing SET charged=0"}} {
				_, e := denial.p.Exec(ctx, denial.sql)
				var pg *pgconn.PgError
				if !errors.As(e, &pg) || pg.Code != "42501" {
					t.Fatal("excess lifecycle role", denial.sql, e)
				}
			}
		}
		for _, g := range groups {
			if g.horizon == 0 {
				continue
			}
			wait(g.records[0].state.Binding.HistoryReleaseAt)
			refreshAuditFixtureRecovery(t, ctx, admin, g.scenario.recovery.observation, 30*time.Second)
			keys, e := g.finalizer.DueDownloadStopHistory(ctx)
			if e != nil || len(keys) != 1 {
				t.Fatal("bounded due history", len(keys), e)
			}
			type release struct {
				result audit.OperationHistoryRelease
				err    error
			}
			start := make(chan struct{})
			replies := make(chan release, 4)
			for worker := 0; worker < 4; worker++ {
				go func() {
					<-start
					r, e := g.finalizer.ReleaseDownloadStopHistory(ctx, keys[0])
					replies <- release{r, e}
				}()
			}
			close(start)
			result := audit.OperationHistoryRelease{}
			var releaseErr error
			for worker := 0; worker < 4; worker++ {
				reply := <-replies
				result.Records += reply.result.Records
				result.Overdue = result.Overdue || reply.result.Overdue
				if reply.err != nil {
					releaseErr = reply.err
				}
			}
			if releaseErr != nil || result.Records != 3 || !result.Overdue {
				t.Fatal("concurrent backed history release/missing-audit report", result, releaseErr)
			}
			var charged int64
			if e = admin.QueryRow(ctx, "SELECT charged FROM download_stop_backing WHERE allocation_id=$1", g.allocation.ID).Scan(&charged); e != nil || charged != 1 {
				t.Fatal("unknown writer credit lost", charged, e)
			}
			result, e = evidence.SweepDownloadStopHistory(ctx, g.finalizer)
			if e != nil || result.Records != 0 {
				t.Fatal("history replay refunded", result, e)
			}
		}
	})
}

// A real row lock crosses the shorter accepted backing deadline. Neither the
// parent authority's still-live five seconds nor a pre-lock SQL clock can revive it.
func qualifyStopBackingExpiryAfterLock(t *testing.T, ctx context.Context, admin *pgxpool.Pool, ledger, config *postgres.Downloads, a artifact.DownloadAuthority, backing artifact.DownloadStopBacking, scope artifact.DownloadScope, deadline time.Time) {
	t.Helper()
	originalUntil := backing.ValidUntil
	backing.ExpectedRevision = 1
	backing.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	backing.ValidUntil = backing.ObservedAt.Add(700 * time.Millisecond)
	if e := config.BindDownloadStopBacking(ctx, backing); e != nil {
		t.Fatal("short backing", e)
	}
	tx, e := admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	var blocker int32
	if e = tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&blocker); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SELECT allocation_id FROM download_stop_backing WHERE allocation_id=$1 FOR UPDATE", backing.AllocationID); e != nil {
		t.Fatal(e)
	}
	sessionID := custodyID()
	done := make(chan error, 1)
	joined := false
	opctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		_ = tx.Rollback(ctx)
		if !joined {
			<-done
		}
	}()
	go func() {
		_, e := ledger.ReserveDownload(opctx, evidence.DownloadReservation{Authority: a, IdempotencyDigest: evidence.ContextDownloadKeyDigest("lifecycle-lock-expiry"), Session: artifact.DownloadSession{ID: sessionID, AllocationID: backing.AllocationID, Scope: scope, RequestDigest: evidence.ContextDownloadRequestDigest(scope.ArtifactID), State: artifact.DownloadPreparing, StopProtocol: artifact.DownloadStopProtocol, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Deadline: deadline, OutputLimit: 8192, ReadLimit: 16 << 20, RequestLimit: 4}})
		done <- e
	}()
	blocked := false
	for until := time.Now().Add(2 * time.Second); time.Now().Before(until) && !blocked; {
		if e = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='download_runtime' AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)))", blocker).Scan(&blocked); e != nil {
			t.Fatal(e)
		}
		if !blocked {
			select {
			case e := <-done:
				joined = true
				t.Fatal("reservation did not wait on actual backing lock", e)
			case <-time.After(10 * time.Millisecond):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	if !blocked {
		t.Fatal("did not observe real backing lock wait")
	}
	timer := time.NewTimer(max(0, time.Until(backing.ValidUntil)+20*time.Millisecond))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		joined = true
		if e == nil {
			t.Fatal("expired stop backing admitted after lock")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var charged, rows int64
	if e = admin.QueryRow(ctx, "SELECT charged,(SELECT count(*) FROM artifact_download WHERE id=$2) FROM download_stop_backing WHERE allocation_id=$1", backing.AllocationID, sessionID).Scan(&charged, &rows); e != nil || charged != 0 || rows != 0 {
		t.Fatal("expired admission did not roll back", charged, rows, e)
	}
	backing.ExpectedRevision = 2
	backing.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	backing.ValidUntil = originalUntil
	if e = config.BindDownloadStopBacking(ctx, backing); e != nil {
		t.Fatal("restore current backing", e)
	}
}
