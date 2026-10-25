package integration

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
	"testing"
	"time"
)

func qualifyOperationAuditOverdue(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	for _, h := range []int64{0, 1} {
		name := "operation-audit-overdue-original-no-history"
		if h > 0 {
			name = "operation-audit-overdue-original-backed-history"
		}
		t.Run(name, func(t *testing.T) {
			s := create(t, 1)
			cp := poolFor("operation_audit_config_runtime", "synthetic-operation-config")
			defer cp.Close()
			jp := poolFor("operation_audit_runtime", "synthetic-operation-journal")
			defer jp.Close()
			ap := poolFor("operation_audit_ack_runtime", "synthetic-operation-ack")
			defer ap.Close()
			dp := poolFor("operation_audit_cleanup_runtime", "synthetic-operation-cleanup")
			defer dp.Close()
			fp := poolFor("operation_audit_retire_runtime", "synthetic-operation-retire")
			defer fp.Close()
			config, e := postgres.New(ctx, cp)
			if e != nil {
				t.Fatal(e)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			for _, lane := range []string{"normal", "resolution"} {
				p := app.OperationAuditPool{RootID: s.a.RootID, Lane: lane, AccountVersion: "accounts-v1", Accounts: 2, RecordsPerAccount: 4, RetainedSeconds: 3600, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: now.Add(time.Hour)}
				if e = config.ProvisionOperationAuditPool(ctx, p); e != nil {
					t.Fatal(e)
				}
			}
			policy := value.OperationLifecyclePolicy{RootID: s.a.RootID, Lane: "normal", InstallationID: s.recovery.installation, StoreID: custodyID(), PolicyID: custodyID(), BackupProfileID: custodyID(), PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 8, MaxPurgeLeases: 16, CleanupBudgetSeconds: 2, ProofWindowSeconds: 1, ValidUntil: now.Add(time.Hour), BackupHorizonSeconds: h, OverdueTerminal: value.OperationOverdueTerminal}
			{
				policy.History = &value.OperationHistoryQualification{ID: custodyID(), Digest: artifact.Digest{4}, Layout: value.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
				bb, ww := policy.History.SlotBacking(policy.MaxPurgeLeases)
				policy.BackupReservedBytes = bb * policy.MetadataSlots
				policy.WALReservedBytes = ww * policy.MetadataSlots
			}
			lc := func(p *pgxpool.Pool, lane string) *postgres.OperationLifecycles {
				x, e := postgres.NewOperationLifecycles(ctx, p, s.a.RootID, lane, s.recovery.guard)
				if e != nil {
					t.Fatal(e)
				}
				return x
			}
			producerLedger, cleanup, verified, finalizer := lc(jp, "normal"), lc(dp, "normal"), lc(ap, "normal"), lc(fp, "normal")
			j, e := postgres.NewHealthyOperationJournal(ctx, jp, policy, s.recovery.guard)
			if e != nil {
				t.Fatal(e)
			}
			ack, e := postgres.NewOperationAcknowledgements(ctx, ap, s.a.RootID, "normal", s.recovery.guard)
			if e != nil {
				t.Fatal(e)
			}
			producer, e := objectstore.NewClosedOperationAuditObjects(store, policy.StoreID, keys, keys)
			if e != nil {
				t.Fatal(e)
			}
			legacyObjects := &objectstore.OperationAuditObjects{Store: store, Seal: keys, Open: keys}
			gate, e := app.NewHealthyOperationAuditor(policy, j, ack, legacyObjects, producer, producerLedger, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			purger, e := objectstore.NewOperationAuditPurger(store, policy.StoreID)
			if e != nil {
				t.Fatal(e)
			}
			verifier, e := objectstore.NewOperationAuditAbsenceVerifier(store, policy.StoreID)
			if e != nil {
				t.Fatal(e)
			}
			intent := func() value.OperationIntent {
				n := time.Now().UTC().Truncate(time.Microsecond)
				id := custodyID()
				return value.OperationIntent{ID: id, RootID: s.a.RootID, TraceID: id, Name: "get_capture", InputFormat: "context-input/v1", MACVersion: "audit-v1", AccountVersion: "accounts-v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{1}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(6 * time.Second), RetainUntil: n.Add(20 * time.Second)}
			}
			finish := func(in value.OperationIntent, p value.OperationLifecyclePolicy, g *app.HealthyOperationAuditor) value.OperationIntent {
				t.Helper()
				if e = g.Begin(ctx, in); e != nil {
					t.Fatal(e)
				}
				out := value.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{3}, OutputBytes: 12, MetadataUntil: in.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
				if e = g.Finish(ctx, out); e != nil {
					t.Fatal(e)
				}
				bound, e := app.BindOperationLifecycle(in, p)
				if e != nil {
					t.Fatal(e)
				}
				return bound
			}
			a, b, c := finish(intent(), policy, gate), finish(intent(), policy, gate), finish(intent(), policy, gate)
			unknown := intent()
			lost := &closedAuditLostReply{ClosedOperationObjects: producer}
			ug, e := app.NewHealthyOperationAuditor(policy, j, ack, legacyObjects, lost, producerLedger, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			if !errors.Is(ug.Begin(ctx, unknown), app.ErrUnavailable) {
				t.Fatal("unknown write accepted")
			}
			// New admission keeps its required v3 backing even when overdue
			// cleanup is not selected. This checks that missing opt-in cannot be
			// inferred from elapsed time; actual legacy rows are constructed by
			// the separate real pre48 migration fixture.
			unoptedPolicy := policy
			unoptedPolicy.Lane = "resolution"
			unoptedPolicy.OverdueTerminal = ""
			unoptedPolicy.BackupHorizonSeconds = 0
			oj, e := postgres.NewHealthyOperationJournal(ctx, jp, unoptedPolicy, s.recovery.guard)
			if e != nil {
				t.Fatal(e)
			}
			oa, e := postgres.NewOperationAcknowledgements(ctx, ap, s.a.RootID, "resolution", s.recovery.guard)
			if e != nil {
				t.Fatal(e)
			}
			og, e := app.NewHealthyOperationAuditor(unoptedPolicy, oj, oa, legacyObjects, producer, lc(jp, "resolution"), time.Now)
			if e != nil {
				t.Fatal(e)
			}
			oi := intent()
			oi.Name = "resolve_capture_request"
			unopted := finish(oi, unoptedPolicy, og)
			if _, e = cleanup.BeginOperationPurge(ctx, a.ID, "overdueOriginal"); e == nil {
				t.Fatal("proof window bypassed early")
			}
			extra, _ := app.BindOperationLifecycle(intent(), policy)
			if _, e = j.ReserveOperation(ctx, extra); e == nil {
				t.Fatal("saturated account admitted")
			}
			waitOnly := func(at time.Time) {
				t.Helper()
				timer := time.NewTimer(time.Until(at))
				defer timer.Stop()
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-timer.C:
				}
			}
			wait := func(at time.Time) {
				t.Helper()
				waitOnly(at)
				refreshAuditFixtureRecovery(t, ctx, admin, s.recovery.observation, 30*time.Second)
			}
			wait(c.Lifecycle.OriginalPurgeAt.Add(10 * time.Millisecond))
			var prepared value.OperationRetirement
			for _, in := range []value.OperationIntent{b, c} {
				l, e := cleanup.BeginOperationPurge(ctx, in.ID, "original")
				if e != nil {
					t.Fatal(e)
				}
				if e = purger.PurgeOperationObjects(ctx, l); e != nil {
					t.Fatal(e)
				}
				r, e := cleanup.RecordOriginalOperationPurge(ctx, l)
				if e != nil {
					t.Fatal(e)
				}
				if in.ID == b.ID {
					prepared = r
				} else {
					fresh, e := cleanup.ClaimOperationCertificate(ctx, r)
					if e != nil || !fresh {
						t.Fatal("claim", fresh, e)
					}
				}
			}
			wait(unopted.RetainUntil.Add(50 * time.Millisecond))
			for _, item := range []struct {
				ledger *postgres.OperationLifecycles
				id     string
			}{{cleanup, unknown.ID}, {cleanup, c.ID}, {lc(dp, "resolution"), unopted.ID}} {
				if _, e = item.ledger.BeginOperationPurge(ctx, item.id, "overdueOriginal"); e == nil {
					t.Fatal("unopted or unknown writer promoted", item.id)
				}
			}
			var leases [2]value.OperationPurgeLease
			var errs [2]error
			var wg sync.WaitGroup
			for i := range leases {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					leases[i], errs[i] = cleanup.BeginOperationPurge(ctx, a.ID, "overdueOriginal")
				}(i)
			}
			wg.Wait()
			if errs[0] != nil || errs[1] != nil || leases[0] != leases[1] {
				t.Fatalf("concurrent branch changed lease: %v\n%+v\n%+v", errs, leases[0], leases[1])
			}
			l := leases[0]
			// The cleanup role can request selection but cannot undo its durable fence.
			if _, e = dp.Exec(ctx, "UPDATE operation_audit_lifecycle SET overdue_selected_at=NULL WHERE operation_id=$1", a.ID); e == nil {
				t.Fatal("no-certificate fence reopened")
			}
			if _, e = dp.Exec(ctx, "UPDATE operation_audit_lifecycle SET certificate_started=true WHERE operation_id=$1", a.ID); e == nil {
				t.Fatal("fenced certificate claim accepted")
			}
			var missed int64
			if e = admin.QueryRow(ctx, "SELECT proof_window_missed FROM operation_audit_pool WHERE root_id=$1 AND lane='normal'", s.a.RootID).Scan(&missed); e != nil || missed != 1 {
				t.Fatal("mode counter replay", missed, e)
			}
			var unchanged bool
			if e = admin.QueryRow(ctx, "SELECT original_purge_at=$2 AND certificate_purge_at=$3 AND live_retire_by=$4 FROM operation_audit_lifecycle WHERE operation_id=$1", a.ID, a.Lifecycle.OriginalPurgeAt, a.Lifecycle.CertificatePurgeAt, a.Lifecycle.LiveRetireBy).Scan(&unchanged); e != nil || !unchanged {
				t.Fatal("overdue changed dates", e)
			}
			if e = purger.PurgeOperationObjects(ctx, l); e != nil {
				t.Fatal(e)
			}
			proof, e := cleanup.RecordOverdueOperationPurge(ctx, l)
			if e != nil {
				t.Fatal(e)
			}
			if e = finalizer.RetireOperationAudit(ctx, a.ID); e == nil {
				t.Fatal("purge alone released charge")
			}
			if e = verifier.VerifyOperationAbsence(ctx, l); e != nil {
				t.Fatal(e)
			}
			tx, e := admin.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			var blocker int
			if e = tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&blocker); e != nil {
				t.Fatal(e)
			}
			if _, e = tx.Exec(ctx, "SELECT 1 FROM operation_audit_account WHERE root_id=$1 AND lane='normal' FOR UPDATE", s.a.RootID); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- verified.AcknowledgeOverdueOperationPurge(ctx, l, proof) }()
			blocked := false
			limit := time.Now().Add(2 * time.Second)
			for time.Now().Before(limit) {
				if e = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='operation_audit_ack_runtime' AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)))", blocker).Scan(&blocked); e != nil {
					t.Fatal(e)
				}
				if blocked {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !blocked {
				t.Fatal("ack did not block on real account row")
			}
			waitOnly(l.Until.Add(20 * time.Millisecond))
			if e = tx.Rollback(ctx); e != nil {
				t.Fatal(e)
			}
			if e = <-done; e == nil {
				t.Fatal("expired acknowledgement accepted")
			}
			l, e = cleanup.BeginOperationPurge(ctx, a.ID, "overdueOriginal")
			if e != nil {
				t.Fatal(e)
			}
			if e = purger.PurgeOperationObjects(ctx, l); e != nil {
				t.Fatal(e)
			}
			proof, e = cleanup.RecordOverdueOperationPurge(ctx, l)
			if e != nil {
				t.Fatal(e)
			}
			if e = verifier.VerifyOperationAbsence(ctx, l); e != nil {
				t.Fatal(e)
			}
			if e = verified.AcknowledgeOverdueOperationPurge(ctx, l, proof); e != nil {
				t.Fatal(e)
			}
			ft, e := fp.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			var finished bool
			if e = ft.QueryRow(ctx, "SELECT finish_operation_audit_retirement($1,$2,$3)", s.a.RootID, a.ID, policy.InstallationID).Scan(&finished); e != nil || !finished {
				t.Fatal("provisional retirement", e)
			}
			var rows int
			if e = ft.QueryRow(ctx, "SELECT count(*) FROM operation_audit WHERE id=$1", a.ID).Scan(&rows); e != nil || rows != 0 {
				t.Fatal("operation not provisionally deleted", e)
			}
			if e = ft.Rollback(ctx); e != nil {
				t.Fatal(e)
			}
			if e = admin.QueryRow(ctx, "SELECT count(*) FROM operation_audit WHERE id=$1", a.ID).Scan(&rows); e != nil || rows != 1 {
				t.Fatal("rollback lost original", e)
			}
			if e = finalizer.RetireOperationAudit(ctx, a.ID); e != nil {
				t.Fatal(e)
			}
			service := app.OperationOverdueCleanup{Journal: cleanup, Acknowledgements: verified, Finalizer: finalizer, Objects: purger, Verifier: verifier}
			if e = service.Advance(ctx, b.ID); e != nil {
				t.Fatal("never claimed certificate blocked late purge", e)
			}
			if fresh, e := cleanup.ClaimOperationCertificate(ctx, prepared); e == nil || fresh {
				t.Fatal("retired request regained certificate claim")
			}
			if e = admin.QueryRow(ctx, "SELECT proof_window_missed FROM operation_audit_pool WHERE root_id=$1 AND lane='normal'", s.a.RootID).Scan(&missed); e != nil || missed != 2 {
				t.Fatal("missed proof count", missed, e)
			}
			var charged int64
			if h > 0 {
				if e = admin.QueryRow(ctx, "SELECT charged FROM operation_audit_account WHERE root_id=$1 AND lane='normal'", s.a.RootID).Scan(&charged); e != nil || charged != 4 {
					t.Fatal("history/unknown charge released early", charged, e)
				}
				var eligible time.Time
				if e = admin.QueryRow(ctx, "SELECT max(eligible_at) FROM operation_audit_history WHERE root_id=$1", s.a.RootID).Scan(&eligible); e != nil {
					t.Fatal(e)
				}
				wait(eligible.Add(20 * time.Millisecond))
				result, e := (app.OperationHistoryCleanup{Journal: finalizer, Finalizer: finalizer}).Sweep(ctx)
				if e != nil || result.Records != 2 || !result.Overdue {
					t.Fatal("history drain", result, e)
				}
			}
			if e = admin.QueryRow(ctx, "SELECT charged FROM operation_audit_account WHERE root_id=$1 AND lane='normal'", s.a.RootID).Scan(&charged); e != nil || charged != 2 {
				t.Fatal("unknown charges altered", charged, e)
			}
			for _, p := range []*pgxpool.Pool{cp, jp, ap, dp, fp} {
				_, e = p.Exec(ctx, "UPDATE operation_audit_pool SET proof_window_missed=0 WHERE root_id=$1", s.a.RootID)
				var pe *pgconn.PgError
				if !errors.As(e, &pe) || pe.Code != "42501" {
					t.Fatal("counter privilege broadened", e)
				}
			}
			for _, p := range []*pgxpool.Pool{jp, ap, fp} {
				_, e = p.Exec(ctx, "UPDATE operation_audit_lifecycle SET overdue_selected_at=clock_timestamp() WHERE operation_id=$1", unknown.ID)
				var pe *pgconn.PgError
				if !errors.As(e, &pe) || pe.Code != "42501" {
					t.Fatal("mode privilege broadened", e)
				}
			}
		})
	}
}
