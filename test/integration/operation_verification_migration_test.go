package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Separately owned SQL-only compatibility database, following the control37
// migration fixture. Real historical triggers remain enabled throughout. The
// minimized completions/receipts below are explicitly synthetic; actual S3
// certificate creation and independent verification run in the sibling case.
func qualifyOperationVerificationMigration(t *testing.T, ctx context.Context, admin *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Run("operation-audit-verifier-migration-preserves-history-and-spend", func(t *testing.T) {
		name := "operation_verifier_" + strings.ReplaceAll(custodyID(), "-", "")
		if _, e := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Fatal(e)
		}
		cfg := admin.Config().Copy()
		cfg.ConnConfig.Database = name
		cfg.MaxConns = 1
		var scratch *pgxpool.Pool
		defer func() {
			if scratch != nil {
				scratch.Close()
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, e := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
				t.Error("migration database cleanup", e)
			}
		}()
		scratch, e := pgxpool.NewWithConfig(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		paths, e := filepath.Glob("../../migrations/[0-9]*.sql")
		if e != nil {
			t.Fatal(e)
		}
		sort.Strings(paths)
		var migration []byte
		for _, path := range paths {
			v, e := strconv.Atoi(filepath.Base(path)[:5])
			if e != nil {
				t.Fatal(e)
			}
			body, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if v == 48 {
				migration = body
				break
			}
			if _, e = scratch.Exec(ctx, string(body)); e != nil {
				t.Fatalf("historical migration %d: %v", v, e)
			}
		}
		if len(migration) == 0 {
			t.Fatal("missing actual migration48")
		}
		exec := func(sql string, args ...any) {
			t.Helper()
			if _, e := scratch.Exec(ctx, sql, args...); e != nil {
				t.Fatal("historical SQL transition", e)
			}
		}
		encode := func(v any) []byte {
			t.Helper()
			b, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			return b
		}
		now := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
		wait := func(until time.Time) {
			t.Helper()
			timer := time.NewTimer(time.Until(until.Add(time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		type historical struct {
			in       value.OperationIntent
			epoch    string
			original []byte
		}
		var records []historical
		insert := func(in value.OperationIntent, epoch string) error {
			_, e := scratch.Exec(ctx, "INSERT INTO operation_audit(id,root_id,lane,issuer_epoch,principal_digest,intent,request_until,write_until,retain_until) VALUES($1,$2,'normal',$3,$4,$5,$6,$7,$8)", in.ID, in.RootID, epoch, in.PrincipalDigest[:], encode(in), in.RequestUntil, in.WriteUntil, in.RetainUntil)
			return e
		}
		fresh := func(p value.OperationLifecyclePolicy) value.OperationIntent {
			n := now()
			id := custodyID()
			in := value.OperationIntent{ID: id, RootID: p.RootID, TraceID: id, Name: "get_capture", InputFormat: "context-input/v1", MACVersion: "audit-v1", AccountVersion: "accounts-v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(5 * time.Second), RetainUntil: n.Add(60 * time.Second)}
			bound, e := app.BindOperationLifecycle(in, p)
			if e != nil {
				t.Fatal(e)
			}
			return bound
		}
		for _, layout := range []string{"", value.OperationHistoryLayout, value.OperationOverdueHistoryLayout} {
			scenario := create(t, 1)
			var initialAudit string
			if e = admin.QueryRow(ctx, "SELECT initial_audit_id FROM permission_stream WHERE id=$1", scenario.a.RootID).Scan(&initialAudit); e != nil {
				t.Fatal(e)
			}
			tx, e := scratch.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			for _, row := range []struct{ table, key string }{{"permission_stream", scenario.a.RootID}, {"authority_audit", initialAudit}} {
				var raw []byte
				if e = admin.QueryRow(ctx, "SELECT to_jsonb(t) FROM "+pgx.Identifier{row.table}.Sanitize()+" t WHERE id=$1", row.key).Scan(&raw); e != nil {
					tx.Rollback(ctx)
					t.Fatal(e)
				}
				if _, e = tx.Exec(ctx, "INSERT INTO "+pgx.Identifier{row.table}.Sanitize()+" SELECT (jsonb_populate_record(NULL::"+pgx.Identifier{row.table}.Sanitize()+",$1::jsonb)).*", raw); e != nil {
					tx.Rollback(ctx)
					t.Fatal(e)
				}
			}
			if e = tx.Commit(ctx); e != nil {
				t.Fatal(e)
			}
			epoch := custodyID()
			// Only fixture recovery acceptance is synthesized, for this exact scratch
			// database incarnation. Runtime observers cannot perform this transition.
			exec("INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()),$1,$2,'synthetic-verifier-migration',1,$3,false,false,statement_timestamp(),statement_timestamp()+interval '30 seconds')", scenario.recovery.installation, epoch, make([]byte, 32))
			n := now()
			exec("INSERT INTO operation_audit_pool(root_id,lane,account_version,revision,valid_until,account_limit,records_per_account,retained_seconds) VALUES($1,'normal','accounts-v1',1,$2,1,10,3600)", scenario.a.RootID, n.Add(time.Hour))
			p := value.OperationLifecyclePolicy{RootID: scenario.a.RootID, Lane: "normal", InstallationID: scenario.recovery.installation, StoreID: custodyID(), PolicyID: custodyID(), BackupProfileID: custodyID(), PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 10, MaxPurgeLeases: 8, CleanupBudgetSeconds: 3, ProofWindowSeconds: 1, ValidUntil: n.Add(time.Hour)}
			if layout != "" {
				p.BackupHorizonSeconds = 2
				p.History = &value.OperationHistoryQualification{ID: custodyID(), Digest: artifact.Digest{3}, Layout: layout, MaximumRowFootprintBytes: 256 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 2}
				bb, ww := p.History.SlotBacking(p.MaxPurgeLeases)
				p.BackupReservedBytes, p.WALReservedBytes = bb*p.MetadataSlots, ww*p.MetadataSlots
				if layout == value.OperationOverdueHistoryLayout {
					p.OverdueTerminal = value.OperationOverdueTerminal
				}
			}
			in := fresh(p)
			if e = insert(in, epoch); e != nil {
				t.Fatal("actual pre48 admission", layout, e)
			}
			records = append(records, historical{in, epoch, encode(in)})
		}
		// Prepare one independently acknowledged legacy certificate under the actual
		// old guard. The only synthetic facts here are the explicit test receipts.
		p := records[0].in.Lifecycle.Policy
		in := fresh(p)
		in.Lifecycle = nil
		in.RetainUntil = in.CreatedAt.Add(20 * time.Second)
		in, e = app.BindOperationLifecycle(in, p)
		if e != nil {
			t.Fatal(e)
		}
		if e = insert(in, records[0].epoch); e != nil {
			t.Fatal(e)
		}
		receipts := []value.Receipt{}
		completions := []value.OperationWriteCompletion{}
		for _, phase := range []string{"intent", "outcome"} {
			var record any = in
			if phase == "intent" {
				exec("UPDATE operation_audit SET intent_started=true WHERE id=$1", in.ID)
			} else {
				out := value.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{1}, OutputBytes: 1, MetadataUntil: in.RequestUntil, RecordedAt: now()}
				record = out
				exec("UPDATE operation_audit SET outcome=$2,outcome_started=true WHERE id=$1", in.ID, encode(out))
			}
			r := value.Receipt{Key: value.OperationAuditKey(in.RootID, in.ID, phase), ETag: "synthetic-migration", Bytes: 100, SHA256: artifact.Digest{1}}
			c := value.OperationWriteCompletion{Protocol: value.OperationWriterProtocol, RootID: in.RootID, OperationID: in.ID, StoreID: p.StoreID, Phase: phase, RecordDigest: app.OperationLifecycleDigest(record), Receipt: r, StoredAt: now(), ClosedAt: now()}
			exec("UPDATE operation_audit_lifecycle SET "+phase+"_completion=$2 WHERE operation_id=$1", in.ID, encode(c))
			exec("UPDATE operation_audit SET "+phase+"_receipt=$2 WHERE id=$1", in.ID, encode(r))
			receipts = append(receipts, r)
			completions = append(completions, c)
		}
		var postmaster time.Time
		var oid uint32
		if e = scratch.QueryRow(ctx, "SELECT pg_postmaster_start_time(),oid FROM pg_database WHERE datname=current_database()").Scan(&postmaster, &oid); e != nil {
			t.Fatal(e)
		}
		wait(in.Lifecycle.OriginalPurgeAt)
		lease := value.OperationPurgeLease{RootID: in.RootID, OperationID: in.ID, StoreID: p.StoreID, InstallationID: p.InstallationID, IssuerEpoch: records[0].epoch, Phase: "original", PostmasterAt: postmaster, DatabaseOID: oid, ObjectsDigest: app.OperationLifecycleDigest(receipts), WritersDigest: app.OperationLifecycleDigest(completions), Fence: 1, StartedAt: now(), Until: now().Add(2 * time.Second)}
		exec("UPDATE operation_audit_lifecycle SET lease=$2,lease_fence=1 WHERE operation_id=$1", in.ID, encode(lease))
		r := value.OperationRetirement{RootID: in.RootID, OperationID: in.ID, StoreID: p.StoreID, InstallationID: p.InstallationID, IssuerEpoch: records[0].epoch, PostmasterAt: postmaster, DatabaseOID: oid, ObjectsDigest: lease.ObjectsDigest, WritersDigest: lease.WritersDigest, PurgeFence: 1, PurgedAt: now(), CertificateWriteUntil: in.Lifecycle.CertificatePurgeAt.Add(-time.Second), CertificatePurgeAt: in.Lifecycle.CertificatePurgeAt, LiveRetireBy: in.Lifecycle.LiveRetireBy}
		exec("UPDATE operation_audit_lifecycle SET retirement=$2,certificate_started=true WHERE operation_id=$1", in.ID, encode(r))
		receipt := value.Receipt{Key: value.OperationAuditKey(in.RootID, in.ID, "deletion-certificate"), ETag: "synthetic-migration", Bytes: 100, SHA256: artifact.Digest{3}}
		completed := value.OperationWriteCompletion{Protocol: value.OperationWriterProtocol, RootID: in.RootID, OperationID: in.ID, StoreID: p.StoreID, Phase: "deletion-certificate", RecordDigest: app.OperationLifecycleDigest(r), Receipt: receipt, StoredAt: now(), ClosedAt: now()}
		exec("UPDATE operation_audit_lifecycle SET certificate_completion=$2 WHERE operation_id=$1", in.ID, encode(completed))
		exec("UPDATE operation_audit_lifecycle SET certificate_receipt=$2,certificate_acknowledged_at=clock_timestamp() WHERE operation_id=$1", in.ID, encode(receipt))
		if _, e = scratch.Exec(ctx, string(migration)); e != nil {
			t.Fatal("actual migration48", e)
		}
		var unspent int64
		if e = scratch.QueryRow(ctx, "SELECT count(*) FROM operation_audit_lifecycle WHERE certificate_verify_attempts<>2").Scan(&unspent); e != nil || unspent != 0 {
			t.Fatal("historical budget refilled", unspent, e)
		}
		for _, old := range records {
			var raw []byte
			if e = scratch.QueryRow(ctx, "SELECT intent FROM operation_audit WHERE id=$1", old.in.ID).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			var got value.OperationIntent
			if json.Unmarshal(raw, &got) != nil || string(encode(got)) != string(old.original) {
				t.Fatal("migration rewrote original binding")
			}
			if _, e = scratch.Exec(ctx, "UPDATE operation_audit_lifecycle SET certificate_verify_attempts=0 WHERE operation_id=$1", old.in.ID); e == nil {
				t.Fatal("historical attempts reset")
			}
			bad := fresh(old.in.Lifecycle.Policy)
			if e = insert(bad, old.epoch); e == nil {
				t.Fatal("old profile admitted new unbacked record")
			}
			next := old.in.Lifecycle.Policy
			next.History = &value.OperationHistoryQualification{ID: custodyID(), Digest: artifact.Digest{5}, Layout: value.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 256 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 2}
			bb, ww := next.History.SlotBacking(next.MaxPurgeLeases)
			next.BackupReservedBytes, next.WALReservedBytes = bb*next.MetadataSlots, ww*next.MetadataSlots
			wrong := next
			wrong.StoreID = custodyID()
			if e = insert(fresh(wrong), old.epoch); e == nil {
				t.Fatal("upgrade moved retained store")
			}
			wrong = next
			wrong.BackupHorizonSeconds++
			if e = insert(fresh(wrong), old.epoch); e == nil {
				t.Fatal("upgrade changed original backup horizon")
			}
			if old.in.Lifecycle.Policy.History != nil {
				for _, edit := range []func(*value.OperationHistoryQualification){
					func(q *value.OperationHistoryQualification) { q.MaximumRowFootprintBytes = 128 << 10 },
					func(q *value.OperationHistoryQualification) { q.MaximumTransitionWALBytes = 128 << 10 },
					func(q *value.OperationHistoryQualification) { q.BackupCopies = 1 },
					func(q *value.OperationHistoryQualification) { q.WALCopies = 1 },
				} {
					reduced := next
					q := *next.History
					edit(&q)
					reduced.History = &q
					if e = insert(fresh(reduced), old.epoch); e == nil {
						t.Fatal("upgrade reduced an outstanding qualification bound")
					}
				}
			}
			unsupported := fresh(next)
			unsupported.Lifecycle.Policy.History.Layout = "operation-audit-history/v999"
			if e = insert(unsupported, old.epoch); e == nil {
				t.Fatal("SQL accepted unknown future layout")
			}
			underbacked := fresh(next)
			underbacked.Lifecycle.Policy.WALReservedBytes--
			if e = insert(underbacked, old.epoch); e == nil {
				t.Fatal("SQL accepted under-backed v3 transitions")
			}

			admitted := fresh(next)
			if e = insert(admitted, old.epoch); e != nil {
				t.Fatal("explicit covering v3 acceptance failed", e)
			}
			var attempts int64
			if e = scratch.QueryRow(ctx, "SELECT certificate_verify_attempts FROM operation_audit_lifecycle WHERE operation_id=$1", admitted.ID).Scan(&attempts); e != nil || attempts != 0 {
				t.Fatal("new v3 did not get exact fresh allowance", attempts, e)
			}
			if old.in.Lifecycle.Policy.History != nil {
				var layout string
				if e = scratch.QueryRow(ctx, "SELECT history_profile->'History'->>'Layout' FROM operation_audit_pool WHERE root_id=$1 AND lane='normal'", old.in.RootID).Scan(&layout); e != nil || layout != value.OperationVerificationHistoryLayout {
					t.Fatal("residual pool did not retain accepted covering profile", layout, e)
				}
			}
			if e = scratch.QueryRow(ctx, "SELECT certificate_verify_attempts FROM operation_audit_lifecycle WHERE operation_id=$1", old.in.ID).Scan(&attempts); e != nil || attempts != 2 {
				t.Fatal("profile upgrade refilled historical attempts", attempts, e)
			}

		}
		// Existing acknowledgement remains sufficient for historical finalization;
		// no decrypt, fresh counter, new proof dates or capability upgrade is needed.
		wait(in.Lifecycle.CertificatePurgeAt)
		lease.Phase = "terminal"
		lease.Fence = 2
		lease.StartedAt = now()
		lease.Until = lease.StartedAt.Add(5 * time.Second)
		lease.ObjectsDigest = app.OperationLifecycleDigest(append(receipts, receipt))
		exec("UPDATE operation_audit_lifecycle SET lease=$2,lease_fence=2 WHERE operation_id=$1", in.ID, encode(lease))
		terminal := value.OperationTerminalPurge{RootID: in.RootID, OperationID: in.ID, RetirementDigest: app.OperationLifecycleDigest(r), CertificateDigest: app.OperationLifecycleDigest(receipt), Fence: 2, PurgedAt: now(), LeaseUntil: lease.Until}
		exec("UPDATE operation_audit_lifecycle SET terminal_purge=$2 WHERE operation_id=$1", in.ID, encode(terminal))
		exec("UPDATE operation_audit_lifecycle SET terminal_acknowledged_at=clock_timestamp() WHERE operation_id=$1", in.ID)
		var finished bool
		if e = scratch.QueryRow(ctx, "SELECT finish_operation_audit_retirement($1,$2,$3)", in.RootID, in.ID, p.InstallationID).Scan(&finished); e != nil || !finished {
			t.Fatal("acknowledged historical cleanup blocked", e)
		}
		var remaining int64
		if e = scratch.QueryRow(ctx, "SELECT charged FROM operation_audit_account WHERE root_id=$1 AND lane='normal'", in.RootID).Scan(&remaining); e != nil || remaining != 2 {
			t.Fatal("historical cleanup lost uncertain/new charges", remaining, e)
		}
	})
}
