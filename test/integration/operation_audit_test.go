package integration

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
	"testing"
	"time"
)

// Synthetic identity/bootstrap with actual separate-role SQL, encrypted objects
// and S3 lost-reply recovery. This cannot enable a public operation or installer.
func qualifyOperationAudits(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Run("operation-audit-bounded-accounts-resolve-and-unknown-write", func(t *testing.T) {
		s := create(t, 1)
		configPool := poolFor("operation_audit_config_runtime", "synthetic-operation-config")
		defer configPool.Close()
		config, e := postgres.New(ctx, configPool)
		if e != nil {
			t.Fatal(e)
		}
		journalPool := poolFor("operation_audit_runtime", "synthetic-operation-journal")
		defer journalPool.Close()
		ackPool := poolFor("operation_audit_ack_runtime", "synthetic-operation-ack")
		defer ackPool.Close()
		objects := &objectstore.OperationAuditObjects{Store: store, Seal: keys, Open: keys}
		gates := map[string]app.OperationAuditor{}
		journals := map[string]*postgres.OperationJournal{}
		for _, lane := range []string{"normal", "resolution"} {
			now := time.Now().UTC().Truncate(time.Microsecond)
			if e = config.ProvisionOperationAuditPool(ctx, app.OperationAuditPool{RootID: s.a.RootID, Lane: lane, AccountVersion: "accounts-v1", Accounts: 2, RecordsPerAccount: 2, RetainedSeconds: 3600, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: now.Add(time.Hour)}); e != nil {
				t.Fatal(e)
			}
			j, e := postgres.NewOperationJournal(ctx, journalPool, s.a.RootID, lane, s.recovery.guard)
			if e != nil {
				t.Fatal(e)
			}
			a, e := postgres.NewOperationAcknowledgements(ctx, ackPool, s.a.RootID, lane, s.recovery.guard)
			if e != nil {
				t.Fatal(e)
			}
			journals[lane] = j
			gates[lane] = app.OperationAuditor{Journal: j, Acknowledgements: a, Objects: objects, Now: time.Now}
		}
		in := func(actor byte, name string) audit.OperationIntent {
			now := time.Now().UTC().Truncate(time.Microsecond)
			id := custodyID()
			return audit.OperationIntent{ID: id, TraceID: id, RootID: s.a.RootID, Name: name, InputFormat: "context-input/v1", MACVersion: "audit-v1", AccountVersion: "accounts-v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{actor}, InputDigest: artifact.Digest{1}, CreatedAt: now, RequestUntil: now.Add(5 * time.Second), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
		}
		out := func(i audit.OperationIntent) audit.OperationOutcome {
			return audit.OperationOutcome{Intent: i, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{9}, OutputBytes: 13, MetadataUntil: i.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
		}
		first := in(1, "get_capture")
		gate := gates["normal"]
		if e = gate.Begin(ctx, first); e != nil {
			t.Fatal("begin", e)
		}
		result := out(first)
		if e = gate.Finish(ctx, result); e != nil {
			t.Fatal("finish", e)
		}
		// Exact audit replay never repeats the two object creations or charges.
		if e = gate.Finish(ctx, result); e != nil {
			t.Fatal("exact outcome replay", e)
		}
		second := in(1, "get_capture")
		second.Actor.ClientID = "mcp"
		second.MACVersion = "audit-v2"
		if e = gate.Begin(ctx, second); e != nil {
			t.Fatal("second allowed slot", e)
		}
		if e = gate.Begin(ctx, in(1, "get_capture")); e != app.ErrUnavailable {
			t.Fatal("one principal escaped finite quota", e)
		}
		// A new subject can still use its independently backed capacity.
		if e = gate.Begin(ctx, in(2, "get_capture")); e != nil {
			t.Fatal("another backed account starved", e)
		}
		if e = gate.Begin(ctx, in(3, "get_capture")); e != app.ErrUnavailable {
			t.Fatal("lazy account creation unbounded", e)
		}
		if e = gates["resolution"].Begin(ctx, in(1, "resolve_capture_request")); e != nil {
			t.Fatal("normal exhaustion starved resolution", e)
		}
		var accounts, charged int64
		if e = admin.QueryRow(ctx, "SELECT accounts FROM operation_audit_pool WHERE root_id=$1 AND lane='normal'", s.a.RootID).Scan(&accounts); e != nil || accounts != 2 {
			t.Fatal("wrong account spend", accounts, e)
		}
		if e = admin.QueryRow(ctx, "SELECT sum(charged) FROM operation_audit_account WHERE root_id=$1 AND lane='normal'", s.a.RootID).Scan(&charged); e != nil || charged != 3 {
			t.Fatal("failed/replayed request charged", charged, e)
		}
		// A lost successful object response can only perform an exact GET afterward.
		uncertain := &operationLostReply{OperationObjects: objects, lose: true}
		resolution := gates["resolution"]
		resolution.Objects = uncertain
		request := in(2, "resolve_capture_request")
		if e = resolution.Begin(ctx, request); e != app.ErrUnavailable {
			t.Fatal("lost response known", e)
		}
		if e = resolution.Begin(ctx, request); e != nil || uncertain.creates != 1 || uncertain.finds != 1 {
			t.Fatal("unknown reply recreated", e, uncertain.creates, uncertain.finds)
		}
		// Durable audit is purpose-separated from evidence/control charges.
		var captureCount int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM context_capture WHERE root_id=$1", s.a.RootID).Scan(&captureCount); e != nil || captureCount != 0 {
			t.Fatal("audit created capture", captureCount, e)
		}
		for _, test := range []struct {
			p   *pgxpool.Pool
			sql string
		}{
			{journalPool, "UPDATE operation_audit SET intent_receipt=intent_receipt"},
			{ackPool, "UPDATE operation_audit SET outcome=outcome"},
			{ackPool, "INSERT INTO operation_audit SELECT * FROM operation_audit LIMIT 0"},
			{journalPool, "UPDATE operation_audit_account SET charged=0"},
			{journalPool, "UPDATE operation_audit_pool SET account_limit=account_limit+1"},
			{journalPool, "DELETE FROM operation_audit"},
			{journalPool, "SELECT guard_operation_audit()"},
		} {
			_, e = test.p.Exec(ctx, test.sql)
			var pgerr *pgconn.PgError
			if !errors.As(e, &pgerr) || pgerr.Code != "42501" {
				t.Fatal("excess audit role privilege", test.sql, e)
			}
		}
		// Even owner-level attempted rewrites cannot erase charged immutable history.
		for _, sql := range []string{"DELETE FROM operation_audit WHERE id=$1", "UPDATE operation_audit SET intent_started=false WHERE id=$1", `UPDATE operation_audit SET outcome=jsonb_set(outcome,'{ClientReceipt}','"received"') WHERE id=$1`} {
			if _, e = admin.Exec(ctx, sql, first.ID); e == nil {
				t.Fatal("immutable audit changed")
			}
		}
		// Renew configuration and increase backed defaults without resetting
		// accounts; a smaller ceiling cannot erase previous spend.
		now := time.Now().UTC().Truncate(time.Microsecond)
		update := app.OperationAuditPool{RootID: s.a.RootID, Lane: "normal", AccountVersion: "accounts-v1", ExpectedRevision: 1, Accounts: 2, RecordsPerAccount: 1, RetainedSeconds: 3600, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: now.Add(time.Hour)}
		if e = config.ProvisionOperationAuditPool(ctx, update); e != app.ErrUnavailable {
			t.Fatal("backing shrank below charged history", e)
		}
		update.RecordsPerAccount = 3
		if e = config.ProvisionOperationAuditPool(ctx, update); e != nil {
			t.Fatal("renewed backing unavailable", e)
		}
		if e = gate.Begin(ctx, in(1, "get_capture")); e != nil {
			t.Fatal("renewal did not preserve usable principal allowance", e)
		}
		// Exact recovery fencing remains required; audit is not an activation path.
		if _, e = admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", s.recovery.installation); e != nil {
			t.Fatal(e)
		}
		if e = gates["resolution"].Begin(ctx, in(1, "resolve_capture_request")); e != app.ErrUnavailable {
			t.Fatal("recovery blocked audit admitted", e)
		}
	})
	t.Run("operation-audit-original-backing-deadline-after-account-lock", func(t *testing.T) {
		s := create(t, 1)
		cp := poolFor("operation_audit_config_runtime", "synthetic-operation-config")
		defer cp.Close()
		config, err := postgres.New(ctx, cp)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		backing := app.OperationAuditPool{RootID: s.a.RootID, Lane: "normal", AccountVersion: "accounts-v1", Accounts: 2, RecordsPerAccount: 3, RetainedSeconds: 3600, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: now.Add(time.Hour)}
		if err = config.ProvisionOperationAuditPool(ctx, backing); err != nil {
			t.Fatal(err)
		}
		jp := poolFor("operation_audit_runtime", "synthetic-operation-journal")
		defer jp.Close()
		journal, err := postgres.NewOperationJournal(ctx, jp, s.a.RootID, "normal", s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		intent := func() audit.OperationIntent {
			n := time.Now().UTC().Truncate(time.Microsecond)
			id := custodyID()
			return audit.OperationIntent{ID: id, TraceID: id, RootID: s.a.RootID, Name: "get_capture", InputFormat: "context-input/v1", MACVersion: "audit-v1", AccountVersion: "accounts-v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{1}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour)}
		}
		seed := intent()
		if _, err = journal.ReserveOperation(ctx, seed); err != nil {
			t.Fatal("seed account", err)
		}
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var blockerPID int32
		if err = tx.QueryRow(ctx, "SELECT pg_backend_pid() FROM operation_audit_account WHERE root_id=$1 AND lane='normal' AND principal_digest=$2 FOR UPDATE", s.a.RootID, seed.PrincipalDigest[:]).Scan(&blockerPID); err != nil {
			t.Fatal(err)
		}
		now = time.Now().UTC().Truncate(time.Microsecond)
		backing.ExpectedRevision, backing.ObservedAt, backing.FreshUntil, backing.ValidUntil = 1, now, now.Add(5*time.Second), now.Add(600*time.Millisecond)
		if err = config.ProvisionOperationAuditPool(ctx, backing); err != nil {
			t.Fatal("shorten backing", err)
		}
		in := intent()
		done := make(chan error, 1)
		go func() { _, e := journal.ReserveOperation(ctx, in); done <- e }()
		// Identify the actual INSERT's wait on this exact account-lock owner;
		// elapsed time alone is not evidence that the vulnerable path ran.
		blocked := false
		for time.Now().Before(backing.ValidUntil.Add(-25 * time.Millisecond)) {
			if err = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='operation_audit_runtime' AND wait_event_type='Lock' AND query LIKE '%INSERT INTO operation_audit(%' AND $1=ANY(pg_blocking_pids(pid)))", blockerPID).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			select {
			case e := <-done:
				t.Fatal("reservation ended before held account", e)
			default:
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !blocked {
			t.Fatal("reservation never reached the actual account row lock before backing expiry")
		}
		time.Sleep(max(0, time.Until(backing.ValidUntil)+15*time.Millisecond))
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err != app.ErrUnavailable {
			t.Fatal("expired original backing admitted a new audit", err)
		}
		var count, charged int64
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM operation_audit WHERE id=$1", in.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("expired backing left a new record", count, err)
		}
		if err = admin.QueryRow(ctx, "SELECT charged FROM operation_audit_account WHERE root_id=$1 AND lane='normal' AND principal_digest=$2", s.a.RootID, seed.PrincipalDigest[:]).Scan(&charged); err != nil || charged != 1 {
			t.Fatal("expired backing consumed retained charge", charged, err)
		}
		// Re-reading an already reserved exact identity needs no new allowance.
		if _, err = journal.ReserveOperation(ctx, seed); err != nil {
			t.Fatal("expired backing blocked historical exact replay", err)
		}
	})
	t.Run("operation-audit-original-deadline-after-lock", func(t *testing.T) {
		s := create(t, 1)
		cp := poolFor("operation_audit_config_runtime", "synthetic-operation-config")
		defer cp.Close()
		config, e := postgres.New(ctx, cp)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if e = config.ProvisionOperationAuditPool(ctx, app.OperationAuditPool{RootID: s.a.RootID, Lane: "normal", AccountVersion: "accounts-v1", Accounts: 2, RecordsPerAccount: 2, RetainedSeconds: 3600, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: now.Add(time.Hour)}); e != nil {
			t.Fatal(e)
		}
		jp := poolFor("operation_audit_runtime", "synthetic-operation-journal")
		defer jp.Close()
		j, e := postgres.NewOperationJournal(ctx, jp, s.a.RootID, "normal", s.recovery.guard)
		if e != nil {
			t.Fatal(e)
		}
		now = time.Now().UTC().Truncate(time.Microsecond)
		id := custodyID()
		in := audit.OperationIntent{ID: id, TraceID: id, RootID: s.a.RootID, Name: "get_capture", InputFormat: "context-input/v1", MACVersion: "audit-v1", AccountVersion: "accounts-v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{1}, CreatedAt: now, RequestUntil: now.Add(100 * time.Millisecond), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
		tx, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, "SELECT root_id FROM operation_audit_pool WHERE root_id=$1 FOR UPDATE", s.a.RootID); e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { _, e := j.ReserveOperation(ctx, in); done <- e }()
		time.Sleep(150 * time.Millisecond)
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		if e = <-done; e != app.ErrUnavailable {
			t.Fatal("lock wait renewed original interval", e)
		}
		var n int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM operation_audit WHERE id=$1", in.ID).Scan(&n); e != nil || n != 0 {
			t.Fatal("expired waiter spent", n, e)
		}
	})
}

type operationLostReply struct {
	app.OperationObjects
	mu             sync.Mutex
	lose           bool
	creates, finds int
}

func (o *operationLostReply) CreateOperationIntent(ctx context.Context, in audit.OperationIntent) (audit.Receipt, error) {
	o.mu.Lock()
	o.creates++
	lose := o.lose
	o.lose = false
	o.mu.Unlock()
	r, e := o.OperationObjects.CreateOperationIntent(ctx, in)
	if e == nil && lose {
		return audit.Receipt{}, app.ErrUnavailable
	}
	return r, e
}
func (o *operationLostReply) FindOperationIntent(ctx context.Context, in audit.OperationIntent) (audit.Receipt, error) {
	o.mu.Lock()
	o.finds++
	o.mu.Unlock()
	return o.OperationObjects.FindOperationIntent(ctx, in)
}
