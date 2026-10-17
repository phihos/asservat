package postgres

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
)

// InitialSchemaRoot is the protected, original installation journal. Its current
// administrator/guard observations are independent of this database credential.
// None of these values is activation or database-recovery authority.
type InitialSchemaRoot interface {
	ReadInitialSchema(context.Context) (contracts.InitialPreparationRoot, time.Time, error)
	ClaimInitialSchema(context.Context, contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error)
	CompleteInitialSchema(context.Context, contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error)
}

type InitialSchema struct {
	db      *sql.DB
	root    InitialSchemaRoot
	manager contracts.InitialSQLHistoryManager
	bundle  InitialSchemaBundle
	running atomic.Bool
}

// NewInitialSchema accepts only the trusted, separately mounted DDL credential.
// The returned facet owns its connection pool. It cannot take arbitrary SQL,
// migration directories, a down direction or a replacement database binding.
func NewInitialSchema(c *pgx.ConnConfig, root InitialSchemaRoot, manager contracts.InitialSQLHistoryManager) (*InitialSchema, error) {
	if c == nil || root == nil || !validInitialHistoryManager(manager) || c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify || c.TLSConfig.ServerName == "" || c.TLSConfig.MinVersion < tls.VersionTLS13 || len(c.Fallbacks) != 0 || c.Tracer != nil || c.ValidateConnect != nil || c.AfterConnect != nil || c.User == "" || c.Database == "" {
		return nil, cfg.ErrInvalid
	}
	b, e := EmbeddedInitialSchema()
	if e != nil {
		return nil, e
	}
	copy := c.Copy()
	copy.RuntimeParams = map[string]string{"application_name": "asservat-initial-schema", "search_path": "public,pg_catalog", "timezone": "UTC", "lock_timeout": "1000ms", "statement_timeout": "5000ms", "idle_in_transaction_session_timeout": "5000ms", "synchronous_commit": "on", "row_security": "off"}
	copy.ConnectTimeout = 5 * time.Second
	db := stdlib.OpenDB(*copy)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	db.SetConnMaxLifetime(time.Minute)
	return &InitialSchema{db: db, root: root, manager: manager, bundle: b}, nil
}
func (s *InitialSchema) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Run applies at most the finite embedded prefix. Each step has its own current
// original five-second lease; an uncertain SQL/Kubernetes reply stops the run.
// Resuming inspects the same attempt. A completed root permits read-only replay.
func (s *InitialSchema) Run(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !s.running.CompareAndSwap(false, true) {
		return cfg.ErrUnavailable
	}
	defer s.running.Store(false)
	for step := int64(0); step <= s.bundle.Head+1; step++ {
		next, done, e := s.inspect(ctx, true)
		if e != nil {
			return initialSchemaFailure{phase: "inspection", cause: e}
		}
		if done {
			return nil
		}
		if next > s.bundle.Head {
			if e = s.finish(ctx); e != nil {
				return initialSchemaFailure{phase: "manager-and-completion", cause: e}
			}
			return nil
		}
		if e = s.apply(ctx, next); e != nil {
			return initialSchemaFailure{phase: "migration", version: next, cause: e}
		}
	}
	return cfg.ErrUnavailable
}

const initialSchemaLockID int64 = 0x4153534552565343

type initialSchemaLease struct {
	owner     *InitialSchema
	ctx       context.Context
	stop      context.CancelFunc
	until     time.Time
	cancel    context.CancelFunc
	record    contracts.InitialPreparationSchema
	completed bool
	next      int64
	conn      *sql.Conn
	locked    bool
}

func (s *InitialSchema) lease(ctx context.Context) (*initialSchemaLease, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, cfg.ErrUnavailable
	}
	original, end := context.WithTimeout(ctx, 5*time.Second)
	w, until, e := s.root.ReadInitialSchema(original)
	if e != nil {
		end()
		return nil, cfg.ErrUnavailable
	}
	bounded, cancel := context.WithDeadline(original, until)
	l := &initialSchemaLease{owner: s, ctx: bounded, until: until, cancel: end, stop: func() { cancel(); end() }}
	if originalUntil, ok := original.Deadline(); ok && originalUntil.Before(l.until) {
		l.until = originalUntil
	}
	if w.Schema != nil {
		l.record = *w.Schema
		l.completed = w.Schema.CompletedAt != nil
	}
	if e = l.current(); e != nil {
		l.stop()
		return nil, e
	}
	return l, nil
}
func (l *initialSchemaLease) current() error {
	if l.ctx.Err() != nil || l.until.IsZero() || !time.Now().Before(l.until) {
		return cfg.ErrUnavailable
	}
	return nil
}

// narrow retains the earliest observation across every independently current
// root read/claim/completion. A later observation never renews this step.
func (l *initialSchemaLease) narrow(until time.Time) error {
	if until.IsZero() {
		return cfg.ErrUnavailable
	}
	if until.Before(l.until) {
		bounded, cancel := context.WithDeadline(l.ctx, until)
		old := l.stop
		// Goose already holds the preceding context during SessionLock. Cancel the
		// shared original as well so its SQL cannot outlive this shorter observation.
		stopOriginal := context.AfterFunc(bounded, l.cancel)
		l.ctx, l.until = bounded, until
		l.stop = func() { stopOriginal(); cancel(); old() }
	}
	return l.current()
}

func (l *initialSchemaLease) lock(conn *sql.Conn) error {
	l.conn = conn
	var got bool
	if e := conn.QueryRowContext(l.ctx, "SELECT pg_try_advisory_lock($1)", initialSchemaLockID).Scan(&got); e != nil || !got {
		return cfg.ErrUnavailable
	}
	l.locked = true
	if e := l.current(); e != nil {
		return e
	}
	return nil
}
func (l *initialSchemaLease) unlock() error {
	if !l.locked {
		return nil
	}
	l.locked = false
	cleanup, end := context.WithTimeout(context.WithoutCancel(l.ctx), time.Second)
	defer end()
	var released bool
	e := l.conn.QueryRowContext(cleanup, "SELECT pg_advisory_unlock($1)", initialSchemaLockID).Scan(&released)
	if e != nil || !released {
		_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
		return cfg.ErrUnavailable
	}
	return nil
}
func (l *initialSchemaLease) verifyOriginal() error {
	var v contracts.InitialPreparationSchema
	v.BundleDigest, v.Head, v.Manager = l.owner.bundle.Digest, l.owner.bundle.Head, l.owner.manager
	var allowed bool
	var credentialUntil sql.NullTime
	e := l.conn.QueryRowContext(l.ctx, `SELECT d.oid,pg_postmaster_start_time(),r.rolname,r.oid,
 NOT pg_is_in_recovery() AND session_user=current_user AND r.rolcanlogin AND (r.rolsuper OR (d.datdba=r.oid AND has_schema_privilege(r.oid,'public','CREATE'))),r.rolvaliduntil
 FROM pg_database d JOIN pg_roles r ON r.rolname=current_user WHERE d.datname=current_database()`).Scan(&v.DatabaseOID, &v.PostmasterAt, &v.DDLRole.Name, &v.DDLRole.OID, &allowed, &credentialUntil)
	if e != nil || !allowed || v.DDLRole.OID == v.Manager.OID {
		return cfg.ErrUnavailable
	}
	if credentialUntil.Valid {
		if e = l.narrow(credentialUntil.Time); e != nil {
			return e
		}
	}
	v.PostmasterAt = v.PostmasterAt.UTC()
	if l.record.AttemptID != "" {
		old := l.record
		v.AttemptID, v.ClaimedAt, v.CompletedAt = old.AttemptID, old.ClaimedAt, old.CompletedAt
		if !sameInitialSchema(v, old) {
			return cfg.ErrChanged
		}
	}
	if e = initialSchemaManager(l.ctx, l.conn, v.Manager, false); e != nil {
		return e
	}
	if e = l.current(); e != nil {
		return e
	}
	if l.record.AttemptID == "" {
		l.record = v
	}
	return nil
}
func sameInitialSchema(a, b contracts.InitialPreparationSchema) bool {
	return a.AttemptID == b.AttemptID && a.BundleDigest == b.BundleDigest && a.Head == b.Head && a.DatabaseOID == b.DatabaseOID && a.PostmasterAt.Equal(b.PostmasterAt) && a.DDLRole == b.DDLRole && a.Manager == b.Manager && a.ClaimedAt.Equal(b.ClaimedAt) && ((a.CompletedAt == nil && b.CompletedAt == nil) || (a.CompletedAt != nil && b.CompletedAt != nil && a.CompletedAt.Equal(*b.CompletedAt)))
}
func (l *initialSchemaLease) checkRoot() error {
	w, until, e := l.owner.root.ReadInitialSchema(l.ctx)
	if e != nil || w.Schema == nil || !sameInitialSchema(*w.Schema, l.record) {
		return cfg.ErrChanged
	}
	return l.narrow(until)
}

func (s *InitialSchema) inspect(ctx context.Context, claim bool) (next int64, done bool, err error) {
	l, e := s.lease(ctx)
	if e != nil {
		return 0, false, e
	}
	defer func() { l.stop() }()
	conn, e := s.db.Conn(l.ctx)
	if e != nil {
		return 0, false, cfg.ErrUnavailable
	}
	defer conn.Close()
	defer func() {
		if e := l.unlock(); e != nil {
			err = e
		}
	}()
	if e = l.lock(conn); e != nil {
		return 0, false, e
	}
	if e = l.verifyOriginal(); e != nil {
		return 0, false, e
	}
	head, exists, e := initialSchemaHistory(l.ctx, conn, s.bundle.Head, l.record.DDLRole.OID)
	if e != nil {
		return 0, false, e
	}
	if l.record.AttemptID == "" {
		if !claim || exists {
			return 0, false, cfg.ErrChanged
		}
		if e = initialSchemaEmpty(l.ctx, conn, l.record.DDLRole.OID); e != nil {
			return 0, false, e
		}
		w, until, e := s.root.ClaimInitialSchema(l.ctx, l.record)
		if e != nil || w.Schema == nil {
			return 0, false, cfg.ErrUnavailable
		}
		if e = l.narrow(until); e != nil {
			return 0, false, e
		}
		l.record = *w.Schema
	}
	if l.completed {
		if !exists || head != s.bundle.Head {
			return 0, false, cfg.ErrChanged
		}
		if e = initialSchemaInventory(l.ctx, conn, true, false, l.record.DDLRole.OID); e != nil {
			return 0, false, e
		}
		if e = initialSchemaManager(l.ctx, conn, s.manager, true); e != nil {
			return 0, false, e
		}
		if e = l.checkRoot(); e != nil {
			return 0, false, e
		}
		return head + 1, true, nil
	}
	if e = initialSchemaInventory(l.ctx, conn, head == s.bundle.Head, true, l.record.DDLRole.OID); e != nil {
		return 0, false, e
	}
	if !exists {
		if e = initialSchemaEmpty(l.ctx, conn, l.record.DDLRole.OID); e != nil {
			return 0, false, e
		}
		// Do not let Goose's metadata initializer retry a lost CREATE/COMMIT. Only
		// this acknowledged original root and transaction can create its standard row.
		store, _ := database.NewStore(database.DialectPostgres, "public.goose_db_version")
		tx, e := conn.BeginTx(l.ctx, nil)
		if e != nil {
			return 0, false, cfg.ErrUnavailable
		}
		defer tx.Rollback()
		if e = store.CreateVersionTable(l.ctx, tx); e == nil {
			e = store.Insert(l.ctx, tx, database.InsertRequest{Version: 0})
		}
		if e != nil {
			return 0, false, cfg.ErrUnavailable
		}
		if e = l.current(); e != nil {
			return 0, false, e
		}
		if e = tx.Commit(); e != nil {
			return 0, false, cfg.ErrUnavailable
		}
		head, exists, e = initialSchemaHistory(l.ctx, conn, s.bundle.Head, l.record.DDLRole.OID)
		if e != nil || !exists || head != 0 {
			return 0, false, cfg.ErrUnavailable
		}
	}
	if e = l.checkRoot(); e != nil {
		return 0, false, e
	}
	return head + 1, false, nil
}

// gooseStepLocker is private to a single ApplyVersion invocation. It acquires
// and validates the original DB/root before Goose initializes or executes SQL.
type gooseStepLocker struct {
	lease   *initialSchemaLease
	version int64
}

func (g *gooseStepLocker) SessionLock(ctx context.Context, c *sql.Conn) (err error) {
	l := g.lease
	defer func() {
		if err != nil {
			_ = l.unlock()
		}
	}()
	if e := l.lock(c); e != nil {
		return e
	}
	if e := l.verifyOriginal(); e != nil {
		return e
	}
	if l.completed || l.record.AttemptID == "" {
		return cfg.ErrChanged
	}
	head, exists, e := initialSchemaHistory(l.ctx, c, l.owner.bundle.Head, l.record.DDLRole.OID)
	if e != nil || !exists || head+1 != g.version {
		return cfg.ErrChanged
	}
	if e = initialSchemaInventory(l.ctx, c, false, true, l.record.DDLRole.OID); e != nil {
		return e
	}
	return l.checkRoot()
}
func (g *gooseStepLocker) SessionUnlock(_ context.Context, c *sql.Conn) error {
	l := g.lease
	// Goose calls cleanup with a detached context. Authority checks deliberately
	// use the original lease, never that detached cleanup context.
	head, exists, e := initialSchemaHistory(l.ctx, c, l.owner.bundle.Head, l.record.DDLRole.OID)
	if e == nil && (!exists || head != g.version) {
		e = cfg.ErrUnavailable
	}
	if e == nil {
		e = l.checkRoot()
	}
	unlock := l.unlock()
	if e != nil {
		return cfg.ErrUnavailable
	}
	return unlock
}

type initialSchemaStore struct{ database.Store }

func (s initialSchemaStore) CreateVersionTable(context.Context, database.DBTxConn) error {
	return cfg.ErrUnavailable
}
func (s initialSchemaStore) Delete(context.Context, database.DBTxConn, int64) error {
	return cfg.ErrUnavailable
}
func (s initialSchemaStore) TableExists(ctx context.Context, db database.DBTxConn) (bool, error) {
	var exists bool
	e := db.QueryRowContext(ctx, "SELECT to_regclass('public.goose_db_version') IS NOT NULL").Scan(&exists)
	return exists, e
}
func (s *InitialSchema) apply(ctx context.Context, version int64) error {
	l, e := s.lease(ctx)
	if e != nil {
		return e
	}
	defer func() { l.stop() }()
	store, _ := database.NewStore(database.DialectPostgres, "public.goose_db_version")
	p, e := goose.NewProvider(goose.DialectCustom, s.db, migrations.Files(), goose.WithStore(initialSchemaStore{store}), goose.WithSessionLocker(&gooseStepLocker{l, version}), goose.WithDisableGlobalRegistry(true), goose.WithAllowOutofOrder(false), goose.WithVerbose(false))
	if e != nil {
		return cfg.ErrInvalid
	}
	if _, e = p.ApplyVersion(l.ctx, version, true); e != nil {
		return cfg.ErrUnavailable
	}
	return l.current()
}
func (s *InitialSchema) finish(ctx context.Context) (err error) {
	l, e := s.lease(ctx)
	if e != nil {
		return e
	}
	defer func() { l.stop() }()
	conn, e := s.db.Conn(l.ctx)
	if e != nil {
		return cfg.ErrUnavailable
	}
	defer conn.Close()
	defer func() {
		if e := l.unlock(); e != nil {
			err = e
		}
	}()
	if e = l.lock(conn); e != nil {
		return e
	}
	if e = l.verifyOriginal(); e != nil {
		return e
	}
	head, exists, e := initialSchemaHistory(l.ctx, conn, s.bundle.Head, l.record.DDLRole.OID)
	if e != nil || !exists || head != s.bundle.Head {
		return cfg.ErrChanged
	}
	if e = initialSchemaInventory(l.ctx, conn, true, true, l.record.DDLRole.OID); e != nil {
		return e
	}
	if e = l.checkRoot(); e != nil {
		return e
	}
	if e = grantInitialSchemaManager(l.ctx, conn, s.manager); e != nil {
		return e
	}
	if e = l.checkRoot(); e != nil {
		return e
	}
	w, until, e := s.root.CompleteInitialSchema(l.ctx, l.record)
	if e != nil || w.Schema == nil || w.Schema.CompletedAt == nil {
		return cfg.ErrUnavailable
	}
	return l.narrow(until)
}

// Diagnostics identify only a fixed phase and public migration ordinal. Native
// SQL/driver messages and statements never become installer output.
type initialSchemaFailure struct {
	phase   string
	version int64
	cause   error
}

func (e initialSchemaFailure) Error() string { return "initial schema " + e.phase + ": unavailable" }
func (e initialSchemaFailure) Unwrap() error { return e.cause }
func InitialSchemaFailurePhase(err error) (string, int64) {
	var e initialSchemaFailure
	if errors.As(err, &e) {
		return e.phase, e.version
	}
	return "", 0
}
