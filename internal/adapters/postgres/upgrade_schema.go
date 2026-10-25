package postgres

import (
	"context"
	"crypto/tls"
	"database/sql"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
)

// UpgradeSchema applies the embedded migrations an installed database lacks
// (ADR-227). It runs as the operator's DDL role, which owns the schema after
// first installation, and never edits the completed initial-schema record.
// The applied history must be an exact, all-applied prefix of the embedded
// migrations; each step runs under the initial schema's advisory lock and
// requires the previous head; the final inventory must equal this binary's.
type UpgradeSchema struct {
	db     *sql.DB
	bundle InitialSchemaBundle
}

func NewUpgradeSchema(c *pgx.ConnConfig) (*UpgradeSchema, error) {
	if c == nil || c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify || c.TLSConfig.ServerName == "" || c.TLSConfig.MinVersion < tls.VersionTLS13 || len(c.Fallbacks) != 0 || c.Tracer != nil || c.ValidateConnect != nil || c.AfterConnect != nil || c.User == "" || c.Database == "" {
		return nil, cfg.ErrInvalid
	}
	b, e := EmbeddedInitialSchema()
	if e != nil {
		return nil, e
	}
	copy := c.Copy()
	copy.RuntimeParams = map[string]string{"application_name": "asservat-upgrade-schema", "search_path": "public,pg_catalog", "timezone": "UTC", "lock_timeout": "1000ms", "statement_timeout": "60000ms", "idle_in_transaction_session_timeout": "60000ms", "synchronous_commit": "on", "row_security": "off"}
	copy.ConnectTimeout = 5 * time.Second
	db := stdlib.OpenDB(*copy)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	db.SetConnMaxLifetime(time.Minute)
	return &UpgradeSchema{db: db, bundle: b}, nil
}

func (s *UpgradeSchema) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Run returns the head before and after. An already current database is a
// no-op; an interrupted run resumes at the next missing version.
func (s *UpgradeSchema) Run(ctx context.Context) (from, to int64, err error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return 0, 0, cfg.ErrUnavailable
	}
	owner, head, err := s.inspect(ctx)
	if err != nil {
		return 0, 0, err
	}
	from = head
	for version := head + 1; version <= s.bundle.Head; version++ {
		store, _ := database.NewStore(database.DialectPostgres, "public.goose_db_version")
		p, e := goose.NewProvider(goose.DialectCustom, s.db, migrations.Files(), goose.WithStore(initialSchemaStore{store}), goose.WithSessionLocker(&upgradeStepLocker{owner: owner, head: s.bundle.Head, version: version}), goose.WithDisableGlobalRegistry(true), goose.WithAllowOutofOrder(false), goose.WithVerbose(false))
		if e != nil {
			return from, version - 1, cfg.ErrInvalid
		}
		if _, e = p.ApplyVersion(ctx, version, true); e != nil {
			return from, version - 1, cfg.ErrUnavailable
		}
	}
	conn, e := s.db.Conn(ctx)
	if e != nil {
		return from, s.bundle.Head, cfg.ErrUnavailable
	}
	defer conn.Close()
	if e = initialSchemaInventory(ctx, conn, true, false, owner); e != nil {
		return from, s.bundle.Head, e
	}
	return from, s.bundle.Head, nil
}

// inspect requires a completed installation: the version table exists, is
// owned by the connecting role and holds an exact prefix of this binary's
// migrations, and the installation trust root was activated.
func (s *UpgradeSchema) inspect(ctx context.Context) (owner uint32, head int64, err error) {
	conn, e := s.db.Conn(ctx)
	if e != nil {
		return 0, 0, cfg.ErrUnavailable
	}
	defer conn.Close()
	if e = conn.QueryRowContext(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user").Scan(&owner); e != nil {
		return 0, 0, cfg.ErrUnavailable
	}
	head, exists, e := initialSchemaHistory(ctx, conn, s.bundle.Head, owner)
	if e != nil {
		return 0, 0, e
	}
	if !exists || head < 1 {
		return 0, 0, cfg.ErrChanged
	}
	var activated bool
	if e = conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM public.fleet_trust WHERE activated_postmaster_at IS NOT NULL)").Scan(&activated); e != nil || !activated {
		return 0, 0, cfg.ErrChanged
	}
	return owner, head, nil
}

// upgradeStepLocker holds the initial schema's advisory lock for one step and
// requires the database to be exactly one version behind it.
type upgradeStepLocker struct {
	owner   uint32
	head    int64
	version int64
}

func (g *upgradeStepLocker) SessionLock(ctx context.Context, c *sql.Conn) error {
	var got bool
	if e := c.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", initialSchemaLockID).Scan(&got); e != nil || !got {
		return cfg.ErrUnavailable
	}
	head, exists, e := initialSchemaHistory(ctx, c, g.head, g.owner)
	if e != nil || !exists || head+1 != g.version {
		_, _ = c.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", initialSchemaLockID)
		return cfg.ErrChanged
	}
	return nil
}

func (g *upgradeStepLocker) SessionUnlock(ctx context.Context, c *sql.Conn) error {
	var released bool
	if e := c.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", initialSchemaLockID).Scan(&released); e != nil || !released {
		return cfg.ErrUnavailable
	}
	return nil
}
