package postgres

import (
	"context"
	"crypto/tls"
	"database/sql"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// VerifyInitialSchemaCompletion is a read-only resumption prerequisite after
// child-role creation. Creator ADMIN memberships are expected at that stage;
// this facet neither grants their authority nor removes/regrants anything. A
// fully completed installation instead uses the separate passive history path.
func VerifyInitialSchemaCompletion(ctx context.Context, c *pgx.ConnConfig, root InitialSchemaRoot) (contracts.InitialPreparationSchema, time.Time, error) {
	var zero contracts.InitialPreparationSchema
	if ctx == nil || c == nil || root == nil || c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify || c.TLSConfig.MinVersion < tls.VersionTLS13 || c.TLSConfig.ServerName == "" || len(c.Fallbacks) != 0 || c.Tracer != nil || c.ValidateConnect != nil || c.AfterConnect != nil {
		return zero, time.Time{}, cfg.ErrInvalid
	}
	s := &InitialSchema{root: root}
	l, e := s.lease(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	defer func() { l.stop() }()
	b, e := EmbeddedInitialSchema()
	v := l.record
	if e != nil || !l.completed || v.BundleDigest != b.Digest || v.Head != b.Head {
		return zero, time.Time{}, cfg.ErrChanged
	}
	copy := c.Copy()
	copy.RuntimeParams = map[string]string{"application_name": "asservat-initial-schema-check", "search_path": "pg_catalog,public", "timezone": "UTC", "default_transaction_read_only": "on", "lock_timeout": "1000ms", "statement_timeout": "5000ms", "idle_in_transaction_session_timeout": "5000ms"}
	copy.ConnectTimeout = 5 * time.Second
	db := stdlib.OpenDB(*copy)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	defer db.Close()
	tx, e := db.BeginTx(l.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return zero, time.Time{}, cfg.ErrUnavailable
	}
	defer tx.Rollback()
	var same bool
	var managerUntil sql.NullTime
	e = tx.QueryRowContext(l.ctx, `SELECT d.oid=$1 AND pg_postmaster_start_time()=$2 AND NOT pg_is_in_recovery() AND session_user=current_user AND r.oid=$3 AND r.rolname=$4 AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls,r.rolvaliduntil FROM pg_database d JOIN pg_roles r ON r.rolname=current_user WHERE d.datname=current_database()`, v.DatabaseOID, v.PostmasterAt, v.Manager.OID, v.Manager.Name).Scan(&same, &managerUntil)
	if e != nil || !same {
		return zero, time.Time{}, cfg.ErrChanged
	}
	if managerUntil.Valid {
		if e = l.narrow(managerUntil.Time); e != nil {
			return zero, time.Time{}, e
		}
	}
	head, exists, e := initialSchemaHistory(l.ctx, tx, b.Head, v.DDLRole.OID)
	if e != nil || !exists || head != b.Head {
		return zero, time.Time{}, cfg.ErrChanged
	}
	if e = initialSchemaInventory(l.ctx, tx, true, false, v.DDLRole.OID); e != nil {
		return zero, time.Time{}, e
	}
	if e = l.checkRoot(); e != nil {
		return zero, time.Time{}, e
	}
	if e = tx.Commit(); e != nil {
		return zero, time.Time{}, cfg.ErrUnavailable
	}
	if e = l.current(); e != nil {
		return zero, time.Time{}, e
	}
	return v, l.until, nil
}
