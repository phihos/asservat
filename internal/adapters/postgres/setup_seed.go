package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
)

// SeedInstallation creates and activates the installation's static trust row
// (installation ID and issuer epoch, ADR-330 D13). It is idempotent: an
// existing row is never re-keyed. A database that holds another
// installation's trust row is refused.
func SeedInstallation(ctx context.Context, ddl *pgx.ConnConfig, installation, issuerEpoch string) error {
	if ctx == nil || ctx.Err() != nil || ddl == nil || ddl.TLSConfig == nil || ddl.TLSConfig.InsecureSkipVerify || ddl.TLSConfig.MinVersion < tls.VersionTLS13 || installation == "" || issuerEpoch == "" {
		return cfg.ErrInvalid
	}
	c := ddl.Copy()
	c.RuntimeParams = map[string]string{"application_name": "asservat-setup-seed", "search_path": "pg_catalog,public", "timezone": "UTC", "lock_timeout": "5000ms", "statement_timeout": "10000ms", "idle_in_transaction_session_timeout": "10000ms", "synchronous_commit": "on", "row_security": "off"}
	c.ConnectTimeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		return cfg.ErrUnavailable
	}
	defer func() {
		end, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = conn.Close(end)
	}()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return cfg.ErrUnavailable
	}
	defer func() {
		end, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(end)
	}()
	if _, err = tx.Exec(ctx, "LOCK TABLE public.fleet_trust IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return cfg.ErrUnavailable
	}
	var other, replica bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM public.fleet_trust WHERE installation_id<>$1),pg_is_in_recovery()", installation).Scan(&other, &replica); err != nil || replica {
		return cfg.ErrUnavailable
	}
	if other {
		return cfg.ErrChanged
	}
	digest := sha256.Sum256([]byte("asservat-installation-trust/v1\x00" + installation + "\x00" + issuerEpoch))
	if _, err = tx.Exec(ctx, `INSERT INTO public.fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest)
 VALUES($1,$2,$1::text,1,$3) ON CONFLICT(installation_id) DO NOTHING`, installation, issuerEpoch, digest[:]); err != nil {
		return cfg.ErrUnavailable
	}
	var epoch string
	if err = tx.QueryRow(ctx, "SELECT issuer_epoch::text FROM public.fleet_trust WHERE installation_id=$1", installation).Scan(&epoch); err != nil {
		return cfg.ErrUnavailable
	}
	if epoch != issuerEpoch {
		return cfg.ErrChanged
	}
	if _, err = tx.Exec(ctx, `UPDATE public.fleet_trust SET
 activated_postmaster_at=pg_catalog.pg_postmaster_start_time(),
 activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
 WHERE installation_id=$1 AND activated_postmaster_at IS NULL AND activated_database_oid IS NULL`, installation); err != nil {
		return cfg.ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return cfg.ErrUnavailable
	}
	return nil
}
