package postgres

import (
	"context"
	"crypto/tls"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
)

// SeedInstallation creates the installation's trust root, activates it and seeds its first fleet observation,
// from one current read of the fleet ConfigMap. It is idempotent: an existing
// trust row is never re-keyed or unsuspended, and an existing
// observation is left to the hub-worker's observer. A database that holds
// another installation's trust row is refused.
func SeedInstallation(ctx context.Context, ddl *pgx.ConnConfig, a value.Administration) error {
	if ctx == nil || ctx.Err() != nil || ddl == nil || ddl.TLSConfig == nil || ddl.TLSConfig.InsecureSkipVerify || ddl.TLSConfig.MinVersion < tls.VersionTLS13 || !a.Valid(time.Now()) || a.Suspended {
		return cfg.ErrInvalid
	}
	c := ddl.Copy()
	c.RuntimeParams = map[string]string{"application_name": "asservat-setup-seed", "search_path": "pg_catalog,public", "timezone": "UTC", "lock_timeout": "5000ms", "statement_timeout": "10000ms", "idle_in_transaction_session_timeout": "10000ms", "synchronous_commit": "on", "row_security": "off"}
	c.ConnectTimeout = 5 * time.Second
	ctx, cancel := context.WithDeadline(ctx, a.FreshUntil)
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
	if _, err = tx.Exec(ctx, "LOCK TABLE public.fleet_trust,public.fleet_observation IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return cfg.ErrUnavailable
	}
	var other, replica bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM public.fleet_trust WHERE installation_id<>$1),pg_is_in_recovery()", a.InstallationID).Scan(&other, &replica); err != nil || replica {
		return cfg.ErrUnavailable
	}
	if other {
		return cfg.ErrChanged
	}
	observed, fresh := ownerTime(a.ObservedAt), ownerTime(a.FreshUntil)
	if _, err = tx.Exec(ctx, `INSERT INTO public.fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(installation_id) DO NOTHING`, a.InstallationID, a.IssuerEpoch, a.Revision.UID, a.Revision.Generation, a.Revision.Digest[:], observed, fresh); err != nil {
		return cfg.ErrUnavailable
	}
	var epoch string
	if err = tx.QueryRow(ctx, "SELECT issuer_epoch::text FROM public.fleet_trust WHERE installation_id=$1", a.InstallationID).Scan(&epoch); err != nil {
		return cfg.ErrUnavailable
	}
	if epoch != a.IssuerEpoch {
		return cfg.ErrChanged
	}
	// First activation only: a later suspension stays for the hub-worker's
	// observer.
	if _, err = tx.Exec(ctx, `UPDATE public.fleet_trust SET suspended=false,
 activated_postmaster_at=pg_catalog.pg_postmaster_start_time(),
 activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
 observed_at=$2,fresh_until=$3
 WHERE installation_id=$1 AND activated_postmaster_at IS NULL AND activated_database_oid IS NULL`, a.InstallationID, observed, fresh); err != nil {
		return cfg.ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `INSERT INTO public.fleet_observation(installation_id,semantic_version,
 issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,
 activated_database_oid,observed_at,fresh_until)
 SELECT installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,
 activated_postmaster_at,activated_database_oid,$2,$3 FROM public.fleet_trust
 WHERE installation_id=$1 AND activated_postmaster_at IS NOT NULL
 ON CONFLICT(installation_id) DO NOTHING`, a.InstallationID, observed, fresh); err != nil {
		return cfg.ErrUnavailable
	}
	if ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return cfg.ErrUnavailable
	}
	return nil
}
