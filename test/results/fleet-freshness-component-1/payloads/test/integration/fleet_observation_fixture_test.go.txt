package integration

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These helpers belong only to explicit fixture-administrator authority. They
// never activate a database, clear a fence, or stand in for a runtime observer.
// Synthetic fixtures retain their explicitly chosen (at most 30-second) SQL
// windows; production source, basis and activation proofs remain five seconds.
type syntheticFleetDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type syntheticFleetBinding struct {
	installation, issuer, sourceUID, sourceDigest string
	version, sourceGeneration                     int64
	postmaster                                    time.Time
	databaseOID                                   uint32
}

const syntheticFleetColumns = `installation_id::text,semantic_version,issuer_epoch::text,source_uid,source_generation,encode(source_digest,'hex'),activated_postmaster_at,activated_database_oid`

func scanSyntheticFleetBinding(row pgx.Row) (syntheticFleetBinding, error) {
	var b syntheticFleetBinding
	err := row.Scan(&b.installation, &b.version, &b.issuer, &b.sourceUID, &b.sourceGeneration, &b.sourceDigest, &b.postmaster, &b.databaseOID)
	return b, err
}

// Seed only after the caller's explicit synthetic activation. A duplicate seed
// fails; missing/fenced/stale-incarnation roots never acquire an observation.
func seedSyntheticFleetObservation(ctx context.Context, db syntheticFleetDB, installation string) (syntheticFleetBinding, error) {
	return scanSyntheticFleetBinding(db.QueryRow(ctx, `INSERT INTO public.fleet_observation
 (installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,activated_database_oid,observed_at,fresh_until)
 SELECT installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,activated_database_oid,observed_at,fresh_until
 FROM public.fleet_trust WHERE installation_id=$1 AND NOT suspended AND NOT recovery_blocked
 AND activated_postmaster_at=pg_catalog.pg_postmaster_start_time()
 AND activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
 AND NOT pg_catalog.pg_is_in_recovery()
 RETURNING `+syntheticFleetColumns, installation))
}

// This separate, deliberately named fixture-only transition is used only after
// an existing test explicitly restores administrator activation. Ordinary
// renewal cannot adopt a new version, issuer, source or database incarnation.
// Existing dates are copied exactly, without acquiring a new time interval.
func replaceSyntheticFleetObservationAfterActivation(ctx context.Context, db syntheticFleetDB, installation string) (syntheticFleetBinding, error) {
	return scanSyntheticFleetBinding(db.QueryRow(ctx, `INSERT INTO public.fleet_observation AS previous
 (installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,activated_database_oid,observed_at,fresh_until)
 SELECT installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,activated_database_oid,observed_at,fresh_until
 FROM public.fleet_trust WHERE installation_id=$1 AND NOT suspended AND NOT recovery_blocked
 AND activated_postmaster_at=pg_catalog.pg_postmaster_start_time()
 AND activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
 AND NOT pg_catalog.pg_is_in_recovery()
 ON CONFLICT(installation_id) DO UPDATE SET semantic_version=EXCLUDED.semantic_version,
 issuer_epoch=EXCLUDED.issuer_epoch,source_uid=EXCLUDED.source_uid,source_generation=EXCLUDED.source_generation,source_digest=EXCLUDED.source_digest,
 activated_postmaster_at=EXCLUDED.activated_postmaster_at,activated_database_oid=EXCLUDED.activated_database_oid,
 observed_at=EXCLUDED.observed_at,fresh_until=EXCLUDED.fresh_until
 WHERE previous.semantic_version<>EXCLUDED.semantic_version
 RETURNING `+syntheticFleetColumns, installation))
}

// Retain the original complete synthetic binding across every refresh. The
// optional current-window condition preserves the stricter ongoing-native
// fixture rule; ordinary lifecycle fixtures previously allowed an expired
// observation to be renewed after a deliberate wait, without unfencing it.
func renewSyntheticFleetObservation(ctx context.Context, db syntheticFleetDB, b syntheticFleetBinding, valid time.Duration, requireCurrent bool) error {
	if valid <= 0 || valid > 30*time.Second || b.installation == "" || b.version <= 0 {
		return errors.New("synthetic fleet observation interval or binding unavailable")
	}
	tag, err := db.Exec(ctx, `WITH n AS MATERIALIZED(SELECT statement_timestamp() AS at)
 UPDATE public.fleet_observation AS o SET observed_at=n.at,fresh_until=n.at+make_interval(secs=>$9)
 FROM public.fleet_trust AS f,n WHERE o.installation_id=$1 AND f.installation_id=o.installation_id
 AND o.semantic_version=$2 AND o.issuer_epoch=$3 AND o.source_uid=$4 AND o.source_generation=$5 AND o.source_digest=decode($6,'hex')
 AND o.activated_postmaster_at=$7 AND o.activated_database_oid=$8
 AND f.semantic_version=o.semantic_version AND f.issuer_epoch=o.issuer_epoch AND f.source_uid=o.source_uid AND f.source_generation=o.source_generation AND f.source_digest=o.source_digest
 AND f.activated_postmaster_at=o.activated_postmaster_at AND f.activated_database_oid=o.activated_database_oid
 AND NOT f.suspended AND NOT f.recovery_blocked AND NOT pg_catalog.pg_is_in_recovery()
 AND f.activated_postmaster_at=pg_catalog.pg_postmaster_start_time()
 AND f.activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
 AND o.observed_at<=n.at AND (o.observed_at<n.at OR n.at+make_interval(secs=>$9)<=o.fresh_until)
 AND (NOT $10::boolean OR o.fresh_until>n.at)`, b.installation, b.version, b.issuer, b.sourceUID, b.sourceGeneration, b.sourceDigest, b.postmaster, b.databaseOID, valid.Seconds(), requireCurrent)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("synthetic fleet original observation unavailable")
	}
	return nil
}

// Capture the existing producer's binding once when assembling a fixture that
// already has real activation/observation. This read confers no authority and
// does not seed, refresh or replace the actual producer.
func readSyntheticFleetObservationBinding(ctx context.Context, db syntheticFleetDB, installation string) (syntheticFleetBinding, error) {
	return scanSyntheticFleetBinding(db.QueryRow(ctx, `SELECT `+syntheticFleetColumns+` FROM public.fleet_observation AS o
 WHERE o.installation_id=$1 AND EXISTS(SELECT 1 FROM public.fleet_trust AS f
 WHERE f.installation_id=o.installation_id AND f.semantic_version=o.semantic_version
 AND f.issuer_epoch=o.issuer_epoch AND f.source_uid=o.source_uid AND f.source_generation=o.source_generation AND f.source_digest=o.source_digest
 AND f.activated_postmaster_at=o.activated_postmaster_at AND f.activated_database_oid=o.activated_database_oid
 AND NOT f.suspended AND NOT f.recovery_blocked AND NOT pg_catalog.pg_is_in_recovery()
 AND f.activated_postmaster_at=pg_catalog.pg_postmaster_start_time()
 AND f.activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()))`, installation))
}
