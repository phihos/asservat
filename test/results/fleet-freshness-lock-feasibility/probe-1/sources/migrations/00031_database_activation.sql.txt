-- +goose Up
-- A restored enabled flag cannot authenticate a new PostgreSQL process/database.
-- Only independent qualified activation may write these fields. They have no
-- current-value defaults, and ordinary source observation never updates them.
ALTER TABLE fleet_trust ADD COLUMN activated_postmaster_at timestamptz;
ALTER TABLE fleet_trust ADD COLUMN activated_database_oid oid;
ALTER TABLE fleet_trust ADD CONSTRAINT fleet_activation_pair
 CHECK ((activated_postmaster_at IS NULL) = (activated_database_oid IS NULL));

-- Existing processes may still run the previous stored-flag query. Fence those
-- readers too, under the migration's table lock, without activating any root.
-- Later activation must first retire older binaries/credentials and apply the
-- independently qualified recovery protocol. The installation trust root is
-- control state, not a per-artifact backfill.
UPDATE fleet_trust SET suspended=true,recovery_blocked=true;

-- Keep stored control state separate from effective authority. Plain reference
-- columns preserve PostgreSQL row-locking and narrowly granted observation
-- updates; the derived recovery flag is not writable through this view.
-- Fully qualify catalog functions; no runtime-controlled search path resolution.
CREATE VIEW fleet_current_trust AS
 SELECT installation_id,issuer_epoch,source_uid,source_generation,source_digest,
 suspended,
 (recovery_blocked
  OR activated_postmaster_at IS DISTINCT FROM pg_catalog.pg_postmaster_start_time()
  OR activated_database_oid IS DISTINCT FROM
     (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
  OR pg_catalog.pg_is_in_recovery())::boolean AS recovery_blocked,
 observed_at,fresh_until
 FROM fleet_trust;

-- No implicit backfill/activation and no destructive down. Migration itself
-- blocks old roots until qualified activation. The installer grants only view
-- reads/row-lock permission to consumers; activation columns stay private.
