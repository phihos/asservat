-- +goose Up
-- A restored enabled flag cannot authenticate a new PostgreSQL process/database.
-- Only independent qualified activation may write these fields. They have no
-- current-value defaults, and ordinary source observation never updates them.
ALTER TABLE fleet_trust ADD COLUMN activated_postmaster_at timestamptz;
ALTER TABLE fleet_trust ADD COLUMN activated_database_oid oid;
ALTER TABLE fleet_trust ADD CONSTRAINT fleet_activation_pair
 CHECK ((activated_postmaster_at IS NULL) = (activated_database_oid IS NULL));
-- ADR-226: the cluster's system identifier and WAL timeline at activation. A
-- trigger (migration 00080) fills them from PostgreSQL itself, never a caller.
ALTER TABLE fleet_trust ADD COLUMN activated_system_identifier text,
 ADD COLUMN activated_timeline integer;

-- ADR-226 incarnation lineage: the activation start plus every lossless
-- restart that reactivate_restarted_database (00080) re-activated. Append-only;
-- no runtime grant. Rows bound to any lineage start stay valid while the live
-- server is a re-activated restart of the same database, cluster and timeline.
CREATE TABLE database_restart(started_at timestamptz PRIMARY KEY CHECK(isfinite(started_at)),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
-- +goose StatementBegin
CREATE FUNCTION database_restart_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'database restart lineage is append-only' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION database_restart_immutable() FROM PUBLIC;
CREATE TRIGGER database_restart_immutable BEFORE UPDATE OR DELETE ON database_restart
 FOR EACH ROW EXECUTE FUNCTION database_restart_immutable();
CREATE TRIGGER database_restart_no_truncate BEFORE TRUNCATE ON database_restart
 FOR EACH STATEMENT EXECUTE FUNCTION database_restart_immutable();

-- Whether a recorded server start x belongs to the current incarnation: the
-- live start itself, or (on a primary whose live start was re-activated) the
-- activation start or a re-activated restart, while the activation's database
-- OID, system identifier and WAL timeline equal the live ones. A restore (new
-- timeline), logical restore (new OID), another cluster or a restart not yet
-- re-activated is never current. Owner-only: definer functions call it; views
-- inline the same logic because view function calls run as the querying role.
-- +goose StatementBegin
CREATE FUNCTION incarnation_current(x timestamptz) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE live timestamptz:=pg_postmaster_start_time();
BEGIN
 IF x IS NULL THEN RETURN false; END IF;
 IF x=live THEN RETURN true; END IF;
 -- pg_current_wal_lsn() errors in recovery.
 IF pg_is_in_recovery() OR NOT EXISTS(SELECT 1 FROM public.database_restart WHERE started_at=live) THEN
  RETURN false;
 END IF;
 RETURN EXISTS(SELECT 1 FROM public.fleet_trust t
  WHERE (t.activated_postmaster_at=x OR EXISTS(SELECT 1 FROM public.database_restart WHERE started_at=x))
   AND t.activated_postmaster_at<live
   AND t.activated_database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND t.activated_system_identifier=(pg_control_system()).system_identifier::text
   AND t.activated_timeline=('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::integer);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION incarnation_current(timestamptz) FROM PUBLIC;
-- +goose StatementBegin
DO $$
BEGIN
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_proc p,
   LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
  WHERE p.oid='public.incarnation_current(timestamptz)'::regprocedure
    AND a.grantee<>p.proowner AND a.privilege_type='EXECUTE'
  UNION ALL
  SELECT 1 FROM pg_catalog.pg_class c,
   LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
  WHERE c.oid='public.database_restart'::regclass AND a.grantee<>c.relowner
 ) THEN
  RAISE EXCEPTION 'incarnation lineage migration rejects runtime authority from default privileges'
   USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd

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
  OR NOT COALESCE(activated_postmaster_at=pg_catalog.pg_postmaster_start_time()
   OR (EXISTS(SELECT 1 FROM public.database_restart r WHERE r.started_at=pg_catalog.pg_postmaster_start_time())
    AND activated_postmaster_at<pg_catalog.pg_postmaster_start_time()
    AND activated_system_identifier=(pg_catalog.pg_control_system()).system_identifier::text
    AND activated_timeline=CASE WHEN pg_catalog.pg_is_in_recovery() THEN NULL ELSE
     ('x'||pg_catalog.substr(pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()),1,8))::bit(32)::integer END),false)
  OR activated_database_oid IS DISTINCT FROM
     (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
  OR pg_catalog.pg_is_in_recovery())::boolean AS recovery_blocked,
 observed_at,fresh_until
 FROM fleet_trust;

-- No implicit backfill/activation and no destructive down. Migration itself
-- blocks old roots until qualified activation. The installer grants only view
-- reads/row-lock permission to consumers; activation columns stay private.
