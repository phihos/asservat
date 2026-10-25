-- +goose Up
-- ADR-226: a lossless PostgreSQL restart re-activates the existing trust root
-- automatically (ADR-096: "Lossless restarts should be reactivated
-- automatically"). Activation now also records the cluster's system identifier
-- and WAL timeline. A restart keeps the database OID, system identifier and
-- timeline and changes only the server start time. Archive recovery (pgBackRest
-- restore, point-in-time recovery, promotion) starts a new timeline, a logical
-- restore creates a new database OID and another cluster has another system
-- identifier; each of those stays blocked for the separate restore protocol.
ALTER TABLE fleet_trust ADD COLUMN activated_system_identifier text,
 ADD COLUMN activated_timeline integer;

-- Re-records only the server start time, in both rows the effective view
-- joins, when every other recorded incarnation fact still matches, the stored
-- flags are unblocked, the server is a durable primary and time moved forward.
-- Returns whether it re-activated. The guard trigger advances the semantic
-- version, so proofs taken before the restart stay unusable.
-- +goose StatementBegin
CREATE FUNCTION reactivate_restarted_database(i uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.fleet_trust;o public.fleet_observation;started timestamptz:=pg_postmaster_start_time();
 db oid;timeline integer;
BEGIN
 IF i IS NULL OR pg_is_in_recovery() OR current_setting('fsync')<>'on'
   OR current_setting('full_page_writes')<>'on' OR current_setting('synchronous_commit')='off' THEN
  RETURN false;
 END IF;
 -- Unlocked pre-check: an ordinary pass takes no lock.
 IF NOT EXISTS(SELECT 1 FROM public.fleet_trust WHERE installation_id=i
   AND activated_postmaster_at IS NOT NULL AND activated_postmaster_at<started) THEN
  RETURN false;
 END IF;
 db:=(SELECT oid FROM pg_database WHERE datname=current_database());
 timeline:=('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::integer;
 LOCK TABLE public.fleet_trust,public.fleet_observation IN ROW EXCLUSIVE MODE;
 SELECT * INTO r FROM public.fleet_trust WHERE installation_id=i FOR UPDATE;
 IF NOT FOUND OR r.recovery_blocked OR r.activated_postmaster_at IS NULL OR r.activated_postmaster_at>=started
   OR r.activated_database_oid IS DISTINCT FROM db
   OR r.activated_system_identifier IS DISTINCT FROM (pg_control_system()).system_identifier::text
   OR r.activated_timeline IS DISTINCT FROM timeline THEN
  RETURN false;
 END IF;
 SELECT * INTO o FROM public.fleet_observation WHERE installation_id=i FOR UPDATE;
 IF NOT FOUND OR o.activated_postmaster_at IS DISTINCT FROM r.activated_postmaster_at
   OR o.activated_database_oid IS DISTINCT FROM r.activated_database_oid THEN
  RETURN false;
 END IF;
 UPDATE public.fleet_trust SET activated_postmaster_at=started WHERE installation_id=i RETURNING * INTO r;
 UPDATE public.fleet_observation SET activated_postmaster_at=started,semantic_version=r.semantic_version
  WHERE installation_id=i;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION reactivate_restarted_database(uuid) FROM PUBLIC;

-- +goose StatementBegin
DO $$
BEGIN
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_proc p,
   LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
  WHERE p.oid='public.reactivate_restarted_database(uuid)'::regprocedure
    AND a.grantee<>p.proowner AND a.privilege_type='EXECUTE'
 ) THEN
  RAISE EXCEPTION 'restart reactivation migration rejects runtime authority from default privileges'
   USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
-- No destructive down: activation history may not reset.
