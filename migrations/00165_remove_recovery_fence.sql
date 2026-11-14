-- +goose Up
-- REQ-DB-005: a restore runs with every workload scaled to zero and setup's
-- recovery step. No component checks a recovery flag or a database
-- incarnation, so the activation lineage, the restart re-activation and the
-- derived recovery block of migration 00031 go away. fleet_current_trust keeps
-- a constant recovery_blocked column only because stored function bodies still
-- name it; it is never true.
-- Without a current observation the dates are the epoch, so the row is stale.
CREATE OR REPLACE VIEW public.fleet_current_trust AS
 WITH observations AS MATERIALIZED (
  SELECT installation_id,semantic_version,issuer_epoch,source_uid,
   source_generation,source_digest,activated_postmaster_at,
   activated_database_oid,observed_at,fresh_until FROM public.fleet_observation
 )
 SELECT t.installation_id,t.issuer_epoch,t.source_uid,t.source_generation,
 t.source_digest,t.suspended,false AS recovery_blocked,
 COALESCE(o.observed_at,'epoch'::timestamptz) AS observed_at,
 COALESCE(o.fresh_until,'epoch'::timestamptz) AS fresh_until
 FROM public.fleet_trust t LEFT JOIN observations o
 ON o.installation_id=t.installation_id AND o.semantic_version=t.semantic_version
 AND o.issuer_epoch=t.issuer_epoch AND o.source_uid=t.source_uid
 AND o.source_generation=t.source_generation AND o.source_digest=t.source_digest
 AND o.activated_postmaster_at IS NOT DISTINCT FROM t.activated_postmaster_at
 AND o.activated_database_oid IS NOT DISTINCT FROM t.activated_database_oid;

DROP FUNCTION reactivate_restarted_database(uuid);
DROP TABLE database_restart;
DROP FUNCTION database_restart_immutable();
DROP TRIGGER fleet_activation_incarnation ON fleet_trust;
DROP FUNCTION fleet_activation_incarnation();

-- Every recorded server start belongs to the current database: a restart
-- needs no re-activation and a restore is handled by setup's recovery step.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION incarnation_current(x timestamptz) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ SELECT x IS NOT NULL $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION fleet_semantic_version_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE changed boolean;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.semantic_version<>1 THEN RAISE EXCEPTION 'invalid initial fleet version' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.semantic_version IS NULL THEN
  RAISE EXCEPTION 'invalid fleet semantic transition' USING ERRCODE='23514';
 END IF;
 IF NEW.installation_id IS DISTINCT FROM OLD.installation_id THEN
  RAISE EXCEPTION 'fleet installation identity is immutable' USING ERRCODE='23514';
 END IF;
 changed:=ROW(NEW.issuer_epoch,NEW.source_uid,NEW.source_generation,NEW.source_digest,
              NEW.suspended,NEW.activated_postmaster_at,NEW.activated_database_oid)
  IS DISTINCT FROM ROW(OLD.issuer_epoch,OLD.source_uid,OLD.source_generation,OLD.source_digest,
              OLD.suspended,OLD.activated_postmaster_at,OLD.activated_database_oid);
 IF changed OR NEW.semantic_version IS DISTINCT FROM OLD.semantic_version THEN
  IF OLD.semantic_version=9223372036854775807 THEN
   RAISE EXCEPTION 'fleet semantic version exhausted' USING ERRCODE='23514';
  END IF;
  IF NEW.semantic_version<>OLD.semantic_version AND NEW.semantic_version<>OLD.semantic_version+1 THEN
   RAISE EXCEPTION 'invalid fleet semantic transition' USING ERRCODE='23514';
  END IF;
  NEW.semantic_version:=OLD.semantic_version+1;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- The administration observation no longer derives a recovery block. A root
-- that setup has not seeded with an observation stays suspended.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION observe_fleet_administration(i uuid, v bigint, pm timestamptz, db oid, basis_until timestamptz, epoch uuid, uid text, generation bigint, digest bytea, source_suspended boolean, observed timestamptz, fresh timestamptz)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.fleet_trust;o public.fleet_observation;n timestamptz;last_start timestamptz;
 last_end timestamptz;unchanged boolean;has_observation boolean;rows_written bigint;
 seeded boolean;desired_suspended boolean;
BEGIN
 n:=clock_timestamp();
 IF NOT COALESCE(v>=0 AND pm=pg_postmaster_start_time()
   AND db=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT pg_is_in_recovery()
   AND isfinite(basis_until) AND n<basis_until AND basis_until<=n+interval '5 seconds'
   AND isfinite(observed) AND isfinite(fresh) AND observed>='2020-01-01Z'::timestamptz
   AND fresh<'10000-01-01Z'::timestamptz AND observed<=n AND n<fresh
   AND fresh<=observed+interval '5 seconds' AND generation BETWEEN 1 AND 2147483647
   AND octet_length(uid) BETWEEN 1 AND 64 AND octet_length(digest)=32
   AND epoch IS NOT NULL AND i IS NOT NULL AND source_suspended IS NOT NULL,false) THEN RETURN 0; END IF;
 LOCK TABLE public.fleet_trust,public.fleet_observation IN ROW EXCLUSIVE MODE;
 SELECT * INTO r FROM public.fleet_trust WHERE installation_id=i;
 IF NOT FOUND THEN
  IF v<>0 THEN RETURN 0; END IF;
  INSERT INTO public.fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until)
   VALUES(i,epoch,uid,generation,digest,observed,fresh) ON CONFLICT(installation_id) DO NOTHING;
  GET DIAGNOSTICS rows_written=ROW_COUNT;
  IF rows_written<>1 THEN RETURN 0; END IF;
  RETURN 1;
 END IF;
 IF v=0 OR r.semantic_version<>v THEN RETURN 0; END IF;
 seeded:=EXISTS(SELECT 1 FROM public.fleet_observation x WHERE x.installation_id=i
   AND x.issuer_epoch=r.issuer_epoch AND x.source_uid=r.source_uid
   AND x.activated_postmaster_at IS NOT DISTINCT FROM r.activated_postmaster_at
   AND x.activated_database_oid IS NOT DISTINCT FROM r.activated_database_oid);
 desired_suspended:=source_suspended OR NOT seeded;
 unchanged:=r.source_generation=generation AND r.source_digest=digest AND r.suspended=desired_suspended;
 BEGIN
 IF unchanged THEN
  SELECT * INTO STRICT r FROM public.fleet_trust WHERE installation_id=i FOR SHARE;
 ELSE
  SELECT * INTO STRICT r FROM public.fleet_trust WHERE installation_id=i FOR UPDATE;
 END IF;
 EXCEPTION WHEN lock_not_available THEN RETURN 3;
 END;
 SELECT * INTO o FROM public.fleet_observation WHERE installation_id=i FOR UPDATE;
 has_observation:=FOUND;
 n:=clock_timestamp();
 IF NOT(n<fresh AND n<basis_until) OR r.semantic_version<>v OR r.issuer_epoch<>epoch OR r.source_uid<>uid
   OR generation<r.source_generation OR (generation=r.source_generation AND digest<>r.source_digest)
 THEN RETURN 0; END IF;
 -- Never upgrade SHARE after locking observation. A raced classification fails.
 IF seeded IS DISTINCT FROM (has_observation AND o.issuer_epoch=r.issuer_epoch AND o.source_uid=r.source_uid
   AND o.activated_postmaster_at IS NOT DISTINCT FROM r.activated_postmaster_at
   AND o.activated_database_oid IS NOT DISTINCT FROM r.activated_database_oid) THEN RETURN 0; END IF;
 IF unchanged AND (r.source_generation<>generation OR r.source_digest<>digest
   OR r.suspended<>desired_suspended) THEN RETURN 0; END IF;
 last_start:=r.observed_at;last_end:=r.fresh_until;
 IF has_observation THEN
  IF o.observed_at>last_start THEN last_start:=o.observed_at;last_end:=o.fresh_until;
  ELSIF o.observed_at=last_start THEN last_end:=LEAST(last_end,o.fresh_until);END IF;
 END IF;
 IF observed<last_start OR (observed=last_start AND (fresh>last_end OR generation<>r.source_generation
   OR digest<>r.source_digest OR desired_suspended<>r.suspended)) THEN RETURN 2; END IF;
 IF NOT unchanged THEN
  UPDATE public.fleet_trust SET source_generation=generation,source_digest=digest,
   suspended=desired_suspended,observed_at=observed,fresh_until=fresh
   WHERE installation_id=i RETURNING * INTO r;
 END IF;
 IF seeded THEN
  UPDATE public.fleet_observation SET semantic_version=r.semantic_version,
   source_generation=r.source_generation,source_digest=r.source_digest,
   observed_at=observed,fresh_until=observed+interval '30 seconds' WHERE installation_id=i;
 END IF;
 n:=clock_timestamp();
 IF NOT(n<fresh AND n<basis_until) THEN
  RAISE EXCEPTION 'original fleet observation unavailable' USING ERRCODE='23514';
 END IF;
 RETURN 1;
END $$;
-- +goose StatementEnd

ALTER TABLE fleet_trust DROP COLUMN recovery_blocked,
 DROP COLUMN activated_system_identifier, DROP COLUMN activated_timeline;
