-- +goose Up
-- Existing generated credential retirement is an installer upgrade prerequisite.
-- Inspect explicit ACLs, including the parent/PUBLIC grants from which inherited
-- rights arise. Inherent superuser/owner powers are not runtime ACL grants.
-- Do not infer trusted role identity from a name, membership or role comment.
-- +goose StatementBegin
DO $$
BEGIN
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_class c,
   LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
  WHERE c.oid='public.fleet_trust'::regclass AND a.grantee<>c.relowner
    AND a.privilege_type IN ('INSERT','UPDATE','TRIGGER','REFERENCES')
  UNION ALL
  SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_attribute at ON at.attrelid=c.oid,
   LATERAL pg_catalog.aclexplode(at.attacl) a
  WHERE c.oid='public.fleet_trust'::regclass AND a.grantee<>c.relowner
    AND (a.privilege_type IN ('INSERT','REFERENCES') OR (a.privilege_type='UPDATE'
     AND at.attname IN ('issuer_epoch','source_uid','source_generation','source_digest',
       'suspended','recovery_blocked','observed_at','fresh_until','activated_postmaster_at','activated_database_oid')))
 ) THEN
  RAISE EXCEPTION 'fleet observation migration requires retirement of existing direct fleet writer grants'
   USING ERRCODE='55000',HINT='Retire exact original installer-journal credentials and their inherited/PUBLIC writer grants before retrying. Migration does not guess or revoke roles.';
 END IF;
 -- Revoking an old grant does not remove objects installed with it. No
 -- noninternal trigger existed on this table in the qualified schema58 corpus.
 -- Owner-owned references remain within the trusted DDL-administrator boundary.
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
   WHERE tgrelid='public.fleet_trust'::regclass AND NOT tgisinternal)
  OR EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k
   JOIN pg_catalog.pg_class source ON source.oid=k.conrelid
   JOIN pg_catalog.pg_class target ON target.oid=k.confrelid
   WHERE k.contype='f' AND k.confrelid='public.fleet_trust'::regclass
     AND source.relowner<>target.relowner) THEN
  RAISE EXCEPTION 'fleet observation migration requires retirement of untrusted fleet hooks'
   USING ERRCODE='55000',HINT='Review and remove pre-existing noninternal fleet triggers or foreign-owned referencing constraints using exact installer/admin identities before retrying.';
 END IF;
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles r JOIN pg_catalog.pg_class c ON c.oid='public.fleet_trust'::regclass
  WHERE NOT r.rolsuper AND r.oid<>c.relowner AND r.rolname<>'pg_write_all_data'
   AND NOT (pg_catalog.pg_has_role(r.oid,c.relowner,'USAGE') OR pg_catalog.pg_has_role(r.oid,c.relowner,'SET'))
   AND (pg_catalog.pg_has_role(r.oid,'pg_write_all_data','USAGE') OR pg_catalog.pg_has_role(r.oid,'pg_write_all_data','SET'))
 ) THEN
  RAISE EXCEPTION 'fleet observation migration requires retirement of global runtime writer membership'
   USING ERRCODE='55000',HINT='Retire inherited or SET-role reachability to pg_write_all_data before retrying; database owner and superuser remain trusted administrators.';
 END IF;
END $$;
-- +goose StatementEnd

-- Semantic authority is locked through admitted effects. Positive observations
-- use a separate current row; they never acquire an exclusive authority lock.
ALTER TABLE public.fleet_trust ADD COLUMN semantic_version bigint NOT NULL DEFAULT 1
 CHECK(semantic_version > 0);

-- +goose StatementBegin
CREATE FUNCTION fleet_semantic_version_guard() RETURNS trigger
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
              NEW.suspended,NEW.recovery_blocked,NEW.activated_postmaster_at,NEW.activated_database_oid)
  IS DISTINCT FROM ROW(OLD.issuer_epoch,OLD.source_uid,OLD.source_generation,OLD.source_digest,
              OLD.suspended,OLD.recovery_blocked,OLD.activated_postmaster_at,OLD.activated_database_oid);
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
REVOKE ALL ON FUNCTION fleet_semantic_version_guard() FROM PUBLIC;
CREATE TRIGGER fleet_semantic_version_guard BEFORE INSERT OR UPDATE ON public.fleet_trust
 FOR EACH ROW EXECUTE FUNCTION fleet_semantic_version_guard();

CREATE TABLE public.fleet_observation (
 installation_id uuid PRIMARY KEY REFERENCES public.fleet_trust(installation_id),
 semantic_version bigint NOT NULL CHECK(semantic_version>0),
 issuer_epoch uuid NOT NULL,
 source_uid text NOT NULL CHECK(octet_length(source_uid) BETWEEN 1 AND 64),
 source_generation bigint NOT NULL CHECK(source_generation BETWEEN 1 AND 2147483647),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 activated_postmaster_at timestamptz NOT NULL,
 activated_database_oid oid NOT NULL,
 observed_at timestamptz NOT NULL,
 fresh_until timestamptz NOT NULL,
 CHECK(isfinite(observed_at) AND isfinite(fresh_until)
   AND observed_at>='2020-01-01Z'::timestamptz AND fresh_until<'10000-01-01Z'::timestamptz
   AND fresh_until>observed_at AND fresh_until<=observed_at+interval '30 seconds')
);

-- No observation backfill or automatic seed from an activation-field UPDATE.
-- Existing deployments require the separately qualified recovery protocol.
UPDATE public.fleet_trust SET suspended=true,recovery_blocked=true,
 semantic_version=semantic_version+1;

-- Preserve the exact nine-column composite type and its retained column ACLs.
-- MATERIALIZED is necessary: ordinary joins propagate consumer row locks to the
-- observation table and prevent the independent positive refresh again.
CREATE OR REPLACE VIEW public.fleet_current_trust AS
 WITH observations AS MATERIALIZED (
  SELECT installation_id,semantic_version,issuer_epoch,source_uid,
   source_generation,source_digest,activated_postmaster_at,
   activated_database_oid,observed_at,fresh_until FROM public.fleet_observation
 )
 SELECT t.installation_id,t.issuer_epoch,t.source_uid,t.source_generation,
 t.source_digest,t.suspended,
 (t.recovery_blocked
  OR NOT COALESCE(t.activated_postmaster_at=pg_catalog.pg_postmaster_start_time()
   OR (EXISTS(SELECT 1 FROM public.database_restart r WHERE r.started_at=pg_catalog.pg_postmaster_start_time())
    AND t.activated_postmaster_at<pg_catalog.pg_postmaster_start_time()
    AND t.activated_system_identifier=(pg_catalog.pg_control_system()).system_identifier::text
    AND t.activated_timeline=CASE WHEN pg_catalog.pg_is_in_recovery() THEN NULL ELSE
     ('x'||pg_catalog.substr(pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()),1,8))::bit(32)::integer END),false)
  OR t.activated_database_oid IS DISTINCT FROM
    (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
  OR pg_catalog.pg_is_in_recovery()
  OR o.installation_id IS NULL)::boolean AS recovery_blocked,
 COALESCE(o.observed_at,'epoch'::timestamptz) AS observed_at,
 COALESCE(o.fresh_until,'epoch'::timestamptz) AS fresh_until
 FROM public.fleet_trust t LEFT JOIN observations o
 ON o.installation_id=t.installation_id AND o.semantic_version=t.semantic_version
 AND o.issuer_epoch=t.issuer_epoch AND o.source_uid=t.source_uid
 AND o.source_generation=t.source_generation AND o.source_digest=t.source_digest
 AND o.activated_postmaster_at IS NOT DISTINCT FROM t.activated_postmaster_at
 AND o.activated_database_oid IS NOT DISTINCT FROM t.activated_database_oid;

-- Fixed dispositions: 1 persisted, 0 denied, 2 conflict, 3 exact authority-lock abort.
-- Disposition 3 alone is not ADR155 permission: the caller rolls back and
-- independently verifies the original unchanged row/version/incarnation/expiry.
-- Every post-write expiry raises, aborting the statement even for a raw caller.
-- +goose StatementBegin
CREATE FUNCTION observe_fleet_administration(i uuid,v bigint,pm timestamptz,db oid,basis_until timestamptz,
 epoch uuid,uid text,generation bigint,digest bytea,source_suspended boolean,
 observed timestamptz,fresh timestamptz) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.fleet_trust;o public.fleet_observation;n timestamptz;last_start timestamptz;
 last_end timestamptz;effective_block boolean;desired_suspended boolean;unchanged boolean;has_observation boolean;
 rows_written bigint;
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
 -- Match first-activation table-before-row ordering, without excluding active
 -- view SHARE readers. No runtime table-lock/write ACL is needed.
 LOCK TABLE public.fleet_trust,public.fleet_observation IN ROW EXCLUSIVE MODE;
 SELECT * INTO r FROM public.fleet_trust WHERE installation_id=i;
 IF NOT FOUND THEN
  IF v<>0 THEN RETURN 0; END IF;
  INSERT INTO public.fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until)
   VALUES(i,epoch,uid,generation,digest,observed,fresh) ON CONFLICT(installation_id) DO NOTHING;
  GET DIAGNOSTICS rows_written=ROW_COUNT;
  IF rows_written<>1 THEN RETURN 0; END IF;
  -- Defaults remain suspended/recovery blocked, without an observation row.
  n:=clock_timestamp();
  IF NOT(n<fresh AND n<basis_until AND pm=pg_postmaster_start_time()
    AND db=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT pg_is_in_recovery()) THEN
   RAISE EXCEPTION 'original fleet observation unavailable' USING ERRCODE='23514';
  END IF;
  RETURN 1;
 END IF;
 IF v=0 OR r.semantic_version<>v THEN RETURN 0; END IF;
 effective_block:=r.recovery_blocked
   OR NOT (pm=pg_postmaster_start_time() AND public.incarnation_current(r.activated_postmaster_at))
   OR r.activated_database_oid IS DISTINCT FROM db;
 desired_suspended:=source_suspended OR effective_block;
 unchanged:=NOT effective_block AND r.source_generation=generation AND r.source_digest=digest
   AND r.suspended=desired_suspended;
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
 IF NOT(n<fresh AND n<basis_until AND pm=pg_postmaster_start_time()
   AND db=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT pg_is_in_recovery())
   OR r.semantic_version<>v OR r.issuer_epoch<>epoch OR r.source_uid<>uid
   OR generation<r.source_generation OR (generation=r.source_generation AND digest<>r.source_digest)
 THEN RETURN 0; END IF;
 effective_block:=r.recovery_blocked
   OR NOT (pm=pg_postmaster_start_time() AND public.incarnation_current(r.activated_postmaster_at))
   OR r.activated_database_oid IS DISTINCT FROM db;
 desired_suspended:=source_suspended OR effective_block;
 -- Never upgrade SHARE after locking observation. A raced classification fails.
 IF unchanged AND (effective_block OR r.source_generation<>generation OR r.source_digest<>digest
   OR r.suspended<>desired_suspended) THEN RETURN 0; END IF;
 last_start:=r.observed_at;last_end:=r.fresh_until;
 IF has_observation THEN
  IF o.observed_at>last_start THEN last_start:=o.observed_at;last_end:=o.fresh_until;
  ELSIF o.observed_at=last_start THEN last_end:=LEAST(last_end,o.fresh_until);END IF;
 END IF;
 IF observed<last_start OR (observed=last_start AND (fresh>last_end OR generation<>r.source_generation
   OR digest<>r.source_digest OR desired_suspended<>r.suspended)) THEN RETURN 2; END IF;
 IF NOT effective_block THEN
  -- Only the independently qualified initial activation creates this row. A
  -- later source cannot adopt different issuer/root/incarnation binding or
  -- silently repair its absence, even after an administrator changed the base.
  IF NOT has_observation OR o.issuer_epoch<>r.issuer_epoch OR o.source_uid<>r.source_uid
    OR o.activated_postmaster_at IS DISTINCT FROM r.activated_postmaster_at
    OR o.activated_database_oid IS DISTINCT FROM r.activated_database_oid THEN RETURN 0; END IF;
 END IF;
 IF NOT unchanged THEN
  UPDATE public.fleet_trust SET source_generation=generation,source_digest=digest,
   suspended=desired_suspended,observed_at=observed,fresh_until=fresh
   WHERE installation_id=i RETURNING * INTO r;
 END IF;
 IF NOT effective_block THEN
  UPDATE public.fleet_observation SET semantic_version=r.semantic_version,
   source_generation=r.source_generation,source_digest=r.source_digest,
   observed_at=observed,fresh_until=fresh WHERE installation_id=i;
 END IF;
 n:=clock_timestamp();
 IF NOT(n<fresh AND n<basis_until AND pm=pg_postmaster_start_time()
   AND db=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT pg_is_in_recovery()) THEN
  RAISE EXCEPTION 'original fleet observation unavailable' USING ERRCODE='23514';
 END IF;
 RETURN 1;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION observe_fleet_administration(uuid,bigint,timestamptz,oid,timestamptz,uuid,text,bigint,bytea,boolean,timestamptz,timestamptz) FROM PUBLIC;

-- Failure consumes the original version/incarnation but not its expired positive
-- deadline. It owns only this separate bounded restrictive operation. A newer
-- semantic root or accepted observation wins over an old failed native read.
-- +goose StatementBegin
CREATE FUNCTION fence_fleet_observation(i uuid,v bigint,pm timestamptz,db oid,started timestamptz) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.fleet_trust;o public.fleet_observation;call_started timestamptz:=clock_timestamp();
 n timestamptz;latest timestamptz;
BEGIN
 IF NOT COALESCE(i IS NOT NULL AND v>0 AND isfinite(started)
   AND started>='2020-01-01Z'::timestamptz AND started<'10000-01-01Z'::timestamptz
   AND started<=call_started AND pm=pg_postmaster_start_time()
   AND db=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT pg_is_in_recovery(),false)
 THEN RETURN false; END IF;
 LOCK TABLE public.fleet_trust,public.fleet_observation IN ROW EXCLUSIVE MODE;
 SELECT * INTO r FROM public.fleet_trust WHERE installation_id=i FOR UPDATE;
 IF NOT FOUND OR r.semantic_version<>v THEN RETURN false; END IF;
 SELECT * INTO o FROM public.fleet_observation WHERE installation_id=i FOR UPDATE;
 latest:=r.observed_at;
 IF FOUND THEN latest:=GREATEST(latest,o.observed_at);END IF;
 n:=clock_timestamp();
 IF started<latest OR n>=call_started+interval '5 seconds'
   OR pm IS DISTINCT FROM pg_postmaster_start_time()
   OR db IS DISTINCT FROM (SELECT oid FROM pg_database WHERE datname=current_database()) OR pg_is_in_recovery()
 THEN RETURN false; END IF;
 -- Explicit version increment also records an accepted repeated suspension.
 UPDATE public.fleet_trust SET suspended=true,semantic_version=semantic_version+1,
   observed_at=n,fresh_until=n+interval '1 microsecond' WHERE installation_id=i;
 n:=clock_timestamp();
 IF n>=call_started+interval '5 seconds' OR pm IS DISTINCT FROM pg_postmaster_start_time()
   OR db IS DISTINCT FROM (SELECT oid FROM pg_database WHERE datname=current_database()) OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'fleet failure fence unavailable' USING ERRCODE='23514';
 END IF;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION fence_fleet_observation(uuid,bigint,timestamptz,oid,timestamptz) FROM PUBLIC;

-- Named default privileges must not create a new bypass while this migration
-- creates its table/functions. No unknown grantee is silently revoked.
-- +goose StatementBegin
DO $$
BEGIN
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_class c,
   LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
  WHERE c.oid='public.fleet_observation'::regclass AND a.grantee<>c.relowner
    AND a.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES')
 ) OR EXISTS (
  SELECT 1 FROM pg_catalog.pg_proc p,
   LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
  WHERE p.oid IN (
   'public.observe_fleet_administration(uuid,bigint,timestamptz,oid,timestamptz,uuid,text,bigint,bytea,boolean,timestamptz,timestamptz)'::regprocedure,
   'public.fence_fleet_observation(uuid,bigint,timestamptz,oid,timestamptz)'::regprocedure)
    AND a.grantee<>p.proowner AND a.privilege_type='EXECUTE'
 ) THEN
  RAISE EXCEPTION 'fleet observation migration rejects runtime authority from default privileges'
   USING ERRCODE='55000',HINT='Remove the explicit default grants before retrying; install only the purpose-specific generated grants after migration.';
 END IF;
END $$;
-- +goose StatementEnd

-- Runtime roles receive only fixed producer EXECUTE. Fresh initial installation
-- applies this migration before producing role grants. Upgrade retirement and
-- recovery activation require separately qualified orchestration.
-- No destructive down: authority and original observation history may not reset.
