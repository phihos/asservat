-- +goose Up
-- REQ-DB-005: no component checks a recovery flag. Migration 00167 left
-- fleet_current_trust.recovery_blocked as a constant false for the stored
-- function bodies that still named it. This migration removes the term from
-- every function body, then the column from the view.
-- +goose StatementBegin
DO $$
DECLARE f record; def text; next text;
BEGIN
 FOR f IN SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='public' AND p.prosrc ~ 'recovery_blocked' LOOP
  def:=pg_catalog.pg_get_functiondef(f.oid);
  next:=def;
  next:=regexp_replace(next,'NOT\s+(\w+\.)?recovery_blocked\s+AND\s+','','g');
  next:=regexp_replace(next,'\s+AND\s+NOT\s+(\w+\.)?recovery_blocked\M','','g');
  next:=regexp_replace(next,'(\w+\.)?recovery_blocked\s+OR\s+','','g');
  next:=regexp_replace(next,'\s+OR\s+(\w+\.)?recovery_blocked\M','','g');
  next:=regexp_replace(next,'''recoveryBlocked'',(\w+\.)?recovery_blocked,','','g');
  IF next ~ 'recovery_blocked' THEN
   RAISE EXCEPTION 'unhandled recovery_blocked reference in %', f.oid::regprocedure;
  END IF;
  EXECUTE next;
 END LOOP;
END $$;
-- +goose StatementEnd

-- capacity_recovery_current takes the view's row type, so it is recreated
-- with the view. Its definition and the view grants are kept in a temporary
-- table. The view statements stay outside DO blocks so sqlc sees them.
-- +goose StatementBegin
DO $$
DECLARE acl text[];
BEGIN
 SELECT array_agg(format('GRANT %s ON public.fleet_current_trust TO %I',privilege_type,grantee))
  INTO acl FROM information_schema.role_table_grants
  WHERE table_schema='public' AND table_name='fleet_current_trust' AND grantee<>current_user;
 SELECT acl||array_agg(format('GRANT %s(%I) ON public.fleet_current_trust TO %I',privilege_type,column_name,grantee))
  INTO acl FROM information_schema.column_privileges
  WHERE table_schema='public' AND table_name='fleet_current_trust' AND grantee<>current_user
   AND column_name<>'recovery_blocked'
   AND (grantee,privilege_type) NOT IN (SELECT grantee,privilege_type FROM information_schema.role_table_grants
    WHERE table_schema='public' AND table_name='fleet_current_trust');
 CREATE TEMPORARY TABLE migration_00172 ON COMMIT DROP AS
  SELECT pg_catalog.pg_get_functiondef('public.capacity_recovery_current(public.capacity_source,public.fleet_current_trust,jsonb,timestamptz)'::regprocedure) AS fn,acl;
END $$;
-- +goose StatementEnd
DROP FUNCTION public.capacity_recovery_current(public.capacity_source,public.fleet_current_trust,jsonb,timestamptz);
DROP VIEW public.fleet_current_trust;
CREATE VIEW public.fleet_current_trust AS
 WITH observations AS MATERIALIZED (
  SELECT installation_id,semantic_version,issuer_epoch,source_uid,
   source_generation,source_digest,activated_postmaster_at,
   activated_database_oid,observed_at,fresh_until FROM public.fleet_observation
 )
 SELECT t.installation_id,t.issuer_epoch,t.source_uid,t.source_generation,
 t.source_digest,t.suspended,
 COALESCE(o.observed_at,'epoch'::timestamptz) AS observed_at,
 COALESCE(o.fresh_until,'epoch'::timestamptz) AS fresh_until
 FROM public.fleet_trust t LEFT JOIN observations o
 ON o.installation_id=t.installation_id AND o.semantic_version=t.semantic_version
 AND o.issuer_epoch=t.issuer_epoch AND o.source_uid=t.source_uid
 AND o.source_generation=t.source_generation AND o.source_digest=t.source_digest
 AND o.activated_postmaster_at IS NOT DISTINCT FROM t.activated_postmaster_at
 AND o.activated_database_oid IS NOT DISTINCT FROM t.activated_database_oid;
-- +goose StatementBegin
DO $$
DECLARE m record;
BEGIN
 SELECT fn,acl INTO m FROM migration_00172;
 EXECUTE m.fn;
 REVOKE ALL ON FUNCTION public.capacity_recovery_current(public.capacity_source,public.fleet_current_trust,jsonb,timestamptz) FROM PUBLIC;
 IF m.acl IS NOT NULL THEN
  FOR i IN 1..array_length(m.acl,1) LOOP
   IF m.acl[i] IS NOT NULL THEN EXECUTE m.acl[i]; END IF;
  END LOOP;
 END IF;
END $$;
-- +goose StatementEnd
