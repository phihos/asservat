-- +goose Up
-- REQ-DB-005: no component checks a recovery flag. Migration 00167 left
-- fleet_current_trust.recovery_blocked as a constant false for the stored
-- function bodies that still named it. This migration removes the term from
-- every function body, then the column from the view. Rerunning it after a
-- downgrade probe finds no body to change and recreates the same view.
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

-- The view grants survive the recreation through a temporary table. The view
-- statements stay outside DO blocks so sqlc sees them.
-- +goose StatementBegin
DO $$
BEGIN
 CREATE TEMPORARY TABLE migration_00173 ON COMMIT DROP AS
  SELECT format('GRANT %s ON public.fleet_current_trust TO %I',privilege_type,grantee) AS stmt
  FROM information_schema.role_table_grants
  WHERE table_schema='public' AND table_name='fleet_current_trust' AND grantee<>current_user
  UNION ALL
  SELECT format('GRANT %s(%I) ON public.fleet_current_trust TO %I',privilege_type,column_name,grantee)
  FROM information_schema.column_privileges c
  WHERE table_schema='public' AND table_name='fleet_current_trust' AND grantee<>current_user
   AND column_name<>'recovery_blocked'
   AND NOT EXISTS (SELECT 1 FROM information_schema.role_table_grants r
    WHERE r.table_schema='public' AND r.table_name='fleet_current_trust'
     AND r.grantee=c.grantee AND r.privilege_type=c.privilege_type);
END $$;
-- +goose StatementEnd
DROP VIEW IF EXISTS public.fleet_current_trust;
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
DECLARE g record;
BEGIN
 FOR g IN SELECT stmt FROM migration_00173 LOOP EXECUTE g.stmt; END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Earlier migrations replace this view with the constant column in place
-- (00167) and create SQL functions that name it, so a downgrade probe gets
-- the 00167 view back. The stripped function bodies stay stripped; they
-- work with either view.
-- +goose StatementBegin
DO $$
BEGIN
 CREATE TEMPORARY TABLE migration_00173 ON COMMIT DROP AS
  SELECT format('GRANT %s ON public.fleet_current_trust TO %I',privilege_type,grantee) AS stmt
  FROM information_schema.role_table_grants
  WHERE table_schema='public' AND table_name='fleet_current_trust' AND grantee<>current_user
  UNION ALL
  SELECT format('GRANT %s(%I) ON public.fleet_current_trust TO %I',privilege_type,column_name,grantee)
  FROM information_schema.column_privileges c
  WHERE table_schema='public' AND table_name='fleet_current_trust' AND grantee<>current_user
   AND column_name<>'recovery_blocked'
   AND NOT EXISTS (SELECT 1 FROM information_schema.role_table_grants r
    WHERE r.table_schema='public' AND r.table_name='fleet_current_trust'
     AND r.grantee=c.grantee AND r.privilege_type=c.privilege_type);
END $$;
-- +goose StatementEnd
DROP VIEW IF EXISTS public.fleet_current_trust;
CREATE VIEW public.fleet_current_trust AS
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
-- +goose StatementBegin
DO $$
DECLARE g record;
BEGIN
 FOR g IN SELECT stmt FROM migration_00173 LOOP EXECUTE g.stmt; END LOOP;
END $$;
-- +goose StatementEnd
