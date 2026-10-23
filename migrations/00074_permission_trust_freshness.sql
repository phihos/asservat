-- +goose Up
-- ADR-200 revision (2026-10-23): the accepted permission_stream observation and
-- the positive fleet trust observation (fleet_observation, read through
-- fleet_current_trust) are current for 30 seconds after their own observation
-- instead of five, like the binding (00072) and root capacity source (00073).
-- Late hub-worker permission or fleet refreshes no longer lapse every capture,
-- query and download admission. Suspension, accepted deny changes, recovery
-- blocking, database incarnation checks and the failure fence still apply at
-- once; caller receipts and request deadlines keep their original intervals.
-- The functions below change only the named permission/trust bound; their
-- current bodies are rewritten in place so grants and every other check stay;
-- each named text must occur exactly once or the migration fails.
-- +goose StatementBegin
DO $$
DECLARE k name;r record;def text;
BEGIN
 SELECT conname INTO STRICT k FROM pg_catalog.pg_constraint WHERE conrelid='public.permission_stream'::regclass AND contype='c' AND
  pg_catalog.pg_get_constraintdef(oid) LIKE '%fresh_until <= (observed_at + ''00:00:05''::interval)%';
 EXECUTE format('ALTER TABLE public.permission_stream DROP CONSTRAINT %I',k);
 -- The fleet row alone gets the 30-second lifetime; the caller's fresh value
 -- (at most five seconds) still bounds the call. Suspension, recovery and the
 -- failure fence are unchanged.
 FOR r IN SELECT * FROM (VALUES
  ('public.capacity_lock_observation(uuid,text,jsonb,bytea,bytea,bytea)','p.fresh_until<=p.observed_at+interval ''5 seconds''','p.fresh_until<=p.observed_at+interval ''30 seconds'''),
  ('public.capacity_lock_root_observation(uuid,text,jsonb,bytea,bytea)','p.fresh_until>p.observed_at+interval ''5 seconds''','p.fresh_until>p.observed_at+interval ''30 seconds'''),
  ('public.read_capacity_audit_profiles(uuid,uuid,uuid,bytea,text,timestamptz,timestamptz)','p.fresh_until>p.observed_at+interval ''5 seconds''','p.fresh_until>p.observed_at+interval ''30 seconds'''),
  ('public.read_capacity_permission_scopes(uuid,jsonb)','stream.fresh_until>stream.observed_at+interval ''5 seconds''','stream.fresh_until>stream.observed_at+interval ''30 seconds'''),
  ('public.observe_fleet_administration(uuid,bigint,timestamptz,oid,timestamptz,uuid,text,bigint,bytea,boolean,timestamptz,timestamptz)','observed_at=observed,fresh_until=fresh WHERE installation_id=i;','observed_at=observed,fresh_until=observed+interval ''30 seconds'' WHERE installation_id=i;')) AS v(f,old_text,new_text) LOOP
  def:=pg_catalog.pg_get_functiondef(r.f::regprocedure);
  IF (pg_catalog.length(def)-pg_catalog.length(pg_catalog.replace(def,r.old_text,'')))/pg_catalog.length(r.old_text)<>1 THEN
   RAISE EXCEPTION 'unexpected definition of %',r.f USING ERRCODE='55000';END IF;
  EXECUTE pg_catalog.replace(def,r.old_text,r.new_text);
 END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE permission_stream ADD CONSTRAINT permission_stream_observation_lifetime
 CHECK(fresh_until IS NULL OR (fresh_until>observed_at AND fresh_until<=observed_at+interval '30 seconds'));

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE r record;def text;
BEGIN
 FOR r IN SELECT * FROM (VALUES
  ('public.capacity_lock_observation(uuid,text,jsonb,bytea,bytea,bytea)','p.fresh_until<=p.observed_at+interval ''30 seconds''','p.fresh_until<=p.observed_at+interval ''5 seconds'''),
  ('public.capacity_lock_root_observation(uuid,text,jsonb,bytea,bytea)','p.fresh_until>p.observed_at+interval ''30 seconds''','p.fresh_until>p.observed_at+interval ''5 seconds'''),
  ('public.read_capacity_audit_profiles(uuid,uuid,uuid,bytea,text,timestamptz,timestamptz)','p.fresh_until>p.observed_at+interval ''30 seconds''','p.fresh_until>p.observed_at+interval ''5 seconds'''),
  ('public.read_capacity_permission_scopes(uuid,jsonb)','stream.fresh_until>stream.observed_at+interval ''30 seconds''','stream.fresh_until>stream.observed_at+interval ''5 seconds'''),
  ('public.observe_fleet_administration(uuid,bigint,timestamptz,oid,timestamptz,uuid,text,bigint,bytea,boolean,timestamptz,timestamptz)','observed_at=observed,fresh_until=observed+interval ''30 seconds'' WHERE installation_id=i;','observed_at=observed,fresh_until=fresh WHERE installation_id=i;')) AS v(f,old_text,new_text) LOOP
  def:=pg_catalog.pg_get_functiondef(r.f::regprocedure);
  IF (pg_catalog.length(def)-pg_catalog.length(pg_catalog.replace(def,r.old_text,'')))/pg_catalog.length(r.old_text)<>1 THEN
   RAISE EXCEPTION 'unexpected definition of %',r.f USING ERRCODE='55000';END IF;
  EXECUTE pg_catalog.replace(def,r.old_text,r.new_text);
 END LOOP;
END $$;
-- +goose StatementEnd
-- Narrow observations stored under the 30-second rule to five seconds after
-- their own observation (shortening only; an expired row stays expired).
UPDATE permission_stream SET fresh_until=observed_at+interval '5 seconds' WHERE observed_at IS NOT NULL AND fresh_until>observed_at+interval '5 seconds';
UPDATE fleet_observation SET fresh_until=observed_at+interval '5 seconds' WHERE fresh_until>observed_at+interval '5 seconds';
ALTER TABLE permission_stream DROP CONSTRAINT permission_stream_observation_lifetime;
ALTER TABLE permission_stream ADD CONSTRAINT permission_stream_observation_lifetime
 CHECK(fresh_until IS NULL OR (fresh_until>observed_at AND fresh_until<=observed_at+interval '5 seconds'));
