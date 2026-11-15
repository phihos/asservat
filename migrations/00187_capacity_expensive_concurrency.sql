-- +goose Up
-- specs/capacity.md REQ-CAP-002: an expensive action (a profile) is admitted
-- only while fewer than capacity.workload.maxConcurrentExpensive of the
-- workload's expensive attempts are still writable. The capture admission
-- holds the account's allocation row lock, so concurrent admissions count
-- each other. A root without capacity settings is unmanaged and unlimited.
-- REQ-CAP-006: a full account always rejects new expensive work; the
-- onFull setting is removed. No Down: every statement can be reapplied.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_expensive_admits(allocation uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT count(*)<COALESCE((SELECT s.max_concurrent_expensive FROM public.capacity_account w JOIN public.capacity_settings s ON s.root_id=w.root_id WHERE w.allocation_id=allocation),2147483647)
 FROM public.custody_attempt a JOIN public.context_capture c ON c.attempt_id=a.id
 WHERE a.allocation_id=allocation AND a.state='reserved' AND a.write_until>clock_timestamp()
  AND convert_from(c.expectation_json,'UTF8')::jsonb ? 'Profile'
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_expensive_admits(uuid) FROM PUBLIC;

-- +goose StatementBegin
DO $$
DECLARE f record; next text;
BEGIN
 FOR f IN SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='public' AND p.prosrc ~ 'on_full|OnFull' LOOP
  next:=pg_catalog.pg_get_functiondef(f.oid);
  next:=replace(next,',on_full,revision)',',revision)');
  next:=replace(next,',v->>''OnFull'',1)',',1)');
  next:=replace(next,',on_full=v->>''OnFull''','');
  IF next ~ 'on_full|OnFull' THEN
   RAISE EXCEPTION 'unhandled on_full reference in %', f.oid::regprocedure;
  END IF;
  EXECUTE next;
 END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE capacity_settings DROP COLUMN IF EXISTS on_full;
