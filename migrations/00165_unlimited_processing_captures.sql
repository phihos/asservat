-- +goose Up
-- ADR-335 D8 / ADR-330 D7: processing_root.max_captures was a lifetime
-- counter that never decreased, so an installation refused every capture
-- once it had published that many. Concurrency limits bound captures; the
-- lineage projection no longer counts or caps them. The function body is
-- rewritten in place so grants and every other check stay; each named text
-- must occur exactly once or the migration fails.
-- +goose StatementBegin
DO $$
DECLARE r record; def text;
BEGIN
 def:=pg_catalog.pg_get_functiondef('public.project_context_processing()'::regprocedure);
 FOR r IN SELECT * FROM (VALUES
  (' OR p.captures>=p.max_captures',''),
  (E' UPDATE public.processing_root SET captures=captures+1 WHERE root_id=NEW.root_id;\n','')) AS v(old_text,new_text) LOOP
  IF (pg_catalog.length(def)-pg_catalog.length(pg_catalog.replace(def,r.old_text,'')))/pg_catalog.length(r.old_text)<>1 THEN
   RAISE EXCEPTION 'unexpected definition of project_context_processing' USING ERRCODE='55000';END IF;
  def:=pg_catalog.replace(def,r.old_text,r.new_text);
 END LOOP;
 EXECUTE def;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE r record; def text;
BEGIN
 def:=pg_catalog.pg_get_functiondef('public.project_context_processing()'::regprocedure);
 FOR r IN SELECT * FROM (VALUES
  (' OR n>=p.valid_until THEN',' OR n>=p.valid_until OR p.captures>=p.max_captures THEN'),
  (E' RETURN NEW;\nEND',E' UPDATE public.processing_root SET captures=captures+1 WHERE root_id=NEW.root_id;\n RETURN NEW;\nEND')) AS v(old_text,new_text) LOOP
  IF (pg_catalog.length(def)-pg_catalog.length(pg_catalog.replace(def,r.old_text,'')))/pg_catalog.length(r.old_text)<>1 THEN
   RAISE EXCEPTION 'unexpected definition of project_context_processing' USING ERRCODE='55000';END IF;
  def:=pg_catalog.replace(def,r.old_text,r.new_text);
 END LOOP;
 EXECUTE def;
END $$;
-- +goose StatementEnd
