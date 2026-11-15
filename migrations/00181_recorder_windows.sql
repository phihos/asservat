-- +goose Up
-- ADR-335 D8: a saved-log window after the trigger runs up to the capture's
-- configured duration. The composition's maxDuration bounds the action
-- timeout, so the expectation keeps only timeout > after; the 60 s after and
-- 5 min timeout literals go. The function body is rewritten in place like
-- 00165. No Down: the wider bounds stay; a re-Up after a downgrade probe finds
-- the new text and changes nothing.
-- +goose StatementBegin
DO $$
DECLARE def text;
 old_text text:=$t$public.capacity_json_integer(e#>'{Logs,AfterMillis}',0,60000) AND public.capacity_json_integer(e#>'{Logs,TimeoutMillis}',1,300000)$t$;
 new_text text:=$t$public.capacity_json_integer(e#>'{Logs,AfterMillis}',0,9007199254740991) AND public.capacity_json_integer(e#>'{Logs,TimeoutMillis}',1,9007199254740991)$t$;
BEGIN
 def:=pg_catalog.pg_get_functiondef('public.project_context_processing()'::regprocedure);
 IF pg_catalog.strpos(def,new_text)>0 AND pg_catalog.strpos(def,old_text)=0 THEN RETURN; END IF;
 IF (pg_catalog.length(def)-pg_catalog.length(pg_catalog.replace(def,old_text,'')))/pg_catalog.length(old_text)<>1 THEN
  RAISE EXCEPTION 'unexpected definition of project_context_processing' USING ERRCODE='55000'; END IF;
 EXECUTE pg_catalog.replace(def,old_text,new_text);
END $$;
-- +goose StatementEnd
-- A finite sensitive session lasts its recording plus the 10 s start window
-- (authorization.FiniteObservationStartWindow) within the reviewed
-- MaxSessionSeconds; the 15 s raw/HTTP and 60 s argument literals go.
ALTER TABLE policy_observation_session DROP CONSTRAINT IF EXISTS policy_observation_argument_tuple;
ALTER TABLE policy_observation_session ADD CONSTRAINT policy_observation_argument_tuple CHECK(
 (accounting_rule=decode('4d3f2eea2ed280bd7017ea2398a4cde18d94daacbcc4c8741a98d52c56697453','hex') AND argument_definition_digest IS NULL AND event_credit=0 AND max_events_per_second=0
  AND max_probe_bytes=0 AND max_bytes_per_event=0 AND max_tracked_threads=0 AND NOT capture_buffers
  AND duration_millis>=1000 AND session_until>started_at AND session_until<=started_at+(duration_millis+10000)*interval '1 millisecond')
 OR
 (accounting_rule=decode('833bafd01122a099b6a41751e9c545dccd925d54f94faabdfba9f8f9bcd7eef6','hex') AND argument_definition_digest IS NOT NULL AND octet_length(argument_definition_digest)=32
  AND event_credit BETWEEN 1 AND 1000000000 AND max_events_per_second BETWEEN 1 AND 100000
  AND max_probe_bytes IN (256,512) AND max_bytes_per_event BETWEEN 1 AND 4096
  AND (max_probe_bytes=256 OR max_bytes_per_event>=128) AND max_tracked_threads BETWEEN 1 AND 16384
  AND credit>=max_probe_bytes AND max_bytes_per_second>=max_probe_bytes
  AND duration_millis>=1000 AND session_until>started_at
  AND session_until<=started_at+(duration_millis+10000)*interval '1 millisecond'));
