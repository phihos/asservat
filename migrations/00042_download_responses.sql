-- +goose Up
-- Version1 64MiB accounting windows are separate from <=5s delivery authority.
-- Existing 4KiB/legacy sessions and their 1024 batch ceiling are unchanged.
-- No download audit lifecycle retirement is enabled by this migration.
CREATE TABLE download_control_allocation (
 id uuid PRIMARY KEY,root_id uuid NOT NULL,audit_store_id uuid NOT NULL,
 FOREIGN KEY(id,root_id) REFERENCES download_allocation(id,root_id),
 response_limit bigint NOT NULL CHECK(response_limit BETWEEN 1 AND 1024),
 window_limit bigint NOT NULL CHECK(window_limit BETWEEN 1 AND 263168),
 audit_byte_limit bigint NOT NULL CHECK(audit_byte_limit BETWEEN 1 AND 68987912192),
 reserved_responses bigint NOT NULL DEFAULT 0 CHECK(reserved_responses BETWEEN 0 AND response_limit),
 reserved_windows bigint NOT NULL DEFAULT 0 CHECK(reserved_windows BETWEEN 0 AND window_limit),
 reserved_audit_bytes bigint NOT NULL DEFAULT 0 CHECK(reserved_audit_bytes BETWEEN 0 AND audit_byte_limit),
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 audit_write_until timestamptz NOT NULL CHECK(isfinite(audit_write_until)),
 CHECK(audit_write_until>valid_until AND audit_write_until<=valid_until+interval '5 minutes'),
 UNIQUE(id,root_id)
);
CREATE TABLE download_response (
 id uuid PRIMARY KEY,root_id uuid NOT NULL,session_id uuid NOT NULL,owner_id uuid NOT NULL,
 FOREIGN KEY(session_id,root_id) REFERENCES artifact_download(id,root_id),
 generation bigint NOT NULL CHECK(generation>0),
 plan_json jsonb NOT NULL CHECK(jsonb_typeof(plan_json)='object' AND octet_length(plan_json::text)<=4096),
 reserved_windows bigint NOT NULL CHECK(reserved_windows BETWEEN 1 AND 16384),
 started_at timestamptz NOT NULL,until_at timestamptz NOT NULL,
 window_count bigint NOT NULL DEFAULT 0 CHECK(window_count BETWEEN 0 AND reserved_windows),
 completed_windows bigint NOT NULL DEFAULT 0 CHECK(completed_windows BETWEEN 0 AND window_count),
 emitted_bytes bigint NOT NULL DEFAULT 0 CHECK(emitted_bytes BETWEEN 0 AND 1099511627776),
 active_window uuid,
 lease_sequence bigint NOT NULL DEFAULT 0 CHECK(lease_sequence>=0),
 lease_until timestamptz NOT NULL,closed boolean NOT NULL DEFAULT false,
 CHECK(isfinite(started_at) AND until_at>started_at AND until_at<=started_at+interval '8 hours' AND lease_until<=until_at),
 UNIQUE(session_id,generation),UNIQUE(id,session_id)
);
CREATE INDEX download_response_leases ON download_response(root_id,lease_until) WHERE NOT closed;
CREATE TABLE download_window (
 id uuid PRIMARY KEY,response_id uuid NOT NULL,session_id uuid NOT NULL,
 FOREIGN KEY(response_id,session_id) REFERENCES download_response(id,session_id),
 ordinal bigint NOT NULL CHECK(ordinal BETWEEN 1 AND 16384),
 intent_json jsonb NOT NULL CHECK(jsonb_typeof(intent_json)='object' AND octet_length(intent_json::text)<=16384),
 intent_receipt jsonb CHECK(intent_receipt IS NULL OR (jsonb_typeof(intent_receipt)='object' AND octet_length(intent_receipt::text)<=4096)),
 intent_completion jsonb CHECK(intent_completion IS NULL OR (intent_receipt IS NOT NULL AND jsonb_typeof(intent_completion)='object' AND octet_length(intent_completion::text)<=8192)),
 outcome_json jsonb CHECK(outcome_json IS NULL OR (intent_receipt IS NOT NULL AND jsonb_typeof(outcome_json)='object' AND octet_length(outcome_json::text)<=2048)),
 outcome_receipt jsonb CHECK(outcome_receipt IS NULL OR (outcome_json IS NOT NULL AND jsonb_typeof(outcome_receipt)='object' AND octet_length(outcome_receipt::text)<=4096)),
 outcome_completion jsonb CHECK(outcome_completion IS NULL OR (outcome_receipt IS NOT NULL AND jsonb_typeof(outcome_completion)='object' AND octet_length(outcome_completion::text)<=8192)),
 UNIQUE(response_id,ordinal)
);
ALTER TABLE download_response ADD CONSTRAINT download_response_active_window FOREIGN KEY(active_window) REFERENCES download_window(id) DEFERRABLE INITIALLY DEFERRED;

-- +goose StatementBegin
CREATE FUNCTION guard_download_control_allocation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.download_allocation;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download control lifecycle unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.id AND root_id=NEW.root_id;
  IF NEW.reserved_responses<>0 OR NEW.reserved_windows<>0 OR NEW.reserved_audit_bytes<>0 OR NEW.valid_until>a.valid_until OR NEW.window_limit>((a.output_limit-1)/67108864+1)+NEW.response_limit THEN RAISE EXCEPTION 'invalid download control backing' USING ERRCODE='23514';END IF;
 ELSIF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['reserved_responses','reserved_windows','reserved_audit_bytes']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['reserved_responses','reserved_windows','reserved_audit_bytes']) OR NEW.reserved_responses<>OLD.reserved_responses+1 OR NEW.reserved_windows<=OLD.reserved_windows OR NEW.reserved_audit_bytes<>OLD.reserved_audit_bytes+(NEW.reserved_windows-OLD.reserved_windows)*262144 THEN
  RAISE EXCEPTION 'immutable source-managed download control backing' USING ERRCODE='23514';
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER download_control_guard BEFORE INSERT OR UPDATE OR DELETE ON download_control_allocation FOR EACH ROW EXECUTE FUNCTION guard_download_control_allocation();

CREATE FUNCTION guard_download_response() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.artifact_download;c public.download_control_allocation;n timestamptz;used bigint;responses bigint;length bigint;off bigint;read_each bigint;win bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download response lifecycle unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT s FROM public.artifact_download WHERE id=NEW.session_id AND root_id=NEW.root_id FOR UPDATE;
  SELECT * INTO STRICT c FROM public.download_control_allocation WHERE id=s.allocation_id AND root_id=s.root_id FOR UPDATE;
  IF NOT (NEW.plan_json ?& ARRAY['Version','Selection','WholeFile','WindowReadLimit']) OR (NEW.plan_json-ARRAY['Version','Selection','WholeFile','WindowReadLimit'])<>'{}'::jsonb OR jsonb_typeof(NEW.plan_json->'Selection') IS DISTINCT FROM 'object' OR NOT ((NEW.plan_json->'Selection') ?& ARRAY['Offset','Length','Partial']) OR ((NEW.plan_json->'Selection')-ARRAY['Offset','Length','Partial'])<>'{}'::jsonb OR jsonb_typeof(NEW.plan_json->'WholeFile') IS DISTINCT FROM 'boolean' OR jsonb_typeof(NEW.plan_json#>'{Selection,Partial}') IS DISTINCT FROM 'boolean' THEN RAISE EXCEPTION 'closed native response plan required' USING ERRCODE='23514';END IF;
  n:=clock_timestamp();length:=(NEW.plan_json#>>'{Selection,Length}')::bigint;off:=(NEW.plan_json#>>'{Selection,Offset}')::bigint;read_each:=(NEW.plan_json->>'WindowReadLimit')::bigint;
  IF length IS NULL OR off IS NULL OR read_each IS NULL OR (NEW.plan_json->>'Version') IS DISTINCT FROM '1' OR length<0 OR length>1099511627776 OR off<0 OR off>1099511627776-length OR read_each<1 OR (NEW.plan_json->>'WholeFile')::boolean AND off<>0 OR (NEW.plan_json#>>'{Selection,Partial}')::boolean AND length=0 THEN RAISE EXCEPTION 'invalid native response plan' USING ERRCODE='23514';END IF;
  win:=greatest(1,(length+67108863)/67108864);
  SELECT coalesce(sum(reserved_windows),0),count(*) INTO used,responses FROM public.download_response WHERE session_id=s.id;
  IF n>=c.valid_until OR n>=NEW.lease_until OR n>=NEW.until_at OR NEW.until_at>s.deadline OR NEW.until_at>c.valid_until OR NEW.started_at>n OR NEW.lease_until>NEW.started_at+interval '5 seconds' OR NEW.generation<>s.generation+1 OR s.state NOT IN ('Ready','Streaming','Interrupted') OR NEW.window_count<>0 OR NEW.completed_windows<>0 OR NEW.emitted_bytes<>0 OR NEW.active_window IS NOT NULL OR NEW.closed OR NEW.lease_sequence<>0 OR NEW.reserved_windows<>win OR read_each>70368744177664/win OR read_each*win>s.read_limit-s.charged_read OR length>s.output_limit-s.charged_output OR responses>=c.response_limit OR used+win>((s.output_limit-1)/67108864+1)+c.response_limit THEN RAISE EXCEPTION 'download response unavailable' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM public.download_response WHERE session_id=s.id AND generation=s.generation AND NOT closed AND lease_until>n) OR EXISTS(SELECT 1 FROM public.download_batch WHERE id=s.active_batch AND lease_until>n AND outcome_json IS NULL) THEN RAISE EXCEPTION 'download response busy' USING ERRCODE='23514';END IF;
  UPDATE public.download_control_allocation SET reserved_responses=reserved_responses+1,reserved_windows=reserved_windows+win,reserved_audit_bytes=reserved_audit_bytes+win*262144 WHERE id=c.id;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.session_id,NEW.owner_id,NEW.generation,NEW.plan_json,NEW.reserved_windows,NEW.started_at,NEW.until_at) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.session_id,OLD.owner_id,OLD.generation,OLD.plan_json,OLD.reserved_windows,OLD.started_at,OLD.until_at) OR NEW.window_count<OLD.window_count OR NEW.completed_windows<OLD.completed_windows OR NEW.emitted_bytes<OLD.emitted_bytes OR NEW.lease_sequence<OLD.lease_sequence OR OLD.closed AND NOT NEW.closed THEN RAISE EXCEPTION 'immutable native response' USING ERRCODE='23514';END IF;
  IF NEW.lease_sequence<>OLD.lease_sequence AND (NEW.lease_sequence<>OLD.lease_sequence+1 OR NEW.lease_until>clock_timestamp()+interval '5 seconds' OR OLD.closed) OR pg_trigger_depth()<2 AND NEW.lease_sequence=OLD.lease_sequence AND NEW.lease_until IS DISTINCT FROM OLD.lease_until THEN RAISE EXCEPTION 'invalid response lease transition' USING ERRCODE='23514';END IF;
  IF pg_trigger_depth()<2 AND ROW(NEW.window_count,NEW.completed_windows,NEW.emitted_bytes,NEW.active_window) IS DISTINCT FROM ROW(OLD.window_count,OLD.completed_windows,OLD.emitted_bytes,OLD.active_window) THEN RAISE EXCEPTION 'window-managed response accounting' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER download_response_guard BEFORE INSERT OR UPDATE OR DELETE ON download_response FOR EACH ROW EXECUTE FUNCTION guard_download_response();

CREATE FUNCTION guard_download_window() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.download_response;s public.artifact_download;c public.download_control_allocation;w jsonb;n timestamptz;amount bigint;read_bytes bigint;emitted bigint;success boolean;verified boolean;final boolean;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download window lifecycle unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.artifact_download WHERE id=NEW.session_id FOR UPDATE;
 SELECT * INTO STRICT r FROM public.download_response WHERE id=NEW.response_id AND session_id=NEW.session_id FOR UPDATE;
 n:=clock_timestamp();w:=NEW.intent_json->'Window';
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT c FROM public.download_control_allocation WHERE id=s.allocation_id AND root_id=s.root_id;
  IF jsonb_typeof(w) IS DISTINCT FROM 'object' OR NOT (w ?& ARRAY['ID','ResponseID','SessionID','OwnerID','AuditStoreID','Generation','Ordinal','Offset','Length','ReadLimit','StartedAt','WriteUntil','Authority','IntentAcknowledged','Outcome','OutcomeAcknowledged']) OR w->'IntentAcknowledged' IS DISTINCT FROM 'false'::jsonb OR w->'OutcomeAcknowledged' IS DISTINCT FROM 'false'::jsonb OR w->'Outcome' IS DISTINCT FROM 'null'::jsonb OR jsonb_typeof(w->'Authority') IS DISTINCT FROM 'object' OR NOT ((w->'Authority') ?& ARRAY['CheckedAt','ValidUntil','Scope']) OR NEW.intent_json#>'{Response,Plan}' IS DISTINCT FROM r.plan_json OR (NEW.intent_json#>>'{Response,ID}') IS DISTINCT FROM r.id::text OR (NEW.intent_json#>>'{Response,OwnerID}') IS DISTINCT FROM r.owner_id::text THEN RAISE EXCEPTION 'closed original window required' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_each(w-'Outcome') AS v WHERE v.value='null'::jsonb) OR (w#>>'{Authority,CheckedAt}') IS NULL OR (w#>>'{Authority,ValidUntil}') IS NULL OR (w->>'StartedAt')::timestamptz>n OR (w#>>'{Authority,ValidUntil}')::timestamptz>(w#>>'{Authority,CheckedAt}')::timestamptz+interval '5 seconds' OR (w#>>'{Authority,Scope,RootID}') IS DISTINCT FROM s.root_id::text OR (w#>'{Authority,Scope}') IS DISTINCT FROM s.scope_json THEN RAISE EXCEPTION 'window scope/interval mismatch' USING ERRCODE='23514';END IF;
  amount:=(w->>'Length')::bigint;read_bytes:=(w->>'ReadLimit')::bigint;
  IF s.generation<>r.generation OR s.state NOT IN ('Ready','Streaming','Interrupted') OR r.closed OR r.active_window IS NOT NULL OR r.window_count<>r.completed_windows OR r.window_count>=r.reserved_windows OR NEW.ordinal<>r.window_count+1 OR (w->>'ID')::uuid<>NEW.id OR (w->>'ResponseID')::uuid<>r.id OR (w->>'SessionID')::uuid<>s.id OR (w->>'OwnerID')::uuid<>r.owner_id OR (w->>'Generation')::bigint<>r.generation OR (w->>'Ordinal')::bigint<>NEW.ordinal OR (w->>'AuditStoreID')::uuid<>c.audit_store_id OR (w->>'WriteUntil')::timestamptz<>c.audit_write_until OR (w->>'Offset')::bigint<>(r.plan_json#>>'{Selection,Offset}')::bigint+r.emitted_bytes OR amount<>least(67108864,(r.plan_json#>>'{Selection,Length}')::bigint-r.emitted_bytes) OR read_bytes<>(r.plan_json->>'WindowReadLimit')::bigint OR n>=r.until_at OR n>=(w#>>'{Authority,ValidUntil}')::timestamptz OR NEW.intent_receipt IS NOT NULL OR NEW.intent_completion IS NOT NULL OR NEW.outcome_completion IS NOT NULL OR NEW.outcome_json IS NOT NULL OR NEW.outcome_receipt IS NOT NULL THEN RAISE EXCEPTION 'download window unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.artifact_download SET charged_output=charged_output+amount,charged_read=charged_read+read_bytes WHERE id=s.id;
  UPDATE public.download_response SET window_count=window_count+1,active_window=NEW.id,lease_until=least(until_at,(w#>>'{Authority,ValidUntil}')::timestamptz) WHERE id=r.id;
 ELSE
  IF ROW(NEW.id,NEW.response_id,NEW.session_id,NEW.ordinal,NEW.intent_json) IS DISTINCT FROM ROW(OLD.id,OLD.response_id,OLD.session_id,OLD.ordinal,OLD.intent_json) OR OLD.intent_receipt IS NOT NULL AND ROW(NEW.intent_receipt,NEW.intent_completion) IS DISTINCT FROM ROW(OLD.intent_receipt,OLD.intent_completion) OR OLD.outcome_json IS NOT NULL AND NEW.outcome_json IS DISTINCT FROM OLD.outcome_json OR OLD.outcome_receipt IS NOT NULL AND ROW(NEW.outcome_receipt,NEW.outcome_completion) IS DISTINCT FROM ROW(OLD.outcome_receipt,OLD.outcome_completion) THEN RAISE EXCEPTION 'immutable window/audit' USING ERRCODE='23514';END IF;
  IF OLD.outcome_json IS NULL AND NEW.outcome_json IS NOT NULL THEN
   emitted:=(NEW.outcome_json->>'EmittedBytes')::bigint;success:=(NEW.outcome_json->>'Success')::boolean;verified:=(NEW.outcome_json->>'VerifiedFinal')::boolean;
   IF NEW.intent_receipt IS NULL OR emitted IS NULL OR success IS NULL OR verified IS NULL OR emitted<0 OR emitted>(w->>'Length')::bigint OR success AND emitted<>(w->>'Length')::bigint OR verified AND (NOT success OR NEW.ordinal<>r.reserved_windows) THEN RAISE EXCEPTION 'invalid window outcome' USING ERRCODE='23514';END IF;
   UPDATE public.artifact_download SET emitted_bytes=emitted_bytes+emitted WHERE id=s.id;
  END IF;
  IF OLD.outcome_receipt IS NULL AND NEW.outcome_receipt IS NOT NULL THEN
   emitted:=(NEW.outcome_json->>'EmittedBytes')::bigint;success:=(NEW.outcome_json->>'Success')::boolean;verified:=(NEW.outcome_json->>'VerifiedFinal')::boolean;final:=NEW.ordinal=r.reserved_windows;
   IF r.active_window IS DISTINCT FROM NEW.id OR r.completed_windows+1<>NEW.ordinal OR (w->>'Offset')::bigint<>(r.plan_json#>>'{Selection,Offset}')::bigint+r.emitted_bytes THEN RAISE EXCEPTION 'noncontiguous outcome acknowledgement' USING ERRCODE='23514';END IF;
   UPDATE public.download_response SET completed_windows=completed_windows+1,emitted_bytes=emitted_bytes+emitted,active_window=NULL,closed=closed OR NOT success OR final OR n>=until_at WHERE id=r.id;
   IF s.generation=r.generation AND s.state NOT IN ('Completed','Cancelled','Expired','Denied','Failed') THEN
    IF n>=s.deadline OR n>=r.until_at THEN UPDATE public.artifact_download SET state='Expired' WHERE id=s.id;
    ELSIF NOT success OR final THEN UPDATE public.artifact_download SET state=CASE WHEN final AND success AND verified AND (r.plan_json->>'WholeFile')::boolean AND r.emitted_bytes+emitted=(r.plan_json#>>'{Selection,Length}')::bigint THEN 'Completed' ELSE 'Interrupted' END WHERE id=s.id;
    END IF;
   END IF;
  END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER download_window_guard BEFORE INSERT OR UPDATE OR DELETE ON download_window FOR EACH ROW EXECUTE FUNCTION guard_download_window();
REVOKE ALL ON FUNCTION guard_download_control_allocation() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_download_response() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_download_window() FROM PUBLIC;
-- +goose StatementEnd
