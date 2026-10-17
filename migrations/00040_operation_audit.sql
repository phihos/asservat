-- +goose Up
-- Separate audit backing. One record reserves two <=64KiB immutable objects.
-- Normal activity cannot create accounts or spend the protected resolution lane.
CREATE TABLE operation_audit_pool (
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 lane text NOT NULL CHECK(lane IN ('normal','resolution')),
 account_version text NOT NULL CHECK(length(account_version) BETWEEN 1 AND 64),
 revision bigint NOT NULL CHECK(revision>0), paused boolean NOT NULL DEFAULT false,
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 account_limit bigint NOT NULL CHECK(account_limit BETWEEN 1 AND 1000000),
 records_per_account bigint NOT NULL CHECK(records_per_account BETWEEN 1 AND 1000000),
 accounts bigint NOT NULL DEFAULT 0 CHECK(accounts>=0 AND accounts<=account_limit),
 retained_seconds bigint NOT NULL CHECK(retained_seconds BETWEEN 60 AND 316224000),
 PRIMARY KEY(root_id,lane)
);
CREATE TABLE operation_audit_account (
 root_id uuid NOT NULL, lane text NOT NULL,
 principal_digest bytea NOT NULL CHECK(octet_length(principal_digest)=32),
 charged bigint NOT NULL DEFAULT 0 CHECK(charged>=0 AND charged<=1000000),
 PRIMARY KEY(root_id,lane,principal_digest),
 FOREIGN KEY(root_id,lane) REFERENCES operation_audit_pool(root_id,lane)
);
CREATE INDEX operation_audit_account_spend ON operation_audit_account(root_id,lane,charged DESC);
CREATE TABLE operation_audit (
 id uuid PRIMARY KEY, root_id uuid NOT NULL, lane text NOT NULL, issuer_epoch uuid NOT NULL,
 principal_digest bytea NOT NULL CHECK(octet_length(principal_digest)=32),
 intent jsonb NOT NULL CHECK(jsonb_typeof(intent)='object' AND octet_length(intent::text)<=8192),
 request_until timestamptz NOT NULL CHECK(isfinite(request_until)),
 write_until timestamptz NOT NULL CHECK(isfinite(write_until)),
 retain_until timestamptz NOT NULL CHECK(isfinite(retain_until)),
 intent_started boolean NOT NULL DEFAULT false,
 intent_receipt jsonb CHECK(intent_receipt IS NULL OR (jsonb_typeof(intent_receipt)='object' AND octet_length(intent_receipt::text)<=4096)),
 outcome jsonb CHECK(outcome IS NULL OR (jsonb_typeof(outcome)='object' AND octet_length(outcome::text)<=16384)),
 outcome_started boolean NOT NULL DEFAULT false,
 outcome_receipt jsonb CHECK(outcome_receipt IS NULL OR (jsonb_typeof(outcome_receipt)='object' AND octet_length(outcome_receipt::text)<=4096)),
 FOREIGN KEY(root_id,lane,principal_digest) REFERENCES operation_audit_account(root_id,lane,principal_digest),
 CHECK(request_until<=write_until AND write_until<retain_until),
 CHECK(intent_receipt IS NULL OR intent_started),
 CHECK(outcome IS NULL OR intent_receipt IS NOT NULL),
 CHECK(NOT outcome_started OR outcome IS NOT NULL),
 CHECK(outcome_receipt IS NULL OR outcome_started)
);
CREATE INDEX operation_audit_pending ON operation_audit(root_id,write_until,id) WHERE outcome_receipt IS NULL;

-- +goose StatementBegin
CREATE FUNCTION guard_operation_audit_pool() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'audit backing retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NEW.accounts<>0 THEN RAISE EXCEPTION 'invalid initial audit backing' USING ERRCODE='23514'; END IF;
 ELSE
  IF ROW(NEW.root_id,NEW.lane,NEW.account_version) IS DISTINCT FROM ROW(OLD.root_id,OLD.lane,OLD.account_version) THEN
   RAISE EXCEPTION 'immutable audit backing identity' USING ERRCODE='23514'; END IF;
  IF NEW.accounts<>OLD.accounts AND (pg_trigger_depth()<2 OR NEW.accounts<>OLD.accounts+1) THEN
   RAISE EXCEPTION 'audit accounts source managed' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.revision,NEW.paused,NEW.valid_until,NEW.account_limit,NEW.records_per_account,NEW.retained_seconds) IS DISTINCT FROM ROW(OLD.revision,OLD.paused,OLD.valid_until,OLD.account_limit,OLD.records_per_account,OLD.retained_seconds) AND
   (NEW.revision<>OLD.revision+1 OR NEW.accounts<>OLD.accounts) THEN RAISE EXCEPTION 'audit backing revision mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND charged>NEW.records_per_account) THEN
  RAISE EXCEPTION 'audit backing below retained spend' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_operation_audit_account() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'audit account source managed' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.charged<>0 THEN RAISE EXCEPTION 'invalid audit account charge' USING ERRCODE='23514'; END IF;
 ELSIF ROW(NEW.root_id,NEW.lane,NEW.principal_digest) IS DISTINCT FROM ROW(OLD.root_id,OLD.lane,OLD.principal_digest) OR NEW.charged<>OLD.charged+1 THEN
  RAISE EXCEPTION 'immutable audit account' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_operation_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.operation_audit_pool; a public.operation_audit_account; n timestamptz;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP='DELETE' THEN
  RAISE EXCEPTION 'invalid operation audit source' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT p FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
  n:=clock_timestamp();
  IF p.paused OR n>=p.valid_until OR n>=NEW.request_until OR n<(NEW.intent->>'CreatedAt')::timestamptz OR NEW.intent_started OR NEW.intent_receipt IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.outcome_started OR NEW.outcome_receipt IS NOT NULL OR
   NOT (NEW.intent ?& ARRAY['ID','RootID','MACVersion','AccountVersion','Name','CreatedAt','RequestUntil','WriteUntil','RetainUntil']) OR NEW.intent->>'Name' NOT IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','invalid_operation') OR
   (NEW.intent->>'ID')::uuid<>NEW.id OR (NEW.intent->>'RootID')::uuid<>NEW.root_id OR NEW.intent->>'AccountVersion'<>p.account_version OR
   NEW.request_until<>(NEW.intent->>'RequestUntil')::timestamptz OR NEW.write_until<>(NEW.intent->>'WriteUntil')::timestamptz OR NEW.retain_until<>(NEW.intent->>'RetainUntil')::timestamptz OR
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '5 seconds' OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
   NEW.retain_until>(NEW.intent->>'CreatedAt')::timestamptz+make_interval(secs=>p.retained_seconds::double precision) OR
   NEW.lane<>(CASE WHEN NEW.intent->>'Name'='resolve_capture_request' THEN 'resolution' ELSE 'normal' END) THEN
   RAISE EXCEPTION 'operation audit unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO a FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest FOR UPDATE;
  IF NOT FOUND THEN
   IF p.accounts>=p.account_limit THEN RAISE EXCEPTION 'audit accounts exhausted' USING ERRCODE='23514'; END IF;
   UPDATE public.operation_audit_pool SET accounts=accounts+1 WHERE root_id=NEW.root_id AND lane=NEW.lane;
   INSERT INTO public.operation_audit_account(root_id,lane,principal_digest) VALUES(NEW.root_id,NEW.lane,NEW.principal_digest) RETURNING * INTO a;
  END IF;
  IF a.charged>=p.records_per_account THEN RAISE EXCEPTION 'audit records exhausted' USING ERRCODE='23514'; END IF;
  UPDATE public.operation_audit_account SET charged=charged+1 WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.lane,NEW.issuer_epoch,NEW.principal_digest,NEW.intent,NEW.request_until,NEW.write_until,NEW.retain_until) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.lane,OLD.issuer_epoch,OLD.principal_digest,OLD.intent,OLD.request_until,OLD.write_until,OLD.retain_until) OR
   (OLD.intent_started AND NOT NEW.intent_started) OR (OLD.outcome_started AND NOT NEW.outcome_started) OR
   (OLD.intent_receipt IS NOT NULL AND NEW.intent_receipt IS DISTINCT FROM OLD.intent_receipt) OR
   (OLD.outcome IS NOT NULL AND NEW.outcome IS DISTINCT FROM OLD.outcome) OR
   (OLD.outcome_receipt IS NOT NULL AND NEW.outcome_receipt IS DISTINCT FROM OLD.outcome_receipt) THEN
   RAISE EXCEPTION 'immutable operation audit' USING ERRCODE='23514'; END IF;
  n:=clock_timestamp();
  IF n>=NEW.write_until OR (NOT OLD.intent_started AND NEW.intent_started AND n>=NEW.request_until) THEN
   RAISE EXCEPTION 'operation audit interval expired' USING ERRCODE='23514'; END IF;
  IF NEW.outcome IS NOT NULL AND NEW.outcome->'Intent' IS DISTINCT FROM NEW.intent THEN
   RAISE EXCEPTION 'outcome intent mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_operation_audit_pool(),guard_operation_audit_account(),guard_operation_audit() FROM PUBLIC;
CREATE TRIGGER operation_audit_pool_guard BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_pool FOR EACH ROW EXECUTE FUNCTION guard_operation_audit_pool();
CREATE TRIGGER operation_audit_account_guard BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_account FOR EACH ROW EXECUTE FUNCTION guard_operation_audit_account();
CREATE TRIGGER operation_audit_guard BEFORE INSERT OR UPDATE OR DELETE ON operation_audit FOR EACH ROW EXECUTE FUNCTION guard_operation_audit();
-- No release/DELETE: positive writer quiescence, backend purge and independently
-- audited checkpoints remain required before any retained budget can be restored.
