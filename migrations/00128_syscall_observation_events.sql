-- +goose Up
-- ADR-281: reserve syscall events and input bytes atomically from the same
-- approved ad hoc observation pool; existing packet callers spend zero events.
ALTER TABLE adhoc_observation_spend ADD COLUMN events_spent bigint NOT NULL DEFAULT 0 CHECK(events_spent>=0);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_adhoc_observation_spend() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.root_id<>OLD.root_id OR NEW.grant_id<>OLD.grant_id OR NEW.spent<OLD.spent OR NEW.events_spent<OLD.events_spent THEN
  RAISE EXCEPTION 'ad hoc observation spend is monotonic' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION spend_adhoc_observation(r uuid,g uuid,amount bigint,events bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE grant_row public.access_grant; byte_ceiling bigint; event_ceiling bigint; used public.adhoc_observation_spend;
BEGIN
 IF amount IS NULL OR events IS NULL OR amount<1 OR events<0 THEN RETURN false; END IF;
 SELECT * INTO grant_row FROM public.access_grant WHERE root_id=r AND id=g FOR SHARE;
 IF NOT FOUND OR grant_row.kind<>'adHocCapture' OR grant_row.decision IS DISTINCT FROM 'approved'
  OR grant_row.revoked_at IS NOT NULL OR grant_row.expires_at<=clock_timestamp() THEN RETURN false; END IF;
 byte_ceiling:=(convert_from(grant_row.scope,'UTF8')::jsonb#>>'{approval,observationLimits,maxObservedBytes}')::bigint;
 event_ceiling:=COALESCE((convert_from(grant_row.scope,'UTF8')::jsonb#>>'{approval,observationLimits,maxObservedEvents}')::bigint,0);
 IF byte_ceiling IS NULL OR byte_ceiling<1 OR event_ceiling<0 THEN RETURN false; END IF;
 INSERT INTO public.adhoc_observation_spend(root_id,grant_id,spent,events_spent) VALUES(r,g,0,0) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT used FROM public.adhoc_observation_spend WHERE root_id=r AND grant_id=g FOR UPDATE;
 -- The original grant lock prevents revision changes, not passage of time.
 IF grant_row.expires_at<=clock_timestamp() OR amount>byte_ceiling-used.spent OR events>event_ceiling-used.events_spent THEN RETURN false; END IF;
 UPDATE public.adhoc_observation_spend SET spent=spent+amount,events_spent=events_spent+events WHERE root_id=r AND grant_id=g;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION spend_adhoc_observation(uuid,uuid,bigint,bigint) FROM PUBLIC;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION spend_adhoc_observed_bytes(r uuid,g uuid,amount bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.spend_adhoc_observation(r,g,amount,0);
$$;
-- +goose StatementEnd

-- Argument sessions reuse the once-only source fence; packet v1 tuples retain
-- their old zero defaults and canonical encoding. No pool is renewable.
ALTER TABLE policy_acceptance ADD COLUMN observed_events_spent bigint NOT NULL DEFAULT 0 CHECK(observed_events_spent>=0 AND observed_events_spent<=COALESCE((record#>>'{Authority,Limits,MaxObservedEvents}')::bigint,0));
ALTER TABLE access_grant ADD COLUMN policy_observed_events_spent bigint NOT NULL DEFAULT 0 CHECK(policy_observed_events_spent>=0 AND policy_observed_events_spent<=COALESCE((policy_scope#>>'{Limits,MaxObservedEvents}')::bigint,0));
ALTER TABLE policy_observation_session
 ADD COLUMN argument_definition_digest bytea,
 ADD COLUMN event_credit bigint NOT NULL DEFAULT 0,
 ADD COLUMN max_events_per_second bigint NOT NULL DEFAULT 0,
 ADD COLUMN max_probe_bytes bigint NOT NULL DEFAULT 0,
 ADD COLUMN max_bytes_per_event bigint NOT NULL DEFAULT 0,
 ADD COLUMN max_tracked_threads bigint NOT NULL DEFAULT 0,
 ADD COLUMN capture_buffers boolean NOT NULL DEFAULT false,
 DROP CONSTRAINT policy_observation_session_accounting_rule_check,
 DROP CONSTRAINT policy_observation_session_duration_millis_check,
 DROP CONSTRAINT policy_observation_session_check;
ALTER TABLE policy_observation_session ADD CONSTRAINT policy_observation_argument_tuple CHECK(
 (accounting_rule=decode('4d3f2eea2ed280bd7017ea2398a4cde18d94daacbcc4c8741a98d52c56697453','hex') AND argument_definition_digest IS NULL AND event_credit=0 AND max_events_per_second=0
  AND max_probe_bytes=0 AND max_bytes_per_event=0 AND max_tracked_threads=0 AND NOT capture_buffers
  AND duration_millis BETWEEN 1000 AND 15000 AND session_until>started_at AND session_until<=started_at+interval '20 seconds')
 OR
 (accounting_rule=decode('833bafd01122a099b6a41751e9c545dccd925d54f94faabdfba9f8f9bcd7eef6','hex') AND argument_definition_digest IS NOT NULL AND octet_length(argument_definition_digest)=32
  AND event_credit BETWEEN 1 AND 1000000000 AND max_events_per_second BETWEEN 1 AND 100000
  AND max_probe_bytes IN (256,512) AND max_bytes_per_event BETWEEN 1 AND 4096
  AND (max_probe_bytes=256 OR max_bytes_per_event>=128) AND max_tracked_threads BETWEEN 1 AND 16384
  AND credit>=max_probe_bytes AND max_bytes_per_second>=max_probe_bytes
  AND duration_millis BETWEEN 1000 AND 60000 AND session_until>started_at
  AND session_until<=started_at+(duration_millis+10000)*interval '1 millisecond'));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_policy_collection_spend() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.executions_spent<OLD.executions_spent
  OR NEW.collected_bytes_spent<OLD.collected_bytes_spent
  OR NEW.observed_bytes_spent<OLD.observed_bytes_spent
  OR NEW.observed_events_spent<OLD.observed_events_spent THEN
  RAISE EXCEPTION 'policy collection spend never decreases' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_access_grant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 counters text[] := ARRAY['artifacts_spent','bytes_spent','operations_spent',
  'policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent','policy_observed_events_spent'];
 mutable text[] := ARRAY['decision','approver_issuer','approver_subject','approver_client','decision_reason','decision_acr','decision_auth_time','decided_at','decision_key','expires_at',
  'revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision','policy_not_after',
  'artifacts_spent','bytes_spent','operations_spent','policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent','policy_observed_events_spent'];
 spent boolean;
 before_row jsonb;
 after_row jsonb;
BEGIN
 -- Stored generated values are computed after BEFORE triggers. Compare the
 -- immutable source columns, never NEW's not-yet-computed generated fields.
 before_row := to_jsonb(OLD)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 after_row := to_jsonb(NEW)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 IF TG_OP='DELETE' OR (after_row-mutable)<>(before_row-mutable) THEN
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 spent := ROW(NEW.artifacts_spent,NEW.bytes_spent,NEW.operations_spent,NEW.policy_executions_spent,NEW.policy_bytes_spent,NEW.policy_observed_bytes_spent,NEW.policy_observed_events_spent)
   IS DISTINCT FROM ROW(OLD.artifacts_spent,OLD.bytes_spent,OLD.operations_spent,OLD.policy_executions_spent,OLD.policy_bytes_spent,OLD.policy_observed_bytes_spent,OLD.policy_observed_events_spent);
 IF NEW.artifacts_spent<OLD.artifacts_spent OR NEW.bytes_spent<OLD.bytes_spent OR NEW.operations_spent<OLD.operations_spent
  OR NEW.policy_executions_spent<OLD.policy_executions_spent OR NEW.policy_bytes_spent<OLD.policy_bytes_spent OR NEW.policy_observed_bytes_spent<OLD.policy_observed_bytes_spent OR NEW.policy_observed_events_spent<OLD.policy_observed_events_spent THEN
  RAISE EXCEPTION 'access grant spend never decreases' USING ERRCODE='23514';
 END IF;
 IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
  IF spent OR NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after
   OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1
   OR clock_timestamp()>=OLD.review_until OR (OLD.kind='policy' AND clock_timestamp()>=OLD.policy_not_after) THEN
   RAISE EXCEPTION 'access grant decision refused' USING ERRCODE='23514';
  END IF;
 ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
  IF spent OR NEW.revision<>OLD.revision+1 OR (after_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision'])<>(before_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision']) THEN
   RAISE EXCEPTION 'access grant revocation refused' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after THEN
  IF OLD.kind<>'policy' OR NEW.policy_not_after IS NULL OR NEW.policy_not_after>=OLD.policy_not_after
   OR (after_row-ARRAY['policy_not_after','expires_at'])<>(before_row-ARRAY['policy_not_after','expires_at'])
   OR NEW.expires_at IS DISTINCT FROM (CASE WHEN OLD.decision='approved' THEN NEW.policy_not_after ELSE NULL END) THEN
   RAISE EXCEPTION 'access grant deadline only shortens' USING ERRCODE='23514';
  END IF;
 ELSIF spent THEN
  IF OLD.decision IS DISTINCT FROM 'approved' OR OLD.revoked_at IS NOT NULL OR clock_timestamp()>=OLD.expires_at
   OR (after_row-counters)<>(before_row-counters) THEN
   RAISE EXCEPTION 'access grant pool is not usable' USING ERRCODE='23514';
  END IF;
 ELSE
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM adhoc_observation_spend WHERE events_spent<>0)
  OR EXISTS(SELECT 1 FROM policy_acceptance WHERE observed_events_spent<>0)
  OR EXISTS(SELECT 1 FROM access_grant WHERE policy_observed_events_spent<>0)
  OR EXISTS(SELECT 1 FROM policy_observation_session WHERE argument_definition_digest IS NOT NULL OR event_credit<>0 OR max_events_per_second<>0 OR max_probe_bytes<>0 OR max_bytes_per_event<>0 OR max_tracked_threads<>0 OR capture_buffers) THEN
  RAISE EXCEPTION 'retained syscall observation event spend prevents downgrade';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_policy_collection_spend() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.executions_spent<OLD.executions_spent
  OR NEW.collected_bytes_spent<OLD.collected_bytes_spent
  OR NEW.observed_bytes_spent<OLD.observed_bytes_spent THEN
  RAISE EXCEPTION 'policy collection spend never decreases' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_access_grant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 counters text[] := ARRAY['artifacts_spent','bytes_spent','operations_spent',
  'policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent'];
 mutable text[] := ARRAY['decision','approver_issuer','approver_subject','approver_client','decision_reason','decision_acr','decision_auth_time','decided_at','decision_key','expires_at',
  'revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision','policy_not_after',
  'artifacts_spent','bytes_spent','operations_spent','policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent'];
 spent boolean;
 before_row jsonb;
 after_row jsonb;
BEGIN
 -- Stored generated values are computed after BEFORE triggers. Compare the
 -- immutable source columns, never NEW's not-yet-computed generated fields.
 before_row := to_jsonb(OLD)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 after_row := to_jsonb(NEW)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 IF TG_OP='DELETE' OR (after_row-mutable)<>(before_row-mutable) THEN
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 spent := ROW(NEW.artifacts_spent,NEW.bytes_spent,NEW.operations_spent,NEW.policy_executions_spent,NEW.policy_bytes_spent,NEW.policy_observed_bytes_spent)
   IS DISTINCT FROM ROW(OLD.artifacts_spent,OLD.bytes_spent,OLD.operations_spent,OLD.policy_executions_spent,OLD.policy_bytes_spent,OLD.policy_observed_bytes_spent);
 IF NEW.artifacts_spent<OLD.artifacts_spent OR NEW.bytes_spent<OLD.bytes_spent OR NEW.operations_spent<OLD.operations_spent
  OR NEW.policy_executions_spent<OLD.policy_executions_spent OR NEW.policy_bytes_spent<OLD.policy_bytes_spent OR NEW.policy_observed_bytes_spent<OLD.policy_observed_bytes_spent THEN
  RAISE EXCEPTION 'access grant spend never decreases' USING ERRCODE='23514';
 END IF;
 IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
  IF spent OR NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after
   OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1
   OR clock_timestamp()>=OLD.review_until OR (OLD.kind='policy' AND clock_timestamp()>=OLD.policy_not_after) THEN
   RAISE EXCEPTION 'access grant decision refused' USING ERRCODE='23514';
  END IF;
 ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
  IF spent OR NEW.revision<>OLD.revision+1 OR (after_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision'])<>(before_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision']) THEN
   RAISE EXCEPTION 'access grant revocation refused' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after THEN
  IF OLD.kind<>'policy' OR NEW.policy_not_after IS NULL OR NEW.policy_not_after>=OLD.policy_not_after
   OR (after_row-ARRAY['policy_not_after','expires_at'])<>(before_row-ARRAY['policy_not_after','expires_at'])
   OR NEW.expires_at IS DISTINCT FROM (CASE WHEN OLD.decision='approved' THEN NEW.policy_not_after ELSE NULL END) THEN
   RAISE EXCEPTION 'access grant deadline only shortens' USING ERRCODE='23514';
  END IF;
 ELSIF spent THEN
  IF OLD.decision IS DISTINCT FROM 'approved' OR OLD.revoked_at IS NOT NULL OR clock_timestamp()>=OLD.expires_at
   OR (after_row-counters)<>(before_row-counters) THEN
   RAISE EXCEPTION 'access grant pool is not usable' USING ERRCODE='23514';
  END IF;
 ELSE
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE policy_observation_session DROP CONSTRAINT policy_observation_argument_tuple,
 DROP COLUMN argument_definition_digest, DROP COLUMN event_credit, DROP COLUMN max_events_per_second,
 DROP COLUMN max_probe_bytes, DROP COLUMN max_bytes_per_event, DROP COLUMN max_tracked_threads, DROP COLUMN capture_buffers,
 ADD CONSTRAINT policy_observation_session_accounting_rule_check CHECK(accounting_rule=decode('4d3f2eea2ed280bd7017ea2398a4cde18d94daacbcc4c8741a98d52c56697453','hex')),
 ADD CONSTRAINT policy_observation_session_duration_millis_check CHECK(duration_millis BETWEEN 1000 AND 15000),
 ADD CONSTRAINT policy_observation_session_check CHECK(session_until>started_at AND session_until<=started_at+interval '20 seconds');
ALTER TABLE policy_acceptance DROP COLUMN observed_events_spent;
ALTER TABLE access_grant DROP COLUMN policy_observed_events_spent;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION spend_adhoc_observed_bytes(r uuid,g uuid,amount bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE grant_row public.access_grant; ceiling bigint; used bigint;
BEGIN
 SELECT * INTO grant_row FROM public.access_grant WHERE root_id=r AND id=g FOR SHARE;
 IF NOT FOUND OR grant_row.kind<>'adHocCapture' OR grant_row.decision IS DISTINCT FROM 'approved'
  OR grant_row.revoked_at IS NOT NULL OR grant_row.expires_at<=clock_timestamp() OR amount<1 THEN
  RETURN false;
 END IF;
 ceiling:=(convert_from(grant_row.scope,'UTF8')::jsonb#>>'{approval,observationLimits,maxObservedBytes}')::bigint;
 IF ceiling IS NULL OR ceiling<1 THEN
  RETURN false;
 END IF;
 INSERT INTO public.adhoc_observation_spend(root_id,grant_id,spent) VALUES(r,g,0) ON CONFLICT DO NOTHING;
 SELECT spent INTO used FROM public.adhoc_observation_spend WHERE root_id=r AND grant_id=g FOR UPDATE;
 IF used+amount>ceiling THEN
  RETURN false;
 END IF;
 UPDATE public.adhoc_observation_spend SET spent=spent+amount WHERE root_id=r AND grant_id=g;
 RETURN true;
END $$;
-- +goose StatementEnd
DROP FUNCTION spend_adhoc_observation(uuid,uuid,bigint,bigint);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_adhoc_observation_spend() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.root_id<>OLD.root_id OR NEW.grant_id<>OLD.grant_id OR NEW.spent<OLD.spent THEN
  RAISE EXCEPTION 'ad hoc observation spend is monotonic' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE adhoc_observation_spend DROP COLUMN events_spent;
