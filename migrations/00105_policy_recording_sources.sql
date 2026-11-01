-- +goose Up
-- Ordinary source-purpose current state. This is not a capture, occurrence,
-- evidence reservation or audit object. Quiet leaves are not persisted per tick.
CREATE TABLE policy_recording_source (
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 id uuid NOT NULL,
 fence uuid NOT NULL,
 policy_uid text NOT NULL CHECK(octet_length(policy_uid) BETWEEN 1 AND 128),
 acceptance_id uuid NOT NULL,
 action_id text NOT NULL CHECK(octet_length(action_id) BETWEEN 1 AND 128),
 cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_uid text NOT NULL CHECK(octet_length(workload_uid) BETWEEN 1 AND 64),
 pod_uid text NOT NULL CHECK(octet_length(pod_uid) BETWEEN 1 AND 64),
 allocation_id uuid NOT NULL,
 binding_json jsonb NOT NULL CHECK(jsonb_typeof(binding_json)='object' AND octet_length(binding_json::text) BETWEEN 2 AND 8192),
 started_at timestamptz NOT NULL,
 hard_until timestamptz NOT NULL,
 start_by timestamptz NOT NULL,
 initial_leaf_until timestamptz NOT NULL,
 initial_credit bigint NOT NULL CHECK(initial_credit>0),
 credit bigint NOT NULL CHECK(credit>=initial_credit),
 bytes_per_second bigint NOT NULL CHECK(bytes_per_second BETWEEN 1 AND 10737418240),
 ended_at timestamptz,
 slot_released_at timestamptz,
 PRIMARY KEY(root_id,id),
 FOREIGN KEY(acceptance_id) REFERENCES policy_acceptance(id),
 FOREIGN KEY(root_id,allocation_id) REFERENCES context_control_account(root_id,allocation_id),
 CHECK(isfinite(started_at) AND isfinite(hard_until) AND isfinite(start_by) AND hard_until>started_at AND start_by>started_at AND start_by<=started_at+interval '5 seconds' AND start_by<=hard_until),
 CHECK(isfinite(initial_leaf_until) AND initial_leaf_until>started_at AND initial_leaf_until<=started_at+interval '30 seconds' AND initial_leaf_until<=hard_until),
 CHECK(ended_at IS NULL OR (isfinite(ended_at) AND ended_at>=started_at)),
 CHECK(slot_released_at IS NULL OR (ended_at IS NOT NULL AND isfinite(slot_released_at) AND slot_released_at>=ended_at+interval '30 seconds'))
);
-- The logical slot crosses acceptance changes. Neither an old initial leaf nor
-- an unknown ACK frees it while a quietly renewed source can remain live.
CREATE UNIQUE INDEX policy_recording_source_slot ON policy_recording_source(root_id,policy_uid,action_id,pod_uid) WHERE slot_released_at IS NULL;
CREATE INDEX policy_recording_source_ended ON policy_recording_source(root_id,ended_at,id) WHERE ended_at IS NOT NULL AND slot_released_at IS NULL;
CREATE INDEX policy_recording_source_account ON policy_recording_source(root_id,allocation_id) WHERE slot_released_at IS NULL;
REVOKE ALL ON policy_recording_source FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_policy_recording_source() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'source retirement requires qualified retained metadata protocol' USING ERRCODE='23514';
 ELSIF TG_OP='UPDATE' THEN
  -- Terminal/quarantine clocks belong to the row-owning database operation,
  -- never to a caller-provided timestamp or pre-lock SQL projection.
  IF OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL THEN NEW.ended_at:=clock_timestamp(); END IF;
  IF OLD.slot_released_at IS NULL AND NEW.slot_released_at IS NOT NULL THEN NEW.slot_released_at:=clock_timestamp(); END IF;
  IF (to_jsonb(NEW)-ARRAY['credit','ended_at','slot_released_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['credit','ended_at','slot_released_at']) OR
   NEW.credit<OLD.credit OR (OLD.ended_at IS NOT NULL AND (NEW.credit<>OLD.credit OR NEW.ended_at IS DISTINCT FROM OLD.ended_at)) OR
   (OLD.slot_released_at IS NOT NULL AND NEW.slot_released_at IS DISTINCT FROM OLD.slot_released_at) THEN
   RAISE EXCEPTION 'immutable source binding or decreasing/terminal credit' USING ERRCODE='23514';
  END IF;
  IF NEW.credit<>OLD.credit AND (OLD.ended_at IS NOT NULL OR clock_timestamp()>=OLD.hard_until) THEN
   RAISE EXCEPTION 'ended source cannot gain credit' USING ERRCODE='23514';
  END IF;
  IF NEW.slot_released_at IS NOT NULL AND NEW.slot_released_at>clock_timestamp() THEN
   RAISE EXCEPTION 'source slot release cannot anticipate closure' USING ERRCODE='23514';
  END IF;
 ELSE
  IF NEW.ended_at IS NOT NULL OR NEW.slot_released_at IS NOT NULL OR clock_timestamp()<NEW.started_at OR clock_timestamp()>=NEW.start_by OR
   NOT EXISTS(SELECT 1 FROM public.policy_acceptance a WHERE a.id=NEW.acceptance_id AND a.root_id=NEW.root_id AND a.policy_uid=NEW.policy_uid AND a.acknowledged_at IS NOT NULL) THEN
   RAISE EXCEPTION 'source first start interval unavailable' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;

-- One existing full/replay control unit pays for this genuine source record.
-- Its retained identity is separate from capture-FK-only context_control_charge.
-- No release of these monotonic counters is introduced.
CREATE FUNCTION reserve_policy_recording_source() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.context_control_pool; account public.context_control_account;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.policy_recording_source'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'invalid source control charge' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT pool FROM public.context_control_pool WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT account FROM public.context_control_account WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id FOR UPDATE;
 IF NOT pool.configured OR NOT account.configured OR pool.paused OR account.paused OR clock_timestamp()>=pool.valid_until OR clock_timestamp()>=account.valid_until OR
  account.charged_full>=account.full_limit OR account.charged_replay>=account.replay_limit OR
  NOT EXISTS(SELECT 1 FROM public.context_storage_binding b WHERE b.root_id=NEW.root_id AND b.allocation_id=NEW.allocation_id AND b.cluster_id=NEW.cluster_id AND b.namespace_uid=NEW.namespace_uid AND b.workload_uid=NEW.workload_uid) THEN
  RAISE EXCEPTION 'source control backing unavailable' USING ERRCODE='23514';
 END IF;
 UPDATE public.context_control_account SET charged_full=charged_full+1,charged_replay=charged_replay+1 WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_policy_recording_source(),reserve_policy_recording_source() FROM PUBLIC;
CREATE TRIGGER policy_recording_source_guard BEFORE INSERT OR UPDATE OR DELETE ON policy_recording_source FOR EACH ROW EXECUTE FUNCTION guard_policy_recording_source();
CREATE TRIGGER policy_recording_source_backing BEFORE INSERT ON policy_recording_source FOR EACH ROW EXECUTE FUNCTION reserve_policy_recording_source();

-- +goose Down
-- Conservatively refuse rollback after any source identity/spend exists.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM policy_recording_source) THEN RAISE EXCEPTION 'retained source state prevents downgrade' USING ERRCODE='23514'; END IF;
END $$;
-- +goose StatementEnd
DROP TABLE policy_recording_source;
DROP FUNCTION guard_policy_recording_source(),reserve_policy_recording_source();
