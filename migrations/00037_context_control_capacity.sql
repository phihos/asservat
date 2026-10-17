-- +goose Up
-- Logical context-record capacity, not evidence storage or effect authority.
-- There is deliberately no release: terminal labels/time do not settle custody.
CREATE TABLE context_control_pool (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id),
 configured boolean NOT NULL DEFAULT false,
 paused boolean NOT NULL DEFAULT false,
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 valid_until timestamptz,
 full_limit bigint NOT NULL DEFAULT 0 CHECK(full_limit>=0),
 replay_limit bigint NOT NULL DEFAULT 0 CHECK(replay_limit>=0),
 backed_full bigint NOT NULL DEFAULT 0 CHECK(backed_full>=0),
 backed_replay bigint NOT NULL DEFAULT 0 CHECK(backed_replay>=0),
 CHECK(NOT configured OR (revision>0 AND valid_until IS NOT NULL AND isfinite(valid_until) AND backed_full<=full_limit AND backed_replay<=replay_limit)),
 CHECK(configured OR (revision=0 AND valid_until IS NULL AND full_limit=0 AND replay_limit=0))
);
CREATE TABLE context_control_account (
 root_id uuid NOT NULL REFERENCES context_control_pool(root_id),
 allocation_id uuid NOT NULL UNIQUE REFERENCES custody_allocation(id),
 configured boolean NOT NULL DEFAULT false,
 paused boolean NOT NULL DEFAULT false,
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 valid_until timestamptz,
 full_limit bigint NOT NULL DEFAULT 0 CHECK(full_limit>=0),
 replay_limit bigint NOT NULL DEFAULT 0 CHECK(replay_limit>=0),
 charged_full bigint NOT NULL DEFAULT 0 CHECK(charged_full>=0 AND charged_full<=full_limit),
 charged_replay bigint NOT NULL DEFAULT 0 CHECK(charged_replay>=0 AND charged_replay<=replay_limit),
 PRIMARY KEY(root_id,allocation_id),
 CHECK(NOT configured OR (revision>0 AND valid_until IS NOT NULL AND isfinite(valid_until))),
 CHECK(configured OR (revision=0 AND valid_until IS NULL))
);
CREATE TABLE context_control_charge (
 capture_id uuid PRIMARY KEY REFERENCES context_capture(id),
 root_id uuid NOT NULL, allocation_id uuid NOT NULL,
 FOREIGN KEY(capture_id,root_id) REFERENCES context_capture(id,root_id),
 FOREIGN KEY(root_id,allocation_id) REFERENCES context_control_account(root_id,allocation_id)
);
CREATE INDEX context_control_charge_account ON context_control_charge(root_id,allocation_id,capture_id);
CREATE INDEX artifact_download_by_artifact ON artifact_download(artifact_id);

-- Exclusive migration adoption includes ALL history. Unconfigured legacy pools
-- preserve old costs and cannot admit until explicit backing covers those costs.
INSERT INTO context_control_pool(root_id,backed_full,backed_replay)
 SELECT root_id,count(*),count(*) FROM context_capture GROUP BY root_id;
INSERT INTO context_control_account(root_id,allocation_id,full_limit,replay_limit,charged_full,charged_replay)
 SELECT c.root_id,a.allocation_id,count(*),count(*),count(*),count(*)
 FROM context_capture c JOIN custody_attempt a ON a.id=c.attempt_id GROUP BY c.root_id,a.allocation_id;
INSERT INTO context_control_charge(capture_id,root_id,allocation_id)
 SELECT c.id,c.root_id,a.allocation_id FROM context_capture c JOIN custody_attempt a ON a.id=c.attempt_id;

-- +goose StatementBegin
CREATE FUNCTION guard_context_control_pool() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'control pool retirement requires protocol' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.backed_full<>0 OR NEW.backed_replay<>0 OR (NEW.configured AND NEW.revision<>1) THEN RAISE EXCEPTION 'new pool cannot invent backing' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.root_id<>OLD.root_id THEN
  RAISE EXCEPTION 'immutable control backing' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.backed_full,NEW.backed_replay) IS DISTINCT FROM ROW(OLD.backed_full,OLD.backed_replay) AND pg_trigger_depth()<2 THEN
  RAISE EXCEPTION 'control backing is source managed' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.configured,NEW.paused,NEW.revision,NEW.valid_until,NEW.full_limit,NEW.replay_limit) IS DISTINCT FROM ROW(OLD.configured,OLD.paused,OLD.revision,OLD.valid_until,OLD.full_limit,OLD.replay_limit) AND
  (NOT NEW.configured OR NEW.revision<>OLD.revision+1 OR ROW(NEW.backed_full,NEW.backed_replay) IS DISTINCT FROM ROW(OLD.backed_full,OLD.backed_replay)) THEN
  RAISE EXCEPTION 'control pool configuration revision mismatch' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_context_control_account() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'control account retirement requires protocol' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NOT NEW.configured OR NEW.revision<>1 OR NEW.charged_full<>0 OR NEW.charged_replay<>0 THEN RAISE EXCEPTION 'new account requires zero charged configuration' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.root_id,NEW.allocation_id) IS DISTINCT FROM ROW(OLD.root_id,OLD.allocation_id) OR NEW.charged_full<OLD.charged_full OR NEW.charged_replay<OLD.charged_replay THEN
  RAISE EXCEPTION 'immutable control account or decreasing charge' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.charged_full,NEW.charged_replay) IS DISTINCT FROM ROW(OLD.charged_full,OLD.charged_replay) AND
  (pg_trigger_depth()<2 OR NEW.charged_full<>OLD.charged_full+1 OR NEW.charged_replay<>OLD.charged_replay+1) THEN
  RAISE EXCEPTION 'control charge is source managed' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.configured,NEW.paused,NEW.revision,NEW.valid_until,NEW.full_limit,NEW.replay_limit) IS DISTINCT FROM ROW(OLD.configured,OLD.paused,OLD.revision,OLD.valid_until,OLD.full_limit,OLD.replay_limit) AND
  (NOT NEW.configured OR NEW.revision<>OLD.revision+1 OR
   ROW(NEW.charged_full,NEW.charged_replay) IS DISTINCT FROM ROW(OLD.charged_full,OLD.charged_replay)) THEN
  RAISE EXCEPTION 'control account configuration revision mismatch' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- The only backing mutation: exact account configuration with monotonic revision.
-- Shrink releases only unspent backing; retained charges never decrease.
CREATE FUNCTION back_context_control_account() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE previous_full bigint:=0; previous_replay bigint:=0; pool public.context_control_pool;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_control_account'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'invalid control backing source' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.configured,NEW.paused,NEW.revision,NEW.valid_until,NEW.full_limit,NEW.replay_limit) IS NOT DISTINCT FROM ROW(OLD.configured,OLD.paused,OLD.revision,OLD.valid_until,OLD.full_limit,OLD.replay_limit) THEN RETURN NEW; END IF;
  previous_full:=OLD.full_limit; previous_replay:=OLD.replay_limit;
 END IF;
 SELECT * INTO STRICT pool FROM public.context_control_pool WHERE root_id=NEW.root_id FOR UPDATE;
 IF NOT pool.configured OR NOT NEW.configured OR clock_timestamp()>=pool.valid_until OR clock_timestamp()>=NEW.valid_until OR
  NOT EXISTS(SELECT 1 FROM public.context_storage_binding b JOIN public.custody_allocation a ON a.id=b.allocation_id
   WHERE b.root_id=NEW.root_id AND b.allocation_id=NEW.allocation_id AND a.service_class='context') THEN
  RAISE EXCEPTION 'control backing is unavailable' USING ERRCODE='23514';
 END IF;
 IF pool.backed_full<previous_full OR pool.backed_replay<previous_replay OR
  NEW.full_limit>pool.full_limit-(pool.backed_full-previous_full) OR NEW.replay_limit>pool.replay_limit-(pool.backed_replay-previous_replay) THEN
  RAISE EXCEPTION 'control backing exhausted' USING ERRCODE='23514';
 END IF;
 UPDATE public.context_control_pool SET backed_full=(backed_full-previous_full)+NEW.full_limit,backed_replay=(backed_replay-previous_replay)+NEW.replay_limit WHERE root_id=NEW.root_id;
 RETURN NEW;
END $$;
-- The only charge mutation. A separate deferred constraint below prevents a
-- capture writer omitting this row; runtime cannot UPDATE either counter.
CREATE FUNCTION reserve_context_control_charge() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.context_control_pool; account public.context_control_account;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_control_charge'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'invalid control charge source' USING ERRCODE='23514';
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'control charges cannot be removed or rewritten' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT pool FROM public.context_control_pool WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT account FROM public.context_control_account WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id FOR UPDATE;
 IF NOT pool.configured OR NOT account.configured OR pool.paused OR account.paused OR clock_timestamp()>=pool.valid_until OR clock_timestamp()>=account.valid_until OR
  account.charged_full>=account.full_limit OR account.charged_replay>=account.replay_limit OR
  NOT EXISTS(SELECT 1 FROM public.context_capture c JOIN public.custody_attempt a ON a.id=c.attempt_id
   JOIN public.context_storage_binding b ON b.root_id=c.root_id AND b.allocation_id=a.allocation_id
   WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id AND a.allocation_id=NEW.allocation_id) THEN
  RAISE EXCEPTION 'control charge unavailable' USING ERRCODE='23514';
 END IF;
 UPDATE public.context_control_account SET charged_full=charged_full+1,charged_replay=charged_replay+1 WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id;
 RETURN NEW;
END $$;
CREATE FUNCTION require_context_control_charge() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_capture'::regclass OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'invalid accepted control source' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.context_control_charge WHERE capture_id=NEW.id AND root_id=NEW.root_id) THEN
  RAISE EXCEPTION 'accepted context requires retained control charge' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_control_pool(),guard_context_control_account(),back_context_control_account(),reserve_context_control_charge(),require_context_control_charge() FROM PUBLIC;
CREATE TRIGGER context_control_pool_guard BEFORE INSERT OR UPDATE OR DELETE ON context_control_pool FOR EACH ROW EXECUTE FUNCTION guard_context_control_pool();
CREATE TRIGGER context_control_account_guard BEFORE INSERT OR UPDATE OR DELETE ON context_control_account FOR EACH ROW EXECUTE FUNCTION guard_context_control_account();
CREATE TRIGGER context_control_account_backing BEFORE INSERT OR UPDATE ON context_control_account FOR EACH ROW EXECUTE FUNCTION back_context_control_account();
CREATE TRIGGER context_control_charge_guard BEFORE INSERT OR UPDATE OR DELETE ON context_control_charge FOR EACH ROW EXECUTE FUNCTION reserve_context_control_charge();
CREATE CONSTRAINT TRIGGER context_control_capture_charge AFTER INSERT ON context_capture DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_context_control_charge();
-- No destructive down migration; replay identities and uncertain costs survive.
