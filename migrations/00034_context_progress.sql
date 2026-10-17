-- +goose Up
-- Progress is a monotonic control projection, never execution/disclosure or
-- refund authority. The extra sentinel keeps revision exhaustion from blocking
-- privacy/deletion; public readers reject revisions above 1000000000.
ALTER TABLE context_capture ADD COLUMN progress_revision bigint NOT NULL DEFAULT 1
 CHECK(progress_revision BETWEEN 1 AND 1000000001);
ALTER TABLE context_capture ADD COLUMN deadline_observed_at timestamptz
 CHECK(deadline_observed_at IS NULL OR (isfinite(deadline_observed_at) AND deadline_observed_at>=deadline));
CREATE INDEX context_capture_deadline_observation ON context_capture(root_id,deadline,id)
 WHERE deadline_observed_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION guard_context_progress() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.progress_revision<>1 OR NEW.deadline_observed_at IS NOT NULL THEN
   RAISE EXCEPTION 'initial context progress mismatch' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.id,NEW.root_id,NEW.request_key,NEW.submission_digest,NEW.scope_digest,NEW.scope_json,NEW.expectation_json,NEW.pod_pin_json,NEW.attempt_id,NEW.permission_epoch,NEW.permission_sequence,NEW.identity_policy_uid,NEW.identity_policy_generation,NEW.identity_policy_digest,NEW.created_at,NEW.deadline)
 IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.request_key,OLD.submission_digest,OLD.scope_digest,OLD.scope_json,OLD.expectation_json,OLD.pod_pin_json,OLD.attempt_id,OLD.permission_epoch,OLD.permission_sequence,OLD.identity_policy_uid,OLD.identity_policy_generation,OLD.identity_policy_digest,OLD.created_at,OLD.deadline) THEN
  RAISE EXCEPTION 'immutable accepted context' USING ERRCODE='23514';
 END IF;
 IF NEW.progress_revision<>OLD.progress_revision AND
  (pg_trigger_depth()<2 OR NEW.progress_revision<>LEAST(OLD.progress_revision+1,1000000001)) THEN
  RAISE EXCEPTION 'context revision is source managed' USING ERRCODE='23514';
 END IF;
 IF NEW.deadline_observed_at IS DISTINCT FROM OLD.deadline_observed_at THEN
  IF OLD.deadline_observed_at IS NOT NULL OR NEW.deadline_observed_at IS NULL OR clock_timestamp()<OLD.deadline THEN
   RAISE EXCEPTION 'context deadline observation cannot rewind' USING ERRCODE='23514';
  END IF;
  NEW.deadline_observed_at:=clock_timestamp();
  NEW.progress_revision:=LEAST(OLD.progress_revision+1,1000000001);
 END IF;
 IF ROW(NEW.state,NEW.intent_acknowledged_at,NEW.intent_digest,NEW.intent_object_key,NEW.intent_object_version,NEW.intent_object_etag,NEW.intent_object_bytes,NEW.intent_object_sha256)
 IS DISTINCT FROM ROW(OLD.state,OLD.intent_acknowledged_at,OLD.intent_digest,OLD.intent_object_key,OLD.intent_object_version,OLD.intent_object_etag,OLD.intent_object_bytes,OLD.intent_object_sha256) THEN
  IF OLD.intent_acknowledged_at IS NOT NULL THEN
   RAISE EXCEPTION 'immutable context intent acknowledgement' USING ERRCODE='23514';
  END IF;
  NEW.progress_revision:=LEAST(OLD.progress_revision+1,1000000001);
 END IF;
 RETURN NEW;
END $$;

-- No arguments, no dynamic SQL, and only one narrowly fixed UPDATE. The owner
-- is the protected migration/table owner, never a runtime login. Runtime roles
-- cannot invoke/replace/attach this function or write progress_revision.
CREATE FUNCTION advance_context_progress() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_TABLE_SCHEMA<>'public' THEN
  RAISE EXCEPTION 'invalid context progress source' USING ERRCODE='23514';
 END IF;
 IF TG_RELID='public.custody_attempt'::regclass AND TG_OP='UPDATE' THEN
  IF ROW(NEW.state,NEW.copies_digest,NEW.effective_expires_at,NEW.effective_delete_by,NEW.retention_sequence,NEW.deleted_at)
   IS DISTINCT FROM ROW(OLD.state,OLD.copies_digest,OLD.effective_expires_at,OLD.effective_delete_by,OLD.retention_sequence,OLD.deleted_at) THEN
   UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE attempt_id=NEW.id;
  END IF;
 ELSIF TG_RELID='public.context_verification'::regclass AND TG_OP IN ('INSERT','UPDATE') THEN
  IF TG_OP='INSERT' OR NEW IS DISTINCT FROM OLD THEN
   UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE id=NEW.capture_id AND root_id=NEW.root_id;
  END IF;
 ELSIF TG_RELID='public.context_catalog'::regclass AND TG_OP='INSERT' THEN
  UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE id=NEW.capture_id AND root_id=NEW.root_id;
 ELSE
  RAISE EXCEPTION 'invalid context progress source' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_progress() FROM PUBLIC;
REVOKE ALL ON FUNCTION advance_context_progress() FROM PUBLIC;
CREATE TRIGGER context_progress_guard BEFORE INSERT OR UPDATE ON context_capture
 FOR EACH ROW EXECUTE FUNCTION guard_context_progress();
CREATE TRIGGER context_progress_from_custody AFTER UPDATE ON custody_attempt
 FOR EACH ROW EXECUTE FUNCTION advance_context_progress();
CREATE TRIGGER context_progress_from_verification AFTER INSERT OR UPDATE ON context_verification
 FOR EACH ROW EXECUTE FUNCTION advance_context_progress();
CREATE TRIGGER context_progress_from_catalog AFTER INSERT ON context_catalog
 FOR EACH ROW EXECUTE FUNCTION advance_context_progress();
