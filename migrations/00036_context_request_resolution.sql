-- +goose Up
-- Reviewed requests remain passive until the normal guarded admission commits.
-- Closing a draft prevents new admission; it never cancels accepted work.
ALTER TABLE context_capture ADD COLUMN preview_id uuid;
CREATE UNIQUE INDEX context_capture_preview ON context_capture(root_id,preview_id) WHERE preview_id IS NOT NULL;
CREATE INDEX context_capture_legacy_submission ON context_capture(root_id,submission_digest) WHERE preview_id IS NULL;
ALTER TABLE context_preview ADD COLUMN closed_at timestamptz;
ALTER TABLE context_preview ADD COLUMN closed_request_key bytea;
ALTER TABLE context_preview ADD COLUMN closed_submission_digest bytea;
ALTER TABLE context_preview ADD CONSTRAINT context_preview_close_complete CHECK (
 (closed_at IS NULL)=(closed_request_key IS NULL) AND
 (closed_at IS NULL)=(closed_submission_digest IS NULL) AND
 (closed_at IS NULL OR (isfinite(closed_at) AND closed_at>=created_at)) AND
 (closed_request_key IS NULL OR octet_length(closed_request_key)=32) AND
 (closed_submission_digest IS NULL OR octet_length(closed_submission_digest)=32)
);
CREATE TABLE context_preview_fence (
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 preview_id uuid NOT NULL,
 actor_key bytea NOT NULL CHECK(octet_length(actor_key)=32),
 principal_key bytea NOT NULL CHECK(octet_length(principal_key)=32),
 request_key bytea NOT NULL CHECK(octet_length(request_key)=32),
 submission_digest bytea NOT NULL CHECK(octet_length(submission_digest)=32),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(root_id,preview_id,actor_key),
 CHECK(isfinite(created_at) AND isfinite(expires_at)),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
);
CREATE INDEX context_preview_fence_expiry ON context_preview_fence(root_id,expires_at,preview_id);
CREATE INDEX context_preview_fence_principal ON context_preview_fence(root_id,principal_key,expires_at);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_preview_immutable() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.closed_at IS NOT NULL OR NEW.closed_request_key IS NOT NULL OR NEW.closed_submission_digest IS NOT NULL THEN
   RAISE EXCEPTION 'preview cannot begin closed' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 ELSIF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['closed_at','closed_request_key','closed_submission_digest']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['closed_at','closed_request_key','closed_submission_digest']) THEN
   RAISE EXCEPTION 'context preview is immutable' USING ERRCODE='23514';
  END IF;
  IF OLD.closed_at IS NOT NULL THEN
   IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'context preview closure is immutable' USING ERRCODE='23514'; END IF;
  ELSIF NEW.closed_at IS NOT NULL THEN
   NEW.closed_at:=clock_timestamp();
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.deadline>clock_timestamp() THEN
  RAISE EXCEPTION 'context preview is not expired' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
DROP TRIGGER context_preview_immutable ON context_preview;
CREATE TRIGGER context_preview_immutable BEFORE INSERT OR UPDATE OR DELETE ON context_preview
 FOR EACH ROW EXECUTE FUNCTION context_preview_immutable();
CREATE FUNCTION guard_context_preview_fence() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  NEW.created_at:=clock_timestamp();
  NEW.expires_at:=NEW.created_at+interval '5 minutes';
  RETURN NEW;
 ELSIF TG_OP='UPDATE' THEN
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'context preview fence is immutable' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF OLD.expires_at>clock_timestamp() THEN RAISE EXCEPTION 'context preview fence is not expired' USING ERRCODE='23514'; END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER context_preview_fence_guard BEFORE INSERT OR UPDATE OR DELETE ON context_preview_fence
 FOR EACH ROW EXECUTE FUNCTION guard_context_preview_fence();
CREATE OR REPLACE FUNCTION guard_context_progress() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.progress_revision<>1 OR NEW.deadline_observed_at IS NOT NULL THEN
   RAISE EXCEPTION 'initial context progress mismatch' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.id,NEW.root_id,NEW.preview_id,NEW.request_key,NEW.submission_digest,NEW.scope_digest,NEW.scope_json,NEW.expectation_json,NEW.pod_pin_json,NEW.attempt_id,NEW.permission_epoch,NEW.permission_sequence,NEW.identity_policy_uid,NEW.identity_policy_generation,NEW.identity_policy_digest,NEW.created_at,NEW.deadline)
 IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.preview_id,OLD.request_key,OLD.submission_digest,OLD.scope_digest,OLD.scope_json,OLD.expectation_json,OLD.pod_pin_json,OLD.attempt_id,OLD.permission_epoch,OLD.permission_sequence,OLD.identity_policy_uid,OLD.identity_policy_generation,OLD.identity_policy_digest,OLD.created_at,OLD.deadline) THEN
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

REVOKE ALL ON FUNCTION context_preview_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_context_preview_fence() FROM PUBLIC;
-- +goose StatementEnd
