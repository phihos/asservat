-- +goose Up
-- One immutable execution identity per already admitted capture. This journal
-- cannot create another storage reservation or renew a human request.
CREATE TABLE context_execution (
 capture_id uuid PRIMARY KEY REFERENCES context_capture(id),
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 FOREIGN KEY(capture_id,root_id) REFERENCES context_capture(id,root_id),
 attempt_id uuid NOT NULL UNIQUE REFERENCES custody_attempt(id),
 binding_json bytea NOT NULL CHECK(octet_length(binding_json) BETWEEN 1 AND 8192),
 process_json bytea NOT NULL CHECK(octet_length(process_json) BETWEEN 1 AND 4096),
 expectation_digest bytea NOT NULL CHECK(octet_length(expectation_digest)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 not_before timestamptz NOT NULL CHECK(isfinite(not_before)),
 not_after timestamptz NOT NULL CHECK(isfinite(not_after) AND not_after>not_before AND not_after<=not_before+interval '5 seconds'),
 object_uid uuid,
 phase text NOT NULL DEFAULT 'prepared' CHECK(phase IN ('prepared','started','stored','captureFailed','storeUnconfirmed')),
 started_at timestamptz,
 acquired_at timestamptz,
 completed_at timestamptz,
 copies_json bytea CHECK(copies_json IS NULL OR octet_length(copies_json) BETWEEN 1 AND 16384),
 copies_digest bytea CHECK(copies_digest IS NULL OR octet_length(copies_digest)=32),
 CHECK(COALESCE((phase='prepared' AND started_at IS NULL AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase='started' AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase IN ('stored','captureFailed','storeUnconfirmed') AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND isfinite(completed_at) AND completed_at>=started_at AND
 (phase='captureFailed' AND acquired_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR acquired_at>=started_at AND acquired_at<not_after AND completed_at>=acquired_at AND
 (phase='stored' AND copies_json IS NOT NULL AND copies_digest IS NOT NULL OR phase='storeUnconfirmed' AND copies_json IS NULL AND copies_digest IS NULL))),false))
);
-- +goose StatementBegin
CREATE FUNCTION guard_context_execution() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'context execution deletion requires retention protocol' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.phase<>'prepared' OR NEW.object_uid IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR clock_timestamp()>=NEW.not_after THEN
   RAISE EXCEPTION 'invalid first context preparation' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.capture_id,NEW.root_id,NEW.attempt_id,NEW.binding_json,NEW.process_json,NEW.expectation_digest,NEW.created_at,NEW.not_before,NEW.not_after)
 IS DISTINCT FROM ROW(OLD.capture_id,OLD.root_id,OLD.attempt_id,OLD.binding_json,OLD.process_json,OLD.expectation_digest,OLD.created_at,OLD.not_before,OLD.not_after) THEN
  RAISE EXCEPTION 'immutable context execution identity' USING ERRCODE='23514';
 END IF;
 IF OLD.object_uid IS NOT NULL AND NEW.object_uid IS DISTINCT FROM OLD.object_uid OR OLD.object_uid IS NULL AND NEW.object_uid IS NOT NULL AND (OLD.phase<>'prepared' OR NEW.phase<>'prepared' OR clock_timestamp()>=OLD.not_after) THEN
  RAISE EXCEPTION 'immutable context start object' USING ERRCODE='23514';
 END IF;
 IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF OLD.phase='prepared' AND NEW.phase='prepared' AND OLD.object_uid IS NULL AND NEW.object_uid IS NOT NULL THEN RETURN NEW; END IF;
 IF OLD.phase='prepared' AND NEW.phase='started' AND OLD.object_uid IS NOT NULL AND NEW.started_at<=clock_timestamp() AND clock_timestamp()<OLD.not_after THEN RETURN NEW; END IF;
 IF OLD.phase='started' AND NEW.phase IN ('stored','captureFailed','storeUnconfirmed') AND NEW.started_at=OLD.started_at AND NEW.completed_at<=clock_timestamp() THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'context execution cannot repeat or rewrite result' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_execution() FROM PUBLIC;
CREATE TRIGGER context_execution_guard BEFORE INSERT OR UPDATE OR DELETE ON context_execution FOR EACH ROW EXECUTE FUNCTION guard_context_execution();

-- Same fixed source-specific update as migration34; runtime cannot attach it to
-- arbitrary relations, execute it directly, or write capture progress revisions.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_context_progress() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_TABLE_SCHEMA<>'public' THEN RAISE EXCEPTION 'invalid context progress source' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.custody_attempt'::regclass AND TG_OP='UPDATE' THEN
  IF ROW(NEW.state,NEW.copies_digest,NEW.effective_expires_at,NEW.effective_delete_by,NEW.retention_sequence,NEW.deleted_at) IS DISTINCT FROM ROW(OLD.state,OLD.copies_digest,OLD.effective_expires_at,OLD.effective_delete_by,OLD.retention_sequence,OLD.deleted_at) THEN
   UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE attempt_id=NEW.id;
  END IF;
 ELSIF TG_RELID='public.context_verification'::regclass AND TG_OP IN ('INSERT','UPDATE') THEN
  IF TG_OP='INSERT' OR NEW IS DISTINCT FROM OLD THEN UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE id=NEW.capture_id AND root_id=NEW.root_id; END IF;
 ELSIF TG_RELID='public.context_catalog'::regclass AND TG_OP='INSERT' THEN
  UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE id=NEW.capture_id AND root_id=NEW.root_id;
 ELSIF TG_RELID='public.context_execution'::regclass AND TG_OP IN ('INSERT','UPDATE') THEN
  IF TG_OP='INSERT' OR NEW IS DISTINCT FROM OLD THEN UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE id=NEW.capture_id AND root_id=NEW.root_id; END IF;
 ELSE RAISE EXCEPTION 'invalid context progress source' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION advance_context_progress() FROM PUBLIC;
CREATE TRIGGER context_progress_from_execution AFTER INSERT OR UPDATE ON context_execution FOR EACH ROW EXECUTE FUNCTION advance_context_progress();
