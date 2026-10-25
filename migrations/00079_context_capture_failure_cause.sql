-- +goose Up
-- S-02 exit item 2: a capture that fails because its pinned Pod is gone or
-- Kubernetes denied the pod-status read records that cause, so UI and MCP show
-- TargetGone or Denied instead of a generic failure. Both are terminal like
-- captureFailed: no acquisition instant and no copies.
ALTER TABLE context_execution DROP CONSTRAINT context_execution_phase_check,
 ADD CONSTRAINT context_execution_phase_check CHECK(phase IN ('prepared','started','stored','captureFailed','targetGone','denied','storeUnconfirmed'));
-- context_execution_check is the not_after bound (it also names not_before);
-- the row-shape rule is the second unnamed check.
ALTER TABLE context_execution DROP CONSTRAINT context_execution_check1,
 ADD CONSTRAINT context_execution_check1 CHECK(COALESCE((phase='prepared' AND started_at IS NULL AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase='started' AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed') AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND isfinite(completed_at) AND completed_at>=started_at AND
 (phase IN ('captureFailed','targetGone','denied') AND acquired_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR acquired_at>=started_at AND acquired_at<not_after AND completed_at>=acquired_at AND
 (phase='stored' AND copies_json IS NOT NULL AND copies_digest IS NOT NULL OR phase='storeUnconfirmed' AND copies_json IS NULL AND copies_digest IS NULL))),false));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_execution() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
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
 IF OLD.phase='started' AND NEW.phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed') AND NEW.started_at=OLD.started_at AND NEW.completed_at<=clock_timestamp() THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'context execution cannot repeat or rewrite result' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
