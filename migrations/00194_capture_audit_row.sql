-- +goose Up
-- ADR-330 D6/D8: a capture admission writes its audit_event row in the
-- admission transaction. The encrypted capture-intent audit (object pair,
-- acknowledgement, per-allocation backing) and the encrypted reason envelope
-- are removed. The reason is plain SQL data on the preview blueprint and the
-- accepted capture row. Generic operation_audit cleanup (capture_audit_root,
-- capture_audit_role_ok, capture_operation_* lifecycle views) stays until the
-- shared operation audit is dropped.

DROP TRIGGER IF EXISTS context_capture_audit_pair ON context_capture;
DROP TRIGGER IF EXISTS context_capture_private_audit_guard ON context_capture;
DROP TRIGGER IF EXISTS capture_reason_ref_guard ON context_capture;
DROP TRIGGER IF EXISTS operation_audit_capture_dependency ON operation_audit;
DROP TRIGGER IF EXISTS operation_audit_pool_00_capture_reserve ON operation_audit_pool;

DROP VIEW IF EXISTS capture_operation_intents;
DROP TABLE IF EXISTS capture_audit_binding;
DROP TABLE IF EXISTS capture_audit_allocation;

DROP FUNCTION IF EXISTS acknowledge_capture_pair(uuid,jsonb);
DROP FUNCTION IF EXISTS capture_audit_acknowledge(uuid,jsonb,text,jsonb,jsonb,jsonb);
DROP FUNCTION IF EXISTS capture_audit_journal(uuid,jsonb,text,jsonb);
DROP FUNCTION IF EXISTS claim_capture_reconciliation(uuid,jsonb,text);
DROP FUNCTION IF EXISTS read_capture_operation(uuid,uuid);
DROP FUNCTION IF EXISTS read_capture_reason(uuid,uuid);
DROP FUNCTION IF EXISTS reserve_capture_audit(uuid,uuid,jsonb,bytea,timestamptz);
DROP FUNCTION IF EXISTS lock_capture_audit_admission(uuid,uuid);
DROP FUNCTION IF EXISTS configure_capture_audit_backing(uuid,jsonb,jsonb,timestamptz,timestamptz);
DROP FUNCTION IF EXISTS capture_audit_current(uuid,uuid);
DROP FUNCTION IF EXISTS capture_audit_original_until(uuid,operation_audit,timestamptz);
DROP FUNCTION IF EXISTS capture_audit_receipts_current(operation_audit);
DROP FUNCTION IF EXISTS capture_audit_snapshot(operation_audit);
DROP FUNCTION IF EXISTS capture_audit_intent_limit(jsonb);
DROP FUNCTION IF EXISTS capture_audit_read_step(smallint,smallint,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz);
DROP FUNCTION IF EXISTS capture_audit_payload_matches(context_capture,jsonb);
DROP FUNCTION IF EXISTS capture_audit_payload_matches_without_reason(context_capture,jsonb);
DROP FUNCTION IF EXISTS capture_audit_actor_valid(jsonb);
DROP FUNCTION IF EXISTS capture_preview_reason_copied(context_preview);
DROP FUNCTION IF EXISTS capture_reason_preview_id(context_capture);
DROP FUNCTION IF EXISTS erase_copied_preview_reason();
DROP FUNCTION IF EXISTS guard_capture_reason_ref();
DROP FUNCTION IF EXISTS guard_context_capture_audit();
DROP FUNCTION IF EXISTS require_capture_audit_pair();
DROP FUNCTION IF EXISTS retire_capture_audit_binding();
DROP FUNCTION IF EXISTS preserve_capture_audit_guarantees();
DROP FUNCTION IF EXISTS guard_capture_audit_allocation();
DROP FUNCTION IF EXISTS guard_capture_audit_binding();

-- The progress guard no longer watches intent acknowledgement columns.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_progress() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.progress_revision<>1 OR NEW.deadline_observed_at IS NOT NULL THEN
   RAISE EXCEPTION 'initial context progress mismatch' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.id,NEW.root_id,NEW.preview_id,NEW.request_key,NEW.submission_digest,NEW.scope_digest,NEW.scope_json,NEW.expectation_json,NEW.pod_pin_json,NEW.attempt_id,NEW.permission_epoch,NEW.permission_sequence,NEW.identity_policy_uid,NEW.identity_policy_generation,NEW.identity_policy_digest,NEW.created_at,NEW.deadline,NEW.reason)
 IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.preview_id,OLD.request_key,OLD.submission_digest,OLD.scope_digest,OLD.scope_json,OLD.expectation_json,OLD.pod_pin_json,OLD.attempt_id,OLD.permission_epoch,OLD.permission_sequence,OLD.identity_policy_uid,OLD.identity_policy_generation,OLD.identity_policy_digest,OLD.created_at,OLD.deadline,OLD.reason) THEN
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
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- The preview reason lives in the blueprint; only closure columns change.
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
   IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN RAISE EXCEPTION 'context preview closure is immutable' USING ERRCODE='23514'; END IF;
  ELSIF NEW.closed_at IS NOT NULL THEN
   NEW.closed_at:=clock_timestamp();
  END IF;
  RETURN NEW;
 END IF;
 IF public.context_preview_read_until(OLD.root_id,OLD.id)>clock_timestamp() THEN
  RAISE EXCEPTION 'context preview is not expired' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
-- +goose StatementEnd

ALTER TABLE context_preview DROP CONSTRAINT IF EXISTS context_preview_reason_total_bytes;
ALTER TABLE context_preview DROP COLUMN IF EXISTS reason_envelope;

DROP INDEX IF EXISTS context_intent_pending;
ALTER TABLE context_capture DROP CONSTRAINT IF EXISTS context_intent_receipt_complete;
ALTER TABLE context_capture DROP CONSTRAINT IF EXISTS context_capture_state_check;
ALTER TABLE context_capture
 DROP COLUMN IF EXISTS state,
 DROP COLUMN IF EXISTS intent_acknowledged_at,
 DROP COLUMN IF EXISTS intent_digest,
 DROP COLUMN IF EXISTS intent_object_key,
 DROP COLUMN IF EXISTS intent_object_version,
 DROP COLUMN IF EXISTS intent_object_etag,
 DROP COLUMN IF EXISTS intent_object_bytes,
 DROP COLUMN IF EXISTS intent_object_sha256,
 DROP COLUMN IF EXISTS reason_ref,
 ADD COLUMN IF NOT EXISTS reason text CHECK (reason IS NULL OR char_length(reason) BETWEEN 1 AND 512);

