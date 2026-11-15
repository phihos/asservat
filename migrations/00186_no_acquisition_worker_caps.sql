-- +goose Up
-- Acquisition workers have no installation, workload or principal count cap
-- (ADR-335 D9). The capacity concurrency limit bounds expensive work. The
-- principal key and index on download_worker only served that count.
-- No Down: IF EXISTS and CREATE OR REPLACE keep a re-Up after a downgrade
-- probe working, as in 00183.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_worker() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.session_id,NEW.query_id,NEW.root_id,NEW.installation_id,NEW.allocation_id,NEW.query_allocation_id,NEW.baseline_query_allocation_id,NEW.generation,NEW.intent_json,NEW.run_until)
 IS DISTINCT FROM ROW(OLD.id,OLD.session_id,OLD.query_id,OLD.root_id,OLD.installation_id,OLD.allocation_id,OLD.query_allocation_id,OLD.baseline_query_allocation_id,OLD.generation,OLD.intent_json,OLD.run_until)
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json)
 OR (OLD.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at)
 OR (OLD.job_json IS NOT NULL AND NEW.job_json IS DISTINCT FROM OLD.job_json)
 OR (OLD.binding_json IS NOT NULL AND NEW.binding_json IS DISTINCT FROM OLD.binding_json)
 OR (OLD.termination_json IS NOT NULL AND NEW.termination_json IS DISTINCT FROM OLD.termination_json)
 OR (OLD.retired_proof_json IS NOT NULL AND NEW.retired_proof_json IS DISTINCT FROM OLD.retired_proof_json)
 OR (OLD.abandoned_at IS NOT NULL AND NEW.abandoned_at IS DISTINCT FROM OLD.abandoned_at)
 OR (NEW.abandoned_at IS NOT NULL AND clock_timestamp()<NEW.run_until) THEN
  RAISE EXCEPTION 'acquisition worker identity and consumed transitions are immutable';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP INDEX IF EXISTS download_worker_capacity;
ALTER TABLE download_worker DROP COLUMN IF EXISTS principal_key;
