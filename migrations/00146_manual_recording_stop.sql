-- +goose Up
-- ADR-313: Stop applies to every finite manual recording (packet metadata,
-- raw packets, HTTP headers, syscall metadata and arguments), not only to
-- syscall arguments. The request fence, immutable joined completion and
-- joined-execution checks are unchanged; only the accepted expectation set
-- for a new request widens from the argument recording to any Recording.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_snapshot_cancel() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.snapshot_cancel_key IS NOT NULL THEN RAISE EXCEPTION 'cancellation follows committed acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.snapshot_cancel_key,NEW.snapshot_cancel_actor,NEW.snapshot_cancel_requested_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_key,OLD.snapshot_cancel_actor,OLD.snapshot_cancel_requested_at) THEN
  IF OLD.snapshot_cancel_key IS NOT NULL OR NEW.snapshot_cancel_key IS NULL OR (jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Snapshot') IS DISTINCT FROM 'object' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Profile') IS DISTINCT FROM 'object' AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='processes' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='metadata' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Processes')='object',false) AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='logs' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Logs')='object',false) AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Recording') IS DISTINCT FROM 'object') THEN RAISE EXCEPTION 'immutable cancellation request' USING ERRCODE='23514';END IF;
  NEW.snapshot_cancel_requested_at:=clock_timestamp();
 END IF;
 IF ROW(NEW.snapshot_cancel_joined_at,NEW.snapshot_cancel_proof,NEW.snapshot_cancel_proof_digest) IS DISTINCT FROM ROW(OLD.snapshot_cancel_joined_at,OLD.snapshot_cancel_proof,OLD.snapshot_cancel_proof_digest) THEN
  IF OLD.snapshot_cancel_joined_at IS NOT NULL OR NEW.snapshot_cancel_joined_at IS NULL OR NEW.snapshot_cancel_joined_at>clock_timestamp() THEN RAISE EXCEPTION 'immutable cancellation completion' USING ERRCODE='23514';END IF;
  IF NEW.snapshot_cancel_proof IS NULL THEN
   IF EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND started_at IS NOT NULL) THEN RAISE EXCEPTION 'started cancellation needs joined proof' USING ERRCODE='23514';END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND phase='cancelled') THEN RAISE EXCEPTION 'cancellation lacks joined execution' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Restores the schema-145 rule for new requests only; recorded requests and
-- joined proofs stay immutable.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_snapshot_cancel() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.snapshot_cancel_key IS NOT NULL THEN RAISE EXCEPTION 'cancellation follows committed acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.snapshot_cancel_key,NEW.snapshot_cancel_actor,NEW.snapshot_cancel_requested_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_key,OLD.snapshot_cancel_actor,OLD.snapshot_cancel_requested_at) THEN
  IF OLD.snapshot_cancel_key IS NOT NULL OR NEW.snapshot_cancel_key IS NULL OR (jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Snapshot') IS DISTINCT FROM 'object' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Profile') IS DISTINCT FROM 'object' AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='processes' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='metadata' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Processes')='object',false) AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='logs' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Logs')='object',false) AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='syscallArguments' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Kind}'='syscallTrace' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb#>'{Recording,Arguments}')='object',false)) THEN RAISE EXCEPTION 'immutable cancellation request' USING ERRCODE='23514';END IF;
  NEW.snapshot_cancel_requested_at:=clock_timestamp();
 END IF;
 IF ROW(NEW.snapshot_cancel_joined_at,NEW.snapshot_cancel_proof,NEW.snapshot_cancel_proof_digest) IS DISTINCT FROM ROW(OLD.snapshot_cancel_joined_at,OLD.snapshot_cancel_proof,OLD.snapshot_cancel_proof_digest) THEN
  IF OLD.snapshot_cancel_joined_at IS NOT NULL OR NEW.snapshot_cancel_joined_at IS NULL OR NEW.snapshot_cancel_joined_at>clock_timestamp() THEN RAISE EXCEPTION 'immutable cancellation completion' USING ERRCODE='23514';END IF;
  IF NEW.snapshot_cancel_proof IS NULL THEN
   IF EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND started_at IS NOT NULL) THEN RAISE EXCEPTION 'started cancellation needs joined proof' USING ERRCODE='23514';END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND phase='cancelled') THEN RAISE EXCEPTION 'cancellation lacks joined execution' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
