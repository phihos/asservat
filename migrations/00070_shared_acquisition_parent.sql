-- +goose Up
-- ADR-219: one physical acquisition lifecycle with two closed parent kinds.
-- Existing download IDs, immutable JSON/audit records and foreign keys remain.
ALTER TABLE download_worker ALTER COLUMN session_id DROP NOT NULL;
ALTER TABLE download_worker ALTER COLUMN allocation_id DROP NOT NULL;
ALTER TABLE download_worker ADD COLUMN query_id uuid REFERENCES context_query(id);
ALTER TABLE download_worker ADD COLUMN query_allocation_id uuid REFERENCES context_query_allocation(id);
-- Only a never-claimed, expired query reservation can close without a Job.
-- This is proof that no create permission existed, not a refund on expiry.
ALTER TABLE download_worker ADD COLUMN abandoned_at timestamptz;
ALTER TABLE download_worker ADD CONSTRAINT query_unclaimed_abandoned CHECK (
 abandoned_at IS NULL OR (query_id IS NOT NULL AND abandoned_at>=run_until AND
 claimed_at IS NULL AND job_json IS NULL AND binding_json IS NULL AND
 termination_json IS NULL AND retired_proof_json IS NULL)
);
ALTER TABLE download_worker ADD CONSTRAINT acquisition_parent_exact CHECK (
 (session_id IS NOT NULL AND allocation_id IS NOT NULL AND query_id IS NULL AND query_allocation_id IS NULL)
 OR (session_id IS NULL AND allocation_id IS NULL AND query_id IS NOT NULL AND query_allocation_id IS NOT NULL AND generation=1)
);
CREATE UNIQUE INDEX one_query_acquisition_worker ON download_worker(query_id) WHERE query_id IS NOT NULL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_worker() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.session_id,NEW.query_id,NEW.root_id,NEW.installation_id,NEW.allocation_id,NEW.query_allocation_id,NEW.principal_key,NEW.generation,NEW.intent_json,NEW.run_until)
 IS DISTINCT FROM ROW(OLD.id,OLD.session_id,OLD.query_id,OLD.root_id,OLD.installation_id,OLD.allocation_id,OLD.query_allocation_id,OLD.principal_key,OLD.generation,OLD.intent_json,OLD.run_until)
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
END; $$;
-- +goose StatementEnd
-- No destructive down, rewritten audit identity or expiry-based capacity refund.

-- The original query batch already pays for the one regional read. Its exact
-- private operation and positive join live here, not in a fake download row.
ALTER TABLE context_query_batch ADD COLUMN native_operation jsonb;
ALTER TABLE context_query_batch ADD COLUMN native_authority jsonb;
ALTER TABLE context_query_batch ADD COLUMN native_closed boolean NOT NULL DEFAULT false;
ALTER TABLE context_query_batch ADD CONSTRAINT query_native_pair CHECK (
 (native_operation IS NULL AND native_authority IS NULL AND NOT native_closed)
 OR COALESCE((jsonb_typeof(native_operation)='object' AND octet_length(native_operation::text) BETWEEN 2 AND 16384
 AND jsonb_typeof(native_authority)='object' AND octet_length(native_authority::text) BETWEEN 2 AND 65536),false)
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_query_child() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE q public.context_query; n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query child history remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT q FROM public.context_query WHERE id=NEW.query_id FOR UPDATE;
 n:=clock_timestamp();
 IF TG_TABLE_NAME='context_query_batch' AND TG_OP='UPDATE' THEN
  IF ROW(NEW.native_operation,NEW.native_authority,NEW.native_closed) IS DISTINCT FROM ROW(OLD.native_operation,OLD.native_authority,OLD.native_closed) THEN
   IF (to_jsonb(NEW)-ARRAY['native_operation','native_authority','native_closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['native_operation','native_authority','native_closed']) OR
    OLD.closed OR OLD.native_closed OR q.active_batch IS DISTINCT FROM NEW.id OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') THEN
    RAISE EXCEPTION 'query native operation unavailable' USING ERRCODE='23514';
   END IF;
   IF OLD.native_operation IS NULL THEN
    IF NEW.native_closed OR NOT public.context_query_complete_object(NEW.native_operation,ARRAY['Path','Processing','Reference','Kind','HubPodUID','HubProcessEpoch','WorkerPodUID','WorkerPublicKey','SourceVersion','ParentID','Generation','StartedAt','Until']) OR
     NEW.native_operation->>'Kind' IS DISTINCT FROM 'read-approved-context' OR
     NEW.native_operation->'Reference'->>'QueryID' IS DISTINCT FROM q.id::text OR
     COALESCE(NEW.native_operation->'Reference'->>'SessionID','')<>'' OR
     NEW.native_operation->'Reference'->>'WorkerID' IS DISTINCT FROM q.worker_id::text OR
     NEW.native_operation->'Reference'->>'OperationID' IS DISTINCT FROM NEW.id::text OR
     (NEW.native_operation->'Reference'->>'Fence')::bigint IS DISTINCT FROM NEW.generation OR
     NEW.native_operation->>'ParentID' IS DISTINCT FROM NEW.id::text OR
     (NEW.native_operation->>'Generation')::smallint IS DISTINCT FROM NEW.generation OR
     (NEW.native_operation->>'StartedAt')::timestamptz>n OR
     n>=(NEW.native_operation->>'Until')::timestamptz OR
     (NEW.native_operation->>'Until')::timestamptz>(NEW.batch->>'Until')::timestamptz OR
     NEW.native_authority->'Scope' IS DISTINCT FROM q.query->'Scope' THEN
     RAISE EXCEPTION 'query native identity mismatch' USING ERRCODE='23514';
    END IF;
   ELSIF NOT NEW.native_closed OR NEW.native_operation IS DISTINCT FROM OLD.native_operation OR NEW.native_authority IS DISTINCT FROM OLD.native_authority THEN
    RAISE EXCEPTION 'query native identity immutable' USING ERRCODE='23514';
   END IF;
   UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
   RETURN NEW;
  END IF;
 END IF;
 IF TG_TABLE_NAME='context_query_call' THEN
  IF TG_OP<>'INSERT' OR n>=q.deadline OR NOT public.context_query_complete_object(NEW.request,ARRAY['Call','OwnerID','HubProcessEpoch']) OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.request->'Call') OR NEW.request->'Call'->>'ID'<>NEW.operation_id::text OR NEW.request->'Call'->'Principal' IS DISTINCT FROM q.actor OR
   NEW.request->'Call'->>'RootID'<>q.root_id::text OR NEW.is_poll<>(NEW.operation_id<>q.operation_id) OR NEW.request->'Call'->>'Tool' IS DISTINCT FROM (CASE WHEN NEW.is_poll THEN 'get_query_result' ELSE 'get_file_excerpt' END) THEN RAISE EXCEPTION 'query invocation mismatch' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET polls=polls+CASE WHEN NEW.is_poll THEN 1 ELSE 0 END,controls=controls+1 WHERE id=q.id;
 ELSIF TG_TABLE_NAME='context_query_batch' THEN
  IF TG_OP='INSERT' THEN
   IF NOT public.context_query_complete_object(NEW.batch,ARRAY['ID','QueryID','OperationID','Generation','Worker','Request','StartedAt','Until','CleanupUntil']) OR
    n>=q.deadline OR (NEW.batch->>'StartedAt')::timestamptz>n OR n>=(NEW.batch->>'Until')::timestamptz OR
    (NEW.batch->>'Until')::timestamptz>q.deadline OR (NEW.batch->>'Until')::timestamptz>(NEW.batch->'Request'->'Call'->>'Until')::timestamptz OR (NEW.batch->>'CleanupUntil')::timestamptz<>q.cleanup_until OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') OR
    q.active_batch IS NOT NULL OR q.uncertain OR NEW.generation<>q.generation+1 OR NEW.claim_id IS NOT NULL OR NEW.closed OR
    NEW.batch->>'OperationID' IS DISTINCT FROM NEW.operation_id::text OR NEW.batch->>'ID'<>NEW.id::text OR NEW.batch->>'QueryID'<>q.id::text OR (NEW.batch->>'Generation')::smallint<>NEW.generation OR
    NOT EXISTS(SELECT 1 FROM public.context_query_call c WHERE c.operation_id=NEW.operation_id AND c.query_id=q.id AND c.request=NEW.batch->'Request') OR
    NOT EXISTS(SELECT 1 FROM public.context_query_worker w WHERE w.query_id=q.id AND w.binding=NEW.batch->'Worker') THEN RAISE EXCEPTION 'query batch unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET generation=NEW.generation,active_batch=NEW.id,controls=controls+1 WHERE id=q.id;
  ELSE
   IF (to_jsonb(NEW)-ARRAY['claim_id','closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['claim_id','closed']) OR OLD.closed OR q.active_batch IS DISTINCT FROM NEW.id OR
    OLD.claim_id IS NOT NULL AND NEW.claim_id IS DISTINCT FROM OLD.claim_id OR OLD.claim_id IS NULL AND NEW.claim_id IS NULL OR
    OLD.claim_id IS NULL AND NEW.closed OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    NOT NEW.closed AND (OLD.claim_id IS NOT NULL OR n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call')) OR
    NEW.closed AND (NEW.native_operation IS NOT NULL AND NOT NEW.native_closed OR n>=q.cleanup_until OR n>=(NEW.batch->'Request'->'Call'->>'WriteUntil')::timestamptz OR NOT public.context_query_outcome_closed(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch)) THEN RAISE EXCEPTION 'query batch claim or close unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET active_batch=CASE WHEN NEW.closed THEN NULL ELSE active_batch END,controls=controls+1 WHERE id=q.id;
  END IF;
 ELSIF TG_TABLE_NAME='context_query_worker' THEN
  IF TG_OP<>'INSERT' OR NEW.worker_id<>q.worker_id OR NEW.binding->>'QueryID' IS DISTINCT FROM q.id::text OR NEW.binding->>'WorkerID' IS DISTINCT FROM q.worker_id::text THEN RAISE EXCEPTION 'query worker immutable' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 ELSE
  IF TG_OP='INSERT' THEN
   IF NEW.used_roles<>0 OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key binding unavailable' USING ERRCODE='23514'; END IF;
  ELSIF (to_jsonb(NEW)-'used_roles') IS DISTINCT FROM (to_jsonb(OLD)-'used_roles') OR (NEW.used_roles|OLD.used_roles)<>NEW.used_roles OR
   (NEW.used_roles#OLD.used_roles) NOT IN (1,2,4) OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key role already spent' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
