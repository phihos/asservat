-- +goose Up
-- ADR-330 D6: evidence queries no longer read the operation audit. The public
-- `call` audit_event row, written before any output, is the read's audit. A
-- query call is its request ID, principal, tool and original window; keyed
-- replays match on the stored idempotency key and request digest.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_intent_current(r uuid,op uuid,actor jsonb,epoch uuid,call jsonb) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(call->>'ID'=op::text AND call->>'RootID'=r::text AND call->'Principal'=actor
 AND call->>'Tool' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result')
 AND (call->>'StartedAt')::timestamptz<=clock_timestamp() AND clock_timestamp()<(call->>'Until')::timestamptz
 AND EXISTS(SELECT 1 FROM public.fleet_current_trust t WHERE t.issuer_epoch=epoch
  AND NOT t.suspended AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until),false)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_query_child() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE q public.context_query; n timestamptz; begin_tool text; call_tool text; key_batch public.context_query_batch;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query child history remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT q FROM public.context_query WHERE id=NEW.query_id FOR UPDATE;
 n:=clock_timestamp();
 begin_tool:=public.context_query_begin_tool(q.query->'Scope');
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
     NEW.native_authority->'Scope' IS DISTINCT FROM q.query->'Scope' OR
     NEW.native_operation->'SourceVersion' IS DISTINCT FROM q.query#>'{Scope,Version}' OR
     NEW.native_operation->'Path' IS DISTINCT FROM ((NEW.native_authority#>'{Environment,Path}')-'Purpose') OR NEW.native_operation->'Processing' IS DISTINCT FROM NEW.native_authority#>'{Environment,Processing}' OR
     (CASE WHEN q.query#>'{Scope,Comparison}' IS NOT NULL THEN
      NOT public.capacity_json_fields(NEW.native_operation->'Baseline',ARRAY['Path','Processing','SourceVersion']) OR
      NEW.native_authority#>'{Baseline,Baseline}' IS NOT NULL OR NEW.native_authority#>'{Baseline,Scope}' IS DISTINCT FROM public.context_query_comparison_source(q.query->'Scope',true) OR
      NEW.native_operation#>'{Baseline,SourceVersion}' IS DISTINCT FROM q.query#>'{Scope,Comparison,Baseline,Version}' OR NEW.native_operation#>'{Baseline,Path}' IS DISTINCT FROM ((NEW.native_authority#>'{Baseline,Environment,Path}')-'Purpose') OR NEW.native_operation#>'{Baseline,Processing}' IS DISTINCT FROM NEW.native_authority#>'{Baseline,Environment,Processing}'
     ELSE NEW.native_operation ? 'Baseline' OR NEW.native_authority ? 'Baseline' END) THEN
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
  call_tool:=begin_tool;
  IF NEW.is_poll THEN call_tool:='get_query_result'; END IF;
  IF TG_OP<>'INSERT' OR n>=q.deadline OR NOT public.context_query_complete_object(NEW.request,ARRAY['Call','OwnerID','HubProcessEpoch']) OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.request->'Call') OR NEW.request->'Call'->>'ID'<>NEW.operation_id::text OR NEW.request->'Call'->'Principal' IS DISTINCT FROM q.actor OR
   NEW.request->'Call'->>'RootID'<>q.root_id::text OR (NEW.is_poll AND NEW.operation_id=q.operation_id) OR
   (NOT NEW.is_poll AND NEW.operation_id<>q.operation_id AND NOT COALESCE(
    q.query#>>'{Scope,DisplayVersion}' IN ('approved-pcap-query/v1','approved-syscall-query/v1','approved-logs/v1') AND public.context_query_scope_source_valid(q.query->'Scope') AND q.invocation_key IS NOT NULL AND q.request_digest IS NOT NULL,false)) OR NEW.request->'Call'->>'Tool' IS DISTINCT FROM call_tool THEN RAISE EXCEPTION 'query invocation mismatch' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET polls=polls+CASE WHEN NEW.is_poll THEN 1 ELSE 0 END,controls=controls+1 WHERE id=q.id;
 ELSIF TG_TABLE_NAME='context_query_batch' THEN
  IF TG_OP='INSERT' THEN
   IF q.query#>>'{Scope,DisplayVersion}' IN ('approved-pcap-query/v1','approved-syscall-query/v1','approved-logs/v1') AND NOT public.context_packet_query_grant_current(q.root_id,q.id,NEW.id) THEN
    RAISE EXCEPTION 'packet query batch disclosure is not reserved' USING ERRCODE='23514'; END IF;
   IF NOT public.context_query_complete_object(NEW.batch,ARRAY['ID','QueryID','OperationID','Generation','Worker','Request','StartedAt','Until','CleanupUntil']) OR
    n>=q.deadline OR (NEW.batch->>'StartedAt')::timestamptz>n OR n>=(NEW.batch->>'Until')::timestamptz OR
    (NEW.batch->>'Until')::timestamptz>q.deadline OR (NEW.batch->>'Until')::timestamptz>(NEW.batch->'Request'->'Call'->>'Until')::timestamptz OR (NEW.batch->>'CleanupUntil')::timestamptz<>q.cleanup_until OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') OR
    q.active_batch IS NOT NULL OR q.uncertain OR NEW.generation<>q.generation+1 OR NEW.generation>public.context_query_read_batches(q.query->'Scope') OR NEW.claim_id IS NOT NULL OR NEW.closed OR
    NEW.batch->>'OperationID' IS DISTINCT FROM NEW.operation_id::text OR NEW.batch->>'ID'<>NEW.id::text OR NEW.batch->>'QueryID'<>q.id::text OR (NEW.batch->>'Generation')::smallint<>NEW.generation OR
    NOT EXISTS(SELECT 1 FROM public.context_query_call c WHERE c.operation_id=NEW.operation_id AND c.query_id=q.id AND c.request=NEW.batch->'Request' AND (c.is_poll OR c.operation_id=q.operation_id)) OR
    NOT EXISTS(SELECT 1 FROM public.context_query_worker w WHERE w.query_id=q.id AND w.binding=NEW.batch->'Worker') THEN RAISE EXCEPTION 'query batch unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET generation=NEW.generation,active_batch=NEW.id,controls=controls+1 WHERE id=q.id;
  ELSE
   IF (to_jsonb(NEW)-ARRAY['claim_id','closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['claim_id','closed']) OR OLD.closed OR q.active_batch IS DISTINCT FROM NEW.id OR
    OLD.claim_id IS NOT NULL AND NEW.claim_id IS DISTINCT FROM OLD.claim_id OR OLD.claim_id IS NULL AND NEW.claim_id IS NULL OR
    OLD.claim_id IS NULL AND NEW.closed OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    NOT NEW.closed AND (OLD.claim_id IS NOT NULL OR n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call')) OR
    NEW.closed AND (NEW.native_operation IS NOT NULL AND NOT NEW.native_closed OR n>=q.cleanup_until OR n>=(NEW.batch->'Request'->'Call'->>'WriteUntil')::timestamptz) THEN RAISE EXCEPTION 'query batch claim or close unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET active_batch=CASE WHEN NEW.closed THEN NULL ELSE active_batch END,controls=controls+1 WHERE id=q.id;
  END IF;
 ELSIF TG_TABLE_NAME='context_query_worker' THEN
  IF TG_OP<>'INSERT' OR NEW.worker_id<>q.worker_id OR NEW.binding->>'QueryID' IS DISTINCT FROM q.id::text OR NEW.binding->>'WorkerID' IS DISTINCT FROM q.worker_id::text THEN RAISE EXCEPTION 'query worker immutable' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 ELSE
  IF TG_OP='INSERT' AND NEW.source_ordinal IS NULL AND NEW.child_id IS NULL THEN NEW.child_id:=NEW.batch_id; END IF;
  IF q.query#>'{Scope,Comparison}' IS NOT NULL THEN
   SELECT * INTO STRICT key_batch FROM public.context_query_batch WHERE id=NEW.batch_id AND query_id=q.id;
   IF NOT public.capacity_json_fields(NEW.binding,ARRAY['ID','QueryID','BatchID','WorkerID','ProcessEpoch','SourceOrdinal','SourceVersion','AuthorityDigest','PublicKey','Certificate','Scope','CreatedAt','Until']) OR
    key_batch.native_operation IS NULL OR key_batch.native_closed OR key_batch.closed OR key_batch.claim_id IS DISTINCT FROM key_batch.id OR
    NEW.binding->'AuthorityDigest' IS DISTINCT FROM key_batch.native_authority->'DecisionDigest' OR NEW.binding->>'WorkerID' IS DISTINCT FROM q.worker_id::text OR
    NEW.binding->>'ProcessEpoch' IS DISTINCT FROM key_batch.batch#>>'{Worker,ProcessEpoch}' OR NEW.binding->'Certificate' IS DISTINCT FROM key_batch.batch#>'{Worker,Certificate}' OR NEW.binding->'PublicKey' IS DISTINCT FROM key_batch.native_operation->'WorkerPublicKey' OR
    NEW.binding#>>'{Scope,InstallationID}' IS DISTINCT FROM q.query#>>'{Plan,InstallationID}' OR NEW.binding#>>'{Scope,Purpose}' IS DISTINCT FROM 'artifact' OR
    (NEW.binding->>'CreatedAt')::timestamptz<(key_batch.batch->>'StartedAt')::timestamptz OR (NEW.binding->>'CreatedAt')::timestamptz>n OR n>=(NEW.binding->>'Until')::timestamptz OR
    (NEW.binding->>'Until')::timestamptz>(key_batch.batch->>'Until')::timestamptz OR (NEW.binding->>'Until')::timestamptz>(key_batch.native_authority->>'ValidUntil')::timestamptz OR (NEW.binding->>'Until')::timestamptz>(q.query->>'ProviderUntil')::timestamptz THEN RAISE EXCEPTION 'comparison key parent mismatch' USING ERRCODE='23514'; END IF;
   IF NEW.source_ordinal IS NULL OR NEW.child_id=NEW.batch_id OR NEW.binding->>'ID' IS DISTINCT FROM NEW.child_id::text OR NEW.binding->>'QueryID' IS DISTINCT FROM q.id::text OR NEW.binding->>'BatchID' IS DISTINCT FROM NEW.batch_id::text OR (NEW.binding->>'SourceOrdinal')::integer IS DISTINCT FROM NEW.source_ordinal OR
    NEW.binding->'SourceVersion' IS DISTINCT FROM (CASE NEW.source_ordinal WHEN 0 THEN q.query#>'{Scope,Comparison,Baseline,Version}' WHEN 1 THEN q.query#>'{Scope,Version}' END) THEN RAISE EXCEPTION 'comparison key child mismatch' USING ERRCODE='23514'; END IF;
  ELSIF NEW.source_ordinal IS NOT NULL OR NEW.child_id IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'legacy key child mismatch' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' THEN
   IF NEW.used_roles<>0 OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key binding unavailable' USING ERRCODE='23514'; END IF;
  ELSIF (to_jsonb(NEW)-'used_roles') IS DISTINCT FROM (to_jsonb(OLD)-'used_roles') OR (NEW.used_roles|OLD.used_roles)<>NEW.used_roles OR
   (NEW.used_roles#OLD.used_roles) NOT IN (1,2,4) OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key role already spent' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP FUNCTION IF EXISTS context_query_outcome_closed(uuid,uuid,jsonb,uuid);
