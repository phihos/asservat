-- +goose Up
-- Finite argument output is raw. Extend only the accepted recording lineage;
-- profile/snapshot processing and all original coverage/accounting stay intact.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_context_processing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; e jsonb; n timestamptz;
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_catalog'::regclass THEN
  RAISE EXCEPTION 'invalid processing publication source' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF p.initialized_at IS NULL OR n>=p.valid_until OR p.captures>=p.max_captures THEN RAISE EXCEPTION 'processing completeness unavailable' USING ERRCODE='23514'; END IF;
 SELECT convert_from(c.expectation_json,'UTF8')::jsonb INTO STRICT e FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF NOT COALESCE(e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pprof','goTrace') AND jsonb_typeof(e->'Profile')='object' AND e->>'DataClass'='raw' AND
    NOT e ? 'Recording' AND NOT e ? 'Snapshot' AND NOT e ? 'Lifecycle' AND NOT e ? 'CompositionGroup' AND
    (e->>'NativeType'='goTrace' AND e#>>'{Profile,Type}'='runtimeTrace' OR e->>'NativeType'='pprof' AND e#>>'{Profile,Type}' IN ('cpu','heap','allocs','goroutine','block','mutex','threadcreate')) AND
    (e#>>'{Profile,MaxBytes}')::bigint=(e#>>'{Registration,NativeLimit}')::bigint AND
    (e#>>'{Profile,TimeoutMillis}')::bigint BETWEEN (e#>>'{Profile,DurationMillis}')::bigint+5000 AND (e#>>'{Profile,DurationMillis}')::bigint+10000 AND
    length(e#>>'{Profile,Composition}')>0 OR
    e->>'ActionID'='pod-status' AND NOT e ? 'NativeType' AND NOT e ? 'Recording' OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND jsonb_typeof(e->'Recording')='object' AND (e->>'NativeType'='pcapng' AND e#>>'{Recording,Kind}'='packetCapture' OR e->>'NativeType'='rawPcapng' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='rawPackets' OR e->>'NativeType'='httpHeaders' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='httpHeaders' OR e->>'NativeType'='syscallRecords' AND e#>>'{Recording,Kind}'='syscallTrace' OR e->>'NativeType'='syscallArguments' AND e#>>'{Recording,Kind}'='syscallTrace' AND e#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(e#>'{Recording,Arguments}')='object' AND NOT e ? 'Snapshot' AND NOT e ? 'Profile' AND NOT e ? 'Lifecycle') OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pcapng','syscallRecords') AND jsonb_typeof(e->'Snapshot')='object' AND (NOT e ? 'Recording' OR e->'Recording'='null'::jsonb),false) OR NOT COALESCE(e->>'DataClass'='metadata' AND e->>'NativeType' IS DISTINCT FROM 'rawPcapng' AND e->>'NativeType' IS DISTINCT FROM 'httpHeaders' AND e->>'NativeType' IS DISTINCT FROM 'pprof' AND e->>'NativeType' IS DISTINCT FROM 'goTrace' AND e->>'NativeType' IS DISTINCT FROM 'syscallArguments' OR e->>'DataClass'='raw' AND e->>'NativeType' IN ('rawPcapng','pprof','goTrace','syscallArguments') OR e->>'DataClass'='extract' AND e->>'NativeType'='httpHeaders',false) OR
    (e->>'CaptureUID')::uuid IS DISTINCT FROM NEW.capture_id OR (e#>>'{Registration,Location,ArtifactID}')::uuid IS DISTINCT FROM NEW.artifact_id OR
    (e#>>'{Registration,DeleteBy}')::timestamptz>p.valid_until THEN
  RAISE EXCEPTION 'unqualified processing lineage' USING ERRCODE='23514'; END IF;
 -- Renewing installation capacity does not expand an older restrictive rule's
 -- managed-history coverage. The restriction stays effective after its own
 -- administrative deadline; future matching evidence cannot outlive backing.
 IF EXISTS(SELECT 1 FROM public.processing_rule r WHERE r.root_id=NEW.root_id AND r.state='restricted' AND
    (e#>>'{Registration,DeleteBy}')::timestamptz>r.valid_until AND
    ((r.scope->>'Kind'='artifact' AND r.scope#>>'{Location,ArtifactID}'=NEW.artifact_id::text AND r.scope#>>'{Location,AttemptID}'=e#>>'{Registration,Location,AttemptID}' AND r.scope#>>'{Location,ClusterID}'=e#>>'{Registration,Location,ClusterID}') OR
     (r.scope->>'Kind'='workloadInterval' AND r.scope->>'ClusterID'=e#>>'{Registration,Location,ClusterID}' AND r.scope->>'NamespaceUID'=e->>'NamespaceUID' AND r.scope->>'WorkloadUID'=e->>'WorkloadUID' AND
      (e#>>'{Registration,AnchorAt}')::timestamptz>=(r.scope->>'AcquiredFrom')::timestamptz AND (e#>>'{Registration,AnchorAt}')::timestamptz<(r.scope->>'AcquiredUntil')::timestamptz))) THEN
  RAISE EXCEPTION 'retained processing restriction requires coverage reconciliation' USING ERRCODE='23514'; END IF;
 INSERT INTO public.context_processing(artifact_id,root_id,capture_id,attempt_id,cluster_id,namespace_uid,workload_uid,pod_uid,anchor_at,delete_by,retire_by,origin,parents)
 VALUES(NEW.artifact_id,NEW.root_id,NEW.capture_id,(e#>>'{Registration,Location,AttemptID}')::uuid,(e#>>'{Registration,Location,ClusterID}')::uuid,e->>'NamespaceUID',e->>'WorkloadUID',e->>'PodUID',(e#>>'{Registration,AnchorAt}')::timestamptz,(e#>>'{Registration,DeleteBy}')::timestamptz,p.retire_by,'capture','[]');
 UPDATE public.processing_root SET captures=captures+1 WHERE root_id=NEW.root_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- Reuse the existing durable Stop fence for this exact finite raw mode.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_snapshot_cancel() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.snapshot_cancel_key IS NOT NULL THEN RAISE EXCEPTION 'cancellation follows committed acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.snapshot_cancel_key,NEW.snapshot_cancel_actor,NEW.snapshot_cancel_requested_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_key,OLD.snapshot_cancel_actor,OLD.snapshot_cancel_requested_at) THEN
  IF OLD.snapshot_cancel_key IS NOT NULL OR NEW.snapshot_cancel_key IS NULL OR (jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Snapshot') IS DISTINCT FROM 'object' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Profile') IS DISTINCT FROM 'object' AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='syscallArguments' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Kind}'='syscallTrace' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb#>'{Recording,Arguments}')='object',false)) THEN RAISE EXCEPTION 'immutable cancellation request' USING ERRCODE='23514';END IF;
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
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM context_capture WHERE convert_from(expectation_json,'UTF8')::jsonb->>'NativeType'='syscallArguments') THEN
  RAISE EXCEPTION 'retained syscall argument captures must be retired before downgrade';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_context_processing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; e jsonb; n timestamptz;
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_catalog'::regclass THEN
  RAISE EXCEPTION 'invalid processing publication source' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF p.initialized_at IS NULL OR n>=p.valid_until OR p.captures>=p.max_captures THEN RAISE EXCEPTION 'processing completeness unavailable' USING ERRCODE='23514'; END IF;
 SELECT convert_from(c.expectation_json,'UTF8')::jsonb INTO STRICT e FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF NOT COALESCE(e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pprof','goTrace') AND jsonb_typeof(e->'Profile')='object' AND e->>'DataClass'='raw' AND
    NOT e ? 'Recording' AND NOT e ? 'Snapshot' AND NOT e ? 'Lifecycle' AND NOT e ? 'CompositionGroup' AND
    (e->>'NativeType'='goTrace' AND e#>>'{Profile,Type}'='runtimeTrace' OR e->>'NativeType'='pprof' AND e#>>'{Profile,Type}' IN ('cpu','heap','allocs','goroutine','block','mutex','threadcreate')) AND
    (e#>>'{Profile,MaxBytes}')::bigint=(e#>>'{Registration,NativeLimit}')::bigint AND
    (e#>>'{Profile,TimeoutMillis}')::bigint BETWEEN (e#>>'{Profile,DurationMillis}')::bigint+5000 AND (e#>>'{Profile,DurationMillis}')::bigint+10000 AND
    length(e#>>'{Profile,Composition}')>0 OR
    e->>'ActionID'='pod-status' AND NOT e ? 'NativeType' AND NOT e ? 'Recording' OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND jsonb_typeof(e->'Recording')='object' AND (e->>'NativeType'='pcapng' AND e#>>'{Recording,Kind}'='packetCapture' OR e->>'NativeType'='rawPcapng' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='rawPackets' OR e->>'NativeType'='httpHeaders' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='httpHeaders' OR e->>'NativeType'='syscallRecords' AND e#>>'{Recording,Kind}'='syscallTrace') OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pcapng','syscallRecords') AND jsonb_typeof(e->'Snapshot')='object' AND (NOT e ? 'Recording' OR e->'Recording'='null'::jsonb),false) OR NOT COALESCE(e->>'DataClass'='metadata' AND e->>'NativeType' IS DISTINCT FROM 'rawPcapng' AND e->>'NativeType' IS DISTINCT FROM 'httpHeaders' AND e->>'NativeType' IS DISTINCT FROM 'pprof' AND e->>'NativeType' IS DISTINCT FROM 'goTrace' OR e->>'DataClass'='raw' AND e->>'NativeType' IN ('rawPcapng','pprof','goTrace') OR e->>'DataClass'='extract' AND e->>'NativeType'='httpHeaders',false) OR
    (e->>'CaptureUID')::uuid IS DISTINCT FROM NEW.capture_id OR (e#>>'{Registration,Location,ArtifactID}')::uuid IS DISTINCT FROM NEW.artifact_id OR
    (e#>>'{Registration,DeleteBy}')::timestamptz>p.valid_until THEN
  RAISE EXCEPTION 'unqualified processing lineage' USING ERRCODE='23514'; END IF;
 -- Renewing installation capacity does not expand an older restrictive rule's
 -- managed-history coverage. The restriction stays effective after its own
 -- administrative deadline; future matching evidence cannot outlive backing.
 IF EXISTS(SELECT 1 FROM public.processing_rule r WHERE r.root_id=NEW.root_id AND r.state='restricted' AND
    (e#>>'{Registration,DeleteBy}')::timestamptz>r.valid_until AND
    ((r.scope->>'Kind'='artifact' AND r.scope#>>'{Location,ArtifactID}'=NEW.artifact_id::text AND r.scope#>>'{Location,AttemptID}'=e#>>'{Registration,Location,AttemptID}' AND r.scope#>>'{Location,ClusterID}'=e#>>'{Registration,Location,ClusterID}') OR
     (r.scope->>'Kind'='workloadInterval' AND r.scope->>'ClusterID'=e#>>'{Registration,Location,ClusterID}' AND r.scope->>'NamespaceUID'=e->>'NamespaceUID' AND r.scope->>'WorkloadUID'=e->>'WorkloadUID' AND
      (e#>>'{Registration,AnchorAt}')::timestamptz>=(r.scope->>'AcquiredFrom')::timestamptz AND (e#>>'{Registration,AnchorAt}')::timestamptz<(r.scope->>'AcquiredUntil')::timestamptz))) THEN
  RAISE EXCEPTION 'retained processing restriction requires coverage reconciliation' USING ERRCODE='23514'; END IF;
 INSERT INTO public.context_processing(artifact_id,root_id,capture_id,attempt_id,cluster_id,namespace_uid,workload_uid,pod_uid,anchor_at,delete_by,retire_by,origin,parents)
 VALUES(NEW.artifact_id,NEW.root_id,NEW.capture_id,(e#>>'{Registration,Location,AttemptID}')::uuid,(e#>>'{Registration,Location,ClusterID}')::uuid,e->>'NamespaceUID',e->>'WorkloadUID',e->>'PodUID',(e#>>'{Registration,AnchorAt}')::timestamptz,(e#>>'{Registration,DeleteBy}')::timestamptz,p.retire_by,'capture','[]');
 UPDATE public.processing_root SET captures=captures+1 WHERE root_id=NEW.root_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_snapshot_cancel() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.snapshot_cancel_key IS NOT NULL THEN RAISE EXCEPTION 'cancellation follows committed acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.snapshot_cancel_key,NEW.snapshot_cancel_actor,NEW.snapshot_cancel_requested_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_key,OLD.snapshot_cancel_actor,OLD.snapshot_cancel_requested_at) THEN
  IF OLD.snapshot_cancel_key IS NOT NULL OR NEW.snapshot_cancel_key IS NULL OR (jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Snapshot') IS DISTINCT FROM 'object' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Profile') IS DISTINCT FROM 'object') THEN RAISE EXCEPTION 'immutable cancellation request' USING ERRCODE='23514';END IF;
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
