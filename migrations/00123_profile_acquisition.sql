-- +goose Up
-- S-05: reserve multipart obligations at admission, before a connector is
-- selected; bind exactly once at the existing accepted execution preparation.
ALTER TABLE custody_stream ALTER COLUMN writer_epoch DROP NOT NULL;
ALTER TABLE custody_stream ALTER COLUMN plan_digest DROP NOT NULL;
ALTER TABLE custody_stream ADD CONSTRAINT custody_stream_binding_pair CHECK ((writer_epoch IS NULL) = (plan_digest IS NULL));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_custody_stream() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'streaming journal is retained with its attempt' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.attempt_id,NEW.temporary_bytes,NEW.temporary_objects) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.temporary_bytes,OLD.temporary_objects)
  OR NEW.revision<>OLD.revision+1 OR OLD.released_at IS NOT NULL
  OR (NEW.state->>'CreateSpent')::boolean IS DISTINCT FROM true AND (OLD.state->>'CreateSpent')::boolean=true
  OR (NEW.state->>'CompleteSpent')::boolean IS DISTINCT FROM true AND (OLD.state->>'CompleteSpent')::boolean=true THEN
  RAISE EXCEPTION 'streaming journal transition unavailable' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.writer_epoch,NEW.plan_digest) IS DISTINCT FROM ROW(OLD.writer_epoch,OLD.plan_digest) THEN
  -- Exactly one immutable process binding, before any remote effect. No
  -- replacement after an unknown start and no binding while releasing.
  IF OLD.writer_epoch IS NOT NULL OR OLD.plan_digest IS NOT NULL OR NEW.writer_epoch IS NULL OR NEW.plan_digest IS NULL OR
   NEW.state IS DISTINCT FROM OLD.state OR NEW.released_at IS NOT NULL OR
   COALESCE((OLD.state->>'CreateSpent')::boolean,false) OR COALESCE((OLD.state->>'CompleteSpent')::boolean,false) THEN
   RAISE EXCEPTION 'streaming writer already bound or spent' USING ERRCODE='23514'; END IF;
 ELSIF NEW.writer_epoch IS NULL AND
   (NEW.released_at IS NULL OR (NEW.state->>'Aborted')::boolean IS DISTINCT FROM true OR COALESCE((NEW.state->>'CreateSpent')::boolean,false) OR COALESCE((NEW.state->>'CompleteSpent')::boolean,false)) THEN
  -- An unbound journal can only be retired after the existing fenced purge.
  RAISE EXCEPTION 'unbound streaming journal cannot start' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
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

ALTER TABLE context_execution DROP CONSTRAINT context_execution_phase_check,
 ADD CONSTRAINT context_execution_phase_check CHECK(phase IN ('prepared','started','stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled','peerMembershipChanged','peerMembershipStale','profilerBusy'));
-- context_execution_check is the not_after bound (it also names not_before);
-- the row-shape rule is the second unnamed check.
ALTER TABLE context_execution DROP CONSTRAINT context_execution_check1,
 ADD CONSTRAINT context_execution_check1 CHECK(COALESCE((phase='prepared' AND started_at IS NULL AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase='started' AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled','peerMembershipChanged','peerMembershipStale','profilerBusy') AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND isfinite(completed_at) AND completed_at>=started_at AND
 (phase IN ('captureFailed','targetGone','denied','cancelled','peerMembershipChanged','peerMembershipStale','profilerBusy') AND acquired_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR acquired_at>=started_at AND acquired_at<not_after AND completed_at>=acquired_at AND
 (phase='stored' AND copies_json IS NOT NULL AND copies_digest IS NOT NULL OR phase='storeUnconfirmed' AND copies_json IS NULL AND copies_digest IS NULL))),false));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_execution() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'context execution deletion requires retention protocol' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF EXISTS(SELECT 1 FROM public.context_capture WHERE root_id=NEW.root_id AND id=NEW.capture_id AND snapshot_cancel_requested_at IS NOT NULL) THEN RAISE EXCEPTION 'capture cancellation fences preparation' USING ERRCODE='23514';END IF;
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
 IF OLD.phase='prepared' AND NEW.phase='started' AND EXISTS(SELECT 1 FROM public.context_capture WHERE root_id=NEW.root_id AND id=NEW.capture_id AND snapshot_cancel_requested_at IS NOT NULL) THEN RAISE EXCEPTION 'capture cancellation fences start' USING ERRCODE='23514';END IF;
 IF OLD.phase='prepared' AND NEW.phase='started' AND OLD.object_uid IS NOT NULL AND NEW.started_at<=clock_timestamp() AND clock_timestamp()<OLD.not_after THEN RETURN NEW; END IF;
 IF OLD.phase='started' AND NEW.phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled','peerMembershipChanged','peerMembershipStale','profilerBusy') AND NEW.started_at=OLD.started_at AND NEW.completed_at<=clock_timestamp() THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'context execution cannot repeat or rewrite result' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd

-- +goose Down
-- Historical profile rows and still-unbound reservations cannot be represented
-- by the previous runtime. Positive cleanup is required before rollback.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM context_capture WHERE convert_from(expectation_json,'UTF8')::jsonb->>'NativeType' IN ('pprof','goTrace')) OR
    EXISTS(SELECT 1 FROM custody_stream WHERE writer_epoch IS NULL) OR EXISTS(SELECT 1 FROM context_execution WHERE phase='profilerBusy') THEN
  RAISE EXCEPTION 'profile attempts and unbound streams must be retired before downgrade';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE custody_stream DROP CONSTRAINT custody_stream_binding_pair;
ALTER TABLE custody_stream ALTER COLUMN writer_epoch SET NOT NULL;
ALTER TABLE custody_stream ALTER COLUMN plan_digest SET NOT NULL;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_custody_stream() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'streaming journal is retained with its attempt' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.attempt_id,NEW.writer_epoch,NEW.plan_digest,NEW.temporary_bytes,NEW.temporary_objects) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.writer_epoch,OLD.plan_digest,OLD.temporary_bytes,OLD.temporary_objects)
  OR NEW.revision <> OLD.revision + 1
  OR OLD.released_at IS NOT NULL
  OR (NEW.state->>'CreateSpent')::boolean IS DISTINCT FROM true AND (OLD.state->>'CreateSpent')::boolean = true
  OR (NEW.state->>'CompleteSpent')::boolean IS DISTINCT FROM true AND (OLD.state->>'CompleteSpent')::boolean = true THEN
  RAISE EXCEPTION 'streaming journal transition unavailable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
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
 IF NOT COALESCE(e->>'ActionID'='pod-status' AND NOT e ? 'NativeType' AND NOT e ? 'Recording' OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND jsonb_typeof(e->'Recording')='object' AND (e->>'NativeType'='pcapng' AND e#>>'{Recording,Kind}'='packetCapture' OR e->>'NativeType'='rawPcapng' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='rawPackets' OR e->>'NativeType'='httpHeaders' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='httpHeaders' OR e->>'NativeType'='syscallRecords' AND e#>>'{Recording,Kind}'='syscallTrace') OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pcapng','syscallRecords') AND jsonb_typeof(e->'Snapshot')='object' AND (NOT e ? 'Recording' OR e->'Recording'='null'::jsonb),false) OR NOT COALESCE(e->>'DataClass'='metadata' AND e->>'NativeType' IS DISTINCT FROM 'rawPcapng' AND e->>'NativeType' IS DISTINCT FROM 'httpHeaders' OR e->>'DataClass'='raw' AND e->>'NativeType'='rawPcapng' OR e->>'DataClass'='extract' AND e->>'NativeType'='httpHeaders',false) OR
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

ALTER TABLE context_execution DROP CONSTRAINT context_execution_phase_check,
 ADD CONSTRAINT context_execution_phase_check CHECK(phase IN ('prepared','started','stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled','peerMembershipChanged','peerMembershipStale'));
-- context_execution_check is the not_after bound (it also names not_before);
-- the row-shape rule is the second unnamed check.
ALTER TABLE context_execution DROP CONSTRAINT context_execution_check1,
 ADD CONSTRAINT context_execution_check1 CHECK(COALESCE((phase='prepared' AND started_at IS NULL AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase='started' AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND acquired_at IS NULL AND completed_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled','peerMembershipChanged','peerMembershipStale') AND object_uid IS NOT NULL AND started_at>=not_before AND started_at<not_after AND isfinite(completed_at) AND completed_at>=started_at AND
 (phase IN ('captureFailed','targetGone','denied','cancelled','peerMembershipChanged','peerMembershipStale') AND acquired_at IS NULL AND copies_json IS NULL AND copies_digest IS NULL
 OR acquired_at>=started_at AND acquired_at<not_after AND completed_at>=acquired_at AND
 (phase='stored' AND copies_json IS NOT NULL AND copies_digest IS NOT NULL OR phase='storeUnconfirmed' AND copies_json IS NULL AND copies_digest IS NULL))),false));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_execution() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'context execution deletion requires retention protocol' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF EXISTS(SELECT 1 FROM public.context_capture WHERE root_id=NEW.root_id AND id=NEW.capture_id AND snapshot_cancel_requested_at IS NOT NULL) THEN RAISE EXCEPTION 'capture cancellation fences preparation' USING ERRCODE='23514';END IF;
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
 IF OLD.phase='prepared' AND NEW.phase='started' AND EXISTS(SELECT 1 FROM public.context_capture WHERE root_id=NEW.root_id AND id=NEW.capture_id AND snapshot_cancel_requested_at IS NOT NULL) THEN RAISE EXCEPTION 'capture cancellation fences start' USING ERRCODE='23514';END IF;
 IF OLD.phase='prepared' AND NEW.phase='started' AND OLD.object_uid IS NOT NULL AND NEW.started_at<=clock_timestamp() AND clock_timestamp()<OLD.not_after THEN RETURN NEW; END IF;
 IF OLD.phase='started' AND NEW.phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled','peerMembershipChanged','peerMembershipStale') AND NEW.started_at=OLD.started_at AND NEW.completed_at<=clock_timestamp() THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'context execution cannot repeat or rewrite result' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
