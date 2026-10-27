-- +goose Up
-- ADR-248 (S-04 increment 4): a manual networkHeaders packet recording is
-- published like pod status. Its expectation names the generated recorder
-- action ("a" + 24 hex digits), the pcapng native type and the accepted node
-- recording. Only the processing lineage check changes: it admitted pod status
-- only. Additive for older binaries, which never write such an expectation;
-- the ADR-227 compatibility floor stays at 81. The workload download
-- allowance per record grows to fit one recording.
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
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='pcapng' AND jsonb_typeof(e->'Recording')='object',false) OR e->>'DataClass' IS DISTINCT FROM 'metadata' OR
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
REVOKE ALL ON FUNCTION project_context_processing() FROM PUBLIC;

-- The per-record download allowance of a workload account is sized for one
-- recording (ADR-248): 16 MiB output (an 8 MiB PCAPNG and one resume) and
-- 24 MiB authenticated read work per record, instead of pod status's 8 KiB and
-- 12 MiB. These are egress/read counters, not stored bytes; physical evidence
-- funding is unchanged. Existing workload accounts keep their limits.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_context_protocol_backing(context_slice jsonb,h jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE c jsonb:=h->'Capture';nq jsonb:=h->'Native';s jsonb:=h->'Stop';k text;n bigint;
 artifact_bytes constant bigint:=4096+65536+262144+65536+1048576+65536+32768;
 capture_backup numeric;capture_wal numeric;native_backup numeric;native_wal numeric;stop_backup numeric;stop_wal numeric;
BEGIN
 IF NOT public.capacity_json_fields(context_slice,ARRAY['Bytes','Objects']) OR
  NOT public.capacity_json_integer(context_slice->'Bytes',1,9223372036854775807) OR NOT public.capacity_json_integer(context_slice->'Objects',1,9223372036854775807) OR
  NOT public.capacity_json_fields(h,ARRAY['Capture','CapturePurgeLeases','Native','Stop']) OR
  NOT public.capacity_json_fields(c,ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
  c->>'Layout' IS DISTINCT FROM 'capture-intent-history/v1' OR NOT public.capacity_json_uuid(c->'ID') OR NOT public.capacity_json_digest(c->'Digest') OR
  NOT public.capacity_json_integer(c->'MaximumRowFootprintBytes',131072,16777216) OR NOT public.capacity_json_integer(c->'MaximumTransitionWALBytes',131072,67108864) OR
  NOT public.capacity_json_integer(c->'BackupCopies',1,64) OR NOT public.capacity_json_integer(c->'WALCopies',1,64) OR NOT public.capacity_json_integer(h->'CapturePurgeLeases',2,32) OR
  NOT public.capacity_json_fields(nq,ARRAY['ID','Digest','RowBytes','TransitionWALBytes','BackupCopies','WALCopies']) OR
  NOT public.capacity_json_uuid(nq->'ID') OR NOT public.capacity_json_digest(nq->'Digest') OR
  NOT public.capacity_json_integer(nq->'RowBytes',65536,16777216) OR NOT public.capacity_json_integer(nq->'TransitionWALBytes',65536,67108864) OR
  NOT public.capacity_json_integer(nq->'BackupCopies',1,64) OR NOT public.capacity_json_integer(nq->'WALCopies',1,64) OR
  NOT public.capacity_json_fields(s,ARRAY['RootID','InstallationID','StoreID','PolicyID','BackupProfileID','QualificationID','PolicyDigest','BackupProfileDigest','QualificationDigest','Layout','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies','MaxPurgeLeases']) OR
  s->>'Layout' IS DISTINCT FROM 'download-stop-history/v1' THEN RETURN NULL;END IF;
 FOREACH k IN ARRAY ARRAY['RootID','InstallationID','StoreID','PolicyID','BackupProfileID','QualificationID'] LOOP
  IF NOT public.capacity_json_uuid(s->k) THEN RETURN NULL;END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['PolicyDigest','BackupProfileDigest','QualificationDigest'] LOOP
  IF NOT public.capacity_json_digest(s->k) THEN RETURN NULL;END IF;
 END LOOP;
 IF NOT public.capacity_json_integer(s->'BackupHorizonSeconds',0,316224000) OR NOT public.capacity_json_integer(s->'CleanupBudgetSeconds',1,86400) OR
  NOT public.capacity_json_integer(s->'ProofWindowSeconds',1,316224000) OR NOT public.capacity_json_integer(s->'MaximumRowFootprintBytes',131072,16777216) OR
  NOT public.capacity_json_integer(s->'MaximumTransitionWALBytes',131072,67108864) OR NOT public.capacity_json_integer(s->'BackupCopies',1,64) OR
  NOT public.capacity_json_integer(s->'WALCopies',1,64) OR NOT public.capacity_json_integer(s->'MaxPurgeLeases',2,32) THEN RETURN NULL;END IF;
 n:=LEAST((context_slice->>'Bytes')::bigint/artifact_bytes,(context_slice->>'Objects')::bigint/4,512);
 IF n<1 THEN RETURN NULL;END IF;
 capture_backup:=n*2*(c->>'MaximumRowFootprintBytes')::numeric*(c->>'BackupCopies')::numeric;
 capture_wal:=n*2*(c->>'MaximumTransitionWALBytes')::numeric*(c->>'WALCopies')::numeric*(32+3*(h->>'CapturePurgeLeases')::bigint);
 native_backup:=n*2*(nq->>'RowBytes')::numeric*(nq->>'BackupCopies')::numeric*3;
 native_wal:=n*(nq->>'TransitionWALBytes')::numeric*(nq->>'WALCopies')::numeric*(10+4+8*2);
 stop_backup:=n*2*(s->>'MaximumRowFootprintBytes')::numeric*(s->>'BackupCopies')::numeric;
 stop_wal:=n*2*(s->>'MaximumTransitionWALBytes')::numeric*(s->>'WALCopies')::numeric*(20+3*(s->>'MaxPurgeLeases')::bigint);
 IF GREATEST(capture_backup,capture_wal,native_backup,native_wal,stop_backup,stop_wal)>9223372036854775807 THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('Format','protected-context-backing/v1','Records',n,'ReplayRecords',n,
  'Evidence',jsonb_build_object('Bytes',n*artifact_bytes,'Objects',n*4),
  'CaptureObjects',jsonb_build_object('Bytes',n*131072,'Objects',n*2),
  'VerificationObjects',jsonb_build_object('Bytes',n*131072,'Objects',n),
  'DeletionObjects',jsonb_build_object('Bytes',n*131072,'Objects',n),
  'PreparationObjects',jsonb_build_object('Bytes',n*262144,'Objects',n*2),
  'WindowObjects',jsonb_build_object('Bytes',n*524288,'Objects',n*4),
  'StopObjects',jsonb_build_object('Bytes',n*65536,'Objects',n),
  'ProtocolSystemObjects',jsonb_build_object('Bytes',n*1245184,'Objects',n*11),
  'Sessions',n,'OutputBytes',n*16777216,'ReadBytes',n*25165824,'RequestsPerSession',3,'Responses',n*2,'Windows',n*2,
  'NativeRows',n,'NativeKeys',n*2,'NativeTransitionsPerRow',10,'CaptureKeyAttempts',n*13,'StopKeyAttempts',n*12,
  'ArtifactWraps',n*3,'PreparationUnwraps',n*3,'ContentUnwraps',n*6,
  'CaptureBackupBytes',capture_backup::bigint,'CaptureWALBytes',capture_wal::bigint,'NativeBackupBytes',native_backup::bigint,
  'NativeWALBytes',native_wal::bigint,'StopBackupBytes',stop_backup::bigint,'StopWALBytes',stop_wal::bigint);
EXCEPTION WHEN data_exception THEN RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_context_protocol_backing(jsonb,jsonb) FROM PUBLIC;

-- +goose Down
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
 IF e->>'ActionID' IS DISTINCT FROM 'pod-status' OR e->>'DataClass' IS DISTINCT FROM 'metadata' OR
    (e->>'CaptureUID')::uuid IS DISTINCT FROM NEW.capture_id OR (e#>>'{Registration,Location,ArtifactID}')::uuid IS DISTINCT FROM NEW.artifact_id OR
    (e#>>'{Registration,DeleteBy}')::timestamptz>p.valid_until THEN
  RAISE EXCEPTION 'unqualified processing lineage' USING ERRCODE='23514'; END IF;
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
REVOKE ALL ON FUNCTION project_context_processing() FROM PUBLIC;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_context_protocol_backing(context_slice jsonb,h jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE c jsonb:=h->'Capture';nq jsonb:=h->'Native';s jsonb:=h->'Stop';k text;n bigint;
 artifact_bytes constant bigint:=4096+65536+262144+65536+1048576+65536+32768;
 capture_backup numeric;capture_wal numeric;native_backup numeric;native_wal numeric;stop_backup numeric;stop_wal numeric;
BEGIN
 IF NOT public.capacity_json_fields(context_slice,ARRAY['Bytes','Objects']) OR
  NOT public.capacity_json_integer(context_slice->'Bytes',1,9223372036854775807) OR NOT public.capacity_json_integer(context_slice->'Objects',1,9223372036854775807) OR
  NOT public.capacity_json_fields(h,ARRAY['Capture','CapturePurgeLeases','Native','Stop']) OR
  NOT public.capacity_json_fields(c,ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
  c->>'Layout' IS DISTINCT FROM 'capture-intent-history/v1' OR NOT public.capacity_json_uuid(c->'ID') OR NOT public.capacity_json_digest(c->'Digest') OR
  NOT public.capacity_json_integer(c->'MaximumRowFootprintBytes',131072,16777216) OR NOT public.capacity_json_integer(c->'MaximumTransitionWALBytes',131072,67108864) OR
  NOT public.capacity_json_integer(c->'BackupCopies',1,64) OR NOT public.capacity_json_integer(c->'WALCopies',1,64) OR NOT public.capacity_json_integer(h->'CapturePurgeLeases',2,32) OR
  NOT public.capacity_json_fields(nq,ARRAY['ID','Digest','RowBytes','TransitionWALBytes','BackupCopies','WALCopies']) OR
  NOT public.capacity_json_uuid(nq->'ID') OR NOT public.capacity_json_digest(nq->'Digest') OR
  NOT public.capacity_json_integer(nq->'RowBytes',65536,16777216) OR NOT public.capacity_json_integer(nq->'TransitionWALBytes',65536,67108864) OR
  NOT public.capacity_json_integer(nq->'BackupCopies',1,64) OR NOT public.capacity_json_integer(nq->'WALCopies',1,64) OR
  NOT public.capacity_json_fields(s,ARRAY['RootID','InstallationID','StoreID','PolicyID','BackupProfileID','QualificationID','PolicyDigest','BackupProfileDigest','QualificationDigest','Layout','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies','MaxPurgeLeases']) OR
  s->>'Layout' IS DISTINCT FROM 'download-stop-history/v1' THEN RETURN NULL;END IF;
 FOREACH k IN ARRAY ARRAY['RootID','InstallationID','StoreID','PolicyID','BackupProfileID','QualificationID'] LOOP
  IF NOT public.capacity_json_uuid(s->k) THEN RETURN NULL;END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['PolicyDigest','BackupProfileDigest','QualificationDigest'] LOOP
  IF NOT public.capacity_json_digest(s->k) THEN RETURN NULL;END IF;
 END LOOP;
 IF NOT public.capacity_json_integer(s->'BackupHorizonSeconds',0,316224000) OR NOT public.capacity_json_integer(s->'CleanupBudgetSeconds',1,86400) OR
  NOT public.capacity_json_integer(s->'ProofWindowSeconds',1,316224000) OR NOT public.capacity_json_integer(s->'MaximumRowFootprintBytes',131072,16777216) OR
  NOT public.capacity_json_integer(s->'MaximumTransitionWALBytes',131072,67108864) OR NOT public.capacity_json_integer(s->'BackupCopies',1,64) OR
  NOT public.capacity_json_integer(s->'WALCopies',1,64) OR NOT public.capacity_json_integer(s->'MaxPurgeLeases',2,32) THEN RETURN NULL;END IF;
 n:=LEAST((context_slice->>'Bytes')::bigint/artifact_bytes,(context_slice->>'Objects')::bigint/4,512);
 IF n<1 THEN RETURN NULL;END IF;
 capture_backup:=n*2*(c->>'MaximumRowFootprintBytes')::numeric*(c->>'BackupCopies')::numeric;
 capture_wal:=n*2*(c->>'MaximumTransitionWALBytes')::numeric*(c->>'WALCopies')::numeric*(32+3*(h->>'CapturePurgeLeases')::bigint);
 native_backup:=n*2*(nq->>'RowBytes')::numeric*(nq->>'BackupCopies')::numeric*3;
 native_wal:=n*(nq->>'TransitionWALBytes')::numeric*(nq->>'WALCopies')::numeric*(10+4+8*2);
 stop_backup:=n*2*(s->>'MaximumRowFootprintBytes')::numeric*(s->>'BackupCopies')::numeric;
 stop_wal:=n*2*(s->>'MaximumTransitionWALBytes')::numeric*(s->>'WALCopies')::numeric*(20+3*(s->>'MaxPurgeLeases')::bigint);
 IF GREATEST(capture_backup,capture_wal,native_backup,native_wal,stop_backup,stop_wal)>9223372036854775807 THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('Format','protected-context-backing/v1','Records',n,'ReplayRecords',n,
  'Evidence',jsonb_build_object('Bytes',n*artifact_bytes,'Objects',n*4),
  'CaptureObjects',jsonb_build_object('Bytes',n*131072,'Objects',n*2),
  'VerificationObjects',jsonb_build_object('Bytes',n*131072,'Objects',n),
  'DeletionObjects',jsonb_build_object('Bytes',n*131072,'Objects',n),
  'PreparationObjects',jsonb_build_object('Bytes',n*262144,'Objects',n*2),
  'WindowObjects',jsonb_build_object('Bytes',n*524288,'Objects',n*4),
  'StopObjects',jsonb_build_object('Bytes',n*65536,'Objects',n),
  'ProtocolSystemObjects',jsonb_build_object('Bytes',n*1245184,'Objects',n*11),
  'Sessions',n,'OutputBytes',n*8192,'ReadBytes',n*12582912,'RequestsPerSession',3,'Responses',n*2,'Windows',n*2,
  'NativeRows',n,'NativeKeys',n*2,'NativeTransitionsPerRow',10,'CaptureKeyAttempts',n*13,'StopKeyAttempts',n*12,
  'ArtifactWraps',n*3,'PreparationUnwraps',n*3,'ContentUnwraps',n*6,
  'CaptureBackupBytes',capture_backup::bigint,'CaptureWALBytes',capture_wal::bigint,'NativeBackupBytes',native_backup::bigint,
  'NativeWALBytes',native_wal::bigint,'StopBackupBytes',stop_backup::bigint,'StopWALBytes',stop_wal::bigint);
EXCEPTION WHEN data_exception THEN RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_context_protocol_backing(jsonb,jsonb) FROM PUBLIC;
