-- +goose Up
-- The administrator already reserved these bytes in each immutable enrollment.
-- Correct only the physical custody projection; record/object/protocol limits,
-- current authority, charged/uncertain spend and all original dates stay fixed.
-- Lock the complete retained graph before validating or changing any child.
-- Runtime credentials cannot disable triggers or execute this migration.
LOCK TABLE public.capacity_source,public.capacity_pool,public.capacity_cluster,
 public.capacity_namespace,public.capacity_workload,public.custody_pool,
 public.custody_allocation,public.context_storage_binding,public.context_control_pool,
 public.context_control_account,public.download_allocation,public.download_control_allocation,
 public.download_native_backing,public.download_stop_backing,public.capture_audit_allocation,
 public.operation_audit_pool,public.processing_root,public.download_stop_pool,public.capture_audit_root
 IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
DECLARE s public.capacity_source;
BEGIN
 FOR s IN SELECT source.* FROM public.capacity_source source
  WHERE EXISTS(SELECT 1 FROM public.capacity_workload w WHERE w.root_id=source.root_id) LOOP
  IF s.root_mutation_xid IS NOT NULL OR NOT public.capacity_retained_inventory_valid(s) THEN
   RAISE EXCEPTION 'packet evidence migration requires exact retained graph' USING ERRCODE='23514';
  END IF;
 END LOOP;
 CREATE TEMP TABLE packet_evidence_resize ON COMMIT DROP AS
 SELECT w.root_id,a.id,a.pool_id,a.byte_limit AS previous_bytes,
  LEAST((w.plan#>>'{Budget,Context,Bytes}')::numeric,n.records::numeric*9928704)::bigint AS next_bytes,to_jsonb(a)-'byte_limit' AS unchanged
 FROM public.capacity_workload w JOIN public.capacity_source source_row ON source_row.root_id=w.root_id
 JOIN public.custody_allocation a ON a.id=w.allocation_id
 CROSS JOIN LATERAL (SELECT LEAST((w.plan#>>'{Budget,Context,Bytes}')::bigint/1544192,
  (w.plan#>>'{Budget,Context,Objects}')::bigint/4,512) AS records) n;
 IF EXISTS(SELECT 1 FROM packet_evidence_resize r JOIN public.custody_allocation a ON a.id=r.id
  JOIN public.capacity_workload w ON w.allocation_id=a.id
  WHERE r.next_bytes<0 OR a.charged_bytes>r.next_bytes OR
   r.next_bytes>(w.plan#>>'{Budget,Context,Bytes}')::bigint OR
   r.next_bytes>(w.plan#>>'{Budget,Protected,Bytes}')::bigint) THEN
  RAISE EXCEPTION 'packet evidence resize cannot discard charges or exceed original funding' USING ERRCODE='23514';
 END IF;
 CREATE TEMP TABLE packet_evidence_pools ON COMMIT DROP AS
 SELECT p.id,p.allocated_bytes AS previous_bytes,to_jsonb(p)-'allocated_bytes' AS unchanged,
  COALESCE(sum(r.next_bytes-r.previous_bytes),0)::bigint AS delta
 FROM public.custody_pool p JOIN packet_evidence_resize r ON r.pool_id=p.id GROUP BY p.id;
 IF EXISTS(SELECT 1 FROM packet_evidence_pools r JOIN public.custody_pool p ON p.id=r.id
  WHERE p.allocated_bytes+r.delta<0 OR p.allocated_bytes+r.delta>p.byte_limit) THEN
  RAISE EXCEPTION 'packet evidence pool cannot cover retained child bytes' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- Only this named producer-ownership trigger is suspended, while its table is
-- exclusively locked. All constraints remain active. No runtime bypass exists.
ALTER TABLE public.custody_allocation DISABLE TRIGGER aaa_capacity_configuration;
UPDATE public.custody_allocation a SET byte_limit=r.next_bytes
 FROM packet_evidence_resize r WHERE a.id=r.id AND a.byte_limit<>r.next_bytes;
ALTER TABLE public.custody_allocation ENABLE TRIGGER aaa_capacity_configuration;
UPDATE public.custody_pool p SET allocated_bytes=p.allocated_bytes+r.delta
 FROM packet_evidence_pools r WHERE p.id=r.id AND r.delta<>0;
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
  'Evidence',jsonb_build_object('Bytes',LEAST((context_slice->>'Bytes')::numeric,n::numeric*9928704)::bigint,'Objects',n*4),
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
-- +goose StatementBegin
DO $$
DECLARE s public.capacity_source;
BEGIN
 IF EXISTS(SELECT 1 FROM packet_evidence_resize r JOIN public.custody_allocation a ON a.id=r.id
  WHERE a.byte_limit<>r.next_bytes OR to_jsonb(a)-'byte_limit' IS DISTINCT FROM r.unchanged) OR
 EXISTS(SELECT 1 FROM packet_evidence_pools r JOIN public.custody_pool p ON p.id=r.id
  WHERE p.allocated_bytes<>r.previous_bytes+r.delta OR to_jsonb(p)-'allocated_bytes' IS DISTINCT FROM r.unchanged) OR
 NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.custody_allocation'::regclass
  AND tgname='aaa_capacity_configuration' AND tgenabled='O') THEN
  RAISE EXCEPTION 'packet evidence migration changed original identity, spend or deadlines' USING ERRCODE='23514';
 END IF;
 FOR s IN SELECT source.* FROM public.capacity_source source
  WHERE EXISTS(SELECT 1 FROM public.capacity_workload w WHERE w.root_id=source.root_id) LOOP
  IF NOT public.capacity_retained_inventory_valid(s) THEN
   RAISE EXCEPTION 'packet evidence migration produced a nonexact graph' USING ERRCODE='23514';
  END IF;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Refuse atomically if retained charges cannot fit the historical small child.
-- Lock the complete retained graph before validating or changing any child.
-- Runtime credentials cannot disable triggers or execute this migration.
LOCK TABLE public.capacity_source,public.capacity_pool,public.capacity_cluster,
 public.capacity_namespace,public.capacity_workload,public.custody_pool,
 public.custody_allocation,public.context_storage_binding,public.context_control_pool,
 public.context_control_account,public.download_allocation,public.download_control_allocation,
 public.download_native_backing,public.download_stop_backing,public.capture_audit_allocation,
 public.operation_audit_pool,public.processing_root,public.download_stop_pool,public.capture_audit_root
 IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
DECLARE s public.capacity_source;
BEGIN
 FOR s IN SELECT source.* FROM public.capacity_source source
  WHERE EXISTS(SELECT 1 FROM public.capacity_workload w WHERE w.root_id=source.root_id) LOOP
  IF s.root_mutation_xid IS NOT NULL OR NOT public.capacity_retained_inventory_valid(s) THEN
   RAISE EXCEPTION 'packet evidence migration requires exact retained graph' USING ERRCODE='23514';
  END IF;
 END LOOP;
 CREATE TEMP TABLE packet_evidence_resize ON COMMIT DROP AS
 SELECT w.root_id,a.id,a.pool_id,a.byte_limit AS previous_bytes,
  n.records*1544192 AS next_bytes,to_jsonb(a)-'byte_limit' AS unchanged
 FROM public.capacity_workload w JOIN public.capacity_source source_row ON source_row.root_id=w.root_id
 JOIN public.custody_allocation a ON a.id=w.allocation_id
 CROSS JOIN LATERAL (SELECT LEAST((w.plan#>>'{Budget,Context,Bytes}')::bigint/1544192,
  (w.plan#>>'{Budget,Context,Objects}')::bigint/4,512) AS records) n;
 IF EXISTS(SELECT 1 FROM packet_evidence_resize r JOIN public.custody_allocation a ON a.id=r.id
  JOIN public.capacity_workload w ON w.allocation_id=a.id
  WHERE r.next_bytes<0 OR a.charged_bytes>r.next_bytes OR
   r.next_bytes>(w.plan#>>'{Budget,Context,Bytes}')::bigint OR
   r.next_bytes>(w.plan#>>'{Budget,Protected,Bytes}')::bigint) THEN
  RAISE EXCEPTION 'packet evidence resize cannot discard charges or exceed original funding' USING ERRCODE='23514';
 END IF;
 CREATE TEMP TABLE packet_evidence_pools ON COMMIT DROP AS
 SELECT p.id,p.allocated_bytes AS previous_bytes,to_jsonb(p)-'allocated_bytes' AS unchanged,
  COALESCE(sum(r.next_bytes-r.previous_bytes),0)::bigint AS delta
 FROM public.custody_pool p JOIN packet_evidence_resize r ON r.pool_id=p.id GROUP BY p.id;
 IF EXISTS(SELECT 1 FROM packet_evidence_pools r JOIN public.custody_pool p ON p.id=r.id
  WHERE p.allocated_bytes+r.delta<0 OR p.allocated_bytes+r.delta>p.byte_limit) THEN
  RAISE EXCEPTION 'packet evidence pool cannot cover retained child bytes' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- Only this named producer-ownership trigger is suspended, while its table is
-- exclusively locked. All constraints remain active. No runtime bypass exists.
ALTER TABLE public.custody_allocation DISABLE TRIGGER aaa_capacity_configuration;
UPDATE public.custody_allocation a SET byte_limit=r.next_bytes
 FROM packet_evidence_resize r WHERE a.id=r.id AND a.byte_limit<>r.next_bytes;
ALTER TABLE public.custody_allocation ENABLE TRIGGER aaa_capacity_configuration;
UPDATE public.custody_pool p SET allocated_bytes=p.allocated_bytes+r.delta
 FROM packet_evidence_pools r WHERE p.id=r.id AND r.delta<>0;
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
-- +goose StatementBegin
DO $$
DECLARE s public.capacity_source;
BEGIN
 IF EXISTS(SELECT 1 FROM packet_evidence_resize r JOIN public.custody_allocation a ON a.id=r.id
  WHERE a.byte_limit<>r.next_bytes OR to_jsonb(a)-'byte_limit' IS DISTINCT FROM r.unchanged) OR
 EXISTS(SELECT 1 FROM packet_evidence_pools r JOIN public.custody_pool p ON p.id=r.id
  WHERE p.allocated_bytes<>r.previous_bytes+r.delta OR to_jsonb(p)-'allocated_bytes' IS DISTINCT FROM r.unchanged) OR
 NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.custody_allocation'::regclass
  AND tgname='aaa_capacity_configuration' AND tgenabled='O') THEN
  RAISE EXCEPTION 'packet evidence migration changed original identity, spend or deadlines' USING ERRCODE='23514';
 END IF;
 FOR s IN SELECT source.* FROM public.capacity_source source
  WHERE EXISTS(SELECT 1 FROM public.capacity_workload w WHERE w.root_id=source.root_id) LOOP
  IF NOT public.capacity_retained_inventory_valid(s) THEN
   RAISE EXCEPTION 'packet evidence migration produced a nonexact graph' USING ERRCODE='23514';
  END IF;
 END LOOP;
END $$;
-- +goose StatementEnd
