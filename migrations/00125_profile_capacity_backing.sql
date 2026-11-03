-- +goose Up
-- ADR-290: fresh qualified roots select go-profile/v1. Historical root inputs
-- without the marker retain their exact compiler, digests, limits and charges.
-- This migration changes no retained row, original interval or issued budget.
-- +goose StatementBegin
CREATE FUNCTION capacity_context_protocol_backing_legacy(context_slice jsonb,h jsonb) RETURNS jsonb
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
REVOKE ALL ON FUNCTION capacity_context_protocol_backing_legacy(jsonb,jsonb) FROM PUBLIC;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_context_protocol_backing(context_slice jsonb,h jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE base jsonb; n bigint; nq jsonb:=h->'Native';
BEGIN
 IF NOT (h ? 'ProfileProtocol') THEN
  RETURN public.capacity_context_protocol_backing_legacy(context_slice,h);
 END IF;
 IF h->'ProfileProtocol' IS DISTINCT FROM '"go-profile/v1"'::jsonb THEN RETURN NULL; END IF;
 base:=public.capacity_context_protocol_backing_legacy(context_slice,h-'ProfileProtocol');
 IF base IS NULL THEN RETURN NULL; END IF;
 n:=(base->>'Records')::bigint;
 -- One maximum128MiB trace: final136740864 ciphertext bytes plus
 -- temporary135266304 bytes, four final objects, one upload and17parts.
 -- Authored workload funding remains the upper bound; no rounding up.
 RETURN base || jsonb_build_object(
  'Format','protected-profile-context-backing/v1',
  'Evidence',jsonb_build_object('Bytes',LEAST((context_slice->>'Bytes')::numeric,n::numeric*272007168)::bigint,
   'Objects',LEAST((context_slice->>'Objects')::bigint,n*22)),
  'WindowObjects',jsonb_build_object('Bytes',n*1048576,'Objects',n*8),
  'ProtocolSystemObjects',jsonb_build_object('Bytes',n*1769472,'Objects',n*15),
  'OutputBytes',n*268435456,'ReadBytes',n*311164928,
  'Windows',n*4,'NativeKeys',n*4,'NativeTransitionsPerRow',15,'ContentUnwraps',n*12,
  'NativeBackupBytes',n*2*(nq->>'RowBytes')::numeric*(nq->>'BackupCopies')::numeric*5,
  'NativeWALBytes',n*(nq->>'TransitionWALBytes')::numeric*(nq->>'WALCopies')::numeric*(15+4+8*4));
EXCEPTION WHEN data_exception THEN RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_context_protocol_backing(jsonb,jsonb) FROM PUBLIC;

-- +goose Down
-- A marked retained qualification cannot be reinterpreted as the old smaller
-- funding graph. Retirement uses the normal complete inventory/cleanup path.
LOCK TABLE public.capacity_source IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_source WHERE
  (qualification#>'{RootBacking,ContextHistory}') ? 'ProfileProtocol' OR
  (root_plan#>'{Input,ContextHistory}') ? 'ProfileProtocol') THEN
  RAISE EXCEPTION 'profile capacity rollback requires retirement of marked roots' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
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
DROP FUNCTION capacity_context_protocol_backing_legacy(jsonb,jsonb);
