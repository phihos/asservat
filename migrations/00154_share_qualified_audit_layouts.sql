-- +goose Up
-- ADR-323: fresh explicit share-qualified layouts. Retained old layouts keep
-- their exact formulas; no row/profile is promoted or adopted. The existing
-- profile-covers predicate continues to refuse cross-layout replacement.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_layout_valid(lane text,layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE((lane IN ('normal','resolution') AND layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3','operation-audit-history/v4')) OR (lane='identity' AND layout IN ('connector-operation-history/v1','connector-operation-history/v2')) OR (lane='processing' AND layout='processing-release-history/v1') OR (lane='capture' AND layout IN ('capture-intent-history/v1','capture-intent-history/v2')),false)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_fixed_transitions(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE layout WHEN 'operation-audit-history/v1' THEN 16 WHEN 'operation-audit-history/v2' THEN 19 WHEN 'operation-audit-history/v3' THEN 21 WHEN 'operation-audit-history/v4' THEN 24 WHEN 'connector-operation-history/v1' THEN 32 WHEN 'connector-operation-history/v2' THEN 40 WHEN 'processing-release-history/v1' THEN 32 WHEN 'capture-intent-history/v1' THEN 32 WHEN 'capture-intent-history/v2' THEN 34 ELSE NULL END::bigint
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_verifier_backed(layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(layout IN ('operation-audit-history/v3','operation-audit-history/v4','connector-operation-history/v1','connector-operation-history/v2','processing-release-history/v1','capture-intent-history/v1','capture-intent-history/v2'),false)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_minimum_row(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN layout IN ('connector-operation-history/v1','connector-operation-history/v2') THEN 1048576 WHEN layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3','operation-audit-history/v4','processing-release-history/v1','capture-intent-history/v1','capture-intent-history/v2') THEN 131072 ELSE NULL END::bigint
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_capture_audit_allocation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.operation_audit_pool; control public.context_control_account; root public.capture_audit_root; n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'capture audit allocation retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=NEW.root_id;
 IF NOT public.capture_audit_role_ok(NEW.root_id,'source') THEN RAISE EXCEPTION 'capture audit source unavailable' USING ERRCODE='23514';END IF;
 -- Caller holds recovery and permission first. This guard does not acquire
 -- storage/control locks in reverse order; their accepted rows are immutable
 -- identities, and the common permission lock serializes configuration.
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='capture' FOR UPDATE;
 SELECT * INTO STRICT control FROM public.context_control_account WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id;
 n:=clock_timestamp();
 IF n>=root.valid_until OR n>=pool.valid_until OR n>=NEW.valid_until OR NOT control.configured OR NEW.guaranteed_records<control.full_limit OR NEW.guaranteed_records>pool.records_per_account OR NEW.account_version<>pool.account_version OR
  NEW.policy->>'Lane' IS DISTINCT FROM 'capture' OR NOT COALESCE(NEW.policy->'History'->>'Layout' IN ('capture-intent-history/v1','capture-intent-history/v2'),false) OR (NEW.policy->>'RootID')::uuid<>NEW.root_id OR (NEW.policy->>'InstallationID')::uuid<>root.installation_id OR (NEW.policy->>'BackingRevision')::bigint<>pool.revision OR n>=(NEW.policy->>'ValidUntil')::timestamptz THEN
  RAISE EXCEPTION 'capture audit backing unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR (SELECT count(*) FROM public.capture_audit_allocation WHERE root_id=NEW.root_id)>=pool.account_limit THEN RAISE EXCEPTION 'capture audit account reservation exhausted' USING ERRCODE='23514';END IF;
 ELSE
  IF ROW(NEW.root_id,NEW.allocation_id,NEW.account_version,NEW.account_digest) IS DISTINCT FROM ROW(OLD.root_id,OLD.allocation_id,OLD.account_version,OLD.account_digest) OR NEW.revision<>OLD.revision+1 OR NEW.guaranteed_records<OLD.guaranteed_records THEN RAISE EXCEPTION 'capture audit account cannot reset or shrink' USING ERRCODE='23514';END IF;
  IF ((NEW.policy-ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil']) IS DISTINCT FROM (OLD.policy-ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil'])) THEN RAISE EXCEPTION 'capture audit account qualification changed' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_capture_audit_access() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r uuid;l text;source_role boolean;admit_role boolean;journal_role boolean;ack_role boolean;cleanup_role boolean;verifier_role boolean;finalizer_role boolean;completion jsonb;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_TABLE_NAME NOT IN('operation_audit_pool','operation_audit_account','operation_audit','operation_audit_lifecycle','operation_audit_history') THEN RAISE EXCEPTION 'invalid capture audit boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN r:=OLD.root_id;l:=OLD.lane;ELSE r:=NEW.root_id;l:=NEW.lane;END IF;
 IF l<>'capture' THEN
  IF NOT public.capture_audit_login_private() THEN
   IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
  END IF;
  IF l NOT IN ('normal','resolution') OR NOT (public.capture_audit_role_ok(r,'cleanup') OR public.capture_audit_role_ok(r,'verifier') OR public.capture_audit_role_ok(r,'finalizer')) THEN
   RAISE EXCEPTION 'worker cleanup role cannot use this lane' USING ERRCODE='23514';
  END IF;
 END IF;
 source_role:=public.capture_audit_role_ok(r,'source');admit_role:=public.capture_audit_role_ok(r,'admission');journal_role:=public.capture_audit_role_ok(r,'journal');ack_role:=public.capture_audit_role_ok(r,'acknowledge');cleanup_role:=public.capture_audit_role_ok(r,'cleanup');verifier_role:=public.capture_audit_role_ok(r,'verifier');finalizer_role:=public.capture_audit_role_ok(r,'finalizer');
 IF TG_TABLE_NAME='operation_audit_pool' THEN
  IF NOT source_role AND NOT(pg_trigger_depth()>1 AND (admit_role OR finalizer_role)) THEN RAISE EXCEPTION 'capture audit backing role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_account' THEN
  IF pg_trigger_depth()<2 OR NOT(admit_role OR finalizer_role) THEN RAISE EXCEPTION 'capture audit account role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_history' THEN
  IF NOT finalizer_role THEN RAISE EXCEPTION 'capture audit history role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit' THEN
  IF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'capture audit retirement role unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='INSERT' THEN
   IF NOT admit_role OR NOT COALESCE(NEW.intent->'Lifecycle'->'Policy'->'History'->>'Layout' IN ('capture-intent-history/v1','capture-intent-history/v2'),false) OR NEW.intent->>'Name' IS DISTINCT FROM 'persist_capture_intent' THEN RAISE EXCEPTION 'capture audit admission role unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_receipt','outcome_receipt']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_receipt','outcome_receipt']) THEN RAISE EXCEPTION 'capture audit acknowledgement cannot create work' USING ERRCODE='23514';END IF;
  ELSIF NOT journal_role OR ROW(NEW.intent_receipt,NEW.outcome_receipt) IS DISTINCT FROM ROW(OLD.intent_receipt,OLD.outcome_receipt) THEN RAISE EXCEPTION 'capture audit writer cannot acknowledge itself' USING ERRCODE='23514';END IF;
 ELSE
  IF TG_OP='UPDATE' THEN
   FOREACH completion IN ARRAY ARRAY[NEW.intent_completion,NEW.outcome_completion,NEW.certificate_completion] LOOP
    IF completion IS NOT NULL THEN
     PERFORM public.connector_digest(completion->'RecordDigest');
     PERFORM public.connector_digest(completion->'Receipt'->'SHA256');
    END IF;
   END LOOP;
  END IF;
  IF TG_OP='INSERT' THEN
   IF NOT admit_role OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'capture audit lifecycle admission unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'capture audit lifecycle retirement unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_completion','outcome_completion']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_completion','outcome_completion']) THEN RAISE EXCEPTION 'capture writer acknowledgement scope unavailable' USING ERRCODE='23514';END IF;
  ELSIF verifier_role THEN
   IF (to_jsonb(NEW)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) THEN RAISE EXCEPTION 'capture verifier cannot create cleanup work' USING ERRCODE='23514';END IF;
  ELSIF finalizer_role THEN
   IF (to_jsonb(NEW)-'finalization_xid') IS DISTINCT FROM (to_jsonb(OLD)-'finalization_xid') THEN RAISE EXCEPTION 'capture finalizer cannot acknowledge cleanup' USING ERRCODE='23514';END IF;
  ELSIF cleanup_role THEN
   IF ROW(NEW.intent_completion,NEW.outcome_completion,NEW.certificate_verify_attempts,NEW.certificate_receipt,NEW.certificate_acknowledged_at,NEW.terminal_acknowledged_at,NEW.finalization_xid) IS DISTINCT FROM ROW(OLD.intent_completion,OLD.outcome_completion,OLD.certificate_verify_attempts,OLD.certificate_receipt,OLD.certificate_acknowledged_at,OLD.terminal_acknowledged_at,OLD.finalization_xid) THEN RAISE EXCEPTION 'capture cleanup cannot acknowledge itself' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'capture lifecycle role unavailable' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION configure_capture_audit_backing(r uuid,p jsonb,a jsonb,observed timestamptz,fresh_until timestamptz) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.capture_audit_root;trust public.fleet_current_trust;pool public.operation_audit_pool;account public.capture_audit_allocation;n timestamptz;started timestamptz:=clock_timestamp();until_at timestamptz;pool_missing boolean;account_missing boolean;pool_revision bigint:=(p->>'ExpectedRevision')::bigint;account_revision bigint:=(a->>'ExpectedRevision')::bigint;allocation uuid:=(a->'Account'->>'AllocationID')::uuid;desired jsonb:=a->'Account';pol jsonb:=desired->'Policy';
BEGIN
 IF NOT public.capture_audit_role_ok(r,'source') OR octet_length(p::text)>4096 OR octet_length(a::text)>8192 THEN RAISE EXCEPTION 'capture backing source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO pool FROM public.operation_audit_pool WHERE root_id=r AND lane='capture' FOR UPDATE;pool_missing:=NOT FOUND;
 SELECT * INTO account FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation FOR UPDATE;account_missing:=NOT FOUND;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',fresh_until,trust.fresh_until,root.valid_until,(p->>'ValidUntil')::timestamptz,(a->>'ValidUntil')::timestamptz,(pol->>'ValidUntil')::timestamptz);
 IF NOT COALESCE(observed<=n AND fresh_until>observed AND fresh_until<=observed+interval '5 seconds' AND n<until_at AND NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND (p->>'RootID')::uuid=r AND p->>'Lane'='capture' AND pool_revision BETWEEN 0 AND 1152921504606846975 AND account_revision BETWEEN 0 AND 1152921504606846975 AND (desired->>'RootID')::uuid=r AND (desired->>'Revision')::bigint=account_revision+1 AND desired->>'AccountVersion'=p->>'AccountVersion' AND (desired->>'RetainedSeconds')::bigint=(p->>'RetainedSeconds')::bigint AND (pol->>'BackingRevision')::bigint=pool_revision+1 AND (pol->>'InstallationID')::uuid=root.installation_id AND (pol->>'RootID')::uuid=r AND pol->>'Lane'='capture' AND pol->'History'->>'Layout' IN ('capture-intent-history/v1','capture-intent-history/v2') AND (pol->>'MetadataSlots')::bigint>=(p->>'Accounts')::bigint*(p->>'RecordsPerAccount')::bigint AND public.connector_digest(desired->'AccountDigest') IS NOT NULL,false) THEN RAISE EXCEPTION 'capture backing current observation unavailable' USING ERRCODE='23514';END IF;
 IF pool_missing THEN
  IF pool_revision<>0 THEN RAISE EXCEPTION 'capture backing pool missing' USING ERRCODE='23514';END IF;
  INSERT INTO public.operation_audit_pool(root_id,lane,account_version,revision,paused,valid_until,account_limit,records_per_account,retained_seconds)
  VALUES(r,'capture',p->>'AccountVersion',1,(p->>'Paused')::boolean,(p->>'ValidUntil')::timestamptz,(p->>'Accounts')::bigint,(p->>'RecordsPerAccount')::bigint,(p->>'RetainedSeconds')::bigint);
 ELSIF pool.revision=pool_revision+1 THEN
  IF ROW(pool.account_version,pool.paused,pool.valid_until,pool.account_limit,pool.records_per_account,pool.retained_seconds) IS DISTINCT FROM ROW(p->>'AccountVersion',(p->>'Paused')::boolean,(p->>'ValidUntil')::timestamptz,(p->>'Accounts')::bigint,(p->>'RecordsPerAccount')::bigint,(p->>'RetainedSeconds')::bigint) THEN RAISE EXCEPTION 'capture backing pool replay mismatch' USING ERRCODE='23514';END IF;
 ELSE
  IF pool.revision<>pool_revision OR pool.account_version<>p->>'AccountVersion' THEN RAISE EXCEPTION 'capture backing pool revision mismatch' USING ERRCODE='23514';END IF;
  UPDATE public.operation_audit_pool SET revision=revision+1,paused=(p->>'Paused')::boolean,valid_until=(p->>'ValidUntil')::timestamptz,account_limit=(p->>'Accounts')::bigint,records_per_account=(p->>'RecordsPerAccount')::bigint,retained_seconds=(p->>'RetainedSeconds')::bigint WHERE root_id=r AND lane='capture';
 END IF;
 IF account_missing THEN
  IF account_revision<>0 THEN RAISE EXCEPTION 'capture backing account missing' USING ERRCODE='23514';END IF;
  INSERT INTO public.capture_audit_allocation(root_id,allocation_id,account_version,account_digest,revision,paused,valid_until,guaranteed_records,policy)
  VALUES(r,allocation,desired->>'AccountVersion',public.connector_digest(desired->'AccountDigest'),1,(a->>'Paused')::boolean,(a->>'ValidUntil')::timestamptz,(desired->>'Records')::bigint,pol);
 ELSIF account.revision=account_revision+1 THEN
  IF ROW(account.account_version,account.account_digest,account.paused,account.valid_until,account.guaranteed_records,account.policy) IS DISTINCT FROM ROW(desired->>'AccountVersion',public.connector_digest(desired->'AccountDigest'),(a->>'Paused')::boolean,(a->>'ValidUntil')::timestamptz,(desired->>'Records')::bigint,pol) THEN RAISE EXCEPTION 'capture backing account replay mismatch' USING ERRCODE='23514';END IF;
 ELSE
  IF account.revision<>account_revision THEN RAISE EXCEPTION 'capture backing account revision mismatch' USING ERRCODE='23514';END IF;
  UPDATE public.capture_audit_allocation SET revision=revision+1,paused=(a->>'Paused')::boolean,valid_until=(a->>'ValidUntil')::timestamptz,guaranteed_records=(desired->>'Records')::bigint,policy=pol WHERE root_id=r AND allocation_id=allocation;
 END IF;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capture backing expired after lock' USING ERRCODE='23514';END IF;
 RETURN until_at;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_context_protocol_backing_legacy(context_slice jsonb,h jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE c jsonb:=h->'Capture';nq jsonb:=h->'Native';s jsonb:=h->'Stop';k text;n bigint;
 artifact_bytes constant bigint:=4096+65536+262144+65536+1048576+65536+32768;
 capture_backup numeric;capture_wal numeric;native_backup numeric;native_wal numeric;stop_backup numeric;stop_wal numeric;
BEGIN
 IF NOT public.capacity_json_fields(context_slice,ARRAY['Bytes','Objects']) OR
  NOT public.capacity_json_integer(context_slice->'Bytes',1,9223372036854775807) OR NOT public.capacity_json_integer(context_slice->'Objects',1,9223372036854775807) OR
  NOT public.capacity_json_fields(h,ARRAY['Capture','CapturePurgeLeases','Native','Stop']) OR
  NOT public.capacity_json_fields(c,ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
  NOT COALESCE(c->>'Layout' IN ('capture-intent-history/v1','capture-intent-history/v2'),false) OR NOT public.capacity_json_uuid(c->'ID') OR NOT public.capacity_json_digest(c->'Digest') OR
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
 capture_wal:=n*2*(c->>'MaximumTransitionWALBytes')::numeric*(c->>'WALCopies')::numeric*(public.operation_audit_history_fixed_transitions(c->>'Layout')+3*(h->>'CapturePurgeLeases')::bigint);
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_root_audit_valid(v jsonb,r uuid,i uuid,l text,layout_name text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb:=v->'Policy';h jsonb:=p->'History';k text;slots numeric;b numeric;w numeric;transitions bigint;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Accounts','RecordsPerAccount','RetainedSeconds','Policy']) OR
  NOT public.capacity_json_integer(v->'Accounts',1,1000000) OR NOT public.capacity_json_integer(v->'RecordsPerAccount',1,1000000) OR
  NOT public.capacity_json_integer(v->'RetainedSeconds',60,316224000) OR
  NOT public.capacity_json_fields(p,ARRAY['RootID','Lane','InstallationID','StoreID','PolicyID','BackupProfileID','PolicyDigest','BackupProfileDigest','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','ValidUntil','MaxPurgeLeases','History','OverdueTerminal']) OR
  NOT public.capacity_json_fields(h,ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
  (p->>'RootID')::uuid<>r OR (p->>'InstallationID')::uuid<>i OR p->>'Lane' IS DISTINCT FROM l OR h->>'Layout' IS DISTINCT FROM layout_name OR
  NOT public.operation_audit_history_layout_valid(l,layout_name) OR p->>'OverdueTerminal' IS DISTINCT FROM 'overdue-original/v1' OR
  NOT public.capacity_json_integer(p->'BackingRevision',1,1) OR NOT public.capacity_json_integer(p->'MetadataSlots',1,1000000000000) OR
  NOT public.capacity_json_integer(p->'BackupReservedBytes',1,9223372036854775807) OR NOT public.capacity_json_integer(p->'WALReservedBytes',1,9223372036854775807) OR
  NOT public.capacity_json_integer(p->'BackupHorizonSeconds',0,316224000) OR NOT public.capacity_json_integer(p->'CleanupBudgetSeconds',1,86400) OR
  NOT public.capacity_json_integer(p->'ProofWindowSeconds',1,316224000) OR NOT public.capacity_json_integer(p->'MaxPurgeLeases',2,32) OR
  NOT public.capacity_json_text(p->'ValidUntil',20,40) OR NOT isfinite((p->>'ValidUntil')::timestamptz) OR
  NOT public.capacity_json_uuid(h->'ID') OR NOT public.capacity_json_digest(h->'Digest') OR
  NOT public.capacity_json_integer(h->'MaximumRowFootprintBytes',131072,16777216) OR NOT public.capacity_json_integer(h->'MaximumTransitionWALBytes',131072,67108864) OR
  NOT public.capacity_json_integer(h->'BackupCopies',1,64) OR NOT public.capacity_json_integer(h->'WALCopies',1,64) THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['RootID','InstallationID','StoreID','PolicyID','BackupProfileID'] LOOP IF NOT public.capacity_json_uuid(p->k) THEN RETURN false;END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['PolicyDigest','BackupProfileDigest'] LOOP IF NOT public.capacity_json_digest(p->k) THEN RETURN false;END IF;END LOOP;
 slots:=(v->>'Accounts')::numeric*(v->>'RecordsPerAccount')::numeric;
 transitions:=CASE WHEN layout_name='operation-audit-history/v3' THEN 21 WHEN layout_name='operation-audit-history/v4' THEN 24 WHEN layout_name='capture-intent-history/v2' THEN 34 WHEN layout_name IN ('capture-intent-history/v1','processing-release-history/v1') THEN 32 ELSE 0 END;
 b:=2*(h->>'MaximumRowFootprintBytes')::numeric*(h->>'BackupCopies')::numeric;
 w:=2*(h->>'WALCopies')::numeric*((h->>'MaximumTransitionWALBytes')::numeric*(transitions+3*(p->>'MaxPurgeLeases')::bigint)+CASE WHEN layout_name='operation-audit-history/v4' THEN 8388608 ELSE 0 END);
 RETURN transitions>0 AND slots=(p->>'MetadataSlots')::numeric AND
  (p->>'BackupReservedBytes')::numeric>=slots*b AND (p->>'WALReservedBytes')::numeric>=slots*w AND
  (v->>'RetainedSeconds')::bigint>2*(p->>'BackupHorizonSeconds')::bigint+3*(p->>'CleanupBudgetSeconds')::bigint+(p->>'ProofWindowSeconds')::bigint+30;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_compile_root(input_value jsonb,system_pool jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=input_value;q jsonb:=v->'Metadata';env jsonb:=v->'Envelope';h jsonb:=v->'ContextHistory';
 c jsonb:=v->'Capture';ps jsonb:=v->'ProcessingState';lane jsonb;k text;work jsonb;root uuid;installation uuid;
 accounts bigint;per_account bigint;records bigint;slots numeric;
 object_bytes numeric;object_count numeric;sql_bytes numeric:=0;ordinary_sql numeric;backup_bytes numeric:=0;wal_bytes numeric:=0;keys numeric:=0;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Format','RootID','InstallationID','QualificationID','QualificationDigest','SystemPoolUID','AccountVersion','Accounts','RecordsPerAccount','AdmissionSeconds','Capture','Normal','Resolution','Processing','ProcessingState','ProcessingEpoch','ProcessingSourceUID','ProcessingProtectionDigest','ContextHistory','StopRetainedSeconds','Metadata','Envelope']) OR
  v->>'Format' IS DISTINCT FROM 'protected-capacity-root/v1' OR octet_length(v::text)>65536 OR
  NOT public.capacity_json_uuid(v->'RootID') OR NOT public.capacity_json_uuid(v->'InstallationID') OR NOT public.capacity_json_uuid(v->'QualificationID') OR NOT public.capacity_json_digest(v->'QualificationDigest') OR
  NOT public.capacity_json_text(v->'SystemPoolUID',1,64) OR NOT public.capacity_json_text(v->'AccountVersion',1,64) OR
  NOT public.capacity_json_integer(v->'Accounts',1,16) OR NOT public.capacity_json_integer(v->'RecordsPerAccount',1,512) OR
  NOT public.capacity_json_integer(v->'AdmissionSeconds',60,86400) OR NOT public.capacity_json_uuid(v->'ProcessingEpoch') OR NOT public.capacity_json_uuid(v->'ProcessingSourceUID') OR NOT public.capacity_json_digest(v->'ProcessingProtectionDigest') OR
  system_pool->>'Format' IS DISTINCT FROM 'capacity-pool/v1' OR system_pool->>'UID' IS DISTINCT FROM v->>'SystemPoolUID' OR
  NOT public.capacity_json_fields(system_pool->'System',ARRAY['Bytes','Objects']) OR
  NOT public.capacity_json_integer(system_pool->'System'->'Bytes',1,9223372036854775807) OR NOT public.capacity_json_integer(system_pool->'System'->'Objects',1,9223372036854775807) OR
  NOT public.capacity_json_fields(q,ARRAY['ID','Layout','Digest','FixedRowBytes','AccountRowBytes','RecordRowBytes','RecordWALBytes','RecordKeyAttempts','TransitionWALBytes','BackupCopies','WALCopies','ConfigurationTransitions']) OR
  q->>'Layout' IS DISTINCT FROM 'capacity-root-history/v1' OR NOT public.capacity_json_uuid(q->'ID') OR NOT public.capacity_json_digest(q->'Digest') OR
  NOT public.capacity_json_integer(q->'FixedRowBytes',1048576,67108864) OR NOT public.capacity_json_integer(q->'AccountRowBytes',262144,16777216) OR
  NOT public.capacity_json_integer(q->'RecordRowBytes',131072,16777216) OR NOT public.capacity_json_integer(q->'RecordWALBytes',1048576,268435456) OR
  NOT public.capacity_json_integer(q->'RecordKeyAttempts',16,256) OR NOT public.capacity_json_integer(q->'TransitionWALBytes',1048576,268435456) OR
  NOT public.capacity_json_integer(q->'BackupCopies',1,64) OR NOT public.capacity_json_integer(q->'WALCopies',1,64) OR
  NOT public.capacity_json_integer(q->'ConfigurationTransitions',3,1000000) OR
  NOT public.capacity_json_fields(env,ARRAY['SystemObjects','SQLBytes','BackupBytes','WALBytes','KeyAttempts']) OR
  NOT public.capacity_json_fields(env->'SystemObjects',ARRAY['Bytes','Objects']) THEN RETURN NULL;END IF;
 FOREACH k IN ARRAY ARRAY['SQLBytes','BackupBytes','WALBytes','KeyAttempts'] LOOP IF NOT public.capacity_json_integer(env->k,1,9223372036854775807) THEN RETURN NULL;END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['Bytes','Objects'] LOOP IF NOT public.capacity_json_integer(env->'SystemObjects'->k,1,9223372036854775807) THEN RETURN NULL;END IF;END LOOP;
 root:=(v->>'RootID')::uuid;installation:=(v->>'InstallationID')::uuid;accounts:=(v->>'Accounts')::bigint;per_account:=(v->>'RecordsPerAccount')::bigint;records:=accounts*per_account;
 IF NOT public.capacity_root_audit_valid(c,root,installation,'capture',c#>>'{Policy,History,Layout}') OR
  NOT public.capacity_root_audit_valid(v->'Normal',root,installation,'normal',v->'Normal'#>>'{Policy,History,Layout}') OR
  NOT public.capacity_root_audit_valid(v->'Resolution',root,installation,'resolution',v->'Resolution'#>>'{Policy,History,Layout}') OR
  NOT public.capacity_root_audit_valid(v->'Processing',root,installation,'processing','processing-release-history/v1') OR
  NOT public.capacity_processing_backing_valid(ps,root,installation,records,v->'Processing'->'Policy') OR
  (c->>'Accounts')::bigint<>accounts OR (c->>'RecordsPerAccount')::bigint<>per_account OR c->'Policy'->'History' IS DISTINCT FROM h->'Capture' OR
  c->'Policy'->'MaxPurgeLeases' IS DISTINCT FROM h->'CapturePurgeLeases' OR
  h->'Stop'->>'RootID' IS DISTINCT FROM v->>'RootID' OR h->'Stop'->>'InstallationID' IS DISTINCT FROM v->>'InstallationID' OR
  h->'Stop'->>'StoreID' IS DISTINCT FROM c->'Policy'->>'StoreID' OR NOT public.capacity_json_integer(v->'StopRetainedSeconds',60,316224000) OR
  (v->>'StopRetainedSeconds')::bigint<=2*(h->'Stop'->>'BackupHorizonSeconds')::bigint+3*(h->'Stop'->>'CleanupBudgetSeconds')::bigint+(h->'Stop'->>'ProofWindowSeconds')::bigint+30 OR
  (q->>'ConfigurationTransitions')::bigint<3+3*accounts THEN RETURN NULL;END IF;
 work:=public.capacity_context_protocol_backing(jsonb_build_object('Bytes',per_account*1544192,'Objects',per_account*4),h);
 IF work IS NULL OR (work->>'Records')::bigint<>per_account OR
  (c->'Policy'->>'BackupReservedBytes')::numeric<>accounts*(work->>'CaptureBackupBytes')::numeric OR
  (c->'Policy'->>'WALReservedBytes')::numeric<>accounts*(work->>'CaptureWALBytes')::numeric THEN RETURN NULL;END IF;
 object_bytes:=accounts*(work->'ProtocolSystemObjects'->>'Bytes')::numeric;object_count:=accounts*(work->'ProtocolSystemObjects'->>'Objects')::numeric;
 sql_bytes:=(1+(ps->>'MaxRootTransitions')::numeric+(ps->>'MaxCaptures')::numeric+17*(ps->>'MaxRules')::numeric)*(ps->'History'->>'RowBytes')::numeric;
 backup_bytes:=(ps->>'BackupBytes')::numeric;wal_bytes:=(ps->>'WALBytes')::numeric;
 FOREACH k IN ARRAY ARRAY['Normal','Resolution','Processing'] LOOP
  lane:=v->k;
  IF lane->'Policy'->>'StoreID' IS DISTINCT FROM c->'Policy'->>'StoreID' OR
   (lane->'Policy'->>'ValidUntil')::timestamptz IS DISTINCT FROM (c->'Policy'->>'ValidUntil')::timestamptz THEN RETURN NULL;END IF;
  slots:=(lane->'Policy'->>'MetadataSlots')::numeric;
  object_bytes:=object_bytes+slots*131072;object_count:=object_count+slots*2;
  sql_bytes:=sql_bytes+slots*(lane->'Policy'->'History'->>'MaximumRowFootprintBytes')::numeric;
  backup_bytes:=backup_bytes+(lane->'Policy'->>'BackupReservedBytes')::numeric;wal_bytes:=wal_bytes+(lane->'Policy'->>'WALReservedBytes')::numeric;keys:=keys+slots*13;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['CaptureBackupBytes','NativeBackupBytes','StopBackupBytes'] LOOP backup_bytes:=backup_bytes+accounts*(work->>k)::numeric;END LOOP;
 FOREACH k IN ARRAY ARRAY['CaptureWALBytes','NativeWALBytes','StopWALBytes'] LOOP wal_bytes:=wal_bytes+accounts*(work->>k)::numeric;END LOOP;
 FOREACH k IN ARRAY ARRAY['CaptureKeyAttempts','StopKeyAttempts','ArtifactWraps','PreparationUnwraps','ContentUnwraps'] LOOP keys:=keys+accounts*(work->>k)::numeric;END LOOP;
 ordinary_sql:=(q->>'FixedRowBytes')::numeric+accounts*(q->>'AccountRowBytes')::numeric+records*(q->>'RecordRowBytes')::numeric;
 sql_bytes:=sql_bytes+ordinary_sql+records*(h->'Capture'->>'MaximumRowFootprintBytes')::numeric+records*(h->'Stop'->>'MaximumRowFootprintBytes')::numeric+accounts*((work->>'NativeRows')::numeric+(work->>'NativeKeys')::numeric)*(h->'Native'->>'RowBytes')::numeric;
 backup_bytes:=backup_bytes+2*(q->>'BackupCopies')::numeric*ordinary_sql;
 wal_bytes:=wal_bytes+(q->>'ConfigurationTransitions')::numeric*(q->>'TransitionWALBytes')::numeric*(q->>'WALCopies')::numeric+records*(q->>'RecordWALBytes')::numeric*(q->>'WALCopies')::numeric;
 keys:=keys+records*(q->>'RecordKeyAttempts')::numeric;
 IF GREATEST(object_bytes,object_count,sql_bytes,backup_bytes,wal_bytes,keys)>9223372036854775807 OR
  object_bytes>(system_pool->'System'->>'Bytes')::numeric OR object_count>(system_pool->'System'->>'Objects')::numeric OR
  object_bytes>(env->'SystemObjects'->>'Bytes')::numeric OR object_count>(env->'SystemObjects'->>'Objects')::numeric OR
  sql_bytes>(env->>'SQLBytes')::numeric OR backup_bytes>(env->>'BackupBytes')::numeric OR wal_bytes>(env->>'WALBytes')::numeric OR keys>(env->>'KeyAttempts')::numeric THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('Input',v,'Totals',jsonb_build_object('Accounts',accounts,'RecordsPerAccount',per_account,'Records',records,
  'SystemObjects',jsonb_build_object('Bytes',object_bytes::bigint,'Objects',object_count::bigint),
  'SQLBytes',sql_bytes::bigint,'BackupBytes',backup_bytes::bigint,'WALBytes',wal_bytes::bigint,'KeyAttempts',keys::bigint,'ConfigurationTransitions',(q->>'ConfigurationTransitions')::bigint));
EXCEPTION WHEN data_exception THEN RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION read_capacity_audit_profiles(r uuid,i uuid,q uuid,qd bytea,av text,observed timestamptz,original_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;p public.permission_stream;a public.operation_audit_pool;backing public.capacity_pool;processing public.processing_root;
 c jsonb;v jsonb;policy jsonb;result jsonb;n timestamptz;until_at timestamptz;lane_name text;field_name text;normalized jsonb;pool_name text;pool_plan jsonb;
BEGIN
 n:=clock_timestamp();
 IF r IS NULL OR i IS NULL OR q IS NULL OR qd IS NULL OR octet_length(qd)<>32 OR av IS NULL OR octet_length(av) NOT BETWEEN 1 AND 64 OR
  observed IS NULL OR original_until IS NULL OR NOT isfinite(observed) OR NOT isfinite(original_until) OR observed>n OR n>=original_until OR original_until>observed+interval '5 seconds' THEN
  RAISE EXCEPTION 'capacity audit profile input unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=i FOR SHARE;
 SELECT * INTO STRICT p FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 n:=clock_timestamp();c:=s.root_configuration;
 until_at:=LEAST(original_until,t.fresh_until,p.fresh_until,p.lease_until,s.fresh_until,(c->>'PlannedUntil')::timestamptz);
 IF NOT public.capacity_audit_reader_pin_valid(s) OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE oid=s.audit_reader_role AND rolname=session_user) OR
  s.installation_id<>i OR s.qualification_digest<>qd OR s.qualification->>'ID'<>q::text OR s.account_version<>av OR
  t.suspended OR t.recovery_blocked OR t.observed_at IS NULL OR t.observed_at>n OR t.fresh_until IS NULL OR
  p.suspended OR p.observed_at IS NULL OR p.observed_at>n OR p.fresh_until IS NULL OR p.lease_until IS NULL OR p.fresh_until>p.observed_at+interval '30 seconds' OR
  s.suspended OR s.observed_at IS NULL OR s.observed_at>n OR s.fresh_until IS NULL OR s.accepted_revision<1 OR s.accepted_snapshot IS NULL OR
  s.root_plan IS NULL OR s.root_mutation_xid IS NOT NULL OR NOT COALESCE(public.capacity_root_configuration_valid(c),false) OR c->'ReadyAt'='null'::jsonb OR c->'ReconciledAt'<>'null'::jsonb OR
  (c->>'ReadyAt')::timestamptz>n OR public.connector_digest(c->'PlanDigest') IS DISTINCT FROM s.root_plan_digest OR
  s.root_plan->'Input' IS DISTINCT FROM s.qualification->'RootBacking' OR n>=until_at OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.initial_audit_id AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.epoch AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'current capacity audit profile unavailable' USING ERRCODE='23514',
   -- Operator-only diagnostics use already-held rows. Do not repeat role/pin or
   -- audit lookups here; other current-guard failures remain unclassified.
   DETAIL=left(jsonb_build_object(
    'stage','capacity-audit-current',
    'cut',CASE WHEN n>=original_until THEN 'caller' WHEN n>=t.fresh_until THEN 'trust'
      WHEN n>=p.fresh_until OR n>=p.lease_until THEN 'permission' WHEN n>=s.fresh_until THEN 'source'
      WHEN n>=(c->>'PlannedUntil')::timestamptz THEN 'configuration' ELSE 'other-current' END,
    'now',n,'inputObserved',observed,'callerUntil',original_until,'effectiveUntil',until_at,
    'trustObserved',t.observed_at,'trustUntil',t.fresh_until,'trustSuspended',t.suspended,'recoveryBlocked',t.recovery_blocked,
    'permissionObserved',p.observed_at,'permissionUntil',p.fresh_until,'permissionLeaseUntil',p.lease_until,'permissionSuspended',p.suspended,
    'sourceObserved',s.observed_at,'sourceUntil',s.fresh_until,'sourceSuspended',s.suspended,
    'plannedUntil',(c->>'PlannedUntil')::timestamptz,'reconciled',c->'ReconciledAt'<>'null'::jsonb)::text,2048);END IF;
 SELECT x->'Resource'->>'Name' INTO STRICT pool_name FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Pools') x
  WHERE x->'Resource'->>'UID'=s.root_plan->'Input'->>'SystemPoolUID';
 pool_plan:=public.capacity_compile_pool(s.accepted_snapshot,pool_name);
 SELECT * INTO STRICT backing FROM public.capacity_pool WHERE root_id=r AND source_uid=s.root_plan->'Input'->>'SystemPoolUID' FOR SHARE;
 IF pool_plan IS NULL OR NOT (backing.plan IS NOT DISTINCT FROM pool_plan OR public.capacity_pool_extends(backing.plan,pool_plan)) OR public.capacity_backend_for(s,pool_plan) IS NULL OR
  public.capacity_compile_root(s.qualification->'RootBacking',pool_plan) IS DISTINCT FROM s.root_plan THEN
  RAISE EXCEPTION 'capacity audit source backing mismatch' USING ERRCODE='23514';END IF;
 result:=jsonb_build_object('Format','accepted-capacity-audit-profiles/v1','RootID',r,'InstallationID',i,'QualificationID',q,'AccountVersion',av,
  'QualificationDigest',to_jsonb(ARRAY(SELECT get_byte(qd,k) FROM generate_series(0,31) k)),
  'PlanDigest',to_jsonb(ARRAY(SELECT get_byte(s.root_plan_digest,k) FROM generate_series(0,31) k)),
  'ConfigurationRevision',(c->>'Revision')::bigint,'SourceRevision',s.accepted_revision,'ObservedAt',observed);
 -- Stable sorted lock order, also used by the root producer.
 FOREACH lane_name IN ARRAY ARRAY['normal','processing','resolution'] LOOP
  field_name:=CASE lane_name WHEN 'normal' THEN 'Normal' WHEN 'processing' THEN 'Processing' ELSE 'Resolution' END;
  v:=s.root_plan->'Input'->field_name;
  IF NOT public.capacity_root_audit_valid(v,r,i,lane_name,CASE lane_name WHEN 'processing' THEN 'processing-release-history/v1' ELSE v#>>'{Policy,History,Layout}' END) THEN
   RAISE EXCEPTION 'capacity audit layout unavailable' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=r AND lane=lane_name FOR SHARE;
  n:=clock_timestamp();until_at:=LEAST(until_at,a.valid_until);
  IF n>=until_at OR a.paused OR a.account_version<>av OR a.revision<>(c->>'Revision')::bigint OR
   a.valid_until<>(c->>'PlannedUntil')::timestamptz OR a.account_limit<>(v->>'Accounts')::bigint OR
   a.records_per_account<>(v->>'RecordsPerAccount')::bigint OR a.retained_seconds<>(v->>'RetainedSeconds')::bigint THEN
   RAISE EXCEPTION 'capacity audit pool mismatch' USING ERRCODE='23514';END IF;
  -- Only admission revision/date vary. Every other original accepted field,
  -- including H=0 backup/store/layout identity, is retained byte-for-byte.
  policy:=(v->'Policy')||jsonb_build_object('BackingRevision',a.revision,'ValidUntil',public.capacity_json_timestamp(a.valid_until));
  IF lane_name='processing' THEN
   -- The shared permission lock above serializes processing configuration and
   -- decision writers. Read without a late reverse-order business-row lock.
   -- Initialization may still be absent: this profile also precedes that first
   -- independently audited decision and never declares the root initialized.
   SELECT * INTO STRICT processing FROM public.processing_root WHERE root_id=r;
   IF processing.installation_id<>i OR processing.issuer_epoch<>t.issuer_epoch OR
    processing.epoch<>(s.root_plan->'Input'->>'ProcessingEpoch')::uuid OR
    processing.source_uid<>(s.root_plan->'Input'->>'ProcessingSourceUID')::uuid OR
    processing.protection_digest IS DISTINCT FROM public.connector_digest(s.root_plan->'Input'->'ProcessingProtectionDigest') OR
    processing.backing_revision<>(c->>'Revision')::bigint OR processing.valid_until<>a.valid_until OR
    processing.release_policy IS DISTINCT FROM policy THEN
    RAISE EXCEPTION 'processing release profile mismatch' USING ERRCODE='23514';END IF;
  END IF;
  normalized:=policy-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'];
  IF a.history_profile IS NOT NULL AND a.history_profile IS DISTINCT FROM normalized THEN
   RAISE EXCEPTION 'capacity audit history mismatch' USING ERRCODE='23514';END IF;
  result:=result||jsonb_build_object(field_name,jsonb_build_object('Policy',policy,'RetainedSeconds',a.retained_seconds));
 END LOOP;
 n:=clock_timestamp();
 IF n>=until_at OR NOT public.capacity_audit_reader_pin_valid(s) THEN RAISE EXCEPTION 'capacity audit profile expired after read' USING ERRCODE='23514';END IF;
 RETURN result||jsonb_build_object('FreshUntil',until_at);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION finish_capture_operation_retirement(r uuid,i uuid,installation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT public.capture_audit_role_ok(r,'finalizer') OR NOT EXISTS(SELECT 1 FROM public.capture_audit_root p WHERE p.root_id=r AND p.installation_id=installation) THEN RAISE EXCEPTION 'capture finalizer unavailable' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.operation_audit a WHERE a.root_id=r AND a.id=i AND a.lane IN ('capture','normal','resolution')) THEN RETURN false;END IF;
 RETURN public.finish_operation_audit_retirement(r,i,installation);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION finish_capture_operation_history(r uuid,l text,p bytea,releases timestamptz,deletes timestamptz,installation uuid) RETURNS TABLE(records bigint,overdue boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT COALESCE(l IN ('capture','normal','resolution'),false) OR NOT public.capture_audit_role_ok(r,'finalizer') OR NOT EXISTS(SELECT 1 FROM public.capture_audit_root x WHERE x.root_id=r AND x.installation_id=installation) THEN RAISE EXCEPTION 'capture history finalizer unavailable' USING ERRCODE='23514';END IF;
 RETURN QUERY SELECT h.records,h.overdue FROM public.finish_operation_audit_history(r,l,p,releases,deletes,installation) h;
END $$;
-- +goose StatementEnd

-- The existing three cleanup credentials now cover exactly these three
-- lanes. Historical capture names stay fixed; producers remain capture-only.
CREATE OR REPLACE VIEW capture_operation_pool WITH (security_barrier=true) AS
SELECT root_id, lane, account_version, revision, paused, valid_until, account_limit, records_per_account, accounts, retained_seconds, history_profile, history_backing_until, proof_window_missed FROM public.operation_audit_pool
WHERE lane IN ('capture','normal','resolution') AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

CREATE OR REPLACE VIEW capture_operation_account WITH (security_barrier=true) AS
SELECT root_id, lane, principal_digest, charged FROM public.operation_audit_account
WHERE lane IN ('capture','normal','resolution') AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

CREATE OR REPLACE VIEW capture_operation_audit WITH (security_barrier=true) AS
SELECT id, root_id, lane, issuer_epoch, principal_digest, intent, request_until, write_until, retain_until, intent_started, intent_receipt, outcome, outcome_started, outcome_receipt FROM public.operation_audit
WHERE lane IN ('capture','normal','resolution') AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

CREATE OR REPLACE VIEW capture_operation_lifecycle WITH (security_barrier=true) AS
SELECT * FROM public.operation_audit_lifecycle
WHERE lane IN ('capture','normal','resolution') AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

CREATE OR REPLACE VIEW capture_operation_history WITH (security_barrier=true) AS
SELECT root_id,lane,principal_digest,release_at,delete_by,hard_delete_by,eligible_at,installation_id,issuer_epoch,postmaster_at,database_oid,horizon_seconds,history_policy,records,overdue,drain_xid FROM public.operation_audit_history
WHERE lane IN ('capture','normal','resolution') AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

CREATE OR REPLACE VIEW connector_operation_lifecycle WITH (security_barrier=true) AS
SELECT * FROM public.operation_audit_lifecycle
WHERE lane='identity' AND current_user=session_user AND (
 public.connector_identity_role_ok(root_id,'cleanup') OR
 public.connector_identity_role_ok(root_id,'verifier') OR
 public.connector_identity_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

-- +goose StatementBegin
DO $$ BEGIN EXECUTE 'COMMENT ON TABLE public.goose_db_version IS ''asservat:oldest-binary-schema=154'''; END $$;
-- +goose StatementEnd


-- Same versioned per-slot minimum at actual lifecycle admission, not only
-- the protected root compiler. Old layouts retain their original arithmetic.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION create_operation_audit_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b jsonb; p jsonb; t public.fleet_current_trust; a public.operation_audit_pool; n timestamptz:=clock_timestamp(); budget interval; horizon interval; proof interval; prepaid boolean:=false;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid audit lifecycle source' USING ERRCODE='23514'; END IF;
 b:=NEW.intent->'Lifecycle';
 IF b IS NULL THEN RETURN NEW; END IF;
 p:=b->'Policy';
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=(p->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
 n:=clock_timestamp();
 prepaid:=public.connector_retirement_prepaid(NEW);
 budget:=make_interval(secs=>(p->>'CleanupBudgetSeconds')::double precision);
 horizon:=make_interval(secs=>(p->>'BackupHorizonSeconds')::double precision);
 proof:=make_interval(secs=>(p->>'ProofWindowSeconds')::double precision);
 IF (p ? 'OverdueTerminal' AND p->>'OverdueTerminal' IS DISTINCT FROM 'overdue-original/v1') OR b->>'Protocol' IS DISTINCT FROM 'closed-operation-audit/v1' OR jsonb_typeof(p)<>'object' OR
  NOT(p ?& ARRAY['MaxPurgeLeases','RootID','Lane','InstallationID','StoreID','PolicyID','BackupProfileID','PolicyDigest','BackupProfileDigest','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','ValidUntil']) OR
  (p->>'RootID')::uuid<>NEW.root_id OR p->>'Lane'<>NEW.lane OR (p->>'StoreID')::uuid IS NULL OR (p->>'PolicyID')::uuid IS NULL OR (p->>'BackupProfileID')::uuid IS NULL OR
  jsonb_array_length(p->'PolicyDigest')<>32 OR jsonb_array_length(p->'BackupProfileDigest')<>32 OR
  (NOT prepaid AND (p->>'BackingRevision')::bigint<>a.revision) OR (p->>'MetadataSlots')::bigint<a.account_limit*a.records_per_account OR (p->>'MetadataSlots')::bigint>1000000000000 OR
  budget<interval '1 second' OR budget>interval '1 day' OR horizon<interval '0 seconds' OR horizon>interval '3660 days' OR proof<interval '1 second' OR proof>interval '3660 days' OR
  (p->>'BackupReservedBytes')::bigint<0 OR (p->>'WALReservedBytes')::bigint<0 OR horizon>interval '0 seconds' AND ((p->>'BackupReservedBytes')::bigint<=0 OR (p->>'WALReservedBytes')::bigint<=0) OR
  n>=(p->>'ValidUntil')::timestamptz OR n>=NEW.request_until OR (NOT prepaid AND n>=a.valid_until) OR t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR
  (p->>'MaxPurgeLeases')::bigint NOT BETWEEN 2 AND 32 OR
  (b->>'HistoryReleaseAt')::timestamptz<>NEW.retain_until-horizon-budget OR (b->>'HistoryDeleteBy')::timestamptz<>NEW.retain_until-horizon OR
  (b->>'LiveRetireBy')::timestamptz<>NEW.retain_until-2*horizon-budget OR (b->>'CertificatePurgeAt')::timestamptz<>(b->>'LiveRetireBy')::timestamptz-budget OR
  (b->>'OriginalPurgeAt')::timestamptz<>(b->>'CertificatePurgeAt')::timestamptz-proof-budget OR (b->>'OriginalPurgeAt')::timestamptz<=NEW.write_until THEN
  RAISE EXCEPTION 'audit lifecycle backing unavailable' USING ERRCODE='23514'; END IF;
 -- A qualification is an exact accepted layout/profile, with conservative
 -- measured full-transaction bounds. Positive arbitrary byte counts are not a
 -- qualification; source acceptance is deliberately outside this adapter.
 IF p->'History' IS NULL OR NOT public.operation_audit_history_verifier_backed(p->'History'->>'Layout') OR NOT public.operation_audit_history_layout_valid(NEW.lane,p->'History'->>'Layout') OR
   NOT(p->'History' ?& ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
   (p->'History'->>'ID')::uuid IS NULL OR jsonb_array_length(p->'History'->'Digest')<>32 OR
   (p->'History'->>'MaximumRowFootprintBytes')::bigint NOT BETWEEN public.operation_audit_history_minimum_row(p->'History'->>'Layout') AND 16777216 OR
   (p->'History'->>'MaximumTransitionWALBytes')::bigint NOT BETWEEN 131072 AND 67108864 OR
   (p->'History'->>'BackupCopies')::bigint NOT BETWEEN 1 AND 64 OR (p->'History'->>'WALCopies')::bigint NOT BETWEEN 1 AND 64 OR
   (p->>'BackupReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumRowFootprintBytes')::bigint*(p->'History'->>'BackupCopies')::bigint OR
   (p->>'WALReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'WALCopies')::bigint*((p->'History'->>'MaximumTransitionWALBytes')::bigint*(public.operation_audit_history_fixed_transitions(p->'History'->>'Layout')+3*(p->>'MaxPurgeLeases')::bigint)+CASE WHEN p->'History'->>'Layout'='operation-audit-history/v4' THEN 8388608 ELSE 0 END) THEN
   RAISE EXCEPTION 'audit history qualification unavailable' USING ERRCODE='23514'; END IF;

 IF a.history_backing_until IS NOT NULL AND n<a.history_backing_until AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),a.history_profile) THEN
  RAISE EXCEPTION 'residual audit history backing protected' USING ERRCODE='23514'; END IF;
 -- Renewal may refresh a source/revision or increase backing. Outstanding
 -- obligations cannot be moved to a smaller/different backup or account profile.
 IF EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=NEW.root_id AND d.lane=NEW.lane AND
   NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),((d.binding->'Policy') - ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']))) OR
  EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=NEW.root_id AND h.lane=NEW.lane AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),h.history_policy)) THEN
  RAISE EXCEPTION 'outstanding audit history profile mismatch' USING ERRCODE='23514'; END IF;
 IF horizon>interval '0 seconds' THEN
  UPDATE public.operation_audit_pool SET
   history_profile=p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'],
   history_backing_until=GREATEST(history_backing_until,NEW.retain_until)
  WHERE root_id=NEW.root_id AND lane=NEW.lane;
 END IF;
 INSERT INTO public.operation_audit_lifecycle(operation_id,root_id,lane,principal_digest,installation_id,issuer_epoch,postmaster_at,database_oid,binding,original_purge_at,certificate_purge_at,live_retire_by,certificate_verify_attempts)
 VALUES(NEW.id,NEW.root_id,NEW.lane,NEW.principal_digest,t.installation_id,t.issuer_epoch,(SELECT activated_postmaster_at FROM public.fleet_trust WHERE installation_id=t.installation_id),(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),b,(b->>'OriginalPurgeAt')::timestamptz,(b->>'CertificatePurgeAt')::timestamptz,(b->>'LiveRetireBy')::timestamptz,0);
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
LOCK TABLE public.operation_audit_pool,public.operation_audit,public.operation_audit_lifecycle,public.operation_audit_history,public.evidence_share,public.capacity_source,public.capture_audit_allocation IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.operation_audit_pool WHERE history_profile#>>'{History,Layout}' IN ('operation-audit-history/v4','capture-intent-history/v2')) OR
    EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE share_effect_target IS NOT NULL OR binding#>>'{Policy,History,Layout}' IN ('operation-audit-history/v4','capture-intent-history/v2')) OR
    EXISTS(SELECT 1 FROM public.operation_audit_history WHERE history_policy#>>'{History,Layout}' IN ('operation-audit-history/v4','capture-intent-history/v2')) OR
    EXISTS(SELECT 1 FROM public.capture_audit_allocation WHERE policy#>>'{History,Layout}'='capture-intent-history/v2') OR
    EXISTS(SELECT 1 FROM public.evidence_share) OR
    EXISTS(SELECT 1 FROM public.capacity_source WHERE qualification#>>'{RootBacking,Capture,Policy,History,Layout}'='capture-intent-history/v2' OR qualification#>>'{RootBacking,Normal,Policy,History,Layout}'='operation-audit-history/v4' OR qualification#>>'{RootBacking,Resolution,Policy,History,Layout}'='operation-audit-history/v4') THEN
  RAISE EXCEPTION 'retained share-qualified layouts or paid effects prevent rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_layout_valid(lane text,layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE((lane IN ('normal','resolution') AND layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3')) OR (lane='identity' AND layout IN ('connector-operation-history/v1','connector-operation-history/v2')) OR (lane='processing' AND layout='processing-release-history/v1') OR (lane='capture' AND layout='capture-intent-history/v1'),false)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_fixed_transitions(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE layout WHEN 'operation-audit-history/v1' THEN 16 WHEN 'operation-audit-history/v2' THEN 19 WHEN 'operation-audit-history/v3' THEN 21 WHEN 'connector-operation-history/v1' THEN 32 WHEN 'connector-operation-history/v2' THEN 40 WHEN 'processing-release-history/v1' THEN 32 WHEN 'capture-intent-history/v1' THEN 32 ELSE NULL END::bigint
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_verifier_backed(layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(layout IN ('operation-audit-history/v3','connector-operation-history/v1','connector-operation-history/v2','processing-release-history/v1','capture-intent-history/v1'),false)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_minimum_row(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN layout IN ('connector-operation-history/v1','connector-operation-history/v2') THEN 1048576 WHEN layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3','processing-release-history/v1','capture-intent-history/v1') THEN 131072 ELSE NULL END::bigint
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_capture_audit_allocation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.operation_audit_pool; control public.context_control_account; root public.capture_audit_root; n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'capture audit allocation retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=NEW.root_id;
 IF NOT public.capture_audit_role_ok(NEW.root_id,'source') THEN RAISE EXCEPTION 'capture audit source unavailable' USING ERRCODE='23514';END IF;
 -- Caller holds recovery and permission first. This guard does not acquire
 -- storage/control locks in reverse order; their accepted rows are immutable
 -- identities, and the common permission lock serializes configuration.
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='capture' FOR UPDATE;
 SELECT * INTO STRICT control FROM public.context_control_account WHERE root_id=NEW.root_id AND allocation_id=NEW.allocation_id;
 n:=clock_timestamp();
 IF n>=root.valid_until OR n>=pool.valid_until OR n>=NEW.valid_until OR NOT control.configured OR NEW.guaranteed_records<control.full_limit OR NEW.guaranteed_records>pool.records_per_account OR NEW.account_version<>pool.account_version OR
  NEW.policy->>'Lane' IS DISTINCT FROM 'capture' OR NEW.policy->'History'->>'Layout' IS DISTINCT FROM 'capture-intent-history/v1' OR (NEW.policy->>'RootID')::uuid<>NEW.root_id OR (NEW.policy->>'InstallationID')::uuid<>root.installation_id OR (NEW.policy->>'BackingRevision')::bigint<>pool.revision OR n>=(NEW.policy->>'ValidUntil')::timestamptz THEN
  RAISE EXCEPTION 'capture audit backing unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR (SELECT count(*) FROM public.capture_audit_allocation WHERE root_id=NEW.root_id)>=pool.account_limit THEN RAISE EXCEPTION 'capture audit account reservation exhausted' USING ERRCODE='23514';END IF;
 ELSE
  IF ROW(NEW.root_id,NEW.allocation_id,NEW.account_version,NEW.account_digest) IS DISTINCT FROM ROW(OLD.root_id,OLD.allocation_id,OLD.account_version,OLD.account_digest) OR NEW.revision<>OLD.revision+1 OR NEW.guaranteed_records<OLD.guaranteed_records THEN RAISE EXCEPTION 'capture audit account cannot reset or shrink' USING ERRCODE='23514';END IF;
  IF ((NEW.policy-ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil']) IS DISTINCT FROM (OLD.policy-ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil'])) THEN RAISE EXCEPTION 'capture audit account qualification changed' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_capture_audit_access() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r uuid;l text;source_role boolean;admit_role boolean;journal_role boolean;ack_role boolean;cleanup_role boolean;verifier_role boolean;finalizer_role boolean;completion jsonb;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_TABLE_NAME NOT IN('operation_audit_pool','operation_audit_account','operation_audit','operation_audit_lifecycle','operation_audit_history') THEN RAISE EXCEPTION 'invalid capture audit boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN r:=OLD.root_id;l:=OLD.lane;ELSE r:=NEW.root_id;l:=NEW.lane;END IF;
 IF l<>'capture' THEN
  IF public.capture_audit_login_private() THEN RAISE EXCEPTION 'capture audit role cannot use other lanes' USING ERRCODE='23514';END IF;
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 source_role:=public.capture_audit_role_ok(r,'source');admit_role:=public.capture_audit_role_ok(r,'admission');journal_role:=public.capture_audit_role_ok(r,'journal');ack_role:=public.capture_audit_role_ok(r,'acknowledge');cleanup_role:=public.capture_audit_role_ok(r,'cleanup');verifier_role:=public.capture_audit_role_ok(r,'verifier');finalizer_role:=public.capture_audit_role_ok(r,'finalizer');
 IF TG_TABLE_NAME='operation_audit_pool' THEN
  IF NOT source_role AND NOT(pg_trigger_depth()>1 AND (admit_role OR finalizer_role)) THEN RAISE EXCEPTION 'capture audit backing role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_account' THEN
  IF pg_trigger_depth()<2 OR NOT(admit_role OR finalizer_role) THEN RAISE EXCEPTION 'capture audit account role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_history' THEN
  IF NOT finalizer_role THEN RAISE EXCEPTION 'capture audit history role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit' THEN
  IF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'capture audit retirement role unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='INSERT' THEN
   IF NOT admit_role OR NEW.intent->'Lifecycle'->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'capture-intent-history/v1' OR NEW.intent->>'Name' IS DISTINCT FROM 'persist_capture_intent' THEN RAISE EXCEPTION 'capture audit admission role unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_receipt','outcome_receipt']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_receipt','outcome_receipt']) THEN RAISE EXCEPTION 'capture audit acknowledgement cannot create work' USING ERRCODE='23514';END IF;
  ELSIF NOT journal_role OR ROW(NEW.intent_receipt,NEW.outcome_receipt) IS DISTINCT FROM ROW(OLD.intent_receipt,OLD.outcome_receipt) THEN RAISE EXCEPTION 'capture audit writer cannot acknowledge itself' USING ERRCODE='23514';END IF;
 ELSE
  IF TG_OP='UPDATE' THEN
   FOREACH completion IN ARRAY ARRAY[NEW.intent_completion,NEW.outcome_completion,NEW.certificate_completion] LOOP
    IF completion IS NOT NULL THEN
     PERFORM public.connector_digest(completion->'RecordDigest');
     PERFORM public.connector_digest(completion->'Receipt'->'SHA256');
    END IF;
   END LOOP;
  END IF;
  IF TG_OP='INSERT' THEN
   IF NOT admit_role OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'capture audit lifecycle admission unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'capture audit lifecycle retirement unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_completion','outcome_completion']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_completion','outcome_completion']) THEN RAISE EXCEPTION 'capture writer acknowledgement scope unavailable' USING ERRCODE='23514';END IF;
  ELSIF verifier_role THEN
   IF (to_jsonb(NEW)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) THEN RAISE EXCEPTION 'capture verifier cannot create cleanup work' USING ERRCODE='23514';END IF;
  ELSIF finalizer_role THEN
   IF (to_jsonb(NEW)-'finalization_xid') IS DISTINCT FROM (to_jsonb(OLD)-'finalization_xid') THEN RAISE EXCEPTION 'capture finalizer cannot acknowledge cleanup' USING ERRCODE='23514';END IF;
  ELSIF cleanup_role THEN
   IF ROW(NEW.intent_completion,NEW.outcome_completion,NEW.certificate_verify_attempts,NEW.certificate_receipt,NEW.certificate_acknowledged_at,NEW.terminal_acknowledged_at,NEW.finalization_xid) IS DISTINCT FROM ROW(OLD.intent_completion,OLD.outcome_completion,OLD.certificate_verify_attempts,OLD.certificate_receipt,OLD.certificate_acknowledged_at,OLD.terminal_acknowledged_at,OLD.finalization_xid) THEN RAISE EXCEPTION 'capture cleanup cannot acknowledge itself' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'capture lifecycle role unavailable' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION configure_capture_audit_backing(r uuid,p jsonb,a jsonb,observed timestamptz,fresh_until timestamptz) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.capture_audit_root;trust public.fleet_current_trust;pool public.operation_audit_pool;account public.capture_audit_allocation;n timestamptz;started timestamptz:=clock_timestamp();until_at timestamptz;pool_missing boolean;account_missing boolean;pool_revision bigint:=(p->>'ExpectedRevision')::bigint;account_revision bigint:=(a->>'ExpectedRevision')::bigint;allocation uuid:=(a->'Account'->>'AllocationID')::uuid;desired jsonb:=a->'Account';pol jsonb:=desired->'Policy';
BEGIN
 IF NOT public.capture_audit_role_ok(r,'source') OR octet_length(p::text)>4096 OR octet_length(a::text)>8192 THEN RAISE EXCEPTION 'capture backing source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO pool FROM public.operation_audit_pool WHERE root_id=r AND lane='capture' FOR UPDATE;pool_missing:=NOT FOUND;
 SELECT * INTO account FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation FOR UPDATE;account_missing:=NOT FOUND;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',fresh_until,trust.fresh_until,root.valid_until,(p->>'ValidUntil')::timestamptz,(a->>'ValidUntil')::timestamptz,(pol->>'ValidUntil')::timestamptz);
 IF NOT COALESCE(observed<=n AND fresh_until>observed AND fresh_until<=observed+interval '5 seconds' AND n<until_at AND NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND (p->>'RootID')::uuid=r AND p->>'Lane'='capture' AND pool_revision BETWEEN 0 AND 1152921504606846975 AND account_revision BETWEEN 0 AND 1152921504606846975 AND (desired->>'RootID')::uuid=r AND (desired->>'Revision')::bigint=account_revision+1 AND desired->>'AccountVersion'=p->>'AccountVersion' AND (desired->>'RetainedSeconds')::bigint=(p->>'RetainedSeconds')::bigint AND (pol->>'BackingRevision')::bigint=pool_revision+1 AND (pol->>'InstallationID')::uuid=root.installation_id AND (pol->>'RootID')::uuid=r AND pol->>'Lane'='capture' AND pol->'History'->>'Layout'='capture-intent-history/v1' AND (pol->>'MetadataSlots')::bigint>=(p->>'Accounts')::bigint*(p->>'RecordsPerAccount')::bigint AND public.connector_digest(desired->'AccountDigest') IS NOT NULL,false) THEN RAISE EXCEPTION 'capture backing current observation unavailable' USING ERRCODE='23514';END IF;
 IF pool_missing THEN
  IF pool_revision<>0 THEN RAISE EXCEPTION 'capture backing pool missing' USING ERRCODE='23514';END IF;
  INSERT INTO public.operation_audit_pool(root_id,lane,account_version,revision,paused,valid_until,account_limit,records_per_account,retained_seconds)
  VALUES(r,'capture',p->>'AccountVersion',1,(p->>'Paused')::boolean,(p->>'ValidUntil')::timestamptz,(p->>'Accounts')::bigint,(p->>'RecordsPerAccount')::bigint,(p->>'RetainedSeconds')::bigint);
 ELSIF pool.revision=pool_revision+1 THEN
  IF ROW(pool.account_version,pool.paused,pool.valid_until,pool.account_limit,pool.records_per_account,pool.retained_seconds) IS DISTINCT FROM ROW(p->>'AccountVersion',(p->>'Paused')::boolean,(p->>'ValidUntil')::timestamptz,(p->>'Accounts')::bigint,(p->>'RecordsPerAccount')::bigint,(p->>'RetainedSeconds')::bigint) THEN RAISE EXCEPTION 'capture backing pool replay mismatch' USING ERRCODE='23514';END IF;
 ELSE
  IF pool.revision<>pool_revision OR pool.account_version<>p->>'AccountVersion' THEN RAISE EXCEPTION 'capture backing pool revision mismatch' USING ERRCODE='23514';END IF;
  UPDATE public.operation_audit_pool SET revision=revision+1,paused=(p->>'Paused')::boolean,valid_until=(p->>'ValidUntil')::timestamptz,account_limit=(p->>'Accounts')::bigint,records_per_account=(p->>'RecordsPerAccount')::bigint,retained_seconds=(p->>'RetainedSeconds')::bigint WHERE root_id=r AND lane='capture';
 END IF;
 IF account_missing THEN
  IF account_revision<>0 THEN RAISE EXCEPTION 'capture backing account missing' USING ERRCODE='23514';END IF;
  INSERT INTO public.capture_audit_allocation(root_id,allocation_id,account_version,account_digest,revision,paused,valid_until,guaranteed_records,policy)
  VALUES(r,allocation,desired->>'AccountVersion',public.connector_digest(desired->'AccountDigest'),1,(a->>'Paused')::boolean,(a->>'ValidUntil')::timestamptz,(desired->>'Records')::bigint,pol);
 ELSIF account.revision=account_revision+1 THEN
  IF ROW(account.account_version,account.account_digest,account.paused,account.valid_until,account.guaranteed_records,account.policy) IS DISTINCT FROM ROW(desired->>'AccountVersion',public.connector_digest(desired->'AccountDigest'),(a->>'Paused')::boolean,(a->>'ValidUntil')::timestamptz,(desired->>'Records')::bigint,pol) THEN RAISE EXCEPTION 'capture backing account replay mismatch' USING ERRCODE='23514';END IF;
 ELSE
  IF account.revision<>account_revision THEN RAISE EXCEPTION 'capture backing account revision mismatch' USING ERRCODE='23514';END IF;
  UPDATE public.capture_audit_allocation SET revision=revision+1,paused=(a->>'Paused')::boolean,valid_until=(a->>'ValidUntil')::timestamptz,guaranteed_records=(desired->>'Records')::bigint,policy=pol WHERE root_id=r AND allocation_id=allocation;
 END IF;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capture backing expired after lock' USING ERRCODE='23514';END IF;
 RETURN until_at;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_context_protocol_backing_legacy(context_slice jsonb,h jsonb) RETURNS jsonb
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_root_audit_valid(v jsonb,r uuid,i uuid,l text,layout_name text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb:=v->'Policy';h jsonb:=p->'History';k text;slots numeric;b numeric;w numeric;transitions bigint;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Accounts','RecordsPerAccount','RetainedSeconds','Policy']) OR
  NOT public.capacity_json_integer(v->'Accounts',1,1000000) OR NOT public.capacity_json_integer(v->'RecordsPerAccount',1,1000000) OR
  NOT public.capacity_json_integer(v->'RetainedSeconds',60,316224000) OR
  NOT public.capacity_json_fields(p,ARRAY['RootID','Lane','InstallationID','StoreID','PolicyID','BackupProfileID','PolicyDigest','BackupProfileDigest','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','ValidUntil','MaxPurgeLeases','History','OverdueTerminal']) OR
  NOT public.capacity_json_fields(h,ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
  (p->>'RootID')::uuid<>r OR (p->>'InstallationID')::uuid<>i OR p->>'Lane' IS DISTINCT FROM l OR h->>'Layout' IS DISTINCT FROM layout_name OR
  p->>'OverdueTerminal' IS DISTINCT FROM 'overdue-original/v1' OR
  NOT public.capacity_json_integer(p->'BackingRevision',1,1) OR NOT public.capacity_json_integer(p->'MetadataSlots',1,1000000000000) OR
  NOT public.capacity_json_integer(p->'BackupReservedBytes',1,9223372036854775807) OR NOT public.capacity_json_integer(p->'WALReservedBytes',1,9223372036854775807) OR
  NOT public.capacity_json_integer(p->'BackupHorizonSeconds',0,316224000) OR NOT public.capacity_json_integer(p->'CleanupBudgetSeconds',1,86400) OR
  NOT public.capacity_json_integer(p->'ProofWindowSeconds',1,316224000) OR NOT public.capacity_json_integer(p->'MaxPurgeLeases',2,32) OR
  NOT public.capacity_json_text(p->'ValidUntil',20,40) OR NOT isfinite((p->>'ValidUntil')::timestamptz) OR
  NOT public.capacity_json_uuid(h->'ID') OR NOT public.capacity_json_digest(h->'Digest') OR
  NOT public.capacity_json_integer(h->'MaximumRowFootprintBytes',131072,16777216) OR NOT public.capacity_json_integer(h->'MaximumTransitionWALBytes',131072,67108864) OR
  NOT public.capacity_json_integer(h->'BackupCopies',1,64) OR NOT public.capacity_json_integer(h->'WALCopies',1,64) THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['RootID','InstallationID','StoreID','PolicyID','BackupProfileID'] LOOP IF NOT public.capacity_json_uuid(p->k) THEN RETURN false;END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['PolicyDigest','BackupProfileDigest'] LOOP IF NOT public.capacity_json_digest(p->k) THEN RETURN false;END IF;END LOOP;
 slots:=(v->>'Accounts')::numeric*(v->>'RecordsPerAccount')::numeric;
 transitions:=CASE WHEN layout_name='operation-audit-history/v3' THEN 21 WHEN layout_name IN ('capture-intent-history/v1','processing-release-history/v1') THEN 32 ELSE 0 END;
 b:=2*(h->>'MaximumRowFootprintBytes')::numeric*(h->>'BackupCopies')::numeric;
 w:=2*(h->>'MaximumTransitionWALBytes')::numeric*(h->>'WALCopies')::numeric*(transitions+3*(p->>'MaxPurgeLeases')::bigint);
 RETURN transitions>0 AND slots=(p->>'MetadataSlots')::numeric AND
  (p->>'BackupReservedBytes')::numeric>=slots*b AND (p->>'WALReservedBytes')::numeric>=slots*w AND
  (v->>'RetainedSeconds')::bigint>2*(p->>'BackupHorizonSeconds')::bigint+3*(p->>'CleanupBudgetSeconds')::bigint+(p->>'ProofWindowSeconds')::bigint+30;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_compile_root(input_value jsonb,system_pool jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=input_value;q jsonb:=v->'Metadata';env jsonb:=v->'Envelope';h jsonb:=v->'ContextHistory';
 c jsonb:=v->'Capture';ps jsonb:=v->'ProcessingState';lane jsonb;k text;work jsonb;root uuid;installation uuid;
 accounts bigint;per_account bigint;records bigint;slots numeric;
 object_bytes numeric;object_count numeric;sql_bytes numeric:=0;ordinary_sql numeric;backup_bytes numeric:=0;wal_bytes numeric:=0;keys numeric:=0;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Format','RootID','InstallationID','QualificationID','QualificationDigest','SystemPoolUID','AccountVersion','Accounts','RecordsPerAccount','AdmissionSeconds','Capture','Normal','Resolution','Processing','ProcessingState','ProcessingEpoch','ProcessingSourceUID','ProcessingProtectionDigest','ContextHistory','StopRetainedSeconds','Metadata','Envelope']) OR
  v->>'Format' IS DISTINCT FROM 'protected-capacity-root/v1' OR octet_length(v::text)>65536 OR
  NOT public.capacity_json_uuid(v->'RootID') OR NOT public.capacity_json_uuid(v->'InstallationID') OR NOT public.capacity_json_uuid(v->'QualificationID') OR NOT public.capacity_json_digest(v->'QualificationDigest') OR
  NOT public.capacity_json_text(v->'SystemPoolUID',1,64) OR NOT public.capacity_json_text(v->'AccountVersion',1,64) OR
  NOT public.capacity_json_integer(v->'Accounts',1,16) OR NOT public.capacity_json_integer(v->'RecordsPerAccount',1,512) OR
  NOT public.capacity_json_integer(v->'AdmissionSeconds',60,86400) OR NOT public.capacity_json_uuid(v->'ProcessingEpoch') OR NOT public.capacity_json_uuid(v->'ProcessingSourceUID') OR NOT public.capacity_json_digest(v->'ProcessingProtectionDigest') OR
  system_pool->>'Format' IS DISTINCT FROM 'capacity-pool/v1' OR system_pool->>'UID' IS DISTINCT FROM v->>'SystemPoolUID' OR
  NOT public.capacity_json_fields(system_pool->'System',ARRAY['Bytes','Objects']) OR
  NOT public.capacity_json_integer(system_pool->'System'->'Bytes',1,9223372036854775807) OR NOT public.capacity_json_integer(system_pool->'System'->'Objects',1,9223372036854775807) OR
  NOT public.capacity_json_fields(q,ARRAY['ID','Layout','Digest','FixedRowBytes','AccountRowBytes','RecordRowBytes','RecordWALBytes','RecordKeyAttempts','TransitionWALBytes','BackupCopies','WALCopies','ConfigurationTransitions']) OR
  q->>'Layout' IS DISTINCT FROM 'capacity-root-history/v1' OR NOT public.capacity_json_uuid(q->'ID') OR NOT public.capacity_json_digest(q->'Digest') OR
  NOT public.capacity_json_integer(q->'FixedRowBytes',1048576,67108864) OR NOT public.capacity_json_integer(q->'AccountRowBytes',262144,16777216) OR
  NOT public.capacity_json_integer(q->'RecordRowBytes',131072,16777216) OR NOT public.capacity_json_integer(q->'RecordWALBytes',1048576,268435456) OR
  NOT public.capacity_json_integer(q->'RecordKeyAttempts',16,256) OR NOT public.capacity_json_integer(q->'TransitionWALBytes',1048576,268435456) OR
  NOT public.capacity_json_integer(q->'BackupCopies',1,64) OR NOT public.capacity_json_integer(q->'WALCopies',1,64) OR
  NOT public.capacity_json_integer(q->'ConfigurationTransitions',3,1000000) OR
  NOT public.capacity_json_fields(env,ARRAY['SystemObjects','SQLBytes','BackupBytes','WALBytes','KeyAttempts']) OR
  NOT public.capacity_json_fields(env->'SystemObjects',ARRAY['Bytes','Objects']) THEN RETURN NULL;END IF;
 FOREACH k IN ARRAY ARRAY['SQLBytes','BackupBytes','WALBytes','KeyAttempts'] LOOP IF NOT public.capacity_json_integer(env->k,1,9223372036854775807) THEN RETURN NULL;END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['Bytes','Objects'] LOOP IF NOT public.capacity_json_integer(env->'SystemObjects'->k,1,9223372036854775807) THEN RETURN NULL;END IF;END LOOP;
 root:=(v->>'RootID')::uuid;installation:=(v->>'InstallationID')::uuid;accounts:=(v->>'Accounts')::bigint;per_account:=(v->>'RecordsPerAccount')::bigint;records:=accounts*per_account;
 IF NOT public.capacity_root_audit_valid(c,root,installation,'capture','capture-intent-history/v1') OR
  NOT public.capacity_root_audit_valid(v->'Normal',root,installation,'normal','operation-audit-history/v3') OR
  NOT public.capacity_root_audit_valid(v->'Resolution',root,installation,'resolution','operation-audit-history/v3') OR
  NOT public.capacity_root_audit_valid(v->'Processing',root,installation,'processing','processing-release-history/v1') OR
  NOT public.capacity_processing_backing_valid(ps,root,installation,records,v->'Processing'->'Policy') OR
  (c->>'Accounts')::bigint<>accounts OR (c->>'RecordsPerAccount')::bigint<>per_account OR c->'Policy'->'History' IS DISTINCT FROM h->'Capture' OR
  c->'Policy'->'MaxPurgeLeases' IS DISTINCT FROM h->'CapturePurgeLeases' OR
  h->'Stop'->>'RootID' IS DISTINCT FROM v->>'RootID' OR h->'Stop'->>'InstallationID' IS DISTINCT FROM v->>'InstallationID' OR
  h->'Stop'->>'StoreID' IS DISTINCT FROM c->'Policy'->>'StoreID' OR NOT public.capacity_json_integer(v->'StopRetainedSeconds',60,316224000) OR
  (v->>'StopRetainedSeconds')::bigint<=2*(h->'Stop'->>'BackupHorizonSeconds')::bigint+3*(h->'Stop'->>'CleanupBudgetSeconds')::bigint+(h->'Stop'->>'ProofWindowSeconds')::bigint+30 OR
  (q->>'ConfigurationTransitions')::bigint<3+3*accounts THEN RETURN NULL;END IF;
 work:=public.capacity_context_protocol_backing(jsonb_build_object('Bytes',per_account*1544192,'Objects',per_account*4),h);
 IF work IS NULL OR (work->>'Records')::bigint<>per_account OR
  (c->'Policy'->>'BackupReservedBytes')::numeric<>accounts*(work->>'CaptureBackupBytes')::numeric OR
  (c->'Policy'->>'WALReservedBytes')::numeric<>accounts*(work->>'CaptureWALBytes')::numeric THEN RETURN NULL;END IF;
 object_bytes:=accounts*(work->'ProtocolSystemObjects'->>'Bytes')::numeric;object_count:=accounts*(work->'ProtocolSystemObjects'->>'Objects')::numeric;
 sql_bytes:=(1+(ps->>'MaxRootTransitions')::numeric+(ps->>'MaxCaptures')::numeric+17*(ps->>'MaxRules')::numeric)*(ps->'History'->>'RowBytes')::numeric;
 backup_bytes:=(ps->>'BackupBytes')::numeric;wal_bytes:=(ps->>'WALBytes')::numeric;
 FOREACH k IN ARRAY ARRAY['Normal','Resolution','Processing'] LOOP
  lane:=v->k;
  IF lane->'Policy'->>'StoreID' IS DISTINCT FROM c->'Policy'->>'StoreID' OR
   (lane->'Policy'->>'ValidUntil')::timestamptz IS DISTINCT FROM (c->'Policy'->>'ValidUntil')::timestamptz THEN RETURN NULL;END IF;
  slots:=(lane->'Policy'->>'MetadataSlots')::numeric;
  object_bytes:=object_bytes+slots*131072;object_count:=object_count+slots*2;
  sql_bytes:=sql_bytes+slots*(lane->'Policy'->'History'->>'MaximumRowFootprintBytes')::numeric;
  backup_bytes:=backup_bytes+(lane->'Policy'->>'BackupReservedBytes')::numeric;wal_bytes:=wal_bytes+(lane->'Policy'->>'WALReservedBytes')::numeric;keys:=keys+slots*13;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['CaptureBackupBytes','NativeBackupBytes','StopBackupBytes'] LOOP backup_bytes:=backup_bytes+accounts*(work->>k)::numeric;END LOOP;
 FOREACH k IN ARRAY ARRAY['CaptureWALBytes','NativeWALBytes','StopWALBytes'] LOOP wal_bytes:=wal_bytes+accounts*(work->>k)::numeric;END LOOP;
 FOREACH k IN ARRAY ARRAY['CaptureKeyAttempts','StopKeyAttempts','ArtifactWraps','PreparationUnwraps','ContentUnwraps'] LOOP keys:=keys+accounts*(work->>k)::numeric;END LOOP;
 ordinary_sql:=(q->>'FixedRowBytes')::numeric+accounts*(q->>'AccountRowBytes')::numeric+records*(q->>'RecordRowBytes')::numeric;
 sql_bytes:=sql_bytes+ordinary_sql+records*(h->'Capture'->>'MaximumRowFootprintBytes')::numeric+records*(h->'Stop'->>'MaximumRowFootprintBytes')::numeric+accounts*((work->>'NativeRows')::numeric+(work->>'NativeKeys')::numeric)*(h->'Native'->>'RowBytes')::numeric;
 backup_bytes:=backup_bytes+2*(q->>'BackupCopies')::numeric*ordinary_sql;
 wal_bytes:=wal_bytes+(q->>'ConfigurationTransitions')::numeric*(q->>'TransitionWALBytes')::numeric*(q->>'WALCopies')::numeric+records*(q->>'RecordWALBytes')::numeric*(q->>'WALCopies')::numeric;
 keys:=keys+records*(q->>'RecordKeyAttempts')::numeric;
 IF GREATEST(object_bytes,object_count,sql_bytes,backup_bytes,wal_bytes,keys)>9223372036854775807 OR
  object_bytes>(system_pool->'System'->>'Bytes')::numeric OR object_count>(system_pool->'System'->>'Objects')::numeric OR
  object_bytes>(env->'SystemObjects'->>'Bytes')::numeric OR object_count>(env->'SystemObjects'->>'Objects')::numeric OR
  sql_bytes>(env->>'SQLBytes')::numeric OR backup_bytes>(env->>'BackupBytes')::numeric OR wal_bytes>(env->>'WALBytes')::numeric OR keys>(env->>'KeyAttempts')::numeric THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('Input',v,'Totals',jsonb_build_object('Accounts',accounts,'RecordsPerAccount',per_account,'Records',records,
  'SystemObjects',jsonb_build_object('Bytes',object_bytes::bigint,'Objects',object_count::bigint),
  'SQLBytes',sql_bytes::bigint,'BackupBytes',backup_bytes::bigint,'WALBytes',wal_bytes::bigint,'KeyAttempts',keys::bigint,'ConfigurationTransitions',(q->>'ConfigurationTransitions')::bigint));
EXCEPTION WHEN data_exception THEN RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION read_capacity_audit_profiles(r uuid,i uuid,q uuid,qd bytea,av text,observed timestamptz,original_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;p public.permission_stream;a public.operation_audit_pool;backing public.capacity_pool;processing public.processing_root;
 c jsonb;v jsonb;policy jsonb;result jsonb;n timestamptz;until_at timestamptz;lane_name text;field_name text;normalized jsonb;pool_name text;pool_plan jsonb;
BEGIN
 n:=clock_timestamp();
 IF r IS NULL OR i IS NULL OR q IS NULL OR qd IS NULL OR octet_length(qd)<>32 OR av IS NULL OR octet_length(av) NOT BETWEEN 1 AND 64 OR
  observed IS NULL OR original_until IS NULL OR NOT isfinite(observed) OR NOT isfinite(original_until) OR observed>n OR n>=original_until OR original_until>observed+interval '5 seconds' THEN
  RAISE EXCEPTION 'capacity audit profile input unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=i FOR SHARE;
 SELECT * INTO STRICT p FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 n:=clock_timestamp();c:=s.root_configuration;
 until_at:=LEAST(original_until,t.fresh_until,p.fresh_until,p.lease_until,s.fresh_until,(c->>'PlannedUntil')::timestamptz);
 IF NOT public.capacity_audit_reader_pin_valid(s) OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE oid=s.audit_reader_role AND rolname=session_user) OR
  s.installation_id<>i OR s.qualification_digest<>qd OR s.qualification->>'ID'<>q::text OR s.account_version<>av OR
  t.suspended OR t.recovery_blocked OR t.observed_at IS NULL OR t.observed_at>n OR t.fresh_until IS NULL OR
  p.suspended OR p.observed_at IS NULL OR p.observed_at>n OR p.fresh_until IS NULL OR p.lease_until IS NULL OR p.fresh_until>p.observed_at+interval '30 seconds' OR
  s.suspended OR s.observed_at IS NULL OR s.observed_at>n OR s.fresh_until IS NULL OR s.accepted_revision<1 OR s.accepted_snapshot IS NULL OR
  s.root_plan IS NULL OR s.root_mutation_xid IS NOT NULL OR NOT COALESCE(public.capacity_root_configuration_valid(c),false) OR c->'ReadyAt'='null'::jsonb OR c->'ReconciledAt'<>'null'::jsonb OR
  (c->>'ReadyAt')::timestamptz>n OR public.connector_digest(c->'PlanDigest') IS DISTINCT FROM s.root_plan_digest OR
  s.root_plan->'Input' IS DISTINCT FROM s.qualification->'RootBacking' OR n>=until_at OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.initial_audit_id AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.epoch AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'current capacity audit profile unavailable' USING ERRCODE='23514',
   -- Operator-only diagnostics use already-held rows. Do not repeat role/pin or
   -- audit lookups here; other current-guard failures remain unclassified.
   DETAIL=left(jsonb_build_object(
    'stage','capacity-audit-current',
    'cut',CASE WHEN n>=original_until THEN 'caller' WHEN n>=t.fresh_until THEN 'trust'
      WHEN n>=p.fresh_until OR n>=p.lease_until THEN 'permission' WHEN n>=s.fresh_until THEN 'source'
      WHEN n>=(c->>'PlannedUntil')::timestamptz THEN 'configuration' ELSE 'other-current' END,
    'now',n,'inputObserved',observed,'callerUntil',original_until,'effectiveUntil',until_at,
    'trustObserved',t.observed_at,'trustUntil',t.fresh_until,'trustSuspended',t.suspended,'recoveryBlocked',t.recovery_blocked,
    'permissionObserved',p.observed_at,'permissionUntil',p.fresh_until,'permissionLeaseUntil',p.lease_until,'permissionSuspended',p.suspended,
    'sourceObserved',s.observed_at,'sourceUntil',s.fresh_until,'sourceSuspended',s.suspended,
    'plannedUntil',(c->>'PlannedUntil')::timestamptz,'reconciled',c->'ReconciledAt'<>'null'::jsonb)::text,2048);END IF;
 SELECT x->'Resource'->>'Name' INTO STRICT pool_name FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Pools') x
  WHERE x->'Resource'->>'UID'=s.root_plan->'Input'->>'SystemPoolUID';
 pool_plan:=public.capacity_compile_pool(s.accepted_snapshot,pool_name);
 SELECT * INTO STRICT backing FROM public.capacity_pool WHERE root_id=r AND source_uid=s.root_plan->'Input'->>'SystemPoolUID' FOR SHARE;
 IF pool_plan IS NULL OR NOT (backing.plan IS NOT DISTINCT FROM pool_plan OR public.capacity_pool_extends(backing.plan,pool_plan)) OR public.capacity_backend_for(s,pool_plan) IS NULL OR
  public.capacity_compile_root(s.qualification->'RootBacking',pool_plan) IS DISTINCT FROM s.root_plan THEN
  RAISE EXCEPTION 'capacity audit source backing mismatch' USING ERRCODE='23514';END IF;
 result:=jsonb_build_object('Format','accepted-capacity-audit-profiles/v1','RootID',r,'InstallationID',i,'QualificationID',q,'AccountVersion',av,
  'QualificationDigest',to_jsonb(ARRAY(SELECT get_byte(qd,k) FROM generate_series(0,31) k)),
  'PlanDigest',to_jsonb(ARRAY(SELECT get_byte(s.root_plan_digest,k) FROM generate_series(0,31) k)),
  'ConfigurationRevision',(c->>'Revision')::bigint,'SourceRevision',s.accepted_revision,'ObservedAt',observed);
 -- Stable sorted lock order, also used by the root producer.
 FOREACH lane_name IN ARRAY ARRAY['normal','processing','resolution'] LOOP
  field_name:=CASE lane_name WHEN 'normal' THEN 'Normal' WHEN 'processing' THEN 'Processing' ELSE 'Resolution' END;
  v:=s.root_plan->'Input'->field_name;
  IF NOT public.capacity_root_audit_valid(v,r,i,lane_name,CASE lane_name WHEN 'processing' THEN 'processing-release-history/v1' ELSE 'operation-audit-history/v3' END) THEN
   RAISE EXCEPTION 'capacity audit layout unavailable' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=r AND lane=lane_name FOR SHARE;
  n:=clock_timestamp();until_at:=LEAST(until_at,a.valid_until);
  IF n>=until_at OR a.paused OR a.account_version<>av OR a.revision<>(c->>'Revision')::bigint OR
   a.valid_until<>(c->>'PlannedUntil')::timestamptz OR a.account_limit<>(v->>'Accounts')::bigint OR
   a.records_per_account<>(v->>'RecordsPerAccount')::bigint OR a.retained_seconds<>(v->>'RetainedSeconds')::bigint THEN
   RAISE EXCEPTION 'capacity audit pool mismatch' USING ERRCODE='23514';END IF;
  -- Only admission revision/date vary. Every other original accepted field,
  -- including H=0 backup/store/layout identity, is retained byte-for-byte.
  policy:=(v->'Policy')||jsonb_build_object('BackingRevision',a.revision,'ValidUntil',public.capacity_json_timestamp(a.valid_until));
  IF lane_name='processing' THEN
   -- The shared permission lock above serializes processing configuration and
   -- decision writers. Read without a late reverse-order business-row lock.
   -- Initialization may still be absent: this profile also precedes that first
   -- independently audited decision and never declares the root initialized.
   SELECT * INTO STRICT processing FROM public.processing_root WHERE root_id=r;
   IF processing.installation_id<>i OR processing.issuer_epoch<>t.issuer_epoch OR
    processing.epoch<>(s.root_plan->'Input'->>'ProcessingEpoch')::uuid OR
    processing.source_uid<>(s.root_plan->'Input'->>'ProcessingSourceUID')::uuid OR
    processing.protection_digest IS DISTINCT FROM public.connector_digest(s.root_plan->'Input'->'ProcessingProtectionDigest') OR
    processing.backing_revision<>(c->>'Revision')::bigint OR processing.valid_until<>a.valid_until OR
    processing.release_policy IS DISTINCT FROM policy THEN
    RAISE EXCEPTION 'processing release profile mismatch' USING ERRCODE='23514';END IF;
  END IF;
  normalized:=policy-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'];
  IF a.history_profile IS NOT NULL AND a.history_profile IS DISTINCT FROM normalized THEN
   RAISE EXCEPTION 'capacity audit history mismatch' USING ERRCODE='23514';END IF;
  result:=result||jsonb_build_object(field_name,jsonb_build_object('Policy',policy,'RetainedSeconds',a.retained_seconds));
 END LOOP;
 n:=clock_timestamp();
 IF n>=until_at OR NOT public.capacity_audit_reader_pin_valid(s) THEN RAISE EXCEPTION 'capacity audit profile expired after read' USING ERRCODE='23514';END IF;
 RETURN result||jsonb_build_object('FreshUntil',until_at);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION finish_capture_operation_retirement(r uuid,i uuid,installation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT public.capture_audit_role_ok(r,'finalizer') OR NOT EXISTS(SELECT 1 FROM public.capture_audit_root p WHERE p.root_id=r AND p.installation_id=installation) THEN RAISE EXCEPTION 'capture finalizer unavailable' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.operation_audit a WHERE a.root_id=r AND a.id=i AND a.lane='capture') THEN RETURN false;END IF;
 RETURN public.finish_operation_audit_retirement(r,i,installation);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION finish_capture_operation_history(r uuid,l text,p bytea,releases timestamptz,deletes timestamptz,installation uuid) RETURNS TABLE(records bigint,overdue boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF l IS DISTINCT FROM 'capture' OR NOT public.capture_audit_role_ok(r,'finalizer') OR NOT EXISTS(SELECT 1 FROM public.capture_audit_root x WHERE x.root_id=r AND x.installation_id=installation) THEN RAISE EXCEPTION 'capture history finalizer unavailable' USING ERRCODE='23514';END IF;
 RETURN QUERY SELECT h.records,h.overdue FROM public.finish_operation_audit_history(r,'capture',p,releases,deletes,installation) h;
END $$;
-- +goose StatementEnd
CREATE OR REPLACE VIEW capture_operation_pool WITH (security_barrier=true) AS
SELECT root_id, lane, account_version, revision, paused, valid_until, account_limit, records_per_account, accounts, retained_seconds, history_profile, history_backing_until, proof_window_missed FROM public.operation_audit_pool
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

CREATE OR REPLACE VIEW capture_operation_account WITH (security_barrier=true) AS
SELECT root_id, lane, principal_digest, charged FROM public.operation_audit_account
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

CREATE OR REPLACE VIEW capture_operation_audit WITH (security_barrier=true) AS
SELECT id, root_id, lane, issuer_epoch, principal_digest, intent, request_until, write_until, retain_until, intent_started, intent_receipt, outcome, outcome_started, outcome_receipt FROM public.operation_audit
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

CREATE OR REPLACE VIEW capture_operation_history WITH (security_barrier=true) AS
SELECT root_id,lane,principal_digest,release_at,delete_by,hard_delete_by,eligible_at,installation_id,issuer_epoch,postmaster_at,database_oid,horizon_seconds,history_policy,records,overdue,drain_xid FROM public.operation_audit_history
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;

-- Only these two views are recreated; their owner/table/column grants are
-- restored before returning. This also removes dependencies on SQL153 columns.
-- +goose StatementBegin
DO $rollback_views$
DECLARE saved jsonb; item jsonb; permission jsonb; relation regclass; owner_name text; target text; role_sql text;
BEGIN
 SELECT jsonb_agg(jsonb_build_object('name',c.relname,'owner',pg_get_userbyid(c.relowner),
  'grants',COALESCE((SELECT jsonb_agg(jsonb_build_object('role',CASE WHEN x.grantee=0 THEN NULL ELSE pg_get_userbyid(x.grantee) END,'privilege',x.privilege_type,'grantable',x.is_grantable))
   FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x),'[]'::jsonb),
  'columns',COALESCE((SELECT jsonb_agg(jsonb_build_object('column',a.attname,'role',CASE WHEN x.grantee=0 THEN NULL ELSE pg_get_userbyid(x.grantee) END,'privilege',x.privilege_type,'grantable',x.is_grantable))
   FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb)))
 INTO saved FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ('capture_operation_lifecycle','connector_operation_lifecycle') AND c.relkind='v';
 IF jsonb_array_length(saved)<>2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(saved) v CROSS JOIN LATERAL jsonb_array_elements(v->'columns') g WHERE g->>'column' IN ('share_effect_target','share_effect_xid')) THEN
  RAISE EXCEPTION 'lifecycle view rollback has unsupported shape or marker-column grants' USING ERRCODE='23514';
 END IF;
 FOR item IN SELECT jsonb_array_elements(saved) LOOP
  target:=item->>'name';owner_name:=item->>'owner';
  EXECUTE format('DROP VIEW public.%I',target);
  IF target='capture_operation_lifecycle' THEN
   EXECUTE $capture_definition$CREATE VIEW capture_operation_lifecycle WITH (security_barrier=true) AS
SELECT operation_id, root_id, lane, principal_digest, installation_id, issuer_epoch, postmaster_at, database_oid, binding, original_purge_at, certificate_purge_at, live_retire_by, intent_completion, outcome_completion, lease_fence, lease, retirement, certificate_started, certificate_completion, certificate_receipt, certificate_acknowledged_at, terminal_purge, terminal_acknowledged_at, finalization_xid, overdue_selected_at, overdue_purge, certificate_verify_attempts FROM public.operation_audit_lifecycle
WHERE lane='capture' AND current_user=session_user AND (
 public.capture_audit_role_ok(root_id,'cleanup') OR
 public.capture_audit_role_ok(root_id,'verifier') OR
 public.capture_audit_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;$capture_definition$;
  ELSE
   EXECUTE $connector_definition$CREATE VIEW connector_operation_lifecycle WITH (security_barrier=true) AS
SELECT operation_id, root_id, lane, principal_digest, installation_id, issuer_epoch, postmaster_at, database_oid, binding, original_purge_at, certificate_purge_at, live_retire_by, intent_completion, outcome_completion, lease_fence, lease, retirement, certificate_started, certificate_completion, certificate_receipt, certificate_acknowledged_at, terminal_purge, terminal_acknowledged_at, finalization_xid, overdue_selected_at, overdue_purge, certificate_verify_attempts FROM public.operation_audit_lifecycle
WHERE lane='identity' AND current_user=session_user AND (
 public.connector_identity_role_ok(root_id,'cleanup') OR
 public.connector_identity_role_ok(root_id,'verifier') OR
 public.connector_identity_role_ok(root_id,'finalizer'))
WITH LOCAL CHECK OPTION;$connector_definition$;
  END IF;
  EXECUTE format('ALTER VIEW public.%I OWNER TO %I',target,owner_name);
  relation:=format('public.%I',target)::regclass;
  -- Clear current default privileges before restoring the saved exact set.
  FOR permission IN SELECT jsonb_build_object('role',CASE WHEN x.grantee=0 THEN NULL ELSE pg_get_userbyid(x.grantee) END)
   FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x WHERE c.oid=relation LOOP
   role_sql:=CASE WHEN permission->>'role' IS NULL THEN 'PUBLIC' ELSE format('%I',permission->>'role') END;
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM %s',target,role_sql);
  END LOOP;
  FOR permission IN SELECT jsonb_array_elements(item->'grants') LOOP
   role_sql:=CASE WHEN permission->>'role' IS NULL THEN 'PUBLIC' ELSE format('%I',permission->>'role') END;
   EXECUTE format('GRANT %s ON TABLE public.%I TO %s%s',permission->>'privilege',target,role_sql,CASE WHEN (permission->>'grantable')::boolean THEN ' WITH GRANT OPTION' ELSE '' END);
  END LOOP;
  FOR permission IN SELECT jsonb_array_elements(item->'columns') LOOP
   role_sql:=CASE WHEN permission->>'role' IS NULL THEN 'PUBLIC' ELSE format('%I',permission->>'role') END;
   EXECUTE format('GRANT %s (%I) ON TABLE public.%I TO %s%s',permission->>'privilege',permission->>'column',target,role_sql,CASE WHEN (permission->>'grantable')::boolean THEN ' WITH GRANT OPTION' ELSE '' END);
  END LOOP;
 END LOOP;
END $rollback_views$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ BEGIN EXECUTE 'COMMENT ON TABLE public.goose_db_version IS ''asservat:oldest-binary-schema=153'''; END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION create_operation_audit_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b jsonb; p jsonb; t public.fleet_current_trust; a public.operation_audit_pool; n timestamptz:=clock_timestamp(); budget interval; horizon interval; proof interval; prepaid boolean:=false;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid audit lifecycle source' USING ERRCODE='23514'; END IF;
 b:=NEW.intent->'Lifecycle';
 IF b IS NULL THEN RETURN NEW; END IF;
 p:=b->'Policy';
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=(p->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
 n:=clock_timestamp();
 prepaid:=public.connector_retirement_prepaid(NEW);
 budget:=make_interval(secs=>(p->>'CleanupBudgetSeconds')::double precision);
 horizon:=make_interval(secs=>(p->>'BackupHorizonSeconds')::double precision);
 proof:=make_interval(secs=>(p->>'ProofWindowSeconds')::double precision);
 IF (p ? 'OverdueTerminal' AND p->>'OverdueTerminal' IS DISTINCT FROM 'overdue-original/v1') OR b->>'Protocol' IS DISTINCT FROM 'closed-operation-audit/v1' OR jsonb_typeof(p)<>'object' OR
  NOT(p ?& ARRAY['MaxPurgeLeases','RootID','Lane','InstallationID','StoreID','PolicyID','BackupProfileID','PolicyDigest','BackupProfileDigest','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','ValidUntil']) OR
  (p->>'RootID')::uuid<>NEW.root_id OR p->>'Lane'<>NEW.lane OR (p->>'StoreID')::uuid IS NULL OR (p->>'PolicyID')::uuid IS NULL OR (p->>'BackupProfileID')::uuid IS NULL OR
  jsonb_array_length(p->'PolicyDigest')<>32 OR jsonb_array_length(p->'BackupProfileDigest')<>32 OR
  (NOT prepaid AND (p->>'BackingRevision')::bigint<>a.revision) OR (p->>'MetadataSlots')::bigint<a.account_limit*a.records_per_account OR (p->>'MetadataSlots')::bigint>1000000000000 OR
  budget<interval '1 second' OR budget>interval '1 day' OR horizon<interval '0 seconds' OR horizon>interval '3660 days' OR proof<interval '1 second' OR proof>interval '3660 days' OR
  (p->>'BackupReservedBytes')::bigint<0 OR (p->>'WALReservedBytes')::bigint<0 OR horizon>interval '0 seconds' AND ((p->>'BackupReservedBytes')::bigint<=0 OR (p->>'WALReservedBytes')::bigint<=0) OR
  n>=(p->>'ValidUntil')::timestamptz OR n>=NEW.request_until OR (NOT prepaid AND n>=a.valid_until) OR t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR
  (p->>'MaxPurgeLeases')::bigint NOT BETWEEN 2 AND 32 OR
  (b->>'HistoryReleaseAt')::timestamptz<>NEW.retain_until-horizon-budget OR (b->>'HistoryDeleteBy')::timestamptz<>NEW.retain_until-horizon OR
  (b->>'LiveRetireBy')::timestamptz<>NEW.retain_until-2*horizon-budget OR (b->>'CertificatePurgeAt')::timestamptz<>(b->>'LiveRetireBy')::timestamptz-budget OR
  (b->>'OriginalPurgeAt')::timestamptz<>(b->>'CertificatePurgeAt')::timestamptz-proof-budget OR (b->>'OriginalPurgeAt')::timestamptz<=NEW.write_until THEN
  RAISE EXCEPTION 'audit lifecycle backing unavailable' USING ERRCODE='23514'; END IF;
 -- A qualification is an exact accepted layout/profile, with conservative
 -- measured full-transaction bounds. Positive arbitrary byte counts are not a
 -- qualification; source acceptance is deliberately outside this adapter.
 IF p->'History' IS NULL OR NOT public.operation_audit_history_verifier_backed(p->'History'->>'Layout') OR NOT public.operation_audit_history_layout_valid(NEW.lane,p->'History'->>'Layout') OR
   NOT(p->'History' ?& ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
   (p->'History'->>'ID')::uuid IS NULL OR jsonb_array_length(p->'History'->'Digest')<>32 OR
   (p->'History'->>'MaximumRowFootprintBytes')::bigint NOT BETWEEN public.operation_audit_history_minimum_row(p->'History'->>'Layout') AND 16777216 OR
   (p->'History'->>'MaximumTransitionWALBytes')::bigint NOT BETWEEN 131072 AND 67108864 OR
   (p->'History'->>'BackupCopies')::bigint NOT BETWEEN 1 AND 64 OR (p->'History'->>'WALCopies')::bigint NOT BETWEEN 1 AND 64 OR
   (p->>'BackupReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumRowFootprintBytes')::bigint*(p->'History'->>'BackupCopies')::bigint OR
   (p->>'WALReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumTransitionWALBytes')::bigint*(p->'History'->>'WALCopies')::bigint*(public.operation_audit_history_fixed_transitions(p->'History'->>'Layout')+3*(p->>'MaxPurgeLeases')::bigint) THEN
   RAISE EXCEPTION 'audit history qualification unavailable' USING ERRCODE='23514'; END IF;

 IF a.history_backing_until IS NOT NULL AND n<a.history_backing_until AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),a.history_profile) THEN
  RAISE EXCEPTION 'residual audit history backing protected' USING ERRCODE='23514'; END IF;
 -- Renewal may refresh a source/revision or increase backing. Outstanding
 -- obligations cannot be moved to a smaller/different backup or account profile.
 IF EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=NEW.root_id AND d.lane=NEW.lane AND
   NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),((d.binding->'Policy') - ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']))) OR
  EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=NEW.root_id AND h.lane=NEW.lane AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),h.history_policy)) THEN
  RAISE EXCEPTION 'outstanding audit history profile mismatch' USING ERRCODE='23514'; END IF;
 IF horizon>interval '0 seconds' THEN
  UPDATE public.operation_audit_pool SET
   history_profile=p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'],
   history_backing_until=GREATEST(history_backing_until,NEW.retain_until)
  WHERE root_id=NEW.root_id AND lane=NEW.lane;
 END IF;
 INSERT INTO public.operation_audit_lifecycle(operation_id,root_id,lane,principal_digest,installation_id,issuer_epoch,postmaster_at,database_oid,binding,original_purge_at,certificate_purge_at,live_retire_by,certificate_verify_attempts)
 VALUES(NEW.id,NEW.root_id,NEW.lane,NEW.principal_digest,t.installation_id,t.issuer_epoch,(SELECT activated_postmaster_at FROM public.fleet_trust WHERE installation_id=t.installation_id),(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),b,(b->>'OriginalPurgeAt')::timestamptz,(b->>'CertificatePurgeAt')::timestamptz,(b->>'LiveRetireBy')::timestamptz,0);
 RETURN NEW;
END $$;
-- +goose StatementEnd
