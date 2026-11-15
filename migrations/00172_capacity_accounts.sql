-- +goose Up
-- specs/capacity.md, ADR-335 D2/D8, ADR-330 D1/D8: capacity is the Helm
-- `capacity` values in one row per root and one account per workload. The
-- hub-worker applies the values when it starts (every helm upgrade restarts
-- it); a workload is enrolled on demand in the transaction that first needs
-- its storage. No source observation, plan, renewal or reconciliation loop.
-- Root and workload rows carry the standing date (capacity_standing) instead
-- of a renewed admission window. The context-control record counter, which
-- never released a record, is removed.

DROP TRIGGER IF EXISTS aaa_capacity_configuration ON custody_pool;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON custody_allocation;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON context_storage_binding;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON download_allocation;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON download_control_allocation;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON download_native_backing;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON download_stop_backing;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON download_stop_pool;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON processing_root;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON operation_audit_pool;
 DROP TRIGGER IF EXISTS aaa_capacity_configuration ON capture_audit_allocation;
 DROP TRIGGER IF EXISTS aaa_capacity_capture_root ON capture_audit_root;
 DROP TRIGGER IF EXISTS aaa_capacity_session_snapshot ON artifact_download;
 DROP TRIGGER IF EXISTS zzz_capacity_new_admission ON custody_attempt;
 DROP TRIGGER IF EXISTS zzz_capacity_new_admission ON context_capture;
 DROP TRIGGER IF EXISTS zzz_capacity_new_admission ON operation_audit;
 DROP TRIGGER IF EXISTS zzz_capacity_new_admission ON artifact_download;
 DROP TRIGGER IF EXISTS context_control_capture_charge ON context_capture;
 DROP TRIGGER IF EXISTS policy_recording_source_backing ON policy_recording_source;
 ALTER TABLE artifact_download DROP CONSTRAINT IF EXISTS capacity_download_snapshot_present;
 ALTER TABLE artifact_download DROP COLUMN IF EXISTS capacity_account_id, DROP COLUMN IF EXISTS capacity_backing, DROP COLUMN IF EXISTS capacity_backing_digest;
 DROP TABLE capacity_refresh_demand, capacity_cluster_qualification, capacity_pool_revision, capacity_workload, capacity_namespace, capacity_cluster, capacity_pool, capacity_source, remote_capacity_delivery CASCADE;
 DROP TABLE context_control_charge, context_control_account, context_control_pool CASCADE;

-- +goose StatementBegin
DO $$
DECLARE f regprocedure;
BEGIN
 FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='public' AND (p.proname LIKE '%capacity%' OR p.proname LIKE '%context_control%' OR p.proname IN ('reserve_policy_recording_source'))
   AND p.proname NOT IN ('capacity_json_digest','capacity_json_fields','capacity_json_integer','capacity_json_text','capacity_json_time','capacity_json_timestamp','capacity_json_uuid',
    'guard_browser_session_owner_capacity','lock_context_query_capacity','context_query_capacity_allocation_current')
 LOOP
  EXECUTE format('DROP FUNCTION %s CASCADE',f);
 END LOOP;
END $$;
-- +goose StatementEnd

ALTER TABLE context_storage_binding DROP CONSTRAINT context_storage_binding_check;
ALTER TABLE capture_audit_allocation ADD FOREIGN KEY(allocation_id) REFERENCES custody_allocation(id);

-- The standing date of capacity rows: far enough to never end, finite so
-- every existing date check and JSON encoding still holds (ADR-332 uses the
-- same approach for connector identity).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_standing() RETURNS timestamptz LANGUAGE sql IMMUTABLE AS $$ SELECT '9970-01-01T00:00:00Z'::timestamptz $$;
-- +goose StatementEnd

CREATE TABLE capacity_settings (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id),
 installation_id uuid NOT NULL,
 account_version text NOT NULL,
 qualification jsonb NOT NULL,
 pool_id uuid NOT NULL UNIQUE REFERENCES custody_pool(id),
 evidence_bytes bigint NOT NULL CHECK(evidence_bytes>0),
 reserve_bytes bigint NOT NULL CHECK(reserve_bytes>=0 AND reserve_bytes<evidence_bytes),
 share_bytes bigint CHECK(share_bytes>0),
 limit_bytes bigint NOT NULL CHECK(limit_bytes>0),
 namespace_limit_bytes bigint CHECK(namespace_limit_bytes>0),
 max_concurrent_expensive integer NOT NULL CHECK(max_concurrent_expensive>0),
 on_full text NOT NULL CHECK(on_full IN('RejectNewExpensive','DeleteOldestEligibleInAccount')),
 revision bigint NOT NULL CHECK(revision>0)
);
CREATE TABLE capacity_account (
 allocation_id uuid PRIMARY KEY REFERENCES custody_allocation(id),
 download_allocation_id uuid NOT NULL UNIQUE REFERENCES download_allocation(id),
 root_id uuid NOT NULL REFERENCES capacity_settings(root_id),
 cluster_id uuid NOT NULL, namespace_uid text NOT NULL, workload_uid text NOT NULL,
 protected_bytes bigint NOT NULL CHECK(protected_bytes>0),
 UNIQUE(root_id,cluster_id,namespace_uid,workload_uid)
);

-- +goose StatementBegin
-- Applies the capacity values. The first call creates the root rows from the
-- hub-worker's internal qualification; later calls change only the values.
CREATE OR REPLACE FUNCTION capacity_apply(r uuid,cluster uuid,namespace_uid text,av text,q jsonb,v jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_settings;installation uuid:=(q->'RootBacking'->>'InstallationID')::uuid;i jsonb:=q->'RootBacking';b jsonb:=q->'Backends'->0;
 standing timestamptz:=public.capacity_standing();pool uuid;available bigint;prefix text;oids oid[]:='{}';o oid;k integer;lane_name text;lane jsonb;stop jsonb;slots bigint:=100000;
 retire timestamptz;share bigint;
BEGIN
 IF r IS NULL OR installation IS NULL OR (i->>'RootID')::uuid IS DISTINCT FROM r OR jsonb_array_length(q->'Backends')<>1 OR
  (v->>'EvidenceBytes')::bigint IS NULL OR (v->>'LimitBytes')::bigint IS NULL THEN RAISE EXCEPTION 'capacity settings invalid' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO s FROM public.capacity_settings WHERE root_id=r FOR UPDATE;
 IF NOT FOUND THEN
  pool:=(b->>'PoolID')::uuid;
  prefix:='as_'||replace(installation::text,'-','')||'_pub_';
  FOREACH k IN ARRAY ARRAY[71,40,41,42,43,44,45,16] LOOP
   SELECT oid INTO o FROM pg_catalog.pg_roles WHERE rolname=prefix||lpad(k::text,2,'0');
   IF o IS NULL THEN RAISE EXCEPTION 'capacity role missing' USING ERRCODE='55000';END IF;
   oids:=array_append(oids,o);
  END LOOP;
  INSERT INTO public.capture_audit_root(root_id,installation_id,source_role,admission_role,journal_role,acknowledge_role,cleanup_role,verifier_role,finalizer_role,reader_role,revision,paused,valid_until)
   VALUES(r,installation,oids[1],oids[2],oids[3],oids[4],oids[5],oids[6],oids[7],oids[8],1,false,standing) ON CONFLICT DO NOTHING;
  INSERT INTO public.custody_pool(id,store_id,revision,valid_until,paused,byte_limit,object_limit)
   VALUES(pool,(b->>'EvidenceStoreID')::uuid,1,standing,false,(v->>'EvidenceBytes')::bigint-(v->>'ReserveBytes')::bigint,1125899906842624);
  FOREACH lane_name IN ARRAY ARRAY['normal','processing','resolution','capture'] LOOP
   lane:=i->(CASE lane_name WHEN 'normal' THEN 'Normal' WHEN 'processing' THEN 'Processing' WHEN 'resolution' THEN 'Resolution' ELSE 'Capture' END);
   INSERT INTO public.operation_audit_pool(root_id,lane,account_version,revision,paused,valid_until,account_limit,records_per_account,retained_seconds)
    VALUES(r,lane_name,av,1,false,standing,(lane->>'Accounts')::bigint,(lane->>'RecordsPerAccount')::bigint,(lane->>'RetainedSeconds')::bigint);
  END LOOP;
  retire:=standing+make_interval(secs=>(2*(i->'ProcessingState'->>'BackupHorizonSeconds')::bigint+(i->'ProcessingState'->>'CleanupSeconds')::bigint)::double precision);
  INSERT INTO public.processing_root(root_id,installation_id,issuer_epoch,epoch,source_uid,protection_digest,backing,release_policy,backing_revision,valid_until,retire_by,max_captures,max_rules,max_root_transitions)
   SELECT r,installation,t.issuer_epoch,(i->>'ProcessingEpoch')::uuid,(i->>'ProcessingSourceUID')::uuid,public.connector_digest(i->'ProcessingProtectionDigest'),
    (i->'ProcessingState')||jsonb_build_object('ValidUntil',standing,'RetireBy',retire),
    (i->'Processing'->'Policy')||jsonb_build_object('ValidUntil',public.capacity_json_timestamp(standing)),1,standing,retire,
    (i->'ProcessingState'->>'MaxCaptures')::bigint,(i->'ProcessingState'->>'MaxRules')::bigint,(i->'ProcessingState'->>'MaxRootTransitions')::bigint
   FROM public.fleet_current_trust t WHERE t.installation_id=installation;
  stop:=i->'ContextHistory'->'Stop';
  INSERT INTO public.download_stop_pool(root_id,installation_id,store_id,policy_id,backup_profile_id,policy_digest,backup_profile_digest,slots,cipher_bytes,key_attempts,backup_bytes,wal_bytes,retained_seconds,backup_horizon_seconds,valid_until,lifecycle_policy)
   VALUES(r,installation,(stop->>'StoreID')::uuid,(stop->>'PolicyID')::uuid,(stop->>'BackupProfileID')::uuid,public.connector_digest(stop->'PolicyDigest'),public.connector_digest(stop->'BackupProfileDigest'),
    slots,slots*65536,slots*12,slots*2*(stop->>'MaximumRowFootprintBytes')::bigint*(stop->>'BackupCopies')::bigint,
    slots*2*(stop->>'MaximumTransitionWALBytes')::bigint*(stop->>'WALCopies')::bigint*(20+3*(stop->>'MaxPurgeLeases')::bigint),(i->>'StopRetainedSeconds')::bigint,(stop->>'BackupHorizonSeconds')::bigint,standing,stop);
  INSERT INTO public.capacity_settings(root_id,installation_id,account_version,qualification,pool_id,evidence_bytes,reserve_bytes,share_bytes,limit_bytes,namespace_limit_bytes,max_concurrent_expensive,on_full,revision)
   VALUES(r,installation,av,q,pool,(v->>'EvidenceBytes')::bigint,(v->>'ReserveBytes')::bigint,NULLIF((v->>'ShareBytes')::bigint,0),(v->>'LimitBytes')::bigint,NULLIF((v->>'NamespaceLimitBytes')::bigint,0),
    (v->>'MaxConcurrentExpensive')::integer,v->>'OnFull',1) RETURNING * INTO s;
  IF q ? 'ContextQuery' THEN PERFORM public.ensure_shared_context_query_capacity(r);END IF;
 ELSE
  available:=(v->>'EvidenceBytes')::bigint-(v->>'ReserveBytes')::bigint;
  PERFORM 1 FROM public.custody_pool WHERE id=s.pool_id FOR UPDATE;
  UPDATE public.capacity_settings SET evidence_bytes=(v->>'EvidenceBytes')::bigint,reserve_bytes=(v->>'ReserveBytes')::bigint,share_bytes=NULLIF((v->>'ShareBytes')::bigint,0),limit_bytes=(v->>'LimitBytes')::bigint,
   namespace_limit_bytes=NULLIF((v->>'NamespaceLimitBytes')::bigint,0),max_concurrent_expensive=(v->>'MaxConcurrentExpensive')::integer,on_full=v->>'OnFull',revision=revision+1
   WHERE root_id=r RETURNING * INTO s;
  -- ADR-335 D2/D3: a helm upgrade carries the new share to every enrolled
  -- account. A lower share never drops below the bytes already charged; those
  -- stay used and capacity_charge refuses new charges above the hard limit.
  SELECT count(*) INTO slots FROM public.capacity_account WHERE root_id=r;
  share:=COALESCE(s.share_bytes,available/GREATEST(8,slots));
  UPDATE public.capacity_account SET protected_bytes=share WHERE root_id=r;
  UPDATE public.custody_allocation a SET byte_limit=GREATEST(a.charged_bytes,share)
   FROM public.capacity_account c WHERE c.allocation_id=a.id AND c.root_id=r;
  UPDATE public.custody_pool SET allocated_bytes=(SELECT COALESCE(sum(a.byte_limit),0) FROM public.custody_allocation a WHERE a.pool_id=s.pool_id) WHERE id=s.pool_id;
  UPDATE public.custody_pool SET byte_limit=GREATEST(available,allocated_bytes) WHERE id=s.pool_id;
 END IF;
 RETURN jsonb_build_object('Qualification',s.qualification,'Revision',s.revision);
END $$;

-- Enrolls one workload on demand (REQ-CAP-004). Its protected share is the
-- configured share, or the usable capacity divided by max(8, accounts).
-- When the pool cannot back it, shares of other accounts shrink down to
-- their usage first ("shrinks only allocations without usage").
CREATE OR REPLACE FUNCTION capacity_enroll(r uuid,cluster uuid,namespace_id text,workload text,allocation uuid,download uuid,account_digest bytea) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_settings;p public.custody_pool;w public.capacity_account;i jsonb;share bigint;accounts bigint;standing timestamptz:=public.capacity_standing();
 native jsonb;h jsonb;retire timestamptz;capture public.operation_audit_pool;ns bigint;
BEGIN
 SELECT * INTO w FROM public.capacity_account WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload;
 IF FOUND THEN RETURN w.allocation_id;END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT s FROM public.capacity_settings WHERE root_id=r;
 SELECT * INTO STRICT p FROM public.custody_pool WHERE id=s.pool_id FOR UPDATE;
 SELECT * INTO w FROM public.capacity_account WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload;
 IF FOUND THEN RETURN w.allocation_id;END IF;
 IF allocation IS NULL OR download IS NULL OR allocation=download OR octet_length(account_digest)<>32 THEN RAISE EXCEPTION 'capacity enrollment input invalid' USING ERRCODE='23514';END IF;
 SELECT count(*)+1 INTO accounts FROM public.capacity_account WHERE root_id=r;
 share:=COALESCE(s.share_bytes,p.byte_limit/GREATEST(8,accounts));
 IF p.allocated_bytes+share>p.byte_limit THEN
  WITH shrink AS (
   UPDATE public.custody_allocation a SET byte_limit=GREATEST(a.charged_bytes,share)
   FROM public.capacity_account c WHERE c.allocation_id=a.id AND c.root_id=r AND a.byte_limit>GREATEST(a.charged_bytes,share)
   RETURNING a.id, c.protected_bytes)
  UPDATE public.capacity_account c SET protected_bytes=LEAST(c.protected_bytes,GREATEST(share,1)) FROM shrink WHERE c.allocation_id=shrink.id;
  UPDATE public.custody_pool SET allocated_bytes=(SELECT COALESCE(sum(a.byte_limit),0) FROM public.custody_allocation a WHERE a.pool_id=s.pool_id) WHERE id=s.pool_id RETURNING * INTO p;
  IF p.allocated_bytes+share>p.byte_limit THEN RAISE EXCEPTION 'CapacityNotAllocated' USING ERRCODE='23514';END IF;
 END IF;
 IF s.namespace_limit_bytes IS NOT NULL THEN
  SELECT COALESCE(sum(a.byte_limit),0) INTO ns FROM public.capacity_account c JOIN public.custody_allocation a ON a.id=c.allocation_id
   WHERE c.root_id=r AND c.cluster_id=cluster AND c.namespace_uid=namespace_id;
  IF ns+share>s.namespace_limit_bytes THEN RAISE EXCEPTION 'CapacityNotAllocated' USING ERRCODE='23514';END IF;
 END IF;
 i:=s.qualification->'RootBacking';h:=i->'ContextHistory'->'Native';
 UPDATE public.custody_pool SET allocated_bytes=allocated_bytes+share WHERE id=s.pool_id;
 INSERT INTO public.custody_allocation(id,pool_id,scope_id,service_class,revision,valid_until,paused,byte_limit,object_limit)
  VALUES(allocation,s.pool_id,allocation,'context',1,standing,false,share,1099511627776);
 INSERT INTO public.context_storage_binding(root_id,cluster_id,namespace_uid,workload_uid,allocation_id,source_uid,source_generation,source_digest,observed_at,fresh_until)
  VALUES(r,cluster,namespace_id,workload,allocation,'capacity',1,sha256(convert_to('asservat-capacity/'||r::text,'UTF8')),clock_timestamp(),standing);
 INSERT INTO public.download_allocation(id,root_id,cluster_id,namespace_uid,workload_uid,output_limit,read_limit,valid_until)
  VALUES(download,r,cluster,namespace_id,workload,17592186044416,70368744177664,standing);
 INSERT INTO public.download_control_allocation(id,root_id,audit_store_id,window_limit,audit_byte_limit,valid_until,audit_write_until)
  VALUES(download,r,(i->'Capture'->'Policy'->>'StoreID')::uuid,263168,68987912192,standing,standing+interval '30 seconds');
 retire:=standing+make_interval(secs=>(2*(i->'Capture'->'Policy'->>'BackupHorizonSeconds')::bigint+(i->'Capture'->'Policy'->>'CleanupBudgetSeconds')::bigint)::double precision);
 native:=jsonb_build_object('AllocationID',download,'RootID',r,'PolicyID',s.qualification->'ID','PolicyDigest',s.qualification->'Digest',
  'Rows',100000,'Keys',263168,'TransitionsPerRow',267,
  'BackupBytes',2*(h->>'RowBytes')::numeric*(h->>'BackupCopies')::numeric*(100000+263168),
  'WALBytes',(h->>'TransitionWALBytes')::numeric*(h->>'WALCopies')::numeric*((267+4)*100000+8*263168),
  'BackupHorizonSeconds',i->'Capture'->'Policy'->'BackupHorizonSeconds','CleanupSeconds',i->'Capture'->'Policy'->'CleanupBudgetSeconds',
  'ValidUntil',standing,'RetireBy',retire,'History',h);
 INSERT INTO public.download_native_backing(allocation_id,root_id,policy_json,rows_limit,keys_limit,transitions_per_row,backup_horizon_seconds,cleanup_seconds,valid_until,retire_by,residual_until)
  VALUES(download,r,native,100000,263168,267,(native->>'BackupHorizonSeconds')::bigint,(native->>'CleanupSeconds')::bigint,standing,retire,retire);
 INSERT INTO public.download_stop_backing(allocation_id,root_id,slots) VALUES(download,r,100);
 SELECT * INTO STRICT capture FROM public.operation_audit_pool WHERE root_id=r AND lane='capture';
 INSERT INTO public.capture_audit_allocation(root_id,allocation_id,account_version,account_digest,revision,paused,valid_until,guaranteed_records,policy)
  VALUES(r,allocation,s.account_version,account_digest,1,false,standing,capture.records_per_account,
   (i->'Capture'->'Policy')||jsonb_build_object('BackingRevision',capture.revision,'ValidUntil',public.capacity_json_timestamp(standing)));
 INSERT INTO public.capacity_account(allocation_id,download_allocation_id,root_id,cluster_id,namespace_uid,workload_uid,protected_bytes)
  VALUES(allocation,download,r,cluster,namespace_id,workload,share);
 IF s.qualification ? 'ContextQuery' THEN PERFORM public.ensure_shared_context_query_allocation(r,cluster,namespace_id,workload);END IF;
 RETURN allocation;
END $$;

-- A charge within the account's current limit, or burst: the limit grows
-- while the workload stays below its hard limit and its namespace limit and
-- the pool has unallocated bytes. Accounts without capacity rows keep their
-- fixed limit.
CREATE OR REPLACE FUNCTION capacity_charge(allocation uuid,bytes bigint,objects bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.custody_allocation;s public.capacity_settings;w public.capacity_account;grow bigint;ns bigint;
BEGIN
 SELECT * INTO a FROM public.custody_allocation WHERE id=allocation;
 IF NOT FOUND OR bytes<0 OR objects<0 THEN RETURN false;END IF;
 SELECT * INTO w FROM public.capacity_account WHERE allocation_id=allocation;
 IF FOUND THEN SELECT * INTO STRICT s FROM public.capacity_settings WHERE root_id=w.root_id;PERFORM 1 FROM public.custody_pool WHERE id=a.pool_id FOR UPDATE;END IF;
 SELECT * INTO STRICT a FROM public.custody_allocation WHERE id=allocation FOR UPDATE;
 IF a.charged_objects+objects>a.object_limit THEN RETURN false;END IF;
 IF a.charged_bytes+bytes<=a.byte_limit THEN
  UPDATE public.custody_allocation SET charged_bytes=charged_bytes+bytes,charged_objects=charged_objects+objects WHERE id=allocation;RETURN true;END IF;
 IF w.allocation_id IS NULL OR a.charged_bytes+bytes>GREATEST(s.limit_bytes,w.protected_bytes) THEN RETURN false;END IF;
 grow:=a.charged_bytes+bytes-a.byte_limit;
 IF s.namespace_limit_bytes IS NOT NULL THEN
  SELECT COALESCE(sum(x.byte_limit),0) INTO ns FROM public.capacity_account c JOIN public.custody_allocation x ON x.id=c.allocation_id
   WHERE c.root_id=w.root_id AND c.cluster_id=w.cluster_id AND c.namespace_uid=w.namespace_uid;
  IF ns+grow>s.namespace_limit_bytes THEN RETURN false;END IF;
 END IF;
 UPDATE public.custody_pool SET allocated_bytes=allocated_bytes+grow WHERE id=a.pool_id AND allocated_bytes+grow<=byte_limit;
 IF NOT FOUND THEN RETURN false;END IF;
 UPDATE public.custody_allocation SET byte_limit=byte_limit+grow,charged_bytes=charged_bytes+bytes,charged_objects=charged_objects+objects WHERE id=allocation;
 RETURN true;
END $$;

-- Release returns borrowed burst to the pool; the protected share stays.
CREATE OR REPLACE FUNCTION capacity_release(allocation uuid,bytes bigint,objects bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.custody_allocation;w public.capacity_account;keep bigint;
BEGIN
 SELECT * INTO a FROM public.custody_allocation WHERE id=allocation;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT * INTO w FROM public.capacity_account WHERE allocation_id=allocation;
 IF FOUND THEN PERFORM 1 FROM public.custody_pool WHERE id=a.pool_id FOR UPDATE;END IF;
 SELECT * INTO STRICT a FROM public.custody_allocation WHERE id=allocation FOR UPDATE;
 IF a.charged_bytes<bytes OR a.charged_objects<objects OR bytes<0 OR objects<0 THEN RETURN false;END IF;
 keep:=a.byte_limit;
 IF w.allocation_id IS NOT NULL THEN keep:=LEAST(a.byte_limit,GREATEST(w.protected_bytes,a.charged_bytes-bytes));END IF;
 UPDATE public.custody_pool SET allocated_bytes=allocated_bytes-(a.byte_limit-keep) WHERE id=a.pool_id;
 UPDATE public.custody_allocation SET byte_limit=keep,charged_bytes=charged_bytes-bytes,charged_objects=charged_objects-objects WHERE id=allocation;
 RETURN true;
END $$;

-- Admission deadline of an enrolled workload: the standing date while its
-- rows are active, NULL otherwise.
CREATE OR REPLACE FUNCTION capacity_managed_admission_until(r uuid,allocation uuid,kind text,n timestamptz) RETURNS timestamptz
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT LEAST(a.valid_until,cp.valid_until) FROM public.capacity_account c JOIN public.custody_allocation a ON a.id=c.allocation_id JOIN public.custody_pool cp ON cp.id=a.pool_id
 WHERE c.root_id=r AND CASE WHEN kind='context' THEN c.allocation_id=allocation ELSE c.download_allocation_id=allocation END
  AND NOT a.paused AND NOT cp.paused AND n<a.valid_until AND n<cp.valid_until
$$;

CREATE OR REPLACE FUNCTION read_capacity_qualification(r uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT qualification FROM public.capacity_settings WHERE root_id=r
$$;
CREATE OR REPLACE FUNCTION read_capacity_qualification_pin(r uuid,i uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('qualificationID',s.qualification->>'ID','qualificationDigest',encode(public.connector_digest(s.qualification->'Digest'),'hex'),
  'accountVersion',s.account_version,'capturePolicy',s.qualification->'RootBacking'->'Capture'->'Policy',
  'operationRetentionSeconds',LEAST((s.qualification->'RootBacking'->'Normal'->>'RetainedSeconds')::bigint,(s.qualification->'RootBacking'->'Resolution'->>'RetainedSeconds')::bigint),
  'evidenceStoreID',s.qualification->'Backends'->0->>'EvidenceStoreID')
 FROM public.capacity_settings s WHERE s.root_id=r AND s.installation_id=i
$$;

-- The operation audit lane profiles of a root (accepted-capacity-audit-profiles/v1).
CREATE OR REPLACE FUNCTION read_capacity_audit_profiles(r uuid,i uuid,q uuid,qd bytea,av text,observed timestamptz,original_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_settings;a public.operation_audit_pool;v jsonb;policy jsonb;result jsonb;lane_name text;field_name text;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_settings WHERE root_id=r AND installation_id=i;
 IF s.qualification->>'ID'<>q::text OR public.connector_digest(s.qualification->'Digest')<>qd OR s.account_version<>av OR clock_timestamp()>=original_until THEN
  RAISE EXCEPTION 'capacity audit profile unavailable' USING ERRCODE='23514';END IF;
 result:=jsonb_build_object('Format','accepted-capacity-audit-profiles/v1','RootID',r,'InstallationID',i,'QualificationID',q,'AccountVersion',av,
  'QualificationDigest',to_jsonb(ARRAY(SELECT get_byte(qd,k) FROM generate_series(0,31) k)),'PlanDigest',to_jsonb(ARRAY(SELECT get_byte(qd,k) FROM generate_series(0,31) k)),
  'ConfigurationRevision',1,'SourceRevision',s.revision,'ObservedAt',observed);
 FOREACH lane_name IN ARRAY ARRAY['normal','processing','resolution'] LOOP
  field_name:=CASE lane_name WHEN 'normal' THEN 'Normal' WHEN 'processing' THEN 'Processing' ELSE 'Resolution' END;
  v:=s.qualification->'RootBacking'->field_name;
  SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=r AND lane=lane_name;
  policy:=(v->'Policy')||jsonb_build_object('BackingRevision',a.revision,'ValidUntil',public.capacity_json_timestamp(a.valid_until));
  result:=result||jsonb_build_object(field_name,jsonb_build_object('Policy',policy,'RetainedSeconds',a.retained_seconds));
 END LOOP;
 RETURN result||jsonb_build_object('FreshUntil',original_until);
END $$;

-- Session copies are the live rows: no per-session capacity snapshot.
CREATE OR REPLACE FUNCTION capacity_session_control(s public.artifact_download,c public.download_control_allocation) RETURNS public.download_control_allocation
LANGUAGE sql IMMUTABLE AS $$ SELECT c $$;
CREATE OR REPLACE FUNCTION capacity_session_native(s public.artifact_download,b public.download_native_backing) RETURNS public.download_native_backing
LANGUAGE sql IMMUTABLE AS $$ SELECT b $$;

CREATE OR REPLACE FUNCTION protect_download_allocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['reserved_output','reserved_read']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['reserved_output','reserved_read']) OR NEW.reserved_output<OLD.reserved_output OR NEW.reserved_read<OLD.reserved_read THEN
  RAISE EXCEPTION 'immutable download allocation; reservations cannot be refunded' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION guard_download_control_allocation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.download_allocation;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download control lifecycle unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.id AND root_id=NEW.root_id;
  IF NEW.reserved_windows<>0 OR NEW.reserved_audit_bytes<>0 OR NEW.valid_until>a.valid_until OR NEW.window_limit>((a.output_limit-1)/67108864+1)+1024 THEN RAISE EXCEPTION 'invalid download control backing' USING ERRCODE='23514';END IF;
 ELSIF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['reserved_windows','reserved_audit_bytes']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['reserved_windows','reserved_audit_bytes']) OR NEW.reserved_windows<=OLD.reserved_windows OR NEW.reserved_audit_bytes<>OLD.reserved_audit_bytes+(NEW.reserved_windows-OLD.reserved_windows)*262144 THEN
  RAISE EXCEPTION 'immutable source-managed download control backing' USING ERRCODE='23514';
 END IF;RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_native_backing() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb;q jsonb;need_backup numeric;need_wal numeric;a public.download_allocation;
BEGIN
 IF TG_OP='DELETE' THEN
  IF clock_timestamp()<OLD.residual_until OR EXISTS(SELECT 1 FROM public.download_native_owner WHERE allocation_id=OLD.allocation_id) OR EXISTS(SELECT 1 FROM public.download_native_key WHERE allocation_id=OLD.allocation_id) THEN RAISE EXCEPTION 'native residual history still backed' USING ERRCODE='23514';END IF;RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()>=2 AND (to_jsonb(NEW)-ARRAY['residual_until','overdue']) IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['residual_until','overdue']) AND NEW.residual_until>=OLD.residual_until AND (NOT OLD.overdue OR NEW.overdue) THEN RETURN NEW;END IF;
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['charged_rows','charged_keys']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['charged_rows','charged_keys']) OR NEW.charged_rows<OLD.charged_rows OR NEW.charged_keys<OLD.charged_keys OR (NEW.charged_rows-OLD.charged_rows)+(NEW.charged_keys-OLD.charged_keys)<>1 THEN RAISE EXCEPTION 'immutable native backing' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id;
 p:=NEW.policy_json;q:=p->'History';
 IF NOT(p ?& ARRAY['AllocationID','RootID','PolicyID','PolicyDigest','Rows','Keys','TransitionsPerRow','BackupBytes','WALBytes','BackupHorizonSeconds','CleanupSeconds','ValidUntil','RetireBy','History']) OR jsonb_typeof(q) IS DISTINCT FROM 'object' OR NEW.charged_rows<>0 OR NEW.charged_keys<>0 OR NEW.residual_until<>NEW.retire_by OR NEW.overdue OR NEW.valid_until>a.valid_until OR NEW.valid_until<=clock_timestamp() OR (p->>'AllocationID')::uuid IS DISTINCT FROM NEW.allocation_id OR (p->>'RootID')::uuid IS DISTINCT FROM NEW.root_id OR (p->>'Rows')::bigint IS DISTINCT FROM NEW.rows_limit OR (p->>'Keys')::bigint IS DISTINCT FROM NEW.keys_limit OR (p->>'TransitionsPerRow')::bigint IS DISTINCT FROM NEW.transitions_per_row OR (p->>'BackupHorizonSeconds')::bigint IS DISTINCT FROM NEW.backup_horizon_seconds OR (p->>'CleanupSeconds')::bigint IS DISTINCT FROM NEW.cleanup_seconds OR (p->>'ValidUntil')::timestamptz IS DISTINCT FROM NEW.valid_until OR (p->>'RetireBy')::timestamptz IS DISTINCT FROM NEW.retire_by THEN RAISE EXCEPTION 'invalid native backing' USING ERRCODE='23514';END IF;
 IF NOT(q ?& ARRAY['ID','Digest','RowBytes','TransitionWALBytes','BackupCopies','WALCopies']) OR jsonb_typeof(q->'ID') IS DISTINCT FROM 'string' OR jsonb_typeof(q->'Digest') IS DISTINCT FROM 'array' OR NOT COALESCE((q->>'RowBytes')::bigint BETWEEN 65536 AND 16777216 AND (q->>'TransitionWALBytes')::bigint BETWEEN 65536 AND 67108864 AND (q->>'BackupCopies')::bigint BETWEEN 1 AND 64 AND (q->>'WALCopies')::bigint BETWEEN 1 AND 64,FALSE) THEN RAISE EXCEPTION 'native history qualification missing' USING ERRCODE='23514';END IF;
 need_backup:=2*(q->>'RowBytes')::numeric*(q->>'BackupCopies')::numeric*(NEW.rows_limit+NEW.keys_limit);
 need_wal:=(q->>'TransitionWALBytes')::numeric*(q->>'WALCopies')::numeric*((NEW.transitions_per_row+4)*NEW.rows_limit+8*NEW.keys_limit);
 IF NOT COALESCE((p->>'BackupBytes')::numeric>=need_backup AND (p->>'BackupBytes')::numeric<=9223372036854775807 AND (p->>'WALBytes')::numeric>=need_wal AND (p->>'WALBytes')::numeric<=9223372036854775807,FALSE) THEN RAISE EXCEPTION 'native history backing insufficient' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit_pool() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'audit backing retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.proof_window_missed<>0 OR NEW.revision<>1 OR NEW.accounts<>0 OR NEW.history_profile IS NOT NULL OR NEW.history_backing_until IS NOT NULL THEN RAISE EXCEPTION 'invalid initial audit backing' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.proof_window_missed<>OLD.proof_window_missed AND (pg_trigger_depth()<2 OR NEW.proof_window_missed<>LEAST(OLD.proof_window_missed+1,1152921504606846976)) THEN RAISE EXCEPTION 'proof window aggregate is source managed' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.root_id,NEW.lane,NEW.account_version) IS DISTINCT FROM ROW(OLD.root_id,OLD.lane,OLD.account_version) THEN
   RAISE EXCEPTION 'immutable audit backing identity' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.history_profile,NEW.history_backing_until) IS DISTINCT FROM ROW(OLD.history_profile,OLD.history_backing_until) THEN
   IF pg_trigger_depth()<2 OR NEW.history_profile IS NULL OR NEW.history_backing_until IS NULL OR
    OLD.history_backing_until IS NOT NULL AND NEW.history_backing_until<OLD.history_backing_until OR
    OLD.history_profile IS NOT NULL AND NEW.history_profile IS DISTINCT FROM OLD.history_profile AND
     NOT public.operation_audit_profile_covers(NEW.history_profile,OLD.history_profile) AND
     (clock_timestamp()<OLD.history_backing_until OR EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE root_id=OLD.root_id AND lane=OLD.lane) OR EXISTS(SELECT 1 FROM public.operation_audit_history WHERE root_id=OLD.root_id AND lane=OLD.lane)) THEN
    RAISE EXCEPTION 'audit residual backing is source managed' USING ERRCODE='23514'; END IF;
  END IF;
  IF (NEW.account_limit<OLD.account_limit OR NEW.records_per_account<OLD.records_per_account) AND
   ((OLD.history_backing_until IS NOT NULL AND clock_timestamp()<OLD.history_backing_until) OR
    EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE root_id=OLD.root_id AND lane=OLD.lane AND (binding->'Policy'->>'BackupHorizonSeconds')::bigint>0) OR
    EXISTS(SELECT 1 FROM public.operation_audit_history WHERE root_id=OLD.root_id AND lane=OLD.lane)) THEN
   RAISE EXCEPTION 'audit residual backing cannot shrink' USING ERRCODE='23514'; END IF;
  IF NEW.accounts<>OLD.accounts AND (pg_trigger_depth()<2 OR
   (NEW.accounts<>OLD.accounts+1 AND NOT (NEW.accounts=OLD.accounts-1 AND
    (EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=OLD.root_id AND d.lane=OLD.lane AND d.finalization_xid=pg_current_xact_id() AND d.terminal_acknowledged_at IS NOT NULL) OR
     EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=OLD.root_id AND h.lane=OLD.lane AND h.drain_xid=pg_current_xact_id()))))) THEN
   RAISE EXCEPTION 'audit accounts source managed' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.revision,NEW.paused,NEW.valid_until,NEW.account_limit,NEW.records_per_account,NEW.retained_seconds) IS DISTINCT FROM ROW(OLD.revision,OLD.paused,OLD.valid_until,OLD.account_limit,OLD.records_per_account,OLD.retained_seconds) AND
   (NEW.revision<>OLD.revision+1 OR NEW.accounts<>OLD.accounts) THEN RAISE EXCEPTION 'audit backing revision mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.lane<>'identity' AND EXISTS(SELECT 1 FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND charged>NEW.records_per_account) THEN
  RAISE EXCEPTION 'audit backing below retained spend' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION guard_capture_audit_allocation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.operation_audit_pool; root public.capture_audit_root; n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'capture audit allocation retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=NEW.root_id;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='capture' FOR UPDATE;
 n:=clock_timestamp();
 IF n>=root.valid_until OR n>=pool.valid_until OR n>=NEW.valid_until OR NEW.guaranteed_records>pool.records_per_account OR NEW.account_version<>pool.account_version OR
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
  -- The existing overdue-selection AFTER trigger charges this one counter
  -- through the cleanup login. It grants no backing/profile mutation.
  IF public.capture_audit_login_private() AND NOT source_role AND NOT(pg_trigger_depth()>1 AND (admit_role OR finalizer_role OR
   (cleanup_role AND TG_OP='UPDATE' AND
    (to_jsonb(NEW)-'proof_window_missed') IS NOT DISTINCT FROM (to_jsonb(OLD)-'proof_window_missed') AND
    NEW.proof_window_missed=LEAST(OLD.proof_window_missed+1,1152921504606846976)))) THEN
   RAISE EXCEPTION 'capture audit backing role unavailable' USING ERRCODE='23514';END IF;
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

CREATE OR REPLACE FUNCTION guard_recording_save_group() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'group control retirement requires protocol' USING ERRCODE='23514';
 ELSIF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['progress_revision','cancel_requested_at','cancel_request_key']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['progress_revision','cancel_requested_at','cancel_request_key']) OR
     NEW.progress_revision<>OLD.progress_revision+1 THEN
   RAISE EXCEPTION 'immutable save group' USING ERRCODE='23514';
  END IF;
  IF ROW(NEW.cancel_requested_at,NEW.cancel_request_key) IS DISTINCT FROM ROW(OLD.cancel_requested_at,OLD.cancel_request_key) THEN
   IF OLD.cancel_requested_at IS NOT NULL OR NEW.cancel_requested_at IS NULL OR NEW.cancel_request_key IS NULL THEN
    RAISE EXCEPTION 'immutable group cancellation' USING ERRCODE='23514';
   END IF;
   NEW.cancel_requested_at:=clock_timestamp();
  ELSIF pg_trigger_depth()<2 THEN
   RAISE EXCEPTION 'group progress derives from children' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.progress_revision<>1 OR NEW.cancel_requested_at IS NOT NULL OR NEW.cancel_request_key IS NOT NULL OR
    EXISTS(SELECT 1 FROM public.context_capture WHERE id=NEW.id OR (root_id=NEW.root_id AND request_key=NEW.request_key)) OR
    (SELECT count(DISTINCT x) FROM unnest(NEW.child_ids) x)<>cardinality(NEW.child_ids) OR NEW.id=ANY(NEW.child_ids) THEN
  RAISE EXCEPTION 'invalid new save group' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION lock_capture_audit_admission(r uuid,allocation uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp();n timestamptz;until_at timestamptz;root public.capture_audit_root;trust public.fleet_current_trust;pool public.operation_audit_pool;a public.capture_audit_allocation;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'admission') THEN RAISE EXCEPTION 'capture audit admission unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=r AND lane='capture' FOR UPDATE;
 SELECT * INTO STRICT a FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation FOR UPDATE;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',root.valid_until,trust.fresh_until,pool.valid_until,a.valid_until,(a.policy->>'ValidUntil')::timestamptz);
 IF NOT COALESCE(n<until_at AND trust.observed_at<=n AND NOT trust.recovery_blocked AND NOT trust.suspended AND NOT root.paused AND NOT pool.paused AND NOT a.paused AND a.account_version=pool.account_version AND a.guaranteed_records<=pool.records_per_account AND (a.policy->>'BackingRevision')::bigint=pool.revision,false) THEN RAISE EXCEPTION 'capture audit backing unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('RootID',r,'AllocationID',allocation,'AccountVersion',a.account_version,'AccountDigest',to_jsonb(ARRAY(SELECT get_byte(a.account_digest,k) FROM generate_series(0,31) k)),'Revision',a.revision,'Records',a.guaranteed_records,'RetainedSeconds',pool.retained_seconds,'Policy',a.policy,'ValidUntil',until_at,'HardUntil',LEAST(root.valid_until,pool.valid_until,a.valid_until,(a.policy->>'ValidUntil')::timestamptz));
END $$;
-- +goose StatementEnd

ALTER TABLE context_query_capacity ADD FOREIGN KEY(root_id) REFERENCES capacity_settings(root_id);

-- +goose StatementBegin
-- The shared context-query backing of a root, created with its capacity
-- settings. Dates follow the standing date instead of an admission window.
CREATE OR REPLACE FUNCTION ensure_shared_context_query_capacity(r uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_settings;t public.fleet_current_trust;q jsonb;e jsonb;w jsonb;acceptance uuid;n timestamptz:=clock_timestamp();
 hard timestamptz:=public.capacity_standing();effects timestamptz;cleanup timestamptz;retire timestamptz;plan jsonb;object_count numeric;keys numeric;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_settings WHERE root_id=r;
 IF NOT (s.qualification ? 'ContextQuery') OR EXISTS(SELECT 1 FROM public.context_query_capacity WHERE root_id=r) THEN RETURN;END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id;
 q:=s.qualification->'ContextQuery';e:=q->'Envelope';w:=q->'Profile'->'Worker';acceptance:=(q->>'CapacityID')::uuid;
 effects:=hard+(GREATEST((w->>'Runtime')::numeric,(w->>'CredentialLifetime')::numeric,(w->>'ProviderEffectLifetime')::numeric)/1000)*interval '1 microsecond';
 cleanup:=effects+((w->>'Cleanup')::numeric/1000)*interval '1 microsecond';
 retire:=cleanup+((2*(q->'History'->>'BackupHorizon')::numeric+(q->'History'->>'RetirementCleanup')::numeric)/1000)*interval '1 microsecond';
 object_count:=(e->>'AuditObjects')::numeric;keys:=(e->>'UnwrapAttempts')::numeric+(e->>'SigningAttempts')::numeric+(e->>'ProviderRequests')::numeric;
 plan:=jsonb_build_object('RootID',r,'InstallationID',s.installation_id,'AcceptanceID',acceptance,'Qualification',q,
  'Reservation',jsonb_build_object('SystemObjects',jsonb_build_object('Bytes',(object_count*(q->'History'->>'AuditCipherBytes')::numeric)::bigint,'Objects',object_count::bigint),'SQLBytes',e->'SQLBytes','BackupBytes',e->'BackupBytes','WALBytes',e->'WALBytes','KeyAttempts',keys::bigint),
  'HardUntil',public.capacity_json_timestamp(hard),'EffectsUntil',public.capacity_json_timestamp(effects),'CleanupUntil',public.capacity_json_timestamp(cleanup),'RetireBy',public.capacity_json_timestamp(retire));
 INSERT INTO public.context_query_capacity(root_id,acceptance_id,capacity_id,plan,source_digest,issuer_epoch,postmaster_at,database_oid,accepted_at)
  VALUES(r,acceptance,acceptance,plan,sha256(convert_to(s.qualification::text,'UTF8')),t.issuer_epoch,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()),n);
 INSERT INTO public.context_query_backing(root_id,installation_id,acceptance_id,profile,qualification,envelope,query_limit,principal_query_limit,principal_account_limit,allocation_limit,observed_at,fresh_until,hard_until,effects_until,cleanup_until,retire_by,suspended)
  VALUES(r,s.installation_id,acceptance,q->'Profile',q->'Profile'->'Qualification',e,(q->>'RootQueries')::bigint,(q->>'PrincipalQueries')::bigint,(q->>'PrincipalAccounts')::bigint,(q->>'WorkloadAccounts')::bigint,n,n+interval '5 seconds',hard,effects,cleanup,retire,false);
END $$;

-- The workload's query allocation, created with its capacity account.
CREATE OR REPLACE FUNCTION ensure_shared_context_query_allocation(r uuid,cluster uuid,namespace_id text,workload text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c public.context_query_capacity;b public.context_query_backing;s public.capacity_settings;limit_value bigint;identity jsonb;
BEGIN
 SELECT * INTO c FROM public.context_query_capacity WHERE root_id=r;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM public.context_query_allocation WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload) THEN RETURN;END IF;
 SELECT * INTO STRICT s FROM public.capacity_settings WHERE root_id=r;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r FOR UPDATE;
 limit_value:=(c.plan->'Qualification'->>'WorkloadQueries')::bigint;
 IF (b.allocations+1)::numeric*limit_value>b.query_limit OR b.allocations>=b.allocation_limit THEN RETURN;END IF;
 identity:=jsonb_build_object('UID','capacity','Generation',1,'Digest',to_jsonb(ARRAY(SELECT get_byte(sha256(convert_to('asservat-capacity/'||r::text,'UTF8')),k) FROM generate_series(0,31) k)));
 INSERT INTO public.context_query_allocation(id,root_id,cluster_id,namespace_uid,workload_uid,revision,pool_source,policy_source,query_limit)
  VALUES(gen_random_uuid(),r,cluster,namespace_id,workload,1,identity,identity,limit_value);
END $$;

CREATE OR REPLACE FUNCTION read_shared_context_query_plan(r uuid,cluster uuid,namespace_id text,workload text,actor jsonb,principal_key_value bytea,proposed_account uuid,path jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing;a public.context_query_allocation;account uuid;acceptance uuid;profile jsonb;n timestamptz;until_at timestamptz;
BEGIN
 SELECT acceptance_id INTO STRICT acceptance FROM public.context_query_capacity WHERE root_id=r;
 IF NOT public.lock_context_query_capacity(r,acceptance) OR principal_key_value IS NULL OR octet_length(principal_key_value)<>32 OR octet_length(actor::text)>4096 OR proposed_account IS NULL THEN
  RAISE EXCEPTION 'query capacity reader unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r FOR SHARE;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload FOR SHARE;
 IF NOT public.context_query_capacity_allocation_current(r,a.id) THEN RAISE EXCEPTION 'query allocation unavailable' USING ERRCODE='23514';END IF;
 profile:=jsonb_set(b.profile,'{Path}',path);
 IF path->>'TargetClusterID' IS DISTINCT FROM cluster::text OR NOT public.context_query_shared_profile_current(r,profile) THEN RAISE EXCEPTION 'shared query placement unavailable' USING ERRCODE='23514';END IF;
 SELECT id INTO account FROM public.context_query_principal WHERE root_id=r AND principal_key=principal_key_value FOR SHARE;
 n:=clock_timestamp();until_at:=LEAST(n+interval '5 seconds',b.hard_until);
 RETURN jsonb_build_object('AcceptanceID',acceptance,'AccountID',COALESCE(account,proposed_account),'AllocationID',a.id,'RootID',r,'InstallationID',b.installation_id,
  'ClusterID',a.cluster_id,'NamespaceUID',a.namespace_uid,'WorkloadUID',a.workload_uid,'AllocationRevision',a.revision,'PoolSource',a.pool_source,'PolicySource',a.policy_source,'Principal',actor,'Profile',profile,
  'ObservedAt',public.capacity_json_timestamp(n),'ValidUntil',public.capacity_json_timestamp(until_at),'HardUntil',public.capacity_json_timestamp(b.hard_until),'EffectsUntil',public.capacity_json_timestamp(b.effects_until),'CleanupUntil',public.capacity_json_timestamp(b.cleanup_until),'RetireBy',public.capacity_json_timestamp(b.retire_by));
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_shared_profile_current(r uuid,p jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.context_query_backing;t public.fleet_current_trust;h public.download_worker_configuration;v public.download_worker_configuration_revision;path jsonb:=p->'Path';profile jsonb;snapshot jsonb;n timestamptz;
BEGIN
 SELECT * INTO STRICT s FROM public.context_query_backing WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 SELECT * INTO STRICT h FROM public.download_worker_configuration WHERE installation_id=s.installation_id AND cluster_id=(path->>'AcquisitionClusterID')::uuid AND source_uid=(path->'WorkerConfiguration'->>'UID')::uuid FOR SHARE;
 SELECT * INTO STRICT v FROM public.download_worker_configuration_revision WHERE installation_id=h.installation_id AND cluster_id=h.cluster_id AND source_uid=h.source_uid AND generation=h.generation;
 snapshot:=convert_from(v.snapshot_json,'UTF8')::jsonb;profile:=snapshot->'Profile';n:=clock_timestamp();
 RETURN COALESCE(NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=n AND n<t.fresh_until AND
 h.observed_at<=n AND n<h.fresh_until AND NOT (snapshot->>'Suspended')::boolean AND snapshot->>'RecoveryEpoch'=t.issuer_epoch::text AND
 v.audit_receipt_json IS NOT NULL AND profile->'Configuration'=path->'WorkerConfiguration' AND profile->>'InstallationID'=s.installation_id::text AND profile->>'ClusterID'=path->>'AcquisitionClusterID' AND
 profile->>'StoreCredentialSecret'<>'' AND (profile->>'CPUMillis')::numeric=(p->'Worker'->>'CPUMilli')::numeric AND (profile->>'MemoryBytes')::numeric=(p->'Worker'->>'MemoryBytes')::numeric AND
 (p->'Worker'->>'EphemeralStorageBytes')::numeric=4194304 AND (p->'Worker'->>'Runtime')::numeric<=(profile->>'MaxRuntime')::numeric AND
 path->>'Purpose'='context-projection/v1' AND path->>'ConnectorClusterID'=path->>'AcquisitionClusterID' AND clock_timestamp()<LEAST(t.fresh_until,h.fresh_until),false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd

-- Downloads count bytes, not sessions or responses (specs/capacity.md:
-- sessions are not counted beyond Kubernetes object and rate limits). The
-- response window bound keeps one partial window per request (1024).
ALTER TABLE download_allocation DROP COLUMN session_limit, DROP COLUMN reserved_sessions;
ALTER TABLE download_control_allocation DROP COLUMN response_limit, DROP COLUMN reserved_responses;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_download_stop_backing()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE p public.download_stop_pool; a public.download_allocation;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'stop allocation retirement requires positive proof' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT p FROM public.download_stop_pool WHERE root_id=NEW.root_id FOR UPDATE;
  SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id FOR SHARE;
  IF NEW.charged<>0 OR NEW.slots>p.slots-p.allocated OR clock_timestamp()>=p.valid_until THEN RAISE EXCEPTION 'stop backing unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.download_stop_pool SET allocated=allocated+NEW.slots WHERE root_id=NEW.root_id;
 ELSIF (to_jsonb(NEW)-'charged') IS DISTINCT FROM (to_jsonb(OLD)-'charged') OR pg_trigger_depth()<2 OR (NEW.charged<>OLD.charged+1 AND NEW.charged<>OLD.charged-public.download_stop_charge_releasing(OLD.allocation_id)) THEN
  RAISE EXCEPTION 'immutable stop backing and charge' USING ERRCODE='23514';
 END IF;RETURN NEW;
END $function$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_download_response()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE s public.artifact_download;c public.download_control_allocation;n timestamptz;used bigint;length bigint;off bigint;read_each bigint;win bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download response lifecycle unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT s FROM public.artifact_download WHERE id=NEW.session_id AND root_id=NEW.root_id FOR UPDATE;
  SELECT * INTO STRICT c FROM public.download_control_allocation WHERE id=s.allocation_id AND root_id=s.root_id FOR UPDATE;
  c:=public.capacity_session_control(s,c);
  IF NOT (NEW.plan_json ?& ARRAY['Version','Selection','WholeFile','WindowReadLimit']) OR (NEW.plan_json-ARRAY['Version','Selection','WholeFile','WindowReadLimit'])<>'{}'::jsonb OR jsonb_typeof(NEW.plan_json->'Selection') IS DISTINCT FROM 'object' OR NOT ((NEW.plan_json->'Selection') ?& ARRAY['Offset','Length','Partial']) OR ((NEW.plan_json->'Selection')-ARRAY['Offset','Length','Partial'])<>'{}'::jsonb OR jsonb_typeof(NEW.plan_json->'WholeFile') IS DISTINCT FROM 'boolean' OR jsonb_typeof(NEW.plan_json#>'{Selection,Partial}') IS DISTINCT FROM 'boolean' THEN RAISE EXCEPTION 'closed native response plan required' USING ERRCODE='23514';END IF;
  n:=clock_timestamp();length:=(NEW.plan_json#>>'{Selection,Length}')::bigint;off:=(NEW.plan_json#>>'{Selection,Offset}')::bigint;read_each:=(NEW.plan_json->>'WindowReadLimit')::bigint;
  IF length IS NULL OR off IS NULL OR read_each IS NULL OR (NEW.plan_json->>'Version') IS DISTINCT FROM '1' OR length<0 OR length>1099511627776 OR off<0 OR off>1099511627776-length OR read_each<1 OR (NEW.plan_json->>'WholeFile')::boolean AND off<>0 OR (NEW.plan_json#>>'{Selection,Partial}')::boolean AND length=0 THEN RAISE EXCEPTION 'invalid native response plan' USING ERRCODE='23514';END IF;
  win:=greatest(1,(length+67108863)/67108864);
  SELECT coalesce(sum(reserved_windows),0) INTO used FROM public.download_response WHERE session_id=s.id;
  IF n>=c.valid_until OR n>=NEW.lease_until OR n>=NEW.until_at OR NEW.until_at>s.deadline OR NEW.until_at>c.valid_until OR NEW.started_at>n OR NEW.lease_until>NEW.started_at+interval '5 seconds' OR NEW.generation<>s.generation+1 OR s.state NOT IN ('Ready','Streaming','Interrupted') OR NEW.window_count<>0 OR NEW.completed_windows<>0 OR NEW.emitted_bytes<>0 OR NEW.active_window IS NOT NULL OR NEW.closed OR NEW.lease_sequence<>0 OR NEW.reserved_windows<>win OR read_each>70368744177664/win OR read_each*win>s.read_limit-s.charged_read OR length>s.output_limit-s.charged_output OR used+win>((s.output_limit-1)/67108864+1)+1024 THEN RAISE EXCEPTION 'download response unavailable' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM public.download_response WHERE session_id=s.id AND generation=s.generation AND NOT closed AND lease_until>n) OR EXISTS(SELECT 1 FROM public.download_batch WHERE id=s.active_batch AND lease_until>n AND outcome_json IS NULL) THEN RAISE EXCEPTION 'download response busy' USING ERRCODE='23514';END IF;
  UPDATE public.download_control_allocation SET reserved_windows=reserved_windows+win,reserved_audit_bytes=reserved_audit_bytes+win*262144 WHERE id=c.id;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.session_id,NEW.owner_id,NEW.generation,NEW.plan_json,NEW.reserved_windows,NEW.started_at,NEW.until_at) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.session_id,OLD.owner_id,OLD.generation,OLD.plan_json,OLD.reserved_windows,OLD.started_at,OLD.until_at) OR NEW.window_count<OLD.window_count OR NEW.completed_windows<OLD.completed_windows OR NEW.emitted_bytes<OLD.emitted_bytes OR NEW.lease_sequence<OLD.lease_sequence OR OLD.closed AND NOT NEW.closed THEN RAISE EXCEPTION 'immutable native response' USING ERRCODE='23514';END IF;
  IF NEW.lease_sequence<>OLD.lease_sequence AND (NEW.lease_sequence<>OLD.lease_sequence+1 OR NEW.lease_until>clock_timestamp()+interval '5 seconds' OR OLD.closed) OR pg_trigger_depth()<2 AND NEW.lease_sequence=OLD.lease_sequence AND NEW.lease_until IS DISTINCT FROM OLD.lease_until THEN RAISE EXCEPTION 'invalid response lease transition' USING ERRCODE='23514';END IF;
  IF pg_trigger_depth()<2 AND ROW(NEW.window_count,NEW.completed_windows,NEW.emitted_bytes,NEW.active_window) IS DISTINCT FROM ROW(OLD.window_count,OLD.completed_windows,OLD.emitted_bytes,OLD.active_window) THEN RAISE EXCEPTION 'window-managed response accounting' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $function$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION capacity_charge(uuid,bigint,bigint),capacity_release(uuid,bigint,bigint),capacity_apply(uuid,uuid,text,text,jsonb,jsonb),capacity_enroll(uuid,uuid,text,text,uuid,uuid,bytea),read_capacity_qualification(uuid),read_capacity_qualification_pin(uuid,uuid),read_capacity_audit_profiles(uuid,uuid,uuid,bytea,text,timestamptz,timestamptz),capacity_managed_admission_until(uuid,uuid,text,timestamptz),ensure_shared_context_query_capacity(uuid),ensure_shared_context_query_allocation(uuid,uuid,text,text),read_shared_context_query_plan(uuid,uuid,text,text,jsonb,bytea,uuid,jsonb),context_query_shared_profile_current(uuid,jsonb) FROM PUBLIC;
