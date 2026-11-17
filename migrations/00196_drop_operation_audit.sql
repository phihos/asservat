-- +goose Up
-- REQ-AUT-005 / REQ-DB-004 (ADR-330 D6): every public operation and effect
-- now writes its own audit_event row. Drop the encrypted operation audit:
-- lanes, pools, accounts, records, lifecycles, history, the capture audit
-- roles and their guards. Capacity creates no audit pool and enrollment
-- reserves no audit account. No Down: every statement can be reapplied.
DROP VIEW IF EXISTS capture_operation_pool, capture_operation_account, capture_operation_audit,
 capture_operation_lifecycle, capture_operation_history;
DROP TABLE IF EXISTS operation_audit_lifecycle, operation_audit_history, operation_audit,
 operation_audit_account, operation_audit_pool, capture_audit_root;
DROP FUNCTION IF EXISTS guard_operation_audit_pool(), guard_operation_audit_account(), guard_operation_audit(),
 guard_operation_audit_lifecycle(), guard_operation_audit_history(), create_operation_audit_lifecycle(),
 release_operation_audit_charge(), drain_operation_audit_history(), require_operation_audit_history_retirement(),
 require_operation_audit_retirement(), record_operation_proof_window_missed(),
 operation_lifecycle_retiring(uuid,text,bytea), operation_history_releasing(uuid,text,bytea),
 finish_operation_audit_history(uuid,text,bytea,timestamptz,timestamptz,uuid),
 finish_operation_audit_retirement(uuid,uuid,uuid),
 finish_capture_operation_retirement(uuid,uuid,uuid),
 finish_capture_operation_history(uuid,text,bytea,timestamptz,timestamptz,uuid),
 operation_audit_profile_covers(jsonb,jsonb), operation_audit_human_input_valid(text,text),
 operation_audit_lane(text), operation_audit_history_layout_valid(text,text),
 operation_audit_history_fixed_transitions(text), operation_audit_history_verifier_backed(text),
 operation_audit_history_minimum_row(text), capture_audit_role_ok(uuid,text),
 capture_audit_login_private(), guard_capture_audit_root(), guard_capture_audit_access();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_apply(r uuid, cluster uuid, namespace_uid text, av text, q jsonb, v jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $$
DECLARE s public.capacity_settings;installation uuid:=(q->'RootBacking'->>'InstallationID')::uuid;i jsonb:=q->'RootBacking';b jsonb:=q->'Backends'->0;
 standing timestamptz:=public.capacity_standing();pool uuid;available bigint;slots bigint;
 retire timestamptz;share bigint;
BEGIN
 IF r IS NULL OR installation IS NULL OR (i->>'RootID')::uuid IS DISTINCT FROM r OR jsonb_array_length(q->'Backends')<>1 OR
  (v->>'EvidenceBytes')::bigint IS NULL OR (v->>'LimitBytes')::bigint IS NULL THEN RAISE EXCEPTION 'capacity settings invalid' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO s FROM public.capacity_settings WHERE root_id=r FOR UPDATE;
 IF NOT FOUND THEN
  pool:=(b->>'PoolID')::uuid;
  INSERT INTO public.custody_pool(id,store_id,revision,valid_until,paused,byte_limit,object_limit)
   VALUES(pool,(b->>'EvidenceStoreID')::uuid,1,standing,false,(v->>'EvidenceBytes')::bigint-(v->>'ReserveBytes')::bigint,1125899906842624);
  retire:=standing+make_interval(secs=>(2*(i->'ProcessingState'->>'BackupHorizonSeconds')::bigint+(i->'ProcessingState'->>'CleanupSeconds')::bigint)::double precision);
  INSERT INTO public.processing_root(root_id,installation_id,issuer_epoch,epoch,source_uid,protection_digest,backing,backing_revision,valid_until,retire_by,max_captures,max_rules,max_root_transitions)
   SELECT r,installation,t.issuer_epoch,(i->>'ProcessingEpoch')::uuid,(i->>'ProcessingSourceUID')::uuid,public.connector_digest(i->'ProcessingProtectionDigest'),
    (i->'ProcessingState')||jsonb_build_object('ValidUntil',standing,'RetireBy',retire),
    1,standing,retire,
    (i->'ProcessingState'->>'MaxCaptures')::bigint,(i->'ProcessingState'->>'MaxRules')::bigint,(i->'ProcessingState'->>'MaxRootTransitions')::bigint
   FROM public.fleet_current_trust t WHERE t.installation_id=installation;
  INSERT INTO public.capacity_settings(root_id,installation_id,account_version,qualification,pool_id,evidence_bytes,reserve_bytes,share_bytes,limit_bytes,namespace_limit_bytes,max_concurrent_expensive,revision)
   VALUES(r,installation,av,q,pool,(v->>'EvidenceBytes')::bigint,(v->>'ReserveBytes')::bigint,NULLIF((v->>'ShareBytes')::bigint,0),(v->>'LimitBytes')::bigint,NULLIF((v->>'NamespaceLimitBytes')::bigint,0),
    (v->>'MaxConcurrentExpensive')::integer,1) RETURNING * INTO s;
  IF q ? 'ContextQuery' THEN PERFORM public.ensure_shared_context_query_capacity(r);END IF;
 ELSE
  available:=(v->>'EvidenceBytes')::bigint-(v->>'ReserveBytes')::bigint;
  PERFORM 1 FROM public.custody_pool WHERE id=s.pool_id FOR UPDATE;
  UPDATE public.capacity_settings SET evidence_bytes=(v->>'EvidenceBytes')::bigint,reserve_bytes=(v->>'ReserveBytes')::bigint,share_bytes=NULLIF((v->>'ShareBytes')::bigint,0),limit_bytes=(v->>'LimitBytes')::bigint,
   namespace_limit_bytes=NULLIF((v->>'NamespaceLimitBytes')::bigint,0),max_concurrent_expensive=(v->>'MaxConcurrentExpensive')::integer,revision=revision+1
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
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_enroll(r uuid, cluster uuid, namespace_id text, workload text, allocation uuid, download uuid, account_digest bytea)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $$
DECLARE s public.capacity_settings;p public.custody_pool;w public.capacity_account;i jsonb;share bigint;accounts bigint;standing timestamptz:=public.capacity_standing();
 native jsonb;h jsonb;retire timestamptz;ns bigint;
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
 INSERT INTO public.capacity_account(allocation_id,download_allocation_id,root_id,cluster_id,namespace_uid,workload_uid,protected_bytes)
  VALUES(allocation,download,r,cluster,namespace_id,workload,share);
 IF s.qualification ? 'ContextQuery' THEN PERFORM public.ensure_shared_context_query_allocation(r,cluster,namespace_id,workload);END IF;
 RETURN allocation;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_apply(uuid,uuid,text,text,jsonb,jsonb), capacity_enroll(uuid,uuid,text,text,uuid,uuid,bytea) FROM PUBLIC;
