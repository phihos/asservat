-- +goose Up
-- ADR-219: approved queries use the installed capacity root and exact workload
-- allocation. No second source observer or four-deployment acceptance exists.
-- Earlier, unshipped qualification layouts cannot authorize new work.
ALTER TABLE context_query_backing DROP CONSTRAINT context_query_ephemeral_storage_backed;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_qualification_valid(q jsonb,base jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb:=q->'Profile';h jsonb:=q->'History';k text;calls numeric;controls numeric;audits numeric;need numeric;extra numeric;
BEGIN
 IF NOT public.capacity_json_fields(q,ARRAY['Format','CapacityID','Profile','History','Envelope','RootQueries','PrincipalQueries','PrincipalAccounts','WorkloadAccounts','WorkloadQueries','Admission']) OR
 q->>'Format' IS DISTINCT FROM 'shared-installed-context-query/v1' OR NOT public.capacity_json_uuid(q->'CapacityID') OR NOT public.context_query_cost_valid(p) OR
 NOT public.capacity_json_fields(p,ARRAY['ID','Source','Qualification','Path','Lifetime','Worker','Cost','PollLimit','ControlTransitionLimit']) OR
 NOT public.capacity_json_uuid(p->'ID') OR NOT public.capacity_revision_valid(p->'Source') OR NOT public.capacity_revision_valid(p->'Qualification') OR
 p->'Path' IS DISTINCT FROM jsonb_build_object('Purpose','context-projection/v1','ID','','TargetClusterID','','StoreID','','StorageRegion','','AcquisitionClusterID','','AcquisitionRegion','','ConnectorClusterID','','ConnectorRegion','','HubClusterID','','HubRegion','','WorkerConfiguration',jsonb_build_object('UID','','Generation',0,'Digest',to_jsonb(array_fill(0,ARRAY[32]))),'HubConfiguration',jsonb_build_object('UID','','Generation',0,'Digest',to_jsonb(array_fill(0,ARRAY[32])))) OR
 NOT public.capacity_json_fields(p->'Worker',ARRAY['CPUMilli','MemoryBytes','EphemeralStorageBytes','WorkerTransientBytes','HubTransientBytes','ProviderConcurrency','AuthenticationConcurrency','Runtime','CredentialLifetime','ProviderEffectLifetime','Cleanup']) OR
 NOT public.capacity_json_fields(p->'Cost',ARRAY['Workers','ReadBatches','ReadBytes','StructuredBytes','WireBytes','UnwrapAttempts','ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes']) OR
 NOT public.capacity_json_fields(q->'Envelope',ARRAY['Workers','ReadBatches','ReadBytes','StructuredBytes','WireBytes','UnwrapAttempts','ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes']) OR
 NOT public.capacity_json_fields(h,ARRAY['Layout','Revision','FixedBytes','PrincipalBytes','AllocationBytes','RowBytes','FixedQueryRows','InvocationRows','ControlRows','TransitionWALBytes','BackupCopies','WALCopies','AuditCipherBytes','BackupHorizon','RetirementCleanup']) OR
 h->>'Layout' IS DISTINCT FROM 'shared-context-query-history/v1' OR NOT public.capacity_revision_valid(h->'Revision') OR
 NOT public.capacity_json_integer(q->'Admission',1000000000,31536000000000000) OR (q->>'Admission')::numeric>(base->>'AdmissionSeconds')::numeric*1000000000 THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['Runtime','CredentialLifetime','ProviderEffectLifetime','Cleanup'] LOOP
  IF NOT public.capacity_json_integer(p->'Worker'->k,1000,31536000000000000) OR mod((p->'Worker'->>k)::numeric,1000)<>0 THEN RETURN false;END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['CPUMilli','MemoryBytes','EphemeralStorageBytes','WorkerTransientBytes','HubTransientBytes','ProviderConcurrency','AuthenticationConcurrency'] LOOP
  IF NOT public.capacity_json_integer(p->'Worker'->k,1,1152921504606846976) THEN RETURN false;END IF;
 END LOOP;
 IF (p->'Worker'->>'Runtime')::numeric<(p->>'Lifetime')::numeric OR (p->'Worker'->>'WorkerTransientBytes')::numeric>(p->'Worker'->>'MemoryBytes')::numeric OR
 mod((q->>'Admission')::numeric,1000)<>0 OR mod((p->>'Lifetime')::numeric,1000)<>0 THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['RootQueries','PrincipalQueries','PrincipalAccounts','WorkloadAccounts','WorkloadQueries'] LOOP
  IF NOT public.capacity_json_integer(q->k,1,1000000) THEN RETURN false;END IF;
 END LOOP;
 IF (q->>'PrincipalQueries')::numeric>(q->>'RootQueries')::numeric OR (q->>'PrincipalAccounts')::numeric>(q->>'RootQueries')::numeric OR
 (q->>'WorkloadAccounts')::numeric>(base->>'Accounts')::numeric OR (q->>'WorkloadAccounts')::numeric*(q->>'WorkloadQueries')::numeric>(q->>'RootQueries')::numeric THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['FixedBytes','PrincipalBytes','AllocationBytes','RowBytes','FixedQueryRows','InvocationRows','ControlRows','TransitionWALBytes','AuditCipherBytes'] LOOP
  IF NOT public.capacity_json_integer(h->k,1,1152921504606846976) THEN RETURN false;END IF;
 END LOOP;
 IF NOT public.capacity_json_integer(h->'BackupCopies',1,64) OR NOT public.capacity_json_integer(h->'WALCopies',1,64) OR
 (h->>'BackupCopies')::numeric<(base->'Metadata'->>'BackupCopies')::numeric OR (h->>'WALCopies')::numeric<(base->'Metadata'->>'WALCopies')::numeric OR
 NOT public.capacity_json_integer(h->'BackupHorizon',1000,31536000000000000) OR NOT public.capacity_json_integer(h->'RetirementCleanup',1000,86400000000000) OR
 (h->>'BackupHorizon')::numeric<(base->'Normal'->'Policy'->>'BackupHorizonSeconds')::numeric*1000000000 OR (h->>'RetirementCleanup')::numeric<(base->'Normal'->'Policy'->>'CleanupBudgetSeconds')::numeric*1000000000 OR
 mod((h->>'BackupHorizon')::numeric,1000)<>0 OR mod((h->>'RetirementCleanup')::numeric,1000)<>0 THEN RETURN false;END IF;
 calls:=1+(p->>'PollLimit')::numeric;controls:=(p->>'ControlTransitionLimit')::numeric;audits:=2*calls+2+(p->'Cost'->>'SigningAttempts')::numeric;
 IF (h->>'FixedQueryRows')::numeric<8+(p->'Cost'->>'SigningAttempts')::numeric OR (p->'Cost'->>'SQLRows')::numeric<(h->>'FixedQueryRows')::numeric+calls*(h->>'InvocationRows')::numeric+controls*(h->>'ControlRows')::numeric OR
 (p->'Cost'->>'AuditObjects')::numeric<audits OR (p->'Cost'->>'SQLBytes')::numeric<(p->'Cost'->>'SQLRows')::numeric*(h->>'RowBytes')::numeric OR
 (p->'Cost'->>'BackupBytes')::numeric<(p->'Cost'->>'SQLBytes')::numeric*(h->>'BackupCopies')::numeric OR
 (p->'Cost'->>'WALBytes')::numeric<(controls+9+4*(p->'Cost'->>'SigningAttempts')::numeric)*(h->>'TransitionWALBytes')::numeric*(h->>'WALCopies')::numeric OR
 (p->'Cost'->>'AuthenticationRequests')::numeric<calls+controls+(p->'Cost'->>'SigningAttempts')::numeric OR
 (p->'Cost'->>'ProviderRequests')::numeric<2*audits+(p->'Cost'->>'UnwrapAttempts')::numeric+(p->'Cost'->>'SigningAttempts')::numeric+(p->'Cost'->>'ReadBatches')::numeric THEN RETURN false;END IF;
 extra:=(h->>'FixedBytes')::numeric+(h->>'PrincipalBytes')::numeric*(q->>'PrincipalAccounts')::numeric+(h->>'AllocationBytes')::numeric*(q->>'WorkloadAccounts')::numeric;
 FOREACH k IN ARRAY ARRAY['Workers','ReadBatches','ReadBytes','StructuredBytes','WireBytes','UnwrapAttempts','ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes'] LOOP
  need:=(p->'Cost'->>k)::numeric*(q->>'RootQueries')::numeric;
  IF k='SQLBytes' THEN need:=need+extra;ELSIF k='BackupBytes' THEN need:=need+extra*(h->>'BackupCopies')::numeric;ELSIF k='WALBytes' THEN need:=need+(1+(q->>'PrincipalAccounts')::numeric+(q->>'WorkloadAccounts')::numeric)*(h->>'TransitionWALBytes')::numeric*(h->>'WALCopies')::numeric;END IF;
  IF NOT public.capacity_json_integer(q->'Envelope'->k,1,1152921504606846976) OR (q->'Envelope'->>k)::numeric<need THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION context_query_capacity_plan(s public.capacity_source,acceptance uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE q jsonb:=s.qualification->'ContextQuery';c jsonb:=s.root_configuration;t jsonb:=s.root_plan->'Totals';e jsonb:=q->'Envelope';reservation jsonb;pool public.capacity_pool;k text;
 object_bytes numeric;object_count numeric;keys numeric;hard timestamptz;effects timestamptz;cleanup timestamptz;retire timestamptz;
BEGIN
 IF acceptance IS NULL OR NOT public.context_query_qualification_valid(q,s.qualification->'RootBacking') OR NOT public.capacity_root_configuration_valid(c) OR s.root_plan IS NULL THEN RETURN NULL;END IF;
 SELECT * INTO STRICT pool FROM public.capacity_pool WHERE root_id=s.root_id AND source_uid=s.root_plan->'Input'->>'SystemPoolUID';
 object_count:=(e->>'AuditObjects')::numeric;object_bytes:=object_count*(q->'History'->>'AuditCipherBytes')::numeric;
 keys:=(e->>'UnwrapAttempts')::numeric+(e->>'SigningAttempts')::numeric+(e->>'ProviderRequests')::numeric;
 IF object_bytes>1152921504606846976 OR keys>1152921504606846976 OR
  object_bytes+(t->'SystemObjects'->>'Bytes')::numeric>(s.root_plan#>>'{Input,Envelope,SystemObjects,Bytes}')::numeric OR
  object_count+(t->'SystemObjects'->>'Objects')::numeric>(s.root_plan#>>'{Input,Envelope,SystemObjects,Objects}')::numeric OR
  object_bytes+GREATEST(pool.backed_system_bytes,(t->'SystemObjects'->>'Bytes')::numeric)>pool.system_bytes OR object_count+GREATEST(pool.backed_system_objects,(t->'SystemObjects'->>'Objects')::numeric)>pool.system_objects OR
  keys+(t->>'KeyAttempts')::numeric>(s.root_plan#>>'{Input,Envelope,KeyAttempts}')::numeric THEN RETURN NULL;END IF;
 FOREACH k IN ARRAY ARRAY['SQLBytes','BackupBytes','WALBytes'] LOOP
  IF (e->>k)::numeric+(t->>k)::numeric>(s.root_plan->'Input'->'Envelope'->>k)::numeric THEN RETURN NULL;END IF;
 END LOOP;
 reservation:=jsonb_build_object('SystemObjects',jsonb_build_object('Bytes',object_bytes::bigint,'Objects',object_count::bigint),'SQLBytes',e->'SQLBytes','BackupBytes',e->'BackupBytes','WALBytes',e->'WALBytes','KeyAttempts',keys::bigint);
 -- Dates derive once from the ORIGINAL root attempt, not a renewal, source
 -- heartbeat, poll or caller's requested interval. Only microsecond-aligned
 -- durations are eligible, avoiding PostgreSQL upward rounding.
 FOREACH k IN ARRAY ARRAY['Runtime','CredentialLifetime','ProviderEffectLifetime','Cleanup'] LOOP
  IF NOT public.capacity_json_integer(q->'Profile'->'Worker'->k,1000,31536000000000000) OR mod((q->'Profile'->'Worker'->>k)::numeric,1000)<>0 THEN RETURN NULL;END IF;
 END LOOP;
 IF mod((q->>'Admission')::numeric,1000)<>0 OR mod((q->'History'->>'BackupHorizon')::numeric,1000)<>0 OR mod((q->'History'->>'RetirementCleanup')::numeric,1000)<>0 THEN RETURN NULL;END IF;
 hard:=(c->>'InitialObservedAt')::timestamptz+((q->>'Admission')::numeric/1000)*interval '1 microsecond';
 effects:=hard+(GREATEST((q->'Profile'->'Worker'->>'Runtime')::numeric,(q->'Profile'->'Worker'->>'CredentialLifetime')::numeric,(q->'Profile'->'Worker'->>'ProviderEffectLifetime')::numeric)/1000)*interval '1 microsecond';
 cleanup:=effects+((q->'Profile'->'Worker'->>'Cleanup')::numeric/1000)*interval '1 microsecond';
 retire:=cleanup+((2*(q->'History'->>'BackupHorizon')::numeric+(q->'History'->>'RetirementCleanup')::numeric)/1000)*interval '1 microsecond';
 IF hard>(c->>'PlannedUntil')::timestamptz THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('RootID',s.root_id,'InstallationID',s.installation_id,'AcceptanceID',acceptance,'RootAttemptID',c->'AttemptID','RootPlanDigest',c->'PlanDigest',
  'SetupInputDigest',to_jsonb(ARRAY(SELECT get_byte(decode(s.setup_receipt->>'inputDigest','hex'),byte_index.value) FROM generate_series(0,31) AS byte_index(value))),
  'Qualification',q,'Reservation',reservation,'HardUntil',public.capacity_json_timestamp(hard),'EffectsUntil',public.capacity_json_timestamp(effects),'CleanupUntil',public.capacity_json_timestamp(cleanup),'RetireBy',public.capacity_json_timestamp(retire));
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION guard_context_query_backing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE k text; need numeric;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query obligations remain backed' USING ERRCODE='23514'; END IF;
 IF NOT public.context_query_cost_valid(NEW.profile) OR NEW.qualification IS DISTINCT FROM NEW.profile->'Qualification' THEN RAISE EXCEPTION 'query profile incomplete' USING ERRCODE='23514'; END IF;
 FOREACH k IN ARRAY ARRAY['Workers','ReadBatches','ReadBytes','StructuredBytes','WireBytes','UnwrapAttempts','ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes'] LOOP
  need:=(NEW.profile->'Cost'->>k)::numeric*NEW.query_limit;
  IF (NEW.envelope->>k)::numeric IS NULL OR (NEW.envelope->>k)::numeric<need OR (NEW.envelope->>k)::numeric>1152921504606846976 THEN RAISE EXCEPTION 'query envelope insufficient' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF TG_OP='INSERT' THEN
  IF NEW.allocated<>0 OR NEW.principals<>0 OR NEW.allocations<>0 THEN RAISE EXCEPTION 'query initial spend invalid' USING ERRCODE='23514'; END IF;
 ELSIF (to_jsonb(NEW)-ARRAY['allocated','principals','allocations']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['allocated','principals','allocations']) OR
  NEW.allocated<OLD.allocated OR NEW.principals<OLD.principals OR NEW.allocations<OLD.allocations OR
  (ROW(NEW.allocated,NEW.principals,NEW.allocations) IS DISTINCT FROM ROW(OLD.allocated,OLD.principals,OLD.allocations) AND pg_trigger_depth()<2) OR
  NEW.observed_at<OLD.observed_at OR NEW.observed_at=OLD.observed_at AND NEW.fresh_until>OLD.fresh_until THEN
  RAISE EXCEPTION 'immutable query backing and spend' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION lock_context_query_capacity(r uuid,acceptance uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;a public.context_query_capacity;t public.fleet_current_trust;n timestamptz;until_at timestamptz;expected jsonb;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 SELECT * INTO STRICT a FROM public.context_query_capacity WHERE root_id=r AND acceptance_id=acceptance FOR SHARE;
 n:=clock_timestamp();until_at:=public.capacity_managed_root_until(r,n);expected:=public.context_query_capacity_plan(s,acceptance);
 RETURN COALESCE(until_at IS NOT NULL AND n<until_at AND NOT s.suspended AND s.negative_snapshot IS NULL AND
  public.capacity_setup_original_valid(s) AND expected IS NOT NULL AND a.plan=expected AND
  EXISTS(SELECT 1 FROM public.context_query_backing b WHERE b.root_id=r AND b.acceptance_id=acceptance) AND
  a.capacity_id=(expected->'Qualification'->>'CapacityID')::uuid AND a.observations=0 AND a.issuer_epoch=t.issuer_epoch AND
  a.postmaster_at=pg_postmaster_start_time() AND a.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND
  n<(a.plan->>'HardUntil')::timestamptz AND clock_timestamp()<until_at,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION context_query_capacity_allocation_current(r uuid,allocation uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.context_query_allocation;w public.capacity_workload;p public.capacity_pool;b public.context_query_backing;c public.context_query_capacity;n timestamptz;until_at timestamptz;
BEGIN
 SELECT * INTO STRICT c FROM public.context_query_capacity WHERE root_id=r;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE root_id=r AND id=allocation;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=r AND cluster_id=a.cluster_id AND namespace_uid=a.namespace_uid AND workload_uid=a.workload_uid;
 SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=r AND id=w.pool_id;
 n:=clock_timestamp();until_at:=public.capacity_managed_admission_until(r,w.allocation_id,'context',n);
 RETURN COALESCE(until_at IS NOT NULL AND n<until_at AND NOT b.suspended AND
  a.revision=w.revision AND a.query_limit=(c.plan->'Qualification'->>'WorkloadQueries')::bigint AND
  a.pool_source=jsonb_build_object('UID',w.plan->'PoolUID','Generation',w.plan->'PoolGeneration','Digest',p.plan->'Digest') AND
  a.policy_source=jsonb_build_object('UID',w.plan->'PolicyUID','Generation',w.plan->'PolicyGeneration','Digest',w.plan->'PolicyDigest') AND
  clock_timestamp()<LEAST(until_at,b.hard_until),false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION allocate_context_query_capacity(r uuid,acceptance uuid,cluster uuid,namespace_id text,workload text,new_id uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing;c public.context_query_capacity;w public.capacity_workload;p public.capacity_pool;a public.context_query_allocation;limit_value bigint;until_at timestamptz;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR NOT public.lock_context_query_capacity(r,acceptance) THEN RAISE EXCEPTION 'query allocation source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT c FROM public.context_query_capacity WHERE root_id=r;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r FOR UPDATE;
 IF b.suspended OR clock_timestamp()>=b.hard_until THEN RAISE EXCEPTION 'query backing unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload FOR SHARE;
 SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=r AND id=w.pool_id FOR SHARE;
 until_at:=LEAST(b.hard_until,public.capacity_managed_admission_until(r,w.allocation_id,'context',clock_timestamp()));
 IF public.capacity_managed_admission_until(r,w.allocation_id,'context',clock_timestamp()) IS NULL OR until_at IS NULL OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'query workload capacity unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO a FROM public.context_query_allocation WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload FOR UPDATE;
 IF NOT FOUND THEN
  limit_value:=(c.plan->'Qualification'->>'WorkloadQueries')::bigint;
  IF new_id IS NULL OR (b.allocations+1)::numeric*limit_value>b.query_limit OR b.allocations>=b.allocation_limit THEN RAISE EXCEPTION 'query reserved workload slots exhausted' USING ERRCODE='23514';END IF;
  INSERT INTO public.context_query_allocation(id,root_id,cluster_id,namespace_uid,workload_uid,revision,pool_source,policy_source,query_limit)
   VALUES(new_id,r,cluster,namespace_id,workload,w.revision,jsonb_build_object('UID',w.plan->'PoolUID','Generation',w.plan->'PoolGeneration','Digest',p.plan->'Digest'),
    jsonb_build_object('UID',w.plan->'PolicyUID','Generation',w.plan->'PolicyGeneration','Digest',w.plan->'PolicyDigest'),limit_value) RETURNING * INTO a;
 END IF;
 IF NOT public.context_query_capacity_allocation_current(r,a.id) OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'query allocation changed' USING ERRCODE='23514';END IF;
 RETURN a.id;
END $$;

-- Called only inside existing successful root/workload publication transactions.
-- There is no second native source read or polling owner. Unknown commits retain
-- these same immutable IDs and charges; a later call can only read exact replay.
CREATE FUNCTION ensure_shared_context_query_capacity(r uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;c public.context_query_capacity;b public.context_query_backing;q jsonb;expected jsonb;n timestamptz;until_at timestamptz;acceptance uuid;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') THEN RAISE EXCEPTION 'query capacity producer unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 IF NOT (s.qualification ? 'ContextQuery') THEN RETURN;END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 q:=s.qualification->'ContextQuery';acceptance:=(q->>'CapacityID')::uuid;
 expected:=public.context_query_capacity_plan(s,acceptance);n:=clock_timestamp();until_at:=public.capacity_managed_root_until(r,n);
 IF NOT public.capacity_setup_original_valid(s) OR expected IS NULL OR s.suspended OR s.negative_snapshot IS NOT NULL OR until_at IS NULL OR n>=until_at THEN
 RAISE EXCEPTION 'shared query original backing unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO c FROM public.context_query_capacity WHERE root_id=r FOR UPDATE;
 IF FOUND THEN
  IF c.plan IS DISTINCT FROM expected OR c.issuer_epoch<>t.issuer_epoch OR c.postmaster_at<>pg_postmaster_start_time() OR c.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR c.observations<>0 THEN
   RAISE EXCEPTION 'shared query immutable backing differs' USING ERRCODE='23514';END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM public.context_query_backing WHERE root_id=r) THEN RAISE EXCEPTION 'shared query cannot adopt backing' USING ERRCODE='23514';END IF;
  INSERT INTO public.context_query_capacity(root_id,acceptance_id,capacity_id,plan,source_digest,issuer_epoch,postmaster_at,database_oid,accepted_at)
  VALUES(r,acceptance,acceptance,expected,s.accepted_digest,t.issuer_epoch,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()),n);
  INSERT INTO public.context_query_backing(root_id,installation_id,acceptance_id,profile,qualification,envelope,query_limit,principal_query_limit,principal_account_limit,allocation_limit,observed_at,fresh_until,hard_until,effects_until,cleanup_until,retire_by,suspended)
  VALUES(r,s.installation_id,acceptance,q->'Profile',q->'Profile'->'Qualification',q->'Envelope',(q->>'RootQueries')::bigint,(q->>'PrincipalQueries')::bigint,(q->>'PrincipalAccounts')::bigint,(q->>'WorkloadAccounts')::bigint,n,LEAST(until_at,n+interval '5 seconds'),(expected->>'HardUntil')::timestamptz,(expected->>'EffectsUntil')::timestamptz,(expected->>'CleanupUntil')::timestamptz,(expected->>'RetireBy')::timestamptz,false);
 END IF;
 IF NOT public.lock_context_query_capacity(r,acceptance) OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'shared query source expired' USING ERRCODE='23514';END IF;
END $$;

CREATE FUNCTION ensure_shared_context_query_allocation(r uuid,cluster uuid,namespace_id text,workload text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;acceptance uuid;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') THEN RAISE EXCEPTION 'query allocation producer unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 IF NOT (s.qualification ? 'ContextQuery') THEN RETURN;END IF;
 SELECT acceptance_id INTO STRICT acceptance FROM public.context_query_capacity WHERE root_id=r;
 PERFORM public.allocate_context_query_capacity(r,acceptance,cluster,namespace_id,workload,gen_random_uuid());
END $$;

-- Current accepted worker configuration shares the query effect transaction.
-- This adds no remote source read, pool acquire or new acceptance authority.
CREATE FUNCTION context_query_shared_profile_current(r uuid,p jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;h public.download_worker_configuration;v public.download_worker_configuration_revision;path jsonb:=p->'Path';profile jsonb;snapshot jsonb;n timestamptz;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
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
CREATE FUNCTION read_shared_context_query_plan(r uuid,cluster uuid,namespace_id text,workload text,actor jsonb,principal_key_value bytea,proposed_account uuid,path jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;b public.context_query_backing;a public.context_query_allocation;account uuid;acceptance uuid;profile jsonb;snapshot jsonb;n timestamptz;until_at timestamptz;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT acceptance_id INTO STRICT acceptance FROM public.context_query_capacity WHERE root_id=r;
 IF NOT (public.capacity_role_ok(r,'capacity') OR public.capacity_audit_reader_pin_valid(s) AND EXISTS(SELECT 1 FROM pg_roles WHERE oid=s.audit_reader_role AND rolname=session_user)) OR
  NOT public.lock_context_query_capacity(r,acceptance) OR principal_key_value IS NULL OR octet_length(principal_key_value)<>32 OR octet_length(actor::text)>4096 OR proposed_account IS NULL THEN
  RAISE EXCEPTION 'query capacity reader unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r FOR SHARE;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload FOR SHARE;
 IF NOT public.context_query_capacity_allocation_current(r,a.id) THEN RAISE EXCEPTION 'query workload capacity unavailable' USING ERRCODE='23514';END IF;
 profile:=jsonb_set(b.profile,'{Path}',path);
 IF path->>'TargetClusterID' IS DISTINCT FROM cluster::text OR NOT public.context_query_shared_profile_current(r,profile) THEN RAISE EXCEPTION 'shared query placement unavailable' USING ERRCODE='23514';END IF;
 SELECT id INTO account FROM public.context_query_principal WHERE root_id=r AND principal_key=principal_key_value FOR SHARE;
 n:=clock_timestamp();until_at:=LEAST(n+interval '5 seconds',public.capacity_managed_root_until(r,n),b.hard_until);
 IF until_at IS NULL OR n>=until_at THEN RAISE EXCEPTION 'query capacity read expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('AcceptanceID',acceptance,'AccountID',COALESCE(account,proposed_account),'AllocationID',a.id,'RootID',r,'InstallationID',b.installation_id,
  'ClusterID',a.cluster_id,'NamespaceUID',a.namespace_uid,'WorkloadUID',a.workload_uid,'AllocationRevision',a.revision,'PoolSource',a.pool_source,'PolicySource',a.policy_source,'Principal',actor,'Profile',profile,
  'ObservedAt',public.capacity_json_timestamp(n),'ValidUntil',public.capacity_json_timestamp(until_at),'HardUntil',public.capacity_json_timestamp(b.hard_until),'EffectsUntil',public.capacity_json_timestamp(b.effects_until),'CleanupUntil',public.capacity_json_timestamp(b.cleanup_until),'RetireBy',public.capacity_json_timestamp(b.retire_by));
END $$;
CREATE OR REPLACE FUNCTION guard_context_query() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing; a public.context_query_allocation; p public.context_query_principal; n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query history retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['generation','active_batch','polls','controls','uncertain']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['generation','active_batch','polls','controls','uncertain']) OR
   NEW.generation<OLD.generation OR NEW.generation>OLD.generation+1 OR NEW.polls<OLD.polls OR NEW.controls<>OLD.controls+1 OR OLD.uncertain AND NOT NEW.uncertain OR
   NEW.polls>(NEW.query->'Plan'->'Profile'->>'PollLimit')::bigint OR NEW.controls>(NEW.query->'Plan'->'Profile'->>'ControlTransitionLimit')::bigint THEN RAISE EXCEPTION 'query counters immutable' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.context_query_principal WHERE id=NEW.account_id AND root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF NOT public.context_query_intent_current(NEW.root_id,NEW.operation_id,NEW.actor,NEW.issuer_epoch,NEW.initial_request->'Call') OR
  NOT public.context_query_complete_object(NEW.query,ARRAY['ID','OperationID','WorkerID','Scope','Plan','RecoveryIssuerEpoch','RecoveryRevision','CreatedAt','Deadline','WorkerUntil','CredentialUntil','ProviderUntil','CleanupUntil']) OR
  NOT public.context_query_complete_object(NEW.query->'Plan',ARRAY['AcceptanceID','AccountID','AllocationID','RootID','InstallationID','ClusterID','NamespaceUID','WorkloadUID','AllocationRevision','PoolSource','PolicySource','Principal','Profile','ObservedAt','ValidUntil','HardUntil','EffectsUntil','CleanupUntil','RetireBy']) OR
  NOT public.context_query_complete_object(NEW.query->'Scope',ARRAY['RootID','CaseID','ArtifactID','CaptureID','ClusterID','NamespaceUID','WorkloadUID','PodUID','Version','SourceProjectionDigest','SourceFormat','DisplayVersion','Selection','Principal']) OR
  b.suspended OR p.principal_key<>NEW.principal_key OR NEW.generation<>0 OR NEW.active_batch IS NOT NULL OR NEW.polls<>0 OR NEW.controls<>0 OR NEW.uncertain OR
  (NEW.query->'Plan'->'Profile'-'Path') IS DISTINCT FROM (b.profile-'Path') OR NEW.query->'Plan'->'Profile'->'Path'->>'TargetClusterID' IS DISTINCT FROM a.cluster_id::text OR NOT public.context_query_shared_profile_current(NEW.root_id,NEW.query->'Plan'->'Profile') OR NOT public.context_query_capacity_allocation_current(NEW.root_id,a.id) OR NEW.query->'Plan'->>'AcceptanceID'<>b.acceptance_id::text OR NEW.query->'Plan'->>'AllocationID'<>a.id::text OR
  NEW.query->'Plan'->>'AccountID'<>p.id::text OR NEW.query->'Plan'->>'ClusterID'<>a.cluster_id::text OR NEW.query->'Plan'->>'NamespaceUID'<>a.namespace_uid OR NEW.query->'Plan'->>'WorkloadUID'<>a.workload_uid OR
  NEW.query->'Plan'->'Principal' IS DISTINCT FROM NEW.actor OR NEW.query->'Scope'->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.query->'Scope'->>'ClusterID' IS DISTINCT FROM a.cluster_id::text OR NEW.query->'Scope'->>'NamespaceUID' IS DISTINCT FROM a.namespace_uid OR NEW.query->'Scope'->>'WorkloadUID' IS DISTINCT FROM a.workload_uid OR
  NEW.query->'Plan'->'PoolSource' IS DISTINCT FROM a.pool_source OR NEW.query->'Plan'->'PolicySource' IS DISTINCT FROM a.policy_source OR
  (NEW.query->'Plan'->>'AllocationRevision')::bigint<>a.revision OR NEW.query->'Scope'->'Principal' IS DISTINCT FROM NEW.actor OR
  NEW.query->>'ID'<>NEW.id::text OR NEW.query->>'WorkerID'<>NEW.worker_id::text OR NEW.query->>'OperationID'<>NEW.operation_id::text OR
  (NEW.query->>'CreatedAt')::timestamptz<>NEW.created_at OR (NEW.query->>'Deadline')::timestamptz<>NEW.deadline OR (NEW.query->>'CleanupUntil')::timestamptz<>NEW.cleanup_until OR
  NEW.deadline>NEW.created_at+make_interval(secs=>(b.profile->>'Lifetime')::double precision/1000000000) OR
  (NEW.query->'Plan'->>'RootID')::uuid<>NEW.root_id OR (NEW.query->'Plan'->>'InstallationID')::uuid<>b.installation_id OR
  (NEW.query->'Plan'->>'RetireBy')::timestamptz<>NEW.retire_by OR NEW.retire_by<>b.retire_by OR
  (NEW.query->'Plan'->>'HardUntil')::timestamptz<>b.hard_until OR (NEW.query->'Plan'->>'EffectsUntil')::timestamptz<>b.effects_until OR (NEW.query->'Plan'->>'CleanupUntil')::timestamptz<>b.cleanup_until OR
  NEW.deadline>b.hard_until OR NEW.cleanup_until>b.cleanup_until OR n>=(NEW.query->'Plan'->>'ValidUntil')::timestamptz OR n<(NEW.query->'Plan'->>'ObservedAt')::timestamptz OR
  (NEW.query->>'WorkerUntil')::timestamptz>b.effects_until OR (NEW.query->>'CredentialUntil')::timestamptz>b.effects_until OR (NEW.query->>'ProviderUntil')::timestamptz>b.effects_until OR
  NEW.query->>'RecoveryIssuerEpoch' IS DISTINCT FROM NEW.issuer_epoch::text OR NEW.created_at>n OR NEW.created_at<(NEW.initial_request->'Call'->>'StartedAt')::timestamptz OR
  NEW.postmaster_at<>pg_postmaster_start_time() OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR n>=NEW.deadline THEN
  RAISE EXCEPTION 'query accepted backing unavailable' USING ERRCODE='23514'; END IF;
 UPDATE public.context_query_backing SET allocated=allocated+1 WHERE root_id=NEW.root_id;
 UPDATE public.context_query_allocation SET allocated=allocated+1 WHERE id=NEW.allocation_id;
 UPDATE public.context_query_principal SET allocated=allocated+1 WHERE id=NEW.account_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ensure_shared_context_query_capacity(uuid),ensure_shared_context_query_allocation(uuid,uuid,text,text),context_query_shared_profile_current(uuid,jsonb),read_shared_context_query_plan(uuid,uuid,text,text,jsonb,bytea,uuid,jsonb) FROM PUBLIC;
-- Remove the unused development observation engine instead of keeping a second
-- producer or a compatibility path. Retained historical rows are not adopted.
DROP FUNCTION read_context_query_capacity_source(uuid,jsonb),begin_context_query_capacity_observation(uuid,jsonb,jsonb,uuid,bigint),accept_context_query_capacity(uuid,jsonb,jsonb,jsonb),complete_context_query_capacity_observation(uuid,jsonb,timestamptz),suspend_context_query_capacity(uuid,timestamptz),read_context_query_capacity_plan(uuid,uuid,uuid,text,text,jsonb,bytea,uuid);
