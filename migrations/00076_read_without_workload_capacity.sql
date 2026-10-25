-- +goose Up
-- Maintainer decision (2026-10-23): reading already stored evidence, i.e.
-- approved pod-status inspection and native download preparation/transfer,
-- no longer depends on live capacity observations. capacity_workload,
-- context_storage_binding freshness, capacity_managed_admission_until and
-- capacity_managed_root_until gate collection only (custody_attempt,
-- context_capture and capture-lane operation audit). Reads stay bounded by
-- the shared acquisition worker limit, the immutable query/download charges
-- reserved at acceptance and enrollment, per-principal audit allowances and
-- every authorization, retention, recovery, processing and catalog check.
-- Evidence of a deleted workload remains readable within retention.
DROP TRIGGER zzz_capacity_new_admission ON artifact_download;
DROP FUNCTION demand_capacity_refresh_for_download(uuid,uuid);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION require_capacity_new_admission() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r uuid;a uuid;until_at timestamptz;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'invalid capacity admission source' USING ERRCODE='23514';END IF;
 IF TG_RELID='public.custody_attempt'::regclass THEN
  SELECT p.root_id INTO r FROM public.custody_allocation allocation JOIN public.capacity_pool p ON p.id=allocation.pool_id WHERE allocation.id=NEW.allocation_id;
  IF NOT FOUND THEN RETURN NEW;END IF;
  a:=NEW.allocation_id;
 ELSIF TG_RELID='public.context_capture'::regclass THEN
  r:=NEW.root_id;SELECT allocation_id INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 ELSIF TG_RELID='public.operation_audit'::regclass THEN
  -- Only collection audit is workload-capacity gated; read and other lanes
  -- are bounded by their own per-principal audit allowance.
  IF NEW.lane<>'capture' THEN RETURN NEW;END IF;
  r:=NEW.root_id;SELECT allocation_id INTO STRICT a FROM public.custody_attempt WHERE id=(NEW.intent#>>'{Capture,AttemptID}')::uuid;
 ELSE RAISE EXCEPTION 'invalid capacity admission table' USING ERRCODE='23514';END IF;
 until_at:=public.capacity_managed_admission_until(r,a,'context',clock_timestamp());
 IF until_at IS NULL OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'managed capacity admission incomplete or expired' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

-- The original session snapshot keeps the workload's immutable enrollment
-- identity and its download allocation's dates. It no longer reads the
-- workload's current observation or waits on the capacity source row.
CREATE OR REPLACE FUNCTION require_capacity_download_snapshot() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source public.capacity_source;w public.capacity_workload;p public.capacity_pool;a public.download_allocation;c public.download_control_allocation;b public.download_native_backing;
BEGIN
 IF NEW.capacity_account_id IS NOT NULL OR NEW.capacity_backing IS NOT NULL OR NEW.capacity_backing_digest IS NOT NULL THEN RAISE EXCEPTION 'caller cannot provide capacity session backing' USING ERRCODE='23514';END IF;
 SELECT * INTO source FROM public.capacity_source WHERE root_id=NEW.root_id;
 IF NOT FOUND THEN RETURN NEW;END IF;
 PERFORM 1 FROM public.fleet_trust WHERE installation_id=source.installation_id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE NOWAIT;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=NEW.root_id AND download_allocation_id=NEW.allocation_id;
 SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=w.root_id AND id=w.pool_id;
 SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id FOR SHARE;
 SELECT * INTO STRICT c FROM public.download_control_allocation WHERE id=a.id AND root_id=a.root_id FOR SHARE;
 SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=a.id AND root_id=a.root_id FOR SHARE;
 IF w.ready_at IS NULL OR clock_timestamp()>=LEAST(a.valid_until,c.valid_until) THEN RAISE EXCEPTION 'download allocation backing unavailable' USING ERRCODE='23514';END IF;
 NEW.capacity_account_id:=w.id;
 NEW.capacity_backing:=jsonb_build_object('Format','protected-capacity/v1','AccountID',w.id,'AttemptID',w.attempt_id,'AllocationID',w.download_allocation_id,'Revision',(source.root_configuration->>'Revision')::bigint,
  'PoolSource',jsonb_build_object('UID',p.source_uid,'Generation',p.source_generation,'Digest',p.plan->'Digest'),
  'PolicySource',jsonb_build_object('UID',w.policy_uid,'Generation',w.plan->'PolicyGeneration','Digest',w.plan->'PolicyDigest'),
  'AllocationUntil',a.valid_until,'ControlUntil',c.valid_until,'AuditStoreID',c.audit_store_id,'AuditWriteUntil',c.audit_write_until,'Native',b.policy_json);
 IF NOT public.capacity_session_snapshot_valid(NEW.capacity_backing,w.id,a.id,a.root_id,NEW.deadline) THEN RAISE EXCEPTION 'original capacity session snapshot invalid' USING ERRCODE='23514';END IF;
 NEW.capacity_backing_digest:=public.capacity_session_snapshot_digest(NEW.capacity_backing);
 RETURN NEW;
END $$;

-- The accepted query anchor is immutable. Its own installation incarnation,
-- recovery issuer epoch and original HardUntil bound reads; the live root
-- capacity source (freshness, suspension, negative snapshot) does not.
CREATE OR REPLACE FUNCTION lock_context_query_capacity(r uuid,acceptance uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.context_query_capacity;b public.context_query_backing;t public.fleet_current_trust;
BEGIN
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=b.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT a FROM public.context_query_capacity WHERE root_id=r AND acceptance_id=acceptance FOR SHARE;
 RETURN COALESCE(b.acceptance_id=acceptance AND a.capacity_id=(a.plan->'Qualification'->>'CapacityID')::uuid AND a.observations=0 AND a.issuer_epoch=t.issuer_epoch AND
  public.incarnation_current(a.postmaster_at) AND a.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND
  (a.plan->>'RootID')::uuid=r AND (a.plan->>'HardUntil')::timestamptz=b.hard_until AND clock_timestamp()<b.hard_until,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

-- A workload's query allocation is its immutable reserved charge. Workload
-- deletion, a stale binding or a changed workload revision does not revoke it.
CREATE OR REPLACE FUNCTION context_query_capacity_allocation_current(r uuid,allocation uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.context_query_allocation;b public.context_query_backing;c public.context_query_capacity;
BEGIN
 SELECT * INTO STRICT c FROM public.context_query_capacity WHERE root_id=r;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE root_id=r AND id=allocation;
 RETURN COALESCE(NOT b.suspended AND a.query_limit=(c.plan->'Qualification'->>'WorkloadQueries')::bigint AND clock_timestamp()<b.hard_until,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE OR REPLACE FUNCTION read_shared_context_query_plan(r uuid,cluster uuid,namespace_id text,workload text,actor jsonb,principal_key_value bytea,proposed_account uuid,path jsonb) RETURNS jsonb
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
 IF NOT public.context_query_capacity_allocation_current(r,a.id) THEN RAISE EXCEPTION 'query allocation unavailable' USING ERRCODE='23514';END IF;
 profile:=jsonb_set(b.profile,'{Path}',path);
 IF path->>'TargetClusterID' IS DISTINCT FROM cluster::text OR NOT public.context_query_shared_profile_current(r,profile) THEN RAISE EXCEPTION 'shared query placement unavailable' USING ERRCODE='23514';END IF;
 SELECT id INTO account FROM public.context_query_principal WHERE root_id=r AND principal_key=principal_key_value FOR SHARE;
 n:=clock_timestamp();until_at:=LEAST(n+interval '5 seconds',b.hard_until);
 IF until_at IS NULL OR n>=until_at THEN RAISE EXCEPTION 'query capacity read expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('AcceptanceID',acceptance,'AccountID',COALESCE(account,proposed_account),'AllocationID',a.id,'RootID',r,'InstallationID',b.installation_id,
  'ClusterID',a.cluster_id,'NamespaceUID',a.namespace_uid,'WorkloadUID',a.workload_uid,'AllocationRevision',a.revision,'PoolSource',a.pool_source,'PolicySource',a.policy_source,'Principal',actor,'Profile',profile,
  'ObservedAt',public.capacity_json_timestamp(n),'ValidUntil',public.capacity_json_timestamp(until_at),'HardUntil',public.capacity_json_timestamp(b.hard_until),'EffectsUntil',public.capacity_json_timestamp(b.effects_until),'CleanupUntil',public.capacity_json_timestamp(b.cleanup_until),'RetireBy',public.capacity_json_timestamp(b.retire_by));
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION require_capacity_new_admission() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r uuid;a uuid;n timestamptz;until_at timestamptz;kind text;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'invalid capacity admission source' USING ERRCODE='23514';END IF;
 IF TG_RELID='public.custody_attempt'::regclass THEN
  SELECT p.root_id INTO r FROM public.custody_allocation allocation JOIN public.capacity_pool p ON p.id=allocation.pool_id WHERE allocation.id=NEW.allocation_id;
  IF NOT FOUND THEN RETURN NEW;END IF;
  a:=NEW.allocation_id;kind:='context';
 ELSIF TG_RELID='public.context_capture'::regclass THEN
  r:=NEW.root_id;SELECT allocation_id INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;kind:='context';
 ELSIF TG_RELID='public.artifact_download'::regclass THEN
  r:=NEW.root_id;a:=NEW.allocation_id;kind:='download';
 ELSIF TG_RELID='public.operation_audit'::regclass THEN
  IF NEW.lane NOT IN('normal','resolution','processing','capture') THEN RETURN NEW;END IF;
  r:=NEW.root_id;
  IF NEW.lane='capture' THEN
   SELECT allocation_id INTO STRICT a FROM public.custody_attempt WHERE id=(NEW.intent#>>'{Capture,AttemptID}')::uuid;kind:='context';
  END IF;
 ELSE RAISE EXCEPTION 'invalid capacity admission table' USING ERRCODE='23514';END IF;
 n:=clock_timestamp();
 IF kind IS NULL THEN until_at:=public.capacity_managed_root_until(r,n);
 ELSE until_at:=public.capacity_managed_admission_until(r,a,kind,n);END IF;
 IF until_at IS NULL OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'managed capacity admission incomplete or expired' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION require_capacity_download_snapshot() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source public.capacity_source;w public.capacity_workload;p public.capacity_pool;a public.download_allocation;c public.download_control_allocation;b public.download_native_backing;n timestamptz;until_at timestamptz;
BEGIN
 IF NEW.capacity_account_id IS NOT NULL OR NEW.capacity_backing IS NOT NULL OR NEW.capacity_backing_digest IS NOT NULL THEN RAISE EXCEPTION 'caller cannot provide capacity session backing' USING ERRCODE='23514';END IF;
 SELECT * INTO source FROM public.capacity_source WHERE root_id=NEW.root_id;
 IF NOT FOUND THEN RETURN NEW;END IF;
 -- Supported admission already owns recovery and permission before allocation.
 -- NOWAIT on the defensive prefix avoids a child-to-parent blocking inversion
 -- for an unsupported direct INSERT; it never repairs or retries that effect.
 PERFORM 1 FROM public.fleet_trust WHERE installation_id=source.installation_id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE NOWAIT;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=NEW.root_id FOR SHARE NOWAIT;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=NEW.root_id AND download_allocation_id=NEW.allocation_id FOR SHARE;
 SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=w.root_id AND id=w.pool_id;
 SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id FOR SHARE;
 SELECT * INTO STRICT c FROM public.download_control_allocation WHERE id=a.id AND root_id=a.root_id FOR SHARE;
 SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=a.id AND root_id=a.root_id FOR SHARE;
 n:=clock_timestamp();until_at:=public.capacity_managed_admission_until(NEW.root_id,NEW.allocation_id,'download',n);
 IF until_at IS NULL OR n>=until_at OR NOT public.capacity_workload_general_exact(source,w,true) OR NOT public.capacity_workload_capture_exact(source,w) THEN RAISE EXCEPTION 'managed session backing unavailable' USING ERRCODE='23514';END IF;
 NEW.capacity_account_id:=w.id;
 NEW.capacity_backing:=jsonb_build_object('Format','protected-capacity/v1','AccountID',w.id,'AttemptID',w.attempt_id,'AllocationID',w.download_allocation_id,'Revision',(source.root_configuration->>'Revision')::bigint,
  'PoolSource',jsonb_build_object('UID',p.source_uid,'Generation',p.source_generation,'Digest',p.plan->'Digest'),
  'PolicySource',jsonb_build_object('UID',w.policy_uid,'Generation',w.plan->'PolicyGeneration','Digest',w.plan->'PolicyDigest'),
  'AllocationUntil',a.valid_until,'ControlUntil',c.valid_until,'AuditStoreID',c.audit_store_id,'AuditWriteUntil',c.audit_write_until,'Native',b.policy_json);
 IF NOT public.capacity_session_snapshot_valid(NEW.capacity_backing,w.id,a.id,a.root_id,NEW.deadline) OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'original capacity session snapshot invalid' USING ERRCODE='23514';END IF;
 NEW.capacity_backing_digest:=public.capacity_session_snapshot_digest(NEW.capacity_backing);
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
  public.incarnation_current(a.postmaster_at) AND a.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND
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
CREATE OR REPLACE FUNCTION read_shared_context_query_plan(r uuid,cluster uuid,namespace_id text,workload text,actor jsonb,principal_key_value bytea,proposed_account uuid,path jsonb) RETURNS jsonb
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
CREATE FUNCTION demand_capacity_refresh_for_download(r uuid,allocation uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE n timestamptz:=clock_timestamp();
BEGIN
 IF r IS NULL OR allocation IS NULL THEN RAISE EXCEPTION 'capacity refresh demand invalid' USING ERRCODE='23514';END IF;
 UPDATE public.capacity_refresh_demand d SET requested_at=n,not_after=n+interval '60 seconds'
  FROM public.capacity_workload w
  WHERE w.root_id=r AND w.download_allocation_id=allocation AND w.ready_at IS NOT NULL AND
   d.root_id=w.root_id AND d.cluster_id=w.cluster_id AND d.namespace_uid=w.namespace_uid AND d.workload_uid=w.workload_uid;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION demand_capacity_refresh_for_download(uuid,uuid) FROM PUBLIC;
CREATE TRIGGER zzz_capacity_new_admission AFTER INSERT ON artifact_download FOR EACH ROW EXECUTE FUNCTION require_capacity_new_admission();
