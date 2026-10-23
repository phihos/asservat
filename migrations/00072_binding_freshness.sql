-- +goose Up
-- ADR-200 revision (2026-10-23): a workload's context_storage_binding is
-- current for 30 seconds after its own observation instead of five. Slow or
-- failed hub-worker refreshes no longer make capture, query and download
-- admission flap. The table CHECK already permits 30 seconds; every other
-- root, permission, recovery and request freshness bound is unchanged.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION refresh_capacity_enrollment(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb;s public.capacity_source;w public.capacity_workload;b public.context_storage_binding;until_at timestamptz;n timestamptz;observed timestamptz;
BEGIN
 result:=public.capacity_read_enrollment(r,'capacity',o,plan_bytes,pool_bytes,source_bytes);until_at:=(result->>'FreshUntil')::timestamptz;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=r AND id=(expected->>'ID')::uuid FOR UPDATE;
 IF w.ready_at IS NULL OR w.mutation_xid IS NOT NULL OR s.root_mutation_xid IS NOT NULL OR NOT public.capacity_enrollment_matches_as(w,expected,o) OR
  result->'Enrollment'='null'::jsonb OR NOT public.capacity_workload_general_exact(s,w,true) OR NOT public.capacity_workload_capture_exact(s,w) THEN
  RAISE EXCEPTION 'capacity observation original enrollment unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT b FROM public.context_storage_binding WHERE root_id=r AND allocation_id=w.allocation_id FOR UPDATE;
 n:=clock_timestamp();observed:=(o->>'ObservedAt')::timestamptz;
 IF n>=until_at OR b.observed_at>n OR NOT public.capacity_root_general_exact(s) OR NOT public.capacity_root_capture_exact(s) THEN
  RAISE EXCEPTION 'capacity observation expired after locks' USING ERRCODE='23514';END IF;
 IF b.observed_at>=observed THEN
  -- A concurrent acknowledged observation may be newer. Retain it exactly;
  -- do not extend the current caller beyond either original interval.
  until_at:=LEAST(until_at,b.fresh_until);
  IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity observation replay expired' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt_as(w,o),'FreshUntil',until_at);
 END IF;
 UPDATE public.capacity_source SET configuration_spent=configuration_spent+1,root_mutation_xid=pg_current_xact_id() WHERE root_id=r;
 -- ADR-200 revision: the stored binding lives 30 seconds from its own
 -- observation; the caller's receipt below keeps its original interval.
 UPDATE public.context_storage_binding SET observed_at=observed,fresh_until=observed+interval '30 seconds' WHERE root_id=r AND allocation_id=w.allocation_id;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity observation expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt_as(w,o),'FreshUntil',until_at);
END $$;

CREATE OR REPLACE FUNCTION capacity_managed_admission_until(r uuid,allocation uuid,kind text,n timestamptz) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;w public.capacity_workload;p public.capacity_pool;compiled jsonb;c jsonb;until_at timestamptz;root_until timestamptz;
BEGIN
 IF kind IS NULL OR kind NOT IN ('context','download') OR n IS NULL OR NOT isfinite(n) THEN RETURN NULL;END IF;
 SELECT * INTO s FROM public.capacity_source WHERE root_id=r;
 IF NOT FOUND THEN RETURN 'infinity'::timestamptz;END IF;
 c:=s.root_configuration;root_until:=public.capacity_managed_root_until(r,n);
 IF root_until IS NULL OR n>=root_until THEN RETURN NULL;END IF;
 SELECT * INTO w FROM public.capacity_workload WHERE root_id=r AND CASE WHEN kind='context' THEN allocation_id=allocation ELSE download_allocation_id=allocation END;
 IF NOT FOUND OR w.ready_at IS NULL OR w.ready_completion IS NULL OR w.capture_backed_at IS NULL OR w.capture_completion IS NULL OR w.mutation_xid IS NOT NULL OR w.ready_at>n THEN RETURN NULL;END IF;
 IF NOT public.capacity_workload_general_exact(s,w,true) OR NOT public.capacity_workload_capture_exact(s,w) THEN RETURN NULL;END IF;
 SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=r AND id=w.pool_id;
 compiled:=public.capacity_compile_pool(s.accepted_snapshot,p.source_name);
 -- ADR-197: the stored plan or an additive revision of it, and the
 -- workload's original pool in its revision chain.
 IF compiled IS NULL OR NOT (compiled IS NOT DISTINCT FROM p.plan OR public.capacity_pool_extends(p.plan,compiled)) OR
  NOT (p.plan_digest IS NOT DISTINCT FROM public.connector_digest(w.plan->'PoolDigest') OR
   EXISTS(SELECT 1 FROM public.capacity_pool_revision v WHERE v.root_id=r AND v.pool_id=p.id AND v.plan_digest=public.connector_digest(w.plan->'PoolDigest'))) OR
  w.account_version<>s.account_version OR w.plan->>'QualificationID' IS DISTINCT FROM s.qualification->>'ID' OR
  public.connector_digest(w.plan->'QualificationDigest') IS DISTINCT FROM s.qualification_digest THEN RETURN NULL;END IF;
 -- The physical mapping's own current workload/namespace observation remains
 -- mandatory. A root source heartbeat cannot substitute for it.
 SELECT LEAST(root_until,b.fresh_until,a.valid_until,cp.valid_until,ca.valid_until,control.valid_until) INTO until_at FROM public.context_storage_binding b JOIN public.custody_allocation a ON a.id=b.allocation_id JOIN public.custody_pool cp ON cp.id=a.pool_id
  JOIN public.context_control_account ca ON ca.root_id=b.root_id AND ca.allocation_id=b.allocation_id JOIN public.context_control_pool control ON control.root_id=ca.root_id
  WHERE b.root_id=r AND b.cluster_id=w.cluster_id AND b.namespace_uid=w.namespace_uid AND b.workload_uid=w.workload_uid AND b.allocation_id=w.allocation_id AND
   b.observed_at<=n AND n<b.fresh_until AND b.fresh_until<=b.observed_at+interval '30 seconds' AND NOT a.paused AND n<a.valid_until AND NOT cp.paused AND n<cp.valid_until AND
   ca.configured AND NOT ca.paused AND n<ca.valid_until AND control.configured AND NOT control.paused AND n<control.valid_until;
 RETURN until_at;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION refresh_capacity_enrollment(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb;s public.capacity_source;w public.capacity_workload;b public.context_storage_binding;until_at timestamptz;n timestamptz;observed timestamptz;
BEGIN
 result:=public.capacity_read_enrollment(r,'capacity',o,plan_bytes,pool_bytes,source_bytes);until_at:=(result->>'FreshUntil')::timestamptz;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=r AND id=(expected->>'ID')::uuid FOR UPDATE;
 IF w.ready_at IS NULL OR w.mutation_xid IS NOT NULL OR s.root_mutation_xid IS NOT NULL OR NOT public.capacity_enrollment_matches_as(w,expected,o) OR
  result->'Enrollment'='null'::jsonb OR NOT public.capacity_workload_general_exact(s,w,true) OR NOT public.capacity_workload_capture_exact(s,w) THEN
  RAISE EXCEPTION 'capacity observation original enrollment unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT b FROM public.context_storage_binding WHERE root_id=r AND allocation_id=w.allocation_id FOR UPDATE;
 n:=clock_timestamp();observed:=(o->>'ObservedAt')::timestamptz;
 IF n>=until_at OR b.observed_at>n OR NOT public.capacity_root_general_exact(s) OR NOT public.capacity_root_capture_exact(s) THEN
  RAISE EXCEPTION 'capacity observation expired after locks' USING ERRCODE='23514';END IF;
 IF b.observed_at>=observed THEN
  -- A concurrent acknowledged observation may be newer. Retain it exactly;
  -- do not extend the current caller beyond either original interval.
  until_at:=LEAST(until_at,b.fresh_until);
  IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity observation replay expired' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt_as(w,o),'FreshUntil',until_at);
 END IF;
 UPDATE public.capacity_source SET configuration_spent=configuration_spent+1,root_mutation_xid=pg_current_xact_id() WHERE root_id=r;
 UPDATE public.context_storage_binding SET observed_at=observed,fresh_until=until_at WHERE root_id=r AND allocation_id=w.allocation_id;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity observation expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt_as(w,o),'FreshUntil',until_at);
END $$;

CREATE OR REPLACE FUNCTION capacity_managed_admission_until(r uuid,allocation uuid,kind text,n timestamptz) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;w public.capacity_workload;p public.capacity_pool;compiled jsonb;c jsonb;until_at timestamptz;root_until timestamptz;
BEGIN
 IF kind IS NULL OR kind NOT IN ('context','download') OR n IS NULL OR NOT isfinite(n) THEN RETURN NULL;END IF;
 SELECT * INTO s FROM public.capacity_source WHERE root_id=r;
 IF NOT FOUND THEN RETURN 'infinity'::timestamptz;END IF;
 c:=s.root_configuration;root_until:=public.capacity_managed_root_until(r,n);
 IF root_until IS NULL OR n>=root_until THEN RETURN NULL;END IF;
 SELECT * INTO w FROM public.capacity_workload WHERE root_id=r AND CASE WHEN kind='context' THEN allocation_id=allocation ELSE download_allocation_id=allocation END;
 IF NOT FOUND OR w.ready_at IS NULL OR w.ready_completion IS NULL OR w.capture_backed_at IS NULL OR w.capture_completion IS NULL OR w.mutation_xid IS NOT NULL OR w.ready_at>n THEN RETURN NULL;END IF;
 IF NOT public.capacity_workload_general_exact(s,w,true) OR NOT public.capacity_workload_capture_exact(s,w) THEN RETURN NULL;END IF;
 SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=r AND id=w.pool_id;
 compiled:=public.capacity_compile_pool(s.accepted_snapshot,p.source_name);
 -- ADR-197: the stored plan or an additive revision of it, and the
 -- workload's original pool in its revision chain.
 IF compiled IS NULL OR NOT (compiled IS NOT DISTINCT FROM p.plan OR public.capacity_pool_extends(p.plan,compiled)) OR
  NOT (p.plan_digest IS NOT DISTINCT FROM public.connector_digest(w.plan->'PoolDigest') OR
   EXISTS(SELECT 1 FROM public.capacity_pool_revision v WHERE v.root_id=r AND v.pool_id=p.id AND v.plan_digest=public.connector_digest(w.plan->'PoolDigest'))) OR
  w.account_version<>s.account_version OR w.plan->>'QualificationID' IS DISTINCT FROM s.qualification->>'ID' OR
  public.connector_digest(w.plan->'QualificationDigest') IS DISTINCT FROM s.qualification_digest THEN RETURN NULL;END IF;
 -- The physical mapping's own current workload/namespace observation remains
 -- mandatory. A root source heartbeat cannot substitute for it.
 SELECT LEAST(root_until,b.fresh_until,a.valid_until,cp.valid_until,ca.valid_until,control.valid_until) INTO until_at FROM public.context_storage_binding b JOIN public.custody_allocation a ON a.id=b.allocation_id JOIN public.custody_pool cp ON cp.id=a.pool_id
  JOIN public.context_control_account ca ON ca.root_id=b.root_id AND ca.allocation_id=b.allocation_id JOIN public.context_control_pool control ON control.root_id=ca.root_id
  WHERE b.root_id=r AND b.cluster_id=w.cluster_id AND b.namespace_uid=w.namespace_uid AND b.workload_uid=w.workload_uid AND b.allocation_id=w.allocation_id AND
   b.observed_at<=n AND n<b.fresh_until AND b.fresh_until<=b.observed_at+interval '5 seconds' AND NOT a.paused AND n<a.valid_until AND NOT cp.paused AND n<cp.valid_until AND
   ca.configured AND NOT ca.paused AND n<ca.valid_until AND control.configured AND NOT control.paused AND n<control.valid_until;
 RETURN until_at;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
-- +goose StatementEnd
