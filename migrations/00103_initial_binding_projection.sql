-- +goose Up
-- ADR-200: first Ready and its same-observation refresh use the same original
-- 30-second stored projection as later observations. Proof/receipt bounds stay.
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
 IF b.observed_at>observed OR (b.observed_at=observed AND b.fresh_until=observed+interval '30 seconds') THEN
  -- Retain a newer observation or an already projected exact duplicate;
  -- do not extend the current caller beyond either original interval.
  until_at:=LEAST(until_at,b.fresh_until);
  IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity observation replay expired' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt_as(w,o),'FreshUntil',until_at);
 END IF;
 UPDATE public.capacity_source SET configuration_spent=configuration_spent+1,root_mutation_xid=pg_current_xact_id() WHERE root_id=r;
 -- The first Ready publication may have stored this same observation with
 -- its short phase cutoff. Project it once, using the ORIGINAL observation;
 -- neither the proof nor the returned receipt acquires a new interval.
 UPDATE public.context_storage_binding SET observed_at=observed,fresh_until=observed+interval '30 seconds' WHERE root_id=r AND allocation_id=w.allocation_id;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity observation expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt_as(w,o),'FreshUntil',until_at);
END $$;
-- +goose StatementEnd

-- +goose Down
-- Existing projected observations are retained; restore the prior no-op rule.
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
-- +goose StatementEnd
