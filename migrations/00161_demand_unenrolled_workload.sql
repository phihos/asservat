-- +goose Up
-- ADR-200 first-run correction: a preview of a workload that discovery has not
-- enrolled yet recorded no demand (the function returned for every workload
-- without a ready capacity_workload row), so the first preview after deploying
-- a workload waited out its whole readiness window until discovery happened to
-- enroll it. The demand now also names a not-yet-ready workload; the worker's
-- demand lane runs the same guarded observation and enrollment as discovery.
-- A demand still confers no authority. Expired rows are removed again (the
-- download re-arming that kept them was dropped by 00076), and a new demand is
-- recorded only while the root holds fewer than sixteen active demands, the
-- existing read limit.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION demand_capacity_refresh(r uuid,cluster uuid,ns_uid text,ns_name text,kind text,name text,workload text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE n timestamptz:=clock_timestamp();
BEGIN
 IF r IS NULL OR cluster IS NULL OR octet_length(ns_uid) NOT BETWEEN 1 AND 64 OR octet_length(ns_name) NOT BETWEEN 1 AND 63 OR
  kind IS NULL OR kind NOT IN('Deployment','StatefulSet','Pod') OR octet_length(name) NOT BETWEEN 1 AND 253 OR octet_length(workload) NOT BETWEEN 1 AND 64 THEN
  RAISE EXCEPTION 'capacity refresh demand invalid' USING ERRCODE='23514';END IF;
 DELETE FROM public.capacity_refresh_demand WHERE root_id=r AND not_after<=n;
 IF NOT EXISTS(SELECT 1 FROM public.capacity_refresh_demand d WHERE d.root_id=r AND d.cluster_id=cluster AND d.namespace_uid=ns_uid AND d.workload_uid=workload) AND
  (SELECT count(*) FROM public.capacity_refresh_demand d WHERE d.root_id=r AND d.not_after>n)>=16 THEN
  RETURN;END IF;
 INSERT INTO public.capacity_refresh_demand(root_id,cluster_id,namespace_uid,namespace_name,workload_kind,workload_name,workload_uid,requested_at,not_after)
  VALUES(r,cluster,ns_uid,ns_name,kind,name,workload,n,n+interval '60 seconds')
  ON CONFLICT(root_id,cluster_id,namespace_uid,workload_uid) DO UPDATE SET namespace_name=EXCLUDED.namespace_name,workload_kind=EXCLUDED.workload_kind,
   workload_name=EXCLUDED.workload_name,requested_at=EXCLUDED.requested_at,not_after=EXCLUDED.not_after;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION demand_capacity_refresh(r uuid,cluster uuid,ns_uid text,ns_name text,kind text,name text,workload text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE n timestamptz:=clock_timestamp();
BEGIN
 IF r IS NULL OR cluster IS NULL OR octet_length(ns_uid) NOT BETWEEN 1 AND 64 OR octet_length(ns_name) NOT BETWEEN 1 AND 63 OR
  kind IS NULL OR kind NOT IN('Deployment','StatefulSet','Pod') OR octet_length(name) NOT BETWEEN 1 AND 253 OR octet_length(workload) NOT BETWEEN 1 AND 64 THEN
  RAISE EXCEPTION 'capacity refresh demand invalid' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.capacity_workload w WHERE w.root_id=r AND w.cluster_id=cluster AND w.namespace_uid=ns_uid AND w.workload_uid=workload AND w.ready_at IS NOT NULL) THEN
  RETURN;END IF;
 INSERT INTO public.capacity_refresh_demand(root_id,cluster_id,namespace_uid,namespace_name,workload_kind,workload_name,workload_uid,requested_at,not_after)
  VALUES(r,cluster,ns_uid,ns_name,kind,name,workload,n,n+interval '60 seconds')
  ON CONFLICT(root_id,cluster_id,namespace_uid,workload_uid) DO UPDATE SET namespace_name=EXCLUDED.namespace_name,workload_kind=EXCLUDED.workload_kind,
   workload_name=EXCLUDED.workload_name,requested_at=EXCLUDED.requested_at,not_after=EXCLUDED.not_after;
END $$;
-- +goose StatementEnd
