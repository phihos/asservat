-- +goose Up
-- ADR-200: downloads re-arm the refresh demand of the workload behind their
-- download allocation. Preparation has no workload names, so demand rows now
-- outlive their expiry and keep the names a capture demand recorded; a UID's
-- names never change, and a root holds at most one row per enrolled workload.

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

-- Re-arms the existing demand for the workload behind a download allocation.
-- Without an earlier capture demand there are no names, and it does nothing.
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

-- +goose Down
DROP FUNCTION demand_capacity_refresh_for_download(uuid,uuid);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION demand_capacity_refresh(r uuid,cluster uuid,ns_uid text,ns_name text,kind text,name text,workload text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE n timestamptz:=clock_timestamp();
BEGIN
 IF r IS NULL OR cluster IS NULL OR octet_length(ns_uid) NOT BETWEEN 1 AND 64 OR octet_length(ns_name) NOT BETWEEN 1 AND 63 OR
  kind IS NULL OR kind NOT IN('Deployment','StatefulSet','Pod') OR octet_length(name) NOT BETWEEN 1 AND 253 OR octet_length(workload) NOT BETWEEN 1 AND 64 THEN
  RAISE EXCEPTION 'capacity refresh demand invalid' USING ERRCODE='23514';END IF;
 DELETE FROM public.capacity_refresh_demand WHERE root_id=r AND not_after<=n;
 IF NOT EXISTS(SELECT 1 FROM public.capacity_workload w WHERE w.root_id=r AND w.cluster_id=cluster AND w.namespace_uid=ns_uid AND w.workload_uid=workload AND w.ready_at IS NOT NULL) THEN
  RETURN;END IF;
 INSERT INTO public.capacity_refresh_demand(root_id,cluster_id,namespace_uid,namespace_name,workload_kind,workload_name,workload_uid,requested_at,not_after)
  VALUES(r,cluster,ns_uid,ns_name,kind,name,workload,n,n+interval '60 seconds')
  ON CONFLICT(root_id,cluster_id,namespace_uid,workload_uid) DO UPDATE SET namespace_name=EXCLUDED.namespace_name,workload_kind=EXCLUDED.workload_kind,
   workload_name=EXCLUDED.workload_name,requested_at=EXCLUDED.requested_at,not_after=EXCLUDED.not_after;
END $$;
-- +goose StatementEnd
