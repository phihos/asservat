-- +goose Up
-- ADR-200: on-demand capacity refresh. Admission records a short-lived demand
-- for one enrolled workload; the hub-worker refreshes demanded workloads first.
-- A demand names a workload and confers no authority: the worker still runs
-- every observation, source, recovery, permission and SQL fence check.
CREATE TABLE capacity_refresh_demand (
 root_id uuid NOT NULL REFERENCES capacity_source(root_id),
 cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 namespace_name text NOT NULL CHECK(octet_length(namespace_name) BETWEEN 1 AND 63),
 workload_kind text NOT NULL CHECK(workload_kind IN('Deployment','StatefulSet','Pod')),
 workload_name text NOT NULL CHECK(octet_length(workload_name) BETWEEN 1 AND 253),
 workload_uid text NOT NULL CHECK(octet_length(workload_uid) BETWEEN 1 AND 64),
 requested_at timestamptz NOT NULL, not_after timestamptz NOT NULL,
 PRIMARY KEY(root_id,cluster_id,namespace_uid,workload_uid),
 CHECK(isfinite(requested_at) AND not_after>requested_at AND not_after<=requested_at+interval '60 seconds')
);
REVOKE ALL ON capacity_refresh_demand FROM PUBLIC;

-- +goose StatementBegin
-- Records or extends a demand only for an enrolled, ready workload, so a root
-- holds at most as many demands as it has workloads (sixteen). Anything else
-- is a silent no-op: the caller learns nothing about enrollment state.
CREATE FUNCTION demand_capacity_refresh(r uuid,cluster uuid,ns_uid text,ns_name text,kind text,name text,workload text) RETURNS void
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

-- The capacity writer reads active demands, oldest request first.
CREATE FUNCTION read_capacity_refresh_demands(r uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE out jsonb;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') THEN RAISE EXCEPTION 'capacity refresh demand reader unavailable' USING ERRCODE='23514';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('ClusterID',d.cluster_id,'NamespaceUID',d.namespace_uid,'NamespaceName',d.namespace_name,
  'Kind',d.workload_kind,'Name',d.workload_name,'WorkloadUID',d.workload_uid,'NotAfter',d.not_after) ORDER BY d.requested_at,d.workload_uid),'[]'::jsonb)
 INTO out FROM (SELECT * FROM public.capacity_refresh_demand WHERE root_id=r AND not_after>clock_timestamp() ORDER BY requested_at LIMIT 16) d;
 RETURN out;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION demand_capacity_refresh(uuid,uuid,text,text,text,text,text),read_capacity_refresh_demands(uuid) FROM PUBLIC;

-- +goose Down
DROP FUNCTION read_capacity_refresh_demands(uuid);
DROP FUNCTION demand_capacity_refresh(uuid,uuid,text,text,text,text,text);
DROP TABLE capacity_refresh_demand;
