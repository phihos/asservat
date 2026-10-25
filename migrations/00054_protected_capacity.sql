-- +goose Up
-- Protected installed capacity, not collection/disclosure/recovery authority.
-- This file is under construction in the isolated ADR141 stage. No live schema
-- or runtime role uses these functions until the complete migration qualifies.

CREATE TABLE capacity_source (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id),
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 control_cluster_id uuid NOT NULL,
 control_namespace_uid text NOT NULL CHECK(octet_length(control_namespace_uid) BETWEEN 1 AND 64),
 source_guard_digest bytea NOT NULL CHECK(octet_length(source_guard_digest)=32),
 writer_role oid NOT NULL, capture_role oid NOT NULL CHECK(capture_role<>writer_role),
 -- Fixed public read purpose 34. Its original public role provenance is
 -- accepted by the protected setup producer, never discovered by runtime.
 audit_reader_role oid NOT NULL CHECK(audit_reader_role<>writer_role AND audit_reader_role<>capture_role),
 audit_reader_provenance jsonb NOT NULL CHECK(jsonb_typeof(audit_reader_provenance)='object' AND octet_length(audit_reader_provenance::text)<=4096),
 -- Original protected installer receipt/provenance. No runtime RPC can create
 -- these rows or replace any setup field. The pair is committed atomically.
 setup_receipt jsonb NOT NULL CHECK(jsonb_typeof(setup_receipt)='object' AND octet_length(setup_receipt::text)<=4096),
 setup_input jsonb NOT NULL CHECK(jsonb_typeof(setup_input)='object' AND octet_length(setup_input::text)<=147456),
 setup_roles jsonb NOT NULL CHECK(jsonb_typeof(setup_roles)='array' AND jsonb_array_length(setup_roles)=10 AND octet_length(setup_roles::text)<=16384),
 account_version text NOT NULL CHECK(octet_length(account_version) BETWEEN 1 AND 64),
 -- Installed whole-process/connection ceilings, not a capture caller option.
 process_limit smallint NOT NULL CHECK(process_limit=2),
 qualification jsonb NOT NULL CHECK(jsonb_typeof(qualification)='object' AND octet_length(qualification::text) BETWEEN 2 AND 131072),
 qualification_digest bytea NOT NULL CHECK(octet_length(qualification_digest)=32),
 accepted_revision bigint NOT NULL DEFAULT 0 CHECK(accepted_revision BETWEEN 0 AND 1152921504606846975),
 accepted_snapshot jsonb CHECK(jsonb_typeof(accepted_snapshot)='object' AND octet_length(accepted_snapshot::text)<=262144),
 accepted_digest bytea CHECK(octet_length(accepted_digest)=32),
 -- A complete rejected current snapshot is a bounded negative watermark,
 -- never an active source. Retaining its versions prevents A -> bad B -> A
 -- from silently clearing a known in-place mutation at the same generation.
 negative_snapshot jsonb CHECK(negative_snapshot IS NULL OR jsonb_typeof(negative_snapshot)='object' AND octet_length(negative_snapshot::text)<=262144),
 observed_at timestamptz, fresh_until timestamptz,
 suspended boolean NOT NULL DEFAULT true,
 -- One fixed prepaid root plan and one bounded current configuration. The
 -- original canonical bytes bind Go/SQL without reserializing JSON for hashes.
 root_plan jsonb CHECK(root_plan IS NULL OR jsonb_typeof(root_plan)='object' AND octet_length(root_plan::text)<=65536),
 root_plan_bytes bytea CHECK(root_plan_bytes IS NULL OR octet_length(root_plan_bytes) BETWEEN 2 AND 65536),
 root_plan_digest bytea CHECK(root_plan_digest IS NULL OR octet_length(root_plan_digest)=32),
 root_configuration jsonb CHECK(root_configuration IS NULL OR jsonb_typeof(root_configuration)='object' AND octet_length(root_configuration::text)<=8192),
 configuration_spent bigint NOT NULL DEFAULT 0 CHECK(configuration_spent BETWEEN 0 AND 1000000),
 root_mutation_xid xid8,
 CHECK((root_plan IS NULL)=(root_plan_bytes IS NULL) AND (root_plan IS NULL)=(root_plan_digest IS NULL) AND (root_plan IS NULL)=(root_configuration IS NULL)),
 CHECK((accepted_snapshot IS NULL)=(accepted_digest IS NULL)),
 CHECK(negative_snapshot IS NULL OR suspended),
 CHECK((observed_at IS NULL)=(fresh_until IS NULL)),
 CHECK(accepted_revision>0 OR (accepted_snapshot IS NULL AND observed_at IS NULL AND suspended)),
 CHECK(observed_at IS NULL OR (isfinite(observed_at) AND isfinite(fresh_until) AND fresh_until>observed_at AND fresh_until<=observed_at+interval '5 seconds'))
);

CREATE TABLE capacity_pool (
 root_id uuid NOT NULL REFERENCES capacity_source(root_id),
 id uuid NOT NULL UNIQUE REFERENCES custody_pool(id),
 backend_capacity_id uuid NOT NULL UNIQUE,
 backend_qualification_id uuid NOT NULL,
 backend_qualification_digest bytea NOT NULL CHECK(octet_length(backend_qualification_digest)=32),
 source_uid text NOT NULL CHECK(octet_length(source_uid) BETWEEN 1 AND 64),
 source_name text NOT NULL CHECK(octet_length(source_name) BETWEEN 1 AND 63),
 source_generation bigint NOT NULL CHECK(source_generation BETWEEN 1 AND 2147483647),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1152921504606846975),
 plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object' AND octet_length(plan::text)<=65536),
 plan_digest bytea NOT NULL CHECK(octet_length(plan_digest)=32),
 protected_bytes bigint NOT NULL CHECK(protected_bytes>=0),
 protected_objects bigint NOT NULL CHECK(protected_objects>=0),
 shared_bytes bigint NOT NULL CHECK(shared_bytes>=0), shared_objects bigint NOT NULL CHECK(shared_objects>=0),
 system_bytes bigint NOT NULL CHECK(system_bytes>=0), system_objects bigint NOT NULL CHECK(system_objects>=0),
 account_limit bigint NOT NULL CHECK(account_limit BETWEEN 1 AND 640000),
 namespace_limit bigint NOT NULL CHECK(namespace_limit BETWEEN 1 AND 640000),
 accounts bigint NOT NULL DEFAULT 0 CHECK(accounts BETWEEN 0 AND account_limit),
 namespaces bigint NOT NULL DEFAULT 0 CHECK(namespaces BETWEEN 0 AND namespace_limit),
 backed_bytes bigint NOT NULL DEFAULT 0 CHECK(backed_bytes BETWEEN 0 AND protected_bytes),
 backed_objects bigint NOT NULL DEFAULT 0 CHECK(backed_objects BETWEEN 0 AND protected_objects),
 backed_system_bytes bigint NOT NULL DEFAULT 0 CHECK(backed_system_bytes BETWEEN 0 AND system_bytes),
 backed_system_objects bigint NOT NULL DEFAULT 0 CHECK(backed_system_objects BETWEEN 0 AND system_objects),
 PRIMARY KEY(root_id,id), UNIQUE(root_id,source_uid), UNIQUE(root_id,source_name)
);

CREATE TABLE capacity_cluster (
 root_id uuid NOT NULL, pool_id uuid NOT NULL, cluster_id uuid NOT NULL,
 protected_bytes bigint NOT NULL CHECK(protected_bytes>=0), protected_objects bigint NOT NULL CHECK(protected_objects>=0),
 byte_limit bigint NOT NULL CHECK(byte_limit>=protected_bytes), object_limit bigint NOT NULL CHECK(object_limit>=protected_objects),
 account_limit bigint NOT NULL CHECK(account_limit BETWEEN 1 AND 640000),
 namespace_limit bigint NOT NULL CHECK(namespace_limit BETWEEN 1 AND 640000),
 accounts bigint NOT NULL DEFAULT 0 CHECK(accounts BETWEEN 0 AND account_limit),
 namespaces bigint NOT NULL DEFAULT 0 CHECK(namespaces BETWEEN 0 AND namespace_limit),
 backed_bytes bigint NOT NULL DEFAULT 0 CHECK(backed_bytes BETWEEN 0 AND protected_bytes),
 backed_objects bigint NOT NULL DEFAULT 0 CHECK(backed_objects BETWEEN 0 AND protected_objects),
 PRIMARY KEY(root_id,pool_id,cluster_id), FOREIGN KEY(root_id,pool_id) REFERENCES capacity_pool(root_id,id)
);

CREATE TABLE capacity_namespace (
 root_id uuid NOT NULL, pool_id uuid NOT NULL, cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 byte_limit bigint NOT NULL CHECK(byte_limit>=0), object_limit bigint NOT NULL CHECK(object_limit>=0),
 account_limit bigint NOT NULL CHECK(account_limit BETWEEN 1 AND 10000),
 accounts bigint NOT NULL DEFAULT 0 CHECK(accounts BETWEEN 0 AND account_limit),
 backed_bytes bigint NOT NULL DEFAULT 0 CHECK(backed_bytes BETWEEN 0 AND byte_limit),
 backed_objects bigint NOT NULL DEFAULT 0 CHECK(backed_objects BETWEEN 0 AND object_limit),
 PRIMARY KEY(root_id,pool_id,cluster_id,namespace_uid),
 FOREIGN KEY(root_id,pool_id,cluster_id) REFERENCES capacity_cluster(root_id,pool_id,cluster_id)
);

CREATE TABLE capacity_workload (
 root_id uuid NOT NULL, pool_id uuid NOT NULL, cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL, workload_uid text NOT NULL CHECK(octet_length(workload_uid) BETWEEN 1 AND 64),
 id uuid PRIMARY KEY, attempt_id uuid NOT NULL UNIQUE,
 allocation_id uuid NOT NULL UNIQUE REFERENCES custody_allocation(id),
 download_allocation_id uuid NOT NULL UNIQUE REFERENCES download_allocation(id),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1152921504606846975),
 policy_uid text NOT NULL CHECK(octet_length(policy_uid) BETWEEN 1 AND 64),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object' AND octet_length(plan::text)<=32768),
 plan_digest bytea NOT NULL CHECK(octet_length(plan_digest)=32),
 account_version text NOT NULL CHECK(octet_length(account_version) BETWEEN 1 AND 64),
 account_digest bytea NOT NULL CHECK(octet_length(account_digest)=32),
 protected_bytes bigint NOT NULL CHECK(protected_bytes>0), protected_objects bigint NOT NULL CHECK(protected_objects>0),
 system_bytes bigint NOT NULL CHECK(system_bytes>0), system_objects bigint NOT NULL CHECK(system_objects>0),
 initial_observed_at timestamptz NOT NULL, initial_until timestamptz NOT NULL,
 reserved_at timestamptz NOT NULL, capture_backed_at timestamptz, ready_at timestamptz,
 capture_completion jsonb CHECK(jsonb_typeof(capture_completion)='object' AND octet_length(capture_completion::text)<=8192),
 ready_completion jsonb CHECK(jsonb_typeof(ready_completion)='object' AND octet_length(ready_completion::text)<=8192),
 -- Only purpose-fixed SECURITY DEFINER effects can set/clear this marker.
 -- It must be absent at commit and confers no standalone lasting authority.
 mutation_xid xid8,
 UNIQUE(root_id,cluster_id,namespace_uid,workload_uid), UNIQUE(root_id,id),
 FOREIGN KEY(root_id,pool_id,cluster_id,namespace_uid) REFERENCES capacity_namespace(root_id,pool_id,cluster_id,namespace_uid),
 CHECK(id<>attempt_id AND allocation_id<>download_allocation_id),
 CHECK(isfinite(initial_observed_at) AND isfinite(initial_until) AND initial_until>initial_observed_at AND initial_until<=initial_observed_at+interval '5 seconds'),
 CHECK(reserved_at>=initial_observed_at AND reserved_at<initial_until),
 CHECK((capture_backed_at IS NULL)=(capture_completion IS NULL)),
 CHECK((ready_at IS NULL)=(ready_completion IS NULL)),
 CHECK(capture_backed_at IS NULL OR (isfinite(capture_backed_at) AND capture_backed_at>=reserved_at)),
 CHECK(ready_at IS NULL OR (capture_backed_at IS NOT NULL AND isfinite(ready_at) AND ready_at>=capture_backed_at))
);
CREATE INDEX capacity_workload_original_phase ON capacity_workload(root_id,initial_until,id) WHERE ready_at IS NULL;
REVOKE ALL ON capacity_source,capacity_pool,capacity_cluster,capacity_namespace,capacity_workload FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_role_ok(r uuid,purpose text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.capacity_source s JOIN pg_roles p ON p.rolname=session_user
 WHERE s.root_id=r AND p.rolcanlogin AND NOT p.rolinherit AND NOT p.rolsuper AND NOT p.rolcreatedb AND NOT p.rolcreaterole AND NOT p.rolreplication AND NOT p.rolbypassrls AND p.rolconnlimit=3
 AND p.oid=CASE purpose WHEN 'capacity' THEN s.writer_role WHEN 'capacity-capture' THEN s.capture_role ELSE NULL END
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=p.oid)),false)
$$;

CREATE FUNCTION capacity_recovery_current(s public.capacity_source,t public.fleet_current_trust,a jsonb,n timestamptz) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=n AND n<t.fresh_until AND
 t.installation_id=s.installation_id AND (a->>'InstallationID')::uuid=s.installation_id AND (a->>'IssuerEpoch')::uuid=t.issuer_epoch AND
 a->'Revision'->>'UID'=t.source_uid AND (a->'Revision'->>'Generation')::bigint=t.source_generation AND public.connector_digest(a->'Revision'->'Digest')=t.source_digest AND
 (a->>'ObservedAt')::timestamptz<=n AND n<(a->>'FreshUntil')::timestamptz AND (a->>'FreshUntil')::timestamptz<=(a->>'ObservedAt')::timestamptz+interval '5 seconds' AND (a->>'FreshUntil')::timestamptz<=t.fresh_until,false)
$$;

-- No broad audit SELECT is needed by the runtime. This function returns only
-- already accepted workload scope, never a subject/group or audit record.
-- The same roots remain locked through the post-read deadline check.
CREATE FUNCTION read_capacity_permission_scopes(r uuid,recovery jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source public.capacity_source;trust public.fleet_current_trust;stream public.permission_stream;
 started timestamptz:=clock_timestamp();n timestamptz;until_at timestamptz;scopes jsonb;scope_until timestamptz;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR jsonb_typeof(recovery)<>'object' OR octet_length(recovery::text)>4096 THEN
  RAISE EXCEPTION 'capacity scope reader unavailable' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=source.installation_id FOR SHARE;
 SELECT * INTO STRICT stream FROM public.permission_stream WHERE id=r FOR SHARE;
 -- Taking the source after recovery/permission also serializes setup changes.
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r FOR SHARE;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',trust.fresh_until,stream.fresh_until,stream.lease_until,(recovery->>'FreshUntil')::timestamptz);
 IF NOT public.capacity_recovery_current(source,trust,recovery,n) OR stream.suspended OR stream.initial_audit_id IS NULL OR stream.observed_at IS NULL OR stream.observed_at>n OR stream.fresh_until IS NULL OR stream.fresh_until>stream.observed_at+interval '5 seconds' OR n>=until_at OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=stream.initial_audit_id AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=stream.epoch AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'capacity accepted permission scope unavailable' USING ERRCODE='23514';
 END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('BasisKey',b.basis_key,'BasisUID',b.uid,'ClusterID',b.cluster_id,'NamespaceUID',b.namespace_uid,
  'ScopeDigest',to_jsonb(ARRAY(SELECT get_byte(b.scope_digest,k) FROM generate_series(0,31) k)),'WorkloadUIDs',to_jsonb(b.workload_uids),'NotAfter',b.not_after) ORDER BY b.basis_key),'[]'::jsonb),min(b.not_after)
 INTO scopes,scope_until FROM (
  SELECT p.basis_key,p.uid,p.cluster_id,p.namespace_uid,p.scope_digest,p.workload_uids,p.not_after
  FROM public.permission_basis p WHERE p.stream_id=r AND p.effect='Allow' AND p.seen_sequence=stream.sequence AND (p.not_after IS NULL OR p.not_after>n)
  AND EXISTS(SELECT 1 FROM public.permission_assignment a JOIN public.authority_audit proof ON proof.id=a.activation_audit_id
   WHERE a.stream_id=r AND a.basis_key=p.basis_key AND a.role='workload-maintainer' AND a.retired_at IS NULL AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL)
  ORDER BY p.basis_key LIMIT 1025
 ) b;
 IF jsonb_array_length(scopes)>1024 OR octet_length(scopes::text)>1048576 THEN RAISE EXCEPTION 'capacity scope limit exceeded' USING ERRCODE='23514';END IF;
 until_at:=LEAST(until_at,scope_until);n:=clock_timestamp();
 IF n>=until_at OR NOT public.capacity_recovery_current(source,trust,recovery,n) THEN RAISE EXCEPTION 'capacity scope expired after read' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('RootID',r,'Epoch',stream.epoch,'Sequence',stream.sequence,'TrustDigest',to_jsonb(ARRAY(SELECT get_byte(stream.trust_digest,k) FROM generate_series(0,31) k)),
  'ObservedAt',started,'FreshUntil',until_at,'Scopes',scopes);
END $$;

CREATE FUNCTION require_capacity_marker_closed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.capacity_workload'::regclass OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'invalid capacity marker source' USING ERRCODE='23514';
 END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_workload WHERE id=NEW.id AND mutation_xid IS NOT NULL) THEN RAISE EXCEPTION 'capacity configuration marker remains open' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_role_ok(uuid,text),capacity_recovery_current(capacity_source,fleet_current_trust,jsonb,timestamptz),read_capacity_permission_scopes(uuid,jsonb),require_capacity_marker_closed() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER capacity_workload_closed AFTER INSERT OR UPDATE ON capacity_workload DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_capacity_marker_closed();

-- +goose StatementBegin
CREATE FUNCTION capacity_json_fields(v jsonb,fields text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(jsonb_typeof(v)='object' AND v ?& fields AND (v-fields)='{}'::jsonb,false)
$$;

-- SQL-produced lifecycle policies cross the existing typed Go JSON boundary.
-- Preserve the original instant, but use Go's UTC RFC3339Nano spelling at SQL
-- microsecond precision so exact immutable policy equality remains meaningful.
CREATE FUNCTION capacity_json_timestamp(v timestamptz) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE local_value timestamp;fraction text;year_value numeric;
BEGIN
 IF v IS NULL OR NOT isfinite(v) THEN RAISE EXCEPTION 'invalid capacity policy timestamp' USING ERRCODE='23514';END IF;
 local_value:=v AT TIME ZONE 'UTC';year_value:=extract(year FROM local_value);
 IF year_value<1 OR year_value>9999 THEN RAISE EXCEPTION 'invalid capacity policy timestamp' USING ERRCODE='23514';END IF;
 fraction:=rtrim(to_char(local_value,'US'),'0');
 RETURN to_jsonb(to_char(local_value,'YYYY-MM-DD"T"HH24:MI:SS')||CASE WHEN fraction='' THEN '' ELSE '.'||fraction END||'Z');
END $$;

CREATE FUNCTION capacity_json_text(v jsonb,lo integer,hi integer) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(jsonb_typeof(v)='string' AND octet_length(v#>>'{}') BETWEEN lo AND hi,false)
$$;

CREATE FUNCTION capacity_json_integer(v jsonb,lo bigint,hi bigint) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 -- Do not let numeric-to-bigint rounding turn a fractional declaration into
 -- a different accepted quantity. JSON strings and missing/null values deny.
 IF jsonb_typeof(v) IS DISTINCT FROM 'number' OR (v#>>'{}') !~ '^(0|[1-9][0-9]*)$' THEN RETURN false;END IF;
 RETURN (v#>>'{}')::bigint BETWEEN lo AND hi;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

CREATE FUNCTION capacity_amount_valid(v jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.capacity_json_fields(v,ARRAY['Bytes','Objects']) AND
  public.capacity_json_integer(v->'Bytes',1,1125899906842624) AND
  public.capacity_json_integer(v->'Objects',1,1000000000)
$$;

CREATE FUNCTION capacity_decoded_pool_valid(v jsonb,name text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE slot jsonb;names text[]:='{}';
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Name','Capacity','Safety','System','Burst','Slots']) OR
  v->>'Name' IS DISTINCT FROM name OR NOT public.capacity_json_text(v->'Name',1,63) OR
  NOT public.capacity_amount_valid(v->'Capacity') OR NOT public.capacity_amount_valid(v->'Safety') OR
  NOT public.capacity_amount_valid(v->'System') OR NOT public.capacity_amount_valid(v->'Burst') OR
  jsonb_typeof(v->'Slots') IS DISTINCT FROM 'array' THEN RETURN false;END IF;
 IF jsonb_array_length(v->'Slots') NOT BETWEEN 1 AND 64 THEN RETURN false;END IF;
 FOR slot IN SELECT value FROM jsonb_array_elements(v->'Slots') LOOP
  IF NOT public.capacity_json_fields(slot,ARRAY['Policy','Workloads','Protected']) OR
   NOT public.capacity_json_text(slot->'Policy',1,63) OR slot->>'Policy'=ANY(names) OR
   NOT public.capacity_json_integer(slot->'Workloads',1,10000) OR NOT public.capacity_amount_valid(slot->'Protected') THEN RETURN false;END IF;
  names:=array_append(names,slot->>'Policy');
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

CREATE FUNCTION capacity_decoded_scope_valid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE k text;value jsonb;count_keys integer:=0;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['ClusterID','NamespaceLabels']) OR
  NOT public.capacity_json_text(v->'ClusterID',36,36) OR jsonb_typeof(v->'NamespaceLabels') IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 PERFORM (v->>'ClusterID')::uuid;
 FOR k,value IN SELECT * FROM jsonb_each(v->'NamespaceLabels') LOOP
  IF octet_length(k) NOT BETWEEN 1 AND 253 OR NOT public.capacity_json_text(value,1,63) THEN RETURN false;END IF;
  count_keys:=count_keys+1;
 END LOOP;
 RETURN count_keys BETWEEN 1 AND 16;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

CREATE FUNCTION capacity_decoded_policy_valid(v jsonb,name text,pool text,scope jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(public.capacity_json_fields(v,ARRAY['Name','Pool','Cluster','Protected','Hard','Context','NamespaceMaximum','NamespaceAccounts']) AND
  public.capacity_json_text(v->'Name',1,63) AND public.capacity_json_text(v->'Pool',1,63) AND
  v->>'Name'=name AND v->>'Pool'=pool AND v->>'Cluster'=scope->>'ClusterID' AND public.capacity_decoded_scope_valid(scope) AND
  public.capacity_amount_valid(v->'Protected') AND public.capacity_amount_valid(v->'Hard') AND public.capacity_amount_valid(v->'Context') AND
  public.capacity_amount_valid(v->'NamespaceMaximum') AND public.capacity_json_integer(v->'NamespaceAccounts',1,10000),false)
$$;

CREATE FUNCTION capacity_source_observation_valid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE snap jsonb;refs jsonb;ref jsonb;versions jsonb;ver jsonb;uid text;ids text[]:='{}';names text[]:='{}';d bytea;sd bytea;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Snapshot','Versions','Digest']) OR octet_length(v::text)>262144 THEN RETURN false;END IF;
 snap:=v->'Snapshot';versions:=v->'Versions';
 IF NOT public.capacity_json_fields(snap,ARRAY['ClusterID','ControlNamespace','PoolResourceVersion','PolicyResourceVersion','ObservedAt','FreshUntil','Pools','Policies']) OR
  NOT public.capacity_json_fields(snap->'ControlNamespace',ARRAY['Name','UID']) OR
  NOT public.capacity_json_text(snap->'ClusterID',36,36) OR
  NOT public.capacity_json_text(snap->'ControlNamespace'->'Name',1,63) OR NOT public.capacity_json_text(snap->'ControlNamespace'->'UID',1,64) OR
  NOT public.capacity_json_text(snap->'PoolResourceVersion',1,128) OR NOT public.capacity_json_text(snap->'PolicyResourceVersion',1,128) OR
  NOT public.capacity_json_text(snap->'ObservedAt',1,64) OR NOT public.capacity_json_text(snap->'FreshUntil',1,64) OR
  jsonb_typeof(snap->'Pools')<>'array' OR jsonb_typeof(snap->'Policies')<>'array' OR jsonb_typeof(versions)<>'array' OR
  jsonb_array_length(snap->'Pools')>16 OR jsonb_array_length(snap->'Policies')>64 OR
  jsonb_array_length(versions)<>jsonb_array_length(snap->'Pools')+jsonb_array_length(snap->'Policies') OR
  octet_length(snap->'ControlNamespace'->>'Name') NOT BETWEEN 1 AND 63 OR octet_length(snap->'ControlNamespace'->>'UID') NOT BETWEEN 1 AND 64 OR
  octet_length(snap->>'PoolResourceVersion') NOT BETWEEN 1 AND 128 OR octet_length(snap->>'PolicyResourceVersion') NOT BETWEEN 1 AND 128 OR
  (snap->>'FreshUntil')::timestamptz<=(snap->>'ObservedAt')::timestamptz OR (snap->>'FreshUntil')::timestamptz>(snap->>'ObservedAt')::timestamptz+interval '5 seconds' OR
  NOT isfinite((snap->>'ObservedAt')::timestamptz) OR NOT isfinite((snap->>'FreshUntil')::timestamptz) THEN RETURN false;END IF;
 PERFORM (snap->>'ClusterID')::uuid;
 d:=public.connector_digest(v->'Digest');IF d IS NULL OR d=decode(repeat('00',32),'hex') THEN RETURN false;END IF;
 -- Decoding failures are explicit null scope/budget facts. They are preserved
 -- in a complete source, then excluded only by independently understood scope.
 FOR ref IN SELECT value FROM jsonb_array_elements(snap->'Pools') LOOP
  IF NOT public.capacity_json_fields(ref,ARRAY['Resource','StorageProfile','Assurance','Budget']) OR ref->'Resource'->>'Kind' IS DISTINCT FROM 'EvidenceStoragePool' OR
   NOT public.capacity_json_text(ref->'StorageProfile',0,63) OR NOT public.capacity_json_text(ref->'Assurance',0,32) THEN RETURN false;END IF;
  IF ref->'Budget'<>'null'::jsonb AND (NOT public.capacity_decoded_pool_valid(ref->'Budget',ref->'Resource'->>'Name') OR
   NOT public.capacity_json_text(ref->'StorageProfile',1,63) OR ref->>'Assurance' NOT IN('qualifiedReservedBackend','bestEffort') OR
   public.connector_digest(ref->'Resource'->'SpecDigest')=decode(repeat('00',32),'hex')) THEN RETURN false;END IF;
 END LOOP;
 FOR ref IN SELECT value FROM jsonb_array_elements(snap->'Policies') LOOP
  IF NOT public.capacity_json_fields(ref,ARRAY['Resource','Scope','Pool','Budget']) OR ref->'Resource'->>'Kind' IS DISTINCT FROM 'EvidenceBudgetPolicy' OR
   NOT public.capacity_json_text(ref->'Pool',0,63) THEN RETURN false;END IF;
  IF ref->'Scope'<>'null'::jsonb AND NOT public.capacity_decoded_scope_valid(ref->'Scope') THEN RETURN false;END IF;
  IF ref->'Budget'<>'null'::jsonb AND (NOT public.capacity_decoded_policy_valid(ref->'Budget',ref->'Resource'->>'Name',ref->>'Pool',ref->'Scope') OR
   public.connector_digest(ref->'Resource'->'SpecDigest')=decode(repeat('00',32),'hex')) THEN RETURN false;END IF;
 END LOOP;
 refs:=(snap->'Pools')||(snap->'Policies');
 FOR ref IN SELECT value->'Resource' FROM jsonb_array_elements(refs) LOOP
  IF NOT public.capacity_json_fields(ref,ARRAY['ClusterID','Namespace','NamespaceUID','Kind','Name','UID','ResourceVersion','Generation','SpecDigest','Deleting']) OR
   NOT public.capacity_json_text(ref->'Name',1,63) OR NOT public.capacity_json_text(ref->'UID',1,64) OR NOT public.capacity_json_text(ref->'ResourceVersion',1,128) OR
   NOT public.capacity_json_integer(ref->'Generation',1,2147483647) OR
   ref->>'ClusterID' IS DISTINCT FROM snap->>'ClusterID' OR ref->>'Namespace' IS DISTINCT FROM snap->'ControlNamespace'->>'Name' OR ref->>'NamespaceUID' IS DISTINCT FROM snap->'ControlNamespace'->>'UID' OR
   octet_length(ref->>'Name') NOT BETWEEN 1 AND 63 OR octet_length(ref->>'UID') NOT BETWEEN 1 AND 64 OR octet_length(ref->>'ResourceVersion') NOT BETWEEN 1 AND 128 OR
   (ref->>'Generation')::bigint NOT BETWEEN 1 AND 2147483647 OR jsonb_typeof(ref->'Deleting')<>'boolean' THEN RETURN false;END IF;
  uid:=ref->>'UID';
  IF uid=ANY(ids) OR ((ref->>'Kind')||'/'||(ref->>'Name'))=ANY(names) THEN RETURN false;END IF;
  ids:=array_append(ids,uid);names:=array_append(names,(ref->>'Kind')||'/'||(ref->>'Name'));
  IF (SELECT count(*) FROM jsonb_array_elements(versions) p WHERE p->>'UID'=uid)<>1 THEN RETURN false;END IF;
  SELECT value INTO STRICT ver FROM jsonb_array_elements(versions) WHERE value->>'UID'=uid;
  IF NOT public.capacity_json_fields(ver,ARRAY['Kind','Name','UID','Generation','Deleting','Spec']) OR
   ROW(ver->>'Kind',ver->>'Name',ver->>'UID',ver->'Generation',ver->'Deleting') IS DISTINCT FROM ROW(ref->>'Kind',ref->>'Name',ref->>'UID',ref->'Generation',ref->'Deleting') THEN RETURN false;END IF;
  d:=public.connector_digest(ver->'Spec');sd:=public.connector_digest(ref->'SpecDigest');
  IF d IS NULL OR sd IS NULL OR d=decode(repeat('00',32),'hex') OR (sd<>decode(repeat('00',32),'hex') AND sd<>d) THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE FUNCTION guard_capacity_source() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE roles bigint;root_change boolean;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'retained capacity root retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT count(*) INTO roles FROM pg_roles p WHERE p.oid IN(NEW.writer_role,NEW.capture_role) AND p.rolcanlogin AND NOT p.rolinherit AND NOT p.rolsuper AND NOT p.rolcreatedb AND NOT p.rolcreaterole AND NOT p.rolreplication AND NOT p.rolbypassrls AND p.rolconnlimit=3 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=p.oid);
 IF roles<>2 OR NOT EXISTS(SELECT 1 FROM public.capture_audit_root c WHERE c.root_id=NEW.root_id AND c.installation_id=NEW.installation_id AND c.source_role=NEW.capture_role) OR
  NEW.source_guard_digest=decode(repeat('00',32),'hex') OR NEW.qualification_digest=decode(repeat('00',32),'hex') OR NOT public.capacity_qualification_valid(NEW.qualification) OR
  public.connector_digest(NEW.qualification->'Digest') IS DISTINCT FROM NEW.qualification_digest OR NEW.qualification->'RootBacking'->>'RootID' IS DISTINCT FROM NEW.root_id::text OR
  NEW.qualification->'RootBacking'->>'InstallationID' IS DISTINCT FROM NEW.installation_id::text OR NEW.qualification->'RootBacking'->>'AccountVersion' IS DISTINCT FROM NEW.account_version THEN
  RAISE EXCEPTION 'capacity protected setup pins unavailable' USING ERRCODE='23514';END IF;
 PERFORM (NEW.qualification->>'ID')::uuid;
 IF TG_OP='INSERT' THEN
  IF NOT public.capacity_setup_original_valid(NEW) OR NOT public.capacity_audit_reader_pin_valid(NEW) THEN RAISE EXCEPTION 'capacity original paired setup unavailable' USING ERRCODE='23514';END IF;
  IF NEW.accepted_revision<>0 OR NEW.accepted_snapshot IS NOT NULL OR NEW.accepted_digest IS NOT NULL OR NEW.negative_snapshot IS NOT NULL OR NEW.observed_at IS NOT NULL OR NEW.fresh_until IS NOT NULL OR NOT NEW.suspended OR NEW.root_plan IS NOT NULL OR NEW.configuration_spent<>0 OR NEW.root_mutation_xid IS NOT NULL THEN RAISE EXCEPTION 'capacity root must start unavailable' USING ERRCODE='23514';END IF;
 ELSE
  root_change:=ROW(NEW.root_plan,NEW.root_plan_bytes,NEW.root_plan_digest,NEW.root_configuration,NEW.configuration_spent,NEW.root_mutation_xid) IS DISTINCT FROM ROW(OLD.root_plan,OLD.root_plan_bytes,OLD.root_plan_digest,OLD.root_configuration,OLD.configuration_spent,OLD.root_mutation_xid);
  IF root_change THEN
   IF (to_jsonb(NEW)-ARRAY['root_plan','root_plan_bytes','root_plan_digest','root_configuration','configuration_spent','root_mutation_xid']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['root_plan','root_plan_bytes','root_plan_digest','root_configuration','configuration_spent','root_mutation_xid']) OR
    NOT public.capacity_root_transition_valid(OLD,NEW) THEN RAISE EXCEPTION 'capacity root configuration mutation invalid' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  IF NOT public.capacity_role_ok(OLD.root_id,'capacity') OR
   (to_jsonb(NEW)-ARRAY['accepted_revision','accepted_snapshot','accepted_digest','negative_snapshot','observed_at','fresh_until','suspended']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['accepted_revision','accepted_snapshot','accepted_digest','negative_snapshot','observed_at','fresh_until','suspended']) OR
   NEW.accepted_revision<OLD.accepted_revision OR NEW.accepted_revision>OLD.accepted_revision+1 OR NEW.observed_at IS NULL OR NEW.fresh_until IS NULL OR
   OLD.observed_at IS NOT NULL AND NEW.observed_at<OLD.observed_at OR NEW.observed_at>clock_timestamp() OR clock_timestamp()>=NEW.fresh_until THEN
   RAISE EXCEPTION 'capacity original source pins cannot change' USING ERRCODE='23514';END IF;
  IF NEW.observed_at=OLD.observed_at AND (NEW.fresh_until>OLD.fresh_until OR NOT NEW.suspended AND OLD.suspended) THEN RAISE EXCEPTION 'capacity observation cannot be extended' USING ERRCODE='23514';END IF;
  IF NEW.accepted_snapshot IS DISTINCT FROM OLD.accepted_snapshot AND (NOT public.capacity_source_observation_valid(NEW.accepted_snapshot) OR NOT public.capacity_source_monotonic(OLD.accepted_snapshot,NEW.accepted_snapshot)) THEN
   RAISE EXCEPTION 'capacity accepted source mutation invalid' USING ERRCODE='23514';END IF;
  IF NEW.negative_snapshot IS DISTINCT FROM OLD.negative_snapshot THEN
   IF NEW.negative_snapshot IS NULL THEN
    IF NEW.suspended OR NOT public.capacity_source_monotonic(OLD.negative_snapshot,NEW.accepted_snapshot) THEN RAISE EXCEPTION 'capacity negative source cannot be erased' USING ERRCODE='23514';END IF;
   ELSIF NOT NEW.suspended OR NEW.accepted_revision<>OLD.accepted_revision+1 OR NEW.accepted_snapshot IS DISTINCT FROM OLD.accepted_snapshot OR NEW.accepted_digest IS DISTINCT FROM OLD.accepted_digest OR NOT public.capacity_source_observation_valid(NEW.negative_snapshot) OR NOT public.capacity_source_monotonic(OLD.negative_snapshot,NEW.negative_snapshot) THEN
    RAISE EXCEPTION 'capacity negative source must remain unavailable' USING ERRCODE='23514';END IF;
  END IF;
  IF NEW.accepted_digest IS DISTINCT FROM OLD.accepted_digest AND (NEW.accepted_revision<>OLD.accepted_revision+1 OR NEW.accepted_digest IS DISTINCT FROM public.connector_digest(NEW.accepted_snapshot->'Digest')) THEN
   RAISE EXCEPTION 'capacity source digest changed without revision' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION capacity_source_monotonic(old_value jsonb,new_value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE old_item jsonb;new_item jsonb;old_decoded jsonb;new_decoded jsonb;
BEGIN
 IF old_value IS NULL THEN RETURN true;END IF;
 FOR old_item IN SELECT value FROM jsonb_array_elements(old_value->'Versions') LOOP
  SELECT value INTO new_item FROM jsonb_array_elements(new_value->'Versions') WHERE value->>'UID'=old_item->>'UID';
  IF FOUND AND (ROW(new_item->>'Kind',new_item->>'Name') IS DISTINCT FROM ROW(old_item->>'Kind',old_item->>'Name') OR
   (new_item->>'Generation')::bigint<(old_item->>'Generation')::bigint OR
   ((new_item->>'Generation')::bigint=(old_item->>'Generation')::bigint AND new_item->'Spec' IS DISTINCT FROM old_item->'Spec') OR
   ((old_item->>'Deleting')::boolean AND NOT (new_item->>'Deleting')::boolean)) THEN RETURN false;END IF;
  IF new_item IS NOT NULL AND new_item->'Generation'=old_item->'Generation' THEN
   -- An unchanged canonical spec cannot silently acquire different decoded
   -- quantities/scope. Parser/profile changes need an explicit qualified source
   -- change; neither status progress nor a refreshed root observation is one.
   SELECT value-'Resource' INTO STRICT old_decoded FROM jsonb_array_elements((old_value->'Snapshot'->'Pools')||(old_value->'Snapshot'->'Policies')) WHERE value->'Resource'->>'UID'=old_item->>'UID';
   SELECT value-'Resource' INTO STRICT new_decoded FROM jsonb_array_elements((new_value->'Snapshot'->'Pools')||(new_value->'Snapshot'->'Policies')) WHERE value->'Resource'->>'UID'=old_item->>'UID';
   IF new_decoded IS DISTINCT FROM old_decoded THEN RETURN false;END IF;
  END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE FUNCTION read_capacity_source_revision(r uuid,recovery jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source public.capacity_source;trust public.fleet_current_trust;n timestamptz;started timestamptz:=clock_timestamp();
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') THEN RAISE EXCEPTION 'capacity source role unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=source.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r FOR SHARE;
 n:=clock_timestamp();
 IF n>=started+interval '5 seconds' OR NOT public.capacity_recovery_current(source,trust,recovery,n) THEN RAISE EXCEPTION 'capacity revision observation unavailable' USING ERRCODE='23514';END IF;
 RETURN source.accepted_revision;
END $$;

CREATE FUNCTION accept_capacity_source(r uuid,expected bigint,observation jsonb,protection jsonb,recovery jsonb,qualification uuid,qualification_digest bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source public.capacity_source;trust public.fleet_current_trust;stream public.permission_stream;snap jsonb;
 started timestamptz:=clock_timestamp();n timestamptz;observed timestamptz;until_at timestamptz;revision bigint;digest_value bytea;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR expected NOT BETWEEN 0 AND 1152921504606846974 OR
  NOT public.capacity_source_observation_valid(observation) OR NOT public.capacity_json_fields(protection,ARRAY['ClusterID','ControlNamespaceUID','Digest','ObservedAt','FreshUntil']) THEN
  RAISE EXCEPTION 'capacity source observation unavailable' USING ERRCODE='23514';END IF;
 snap:=observation->'Snapshot';digest_value:=public.connector_digest(observation->'Digest');
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=source.installation_id FOR SHARE;
 SELECT * INTO STRICT stream FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 observed:=GREATEST((snap->>'ObservedAt')::timestamptz,(protection->>'ObservedAt')::timestamptz,(recovery->>'ObservedAt')::timestamptz);
 until_at:=LEAST(started+interval '5 seconds',(snap->>'FreshUntil')::timestamptz,(protection->>'FreshUntil')::timestamptz,(recovery->>'FreshUntil')::timestamptz,trust.fresh_until,stream.fresh_until,stream.lease_until);
 n:=clock_timestamp();
 IF NOT COALESCE(public.capacity_recovery_current(source,trust,recovery,n) AND NOT stream.suspended AND stream.observed_at<=n AND n<stream.fresh_until AND n<stream.lease_until AND
  observed<=n AND n<until_at AND until_at<=observed+interval '5 seconds' AND isfinite(observed) AND isfinite(until_at) AND
  (snap->>'ClusterID')::uuid=source.control_cluster_id AND snap->'ControlNamespace'->>'UID'=source.control_namespace_uid AND
  (protection->>'ClusterID')::uuid=source.control_cluster_id AND protection->>'ControlNamespaceUID'=source.control_namespace_uid AND public.connector_digest(protection->'Digest')=source.source_guard_digest AND
  (protection->>'ObservedAt')::timestamptz<=n AND (protection->>'FreshUntil')::timestamptz>(protection->>'ObservedAt')::timestamptz AND (protection->>'FreshUntil')::timestamptz<=(protection->>'ObservedAt')::timestamptz+interval '5 seconds' AND
  source.qualification->>'ID'=qualification::text AND source.qualification_digest=qualification_digest,false) THEN
  RAISE EXCEPTION 'capacity source acceptance unavailable' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=stream.initial_audit_id AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=stream.epoch AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'capacity permission root unavailable' USING ERRCODE='23514';END IF;
 IF source.observed_at IS NOT NULL AND observed<source.observed_at THEN RAISE EXCEPTION 'capacity source observation superseded' USING ERRCODE='23514';END IF;
 IF source.observed_at=observed THEN
  IF source.suspended OR source.accepted_digest IS DISTINCT FROM digest_value OR source.accepted_snapshot IS DISTINCT FROM observation OR until_at>source.fresh_until OR source.accepted_revision NOT IN(expected,expected+1) THEN
   RAISE EXCEPTION 'capacity source observation cannot be renewed' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Accepted',true,'Revision',source.accepted_revision,'ObservedAt',source.observed_at,'FreshUntil',LEAST(until_at,source.fresh_until));
 END IF;
 IF source.accepted_revision<>expected THEN RAISE EXCEPTION 'capacity source changed' USING ERRCODE='23514';END IF;
 IF NOT public.capacity_source_monotonic(source.accepted_snapshot,observation) OR NOT public.capacity_source_monotonic(source.negative_snapshot,observation) THEN
  -- Commit this known restrictive result before reporting unavailable. Raising
  -- here would roll back the fence and leave the previous source authorizing.
  UPDATE public.capacity_source SET accepted_revision=accepted_revision+1,
   negative_snapshot=CASE WHEN public.capacity_source_monotonic(source.negative_snapshot,observation) THEN observation ELSE source.negative_snapshot END,
   observed_at=observed,fresh_until=until_at,suspended=true WHERE root_id=r;
  IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity negative source expired before commit' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Accepted',false,'Revision',source.accepted_revision+1,'ObservedAt',observed,'FreshUntil',until_at);
 END IF;
 revision:=source.accepted_revision;
 IF revision=0 OR source.suspended OR source.accepted_digest IS DISTINCT FROM digest_value THEN revision:=revision+1;END IF;
 UPDATE public.capacity_source SET accepted_revision=revision,accepted_snapshot=observation,accepted_digest=digest_value,negative_snapshot=NULL,observed_at=observed,fresh_until=until_at,suspended=false WHERE root_id=r;
 n:=clock_timestamp();
 IF n>=until_at OR NOT public.capacity_recovery_current(source,trust,recovery,n) THEN RAISE EXCEPTION 'capacity source expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Accepted',true,'Revision',revision,'ObservedAt',observed,'FreshUntil',until_at);
END $$;

CREATE FUNCTION invalidate_capacity_source(r uuid,expected bigint,recovery jsonb,observed timestamptz,original_until timestamptz) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE source public.capacity_source;trust public.fleet_current_trust;n timestamptz;started timestamptz:=clock_timestamp();
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR expected NOT BETWEEN 0 AND 1152921504606846974 OR NOT isfinite(observed) OR NOT isfinite(original_until) OR original_until<=observed OR original_until>observed+interval '5 seconds' THEN
  RAISE EXCEPTION 'capacity source invalidation unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=source.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT source FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF n>=LEAST(started+interval '5 seconds',original_until) OR observed>n OR NOT public.capacity_recovery_current(source,trust,recovery,n) THEN RAISE EXCEPTION 'capacity source invalidation expired' USING ERRCODE='23514';END IF;
 -- A failed old read cannot fence a successful read begun after it. This is a
 -- conservative negative watermark only; retained plans and spend stay intact.
 IF source.observed_at IS NOT NULL AND observed<source.observed_at THEN RETURN false;END IF;
 IF source.accepted_revision<>expected THEN RAISE EXCEPTION 'capacity invalidation sequence changed' USING ERRCODE='23514';END IF;
 UPDATE public.capacity_source SET accepted_revision=accepted_revision+1,suspended=true,observed_at=observed,fresh_until=original_until WHERE root_id=r;
 n:=clock_timestamp();
 IF n>=LEAST(started+interval '5 seconds',original_until) OR NOT public.capacity_recovery_current(source,trust,recovery,n) THEN RAISE EXCEPTION 'capacity source invalidation expired before commit' USING ERRCODE='23514';END IF;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_timestamp(timestamptz),capacity_json_fields(jsonb,text[]),capacity_json_text(jsonb,integer,integer),capacity_json_integer(jsonb,bigint,bigint),capacity_amount_valid(jsonb),capacity_decoded_pool_valid(jsonb,text),capacity_decoded_scope_valid(jsonb),capacity_decoded_policy_valid(jsonb,text,text,jsonb),capacity_source_observation_valid(jsonb),capacity_source_monotonic(jsonb,jsonb),guard_capacity_source(),read_capacity_source_revision(uuid,jsonb),accept_capacity_source(uuid,bigint,jsonb,jsonb,jsonb,uuid,bytea),invalidate_capacity_source(uuid,bigint,jsonb,timestamptz,timestamptz) FROM PUBLIC;
CREATE TRIGGER capacity_source_guard BEFORE INSERT OR UPDATE OR DELETE ON capacity_source FOR EACH ROW EXECUTE FUNCTION guard_capacity_source();

-- +goose StatementBegin
-- Recompute the complete selected pool from the accepted closed snapshot.
-- This pure function grants no effect. Reserve/renewal will call it again under
-- the source/hierarchy locks; no caller's desired account quantity is trusted.
CREATE FUNCTION capacity_compile_pool(snapshot jsonb,pool_name text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool jsonb;budget jsonb;slot jsonb;policy jsonb;shape jsonb;cluster jsonb;clusters jsonb:='{}';policies jsonb:='[]';cluster_list jsonb;
 pool_count bigint;policy_count bigint;slots bigint:=0;names text[]:='{}';cluster_id text;
 protected_bytes numeric:=0;protected_objects numeric:=0;bytes numeric;objects numeric;
BEGIN
 IF NOT public.capacity_source_observation_valid(snapshot) OR octet_length(pool_name) NOT BETWEEN 1 AND 63 THEN RETURN NULL;END IF;
 SELECT count(*) INTO pool_count FROM jsonb_array_elements(snapshot->'Snapshot'->'Pools') p WHERE p->'Resource'->>'Name'=pool_name;
 IF pool_count<>1 THEN RETURN NULL;END IF;
 SELECT value INTO STRICT pool FROM jsonb_array_elements(snapshot->'Snapshot'->'Pools') WHERE value->'Resource'->>'Name'=pool_name;
 budget:=pool->'Budget';
 IF pool->'Resource'->>'Deleting' IS DISTINCT FROM 'false' OR pool->>'Assurance' IS DISTINCT FROM 'qualifiedReservedBackend' OR
  budget='null'::jsonb OR NOT public.capacity_decoded_pool_valid(budget,pool_name) THEN RETURN NULL;END IF;
 FOR slot IN SELECT value FROM jsonb_array_elements(budget->'Slots') ORDER BY (value->>'Policy') COLLATE "C" LOOP
  SELECT count(*) INTO policy_count FROM jsonb_array_elements(snapshot->'Snapshot'->'Policies') p WHERE p->'Resource'->>'Name'=slot->>'Policy';
  IF policy_count<>1 THEN RETURN NULL;END IF;
  SELECT value INTO STRICT policy FROM jsonb_array_elements(snapshot->'Snapshot'->'Policies') WHERE value->'Resource'->>'Name'=slot->>'Policy';
  shape:=policy->'Budget';
  IF policy->'Resource'->>'Deleting' IS DISTINCT FROM 'false' OR policy->>'Pool' IS DISTINCT FROM pool_name OR shape='null'::jsonb OR
   NOT public.capacity_decoded_policy_valid(shape,slot->>'Policy',pool_name,policy->'Scope') OR
   shape->'Protected' IS DISTINCT FROM slot->'Protected' OR
   (shape->'Hard'->>'Bytes')::bigint<(shape->'Protected'->>'Bytes')::bigint OR (shape->'Hard'->>'Objects')::bigint<(shape->'Protected'->>'Objects')::bigint OR
   (shape->'Protected'->>'Bytes')::bigint<(shape->'Context'->>'Bytes')::bigint OR (shape->'Protected'->>'Objects')::bigint<(shape->'Context'->>'Objects')::bigint OR
   (shape->'NamespaceMaximum'->>'Bytes')::bigint<(shape->'Protected'->>'Bytes')::bigint OR (shape->'NamespaceMaximum'->>'Objects')::bigint<(shape->'Protected'->>'Objects')::bigint THEN RETURN NULL;END IF;
  names:=array_append(names,slot->>'Policy');slots:=slots+(slot->>'Workloads')::bigint;
  -- Numeric intermediates avoid bigint wrap before the pool comparison. Only
  -- quantities proven below the original finite pool are converted to bigint.
  bytes:=(slot->'Protected'->>'Bytes')::numeric*(slot->>'Workloads')::numeric;
  objects:=(slot->'Protected'->>'Objects')::numeric*(slot->>'Workloads')::numeric;
  protected_bytes:=protected_bytes+bytes;protected_objects:=protected_objects+objects;
  IF protected_bytes>(budget->'Capacity'->>'Bytes')::numeric OR protected_objects>(budget->'Capacity'->>'Objects')::numeric THEN RETURN NULL;END IF;
  cluster_id:=shape->>'Cluster';cluster:=clusters->cluster_id;
  cluster:=jsonb_build_object('ProtectedBytes',COALESCE((cluster->>'ProtectedBytes')::numeric,0)+bytes,
   'ProtectedObjects',COALESCE((cluster->>'ProtectedObjects')::numeric,0)+objects,'Slots',COALESCE((cluster->>'Slots')::bigint,0)+(slot->>'Workloads')::bigint);
  clusters:=jsonb_set(clusters,ARRAY[cluster_id],cluster,true);
  policies:=policies||jsonb_build_array(jsonb_build_object('Name',slot->>'Policy','UID',policy->'Resource'->>'UID','Generation',policy->'Resource'->'Generation',
   'Digest',policy->'Resource'->'SpecDigest','Scope',policy->'Scope','Budget',shape,'Slots',(slot->>'Workloads')::bigint));
 END LOOP;
 -- An assigned declaration omitted from the slot inventory cannot borrow
 -- someone else's protected commitment, even if it does not match this target.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot->'Snapshot'->'Policies') p WHERE p->>'Pool'=pool_name AND NOT (p->'Resource'->>'Name'=ANY(names))) OR slots NOT BETWEEN 1 AND 640000 THEN RETURN NULL;END IF;
 bytes:=protected_bytes+(budget->'Safety'->>'Bytes')::numeric+(budget->'System'->>'Bytes')::numeric+(budget->'Burst'->>'Bytes')::numeric;
 objects:=protected_objects+(budget->'Safety'->>'Objects')::numeric+(budget->'System'->>'Objects')::numeric+(budget->'Burst'->>'Objects')::numeric;
 IF bytes>(budget->'Capacity'->>'Bytes')::numeric OR objects>(budget->'Capacity'->>'Objects')::numeric THEN RETURN NULL;END IF;
 SELECT jsonb_agg(jsonb_build_object('ClusterID',key,'ProtectedBytes',(value->>'ProtectedBytes')::bigint,'ProtectedObjects',(value->>'ProtectedObjects')::bigint,
  'ByteLimit',(value->>'ProtectedBytes')::bigint+(budget->'Burst'->>'Bytes')::bigint,'ObjectLimit',(value->>'ProtectedObjects')::bigint+(budget->'Burst'->>'Objects')::bigint,
  'AccountLimit',(value->>'Slots')::bigint) ORDER BY key COLLATE "C") INTO cluster_list FROM jsonb_each(clusters);
 RETURN jsonb_build_object('Format','capacity-pool/v1','Name',pool_name,'UID',pool->'Resource'->>'UID','Generation',pool->'Resource'->'Generation','Digest',pool->'Resource'->'SpecDigest',
  'StorageProfile',pool->>'StorageProfile','Capacity',budget->'Capacity','Safety',budget->'Safety','System',budget->'System','Burst',budget->'Burst',
  'Protected',jsonb_build_object('Bytes',protected_bytes::bigint,'Objects',protected_objects::bigint),'AccountLimit',slots,'NamespaceLimit',slots,'Policies',policies,'Clusters',cluster_list);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_compile_pool(jsonb,text) FROM PUBLIC;

-- +goose StatementBegin
-- Complete typed enrollment input, without an effect or an implicit lookup in
-- a process-local plan cache. The canonical byte hashes preserve exact replay;
-- semantic equality against the recomputed pool independently checks amounts.
-- The calling RPC must additionally hold/recheck recovery, permission, source,
-- namespace guard and every retained parent/child before mutating configuration.
CREATE FUNCTION capacity_enrollment_plan(s public.capacity_source,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb;pool jsonb;expected jsonb;selected_source jsonb;expected_source jsonb;entries jsonb;policy jsonb;candidate jsonb;key_name text;label_value jsonb;
 source_digest bytea;plan_digest bytea;pool_digest bytea;matches bigint:=0;selected_name text;selected_uid text;
BEGIN
 IF octet_length(plan_bytes) NOT BETWEEN 2 AND 32768 OR octet_length(pool_bytes) NOT BETWEEN 2 AND 65536 OR octet_length(source_bytes) NOT BETWEEN 2 AND 262144 OR
  NOT public.capacity_json_fields(o,ARRAY['Key','SourceRevision','SourceDigest','PlanDigest','NamespaceGuardDigest','NamespaceLabels','NamespaceResourceVersion','WorkloadResourceVersion','PermissionEpoch','PermissionSequence','PermissionTrust','Recovery','ObservedAt','FreshUntil']) OR
  NOT public.capacity_json_fields(o->'Key',ARRAY['RootID','ClusterID','NamespaceUID','WorkloadUID']) OR
  octet_length(o::text)>131072 OR o->'Key'->>'RootID' IS DISTINCT FROM s.root_id::text OR
  NOT public.capacity_json_text(o->'Key'->'ClusterID',36,36) OR NOT public.capacity_json_text(o->'Key'->'NamespaceUID',1,64) OR NOT public.capacity_json_text(o->'Key'->'WorkloadUID',1,64) OR
  NOT public.capacity_json_integer(o->'SourceRevision',1,1152921504606846975) OR (o->>'SourceRevision')::bigint<>s.accepted_revision OR
  NOT public.capacity_json_text(o->'NamespaceResourceVersion',1,128) OR NOT public.capacity_json_text(o->'WorkloadResourceVersion',1,128) OR
  jsonb_typeof(o->'NamespaceLabels') IS DISTINCT FROM 'object' THEN RETURN NULL;END IF;
 PERFORM (o->'Key'->>'ClusterID')::uuid;
 IF (SELECT count(*) FROM jsonb_each(o->'NamespaceLabels')) NOT BETWEEN 1 AND 256 THEN RETURN NULL;END IF;
 FOR key_name,label_value IN SELECT * FROM jsonb_each(o->'NamespaceLabels') LOOP
  IF octet_length(key_name) NOT BETWEEN 1 AND 253 OR NOT public.capacity_json_text(label_value,0,63) THEN RETURN NULL;END IF;
 END LOOP;
 p:=convert_from(plan_bytes,'UTF8')::jsonb;pool:=convert_from(pool_bytes,'UTF8')::jsonb;selected_source:=convert_from(source_bytes,'UTF8')::jsonb;
 IF NOT public.capacity_json_fields(p,ARRAY['Format','RootID','InstallationID','QualificationID','AccountVersion','QualificationDigest','SourceDigest','PoolDigest','PoolName','PoolUID','PolicyName','PolicyUID','ClusterID','PoolGeneration','PolicyGeneration','PolicyDigest','Budget','PolicySlots']) OR
  p->>'Format' IS DISTINCT FROM 'capacity-enrollment-plan/v1' OR p->>'RootID' IS DISTINCT FROM s.root_id::text OR p->>'InstallationID' IS DISTINCT FROM s.installation_id::text OR
  p->>'QualificationID' IS DISTINCT FROM s.qualification->>'ID' OR public.connector_digest(p->'QualificationDigest') IS DISTINCT FROM s.qualification_digest OR
  p->>'AccountVersion' IS DISTINCT FROM s.account_version OR p->>'ClusterID' IS DISTINCT FROM o->'Key'->>'ClusterID' OR
  NOT public.capacity_json_text(p->'PoolName',1,63) OR NOT public.capacity_json_text(p->'PolicyName',1,63) THEN RETURN NULL;END IF;
 source_digest:=public.connector_digest(p->'SourceDigest');plan_digest:=public.connector_digest(o->'PlanDigest');pool_digest:=public.connector_digest(p->'PoolDigest');
 IF source_digest IS NULL OR source_digest=decode(repeat('00',32),'hex') OR source_digest IS DISTINCT FROM sha256(source_bytes) OR source_digest IS DISTINCT FROM public.connector_digest(o->'SourceDigest') OR
  plan_digest IS NULL OR plan_digest IS DISTINCT FROM sha256(convert_to('asservat-capacity-enrollment/json-v1','UTF8')||decode('00','hex')||plan_bytes) OR
  pool_digest IS NULL OR pool_digest IS DISTINCT FROM sha256(convert_to('asservat-capacity-pool/json-v1','UTF8')||decode('00','hex')||pool_bytes) THEN RETURN NULL;END IF;
 expected:=public.capacity_compile_pool(s.accepted_snapshot,p->>'PoolName');
 IF expected IS NULL OR pool IS DISTINCT FROM expected OR p->'PoolUID' IS DISTINCT FROM expected->'UID' OR p->'PoolGeneration' IS DISTINCT FROM expected->'Generation' THEN RETURN NULL;END IF;
 -- Rebuild the existing Go selected-source canonical value semantically.
 -- Hash its supplied original bytes, not PostgreSQL's differently spaced JSON
 -- rendering. Whole-object equality rejects hidden/omitted decoded fields.
 SELECT jsonb_agg(entry ORDER BY (entry->'Version'->>'Kind') COLLATE "C",(entry->'Version'->>'UID') COLLATE "C") INTO entries FROM (
  SELECT jsonb_build_object('Version',jsonb_build_object('Kind',v->'Resource'->'Kind','Name',v->'Resource'->'Name','UID',v->'Resource'->'UID','Generation',v->'Resource'->'Generation','Deleting',v->'Resource'->'Deleting','Spec',v->'Resource'->'SpecDigest'),
   'Pool',jsonb_build_object('StorageProfile',v->'StorageProfile','Assurance',v->'Assurance','Budget',v->'Budget')) AS entry
  FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Pools') v WHERE v->'Resource'->>'Name'=p->>'PoolName'
  UNION ALL
  SELECT jsonb_build_object('Version',jsonb_build_object('Kind',v->'Resource'->'Kind','Name',v->'Resource'->'Name','UID',v->'Resource'->'UID','Generation',v->'Resource'->'Generation','Deleting',v->'Resource'->'Deleting','Spec',v->'Resource'->'SpecDigest'),
   'Policy',jsonb_build_object('Pool',v->'Pool','Scope',v->'Scope','Budget',v->'Budget')) AS entry
  FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Policies') v WHERE v->>'Pool'=p->>'PoolName'
 ) selected;
 expected_source:=jsonb_build_object('Format','capacity-selected-source/v1','Cluster',s.accepted_snapshot->'Snapshot'->'ClusterID','ControlUID',s.accepted_snapshot->'Snapshot'->'ControlNamespace'->'UID','Entries',entries);
 IF selected_source IS DISTINCT FROM expected_source THEN RETURN NULL;END IF;
 -- Complete matching is independent of the selected pool. An undecodable
 -- source cannot be assumed irrelevant, while a decoded nonmatching malformed
 -- budget in another pool does not disable this exact target.
 FOR candidate IN SELECT value FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Policies') LOOP
  IF candidate->'Scope'='null'::jsonb OR NOT public.capacity_decoded_scope_valid(candidate->'Scope') THEN RETURN NULL;END IF;
  IF candidate->'Scope'->>'ClusterID'<>p->>'ClusterID' THEN CONTINUE;END IF;
  IF EXISTS(SELECT 1 FROM jsonb_each(candidate->'Scope'->'NamespaceLabels') v WHERE (o->'NamespaceLabels')->v.key IS DISTINCT FROM v.value) THEN CONTINUE;END IF;
  matches:=matches+1;selected_name:=candidate->'Resource'->>'Name';selected_uid:=candidate->'Resource'->>'UID';
 END LOOP;
 IF matches<>1 OR selected_name IS DISTINCT FROM p->>'PolicyName' OR selected_uid IS DISTINCT FROM p->>'PolicyUID' THEN RETURN NULL;END IF;
 SELECT value INTO STRICT policy FROM jsonb_array_elements(expected->'Policies') WHERE value->>'Name'=selected_name;
 IF p->'PolicyUID' IS DISTINCT FROM policy->'UID' OR p->'PolicyGeneration' IS DISTINCT FROM policy->'Generation' OR p->'PolicyDigest' IS DISTINCT FROM policy->'Digest' OR
  p->'Budget' IS DISTINCT FROM policy->'Budget' OR p->'PolicySlots' IS DISTINCT FROM policy->'Slots' THEN RETURN NULL;END IF;
 RETURN p;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_enrollment_plan(capacity_source,jsonb,bytea,bytea,bytea) FROM PUBLIC;

-- +goose StatementBegin
-- Private prefix shared only by the fixed capacity RPCs. In particular, this
-- is not granted to either login as a generic lock/proof API. Every child phase
-- calls it before acquiring hierarchy/child locks and checks its returned
-- ORIGINAL until again after those waits and immediately before returning.
CREATE FUNCTION capacity_lock_observation(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;p public.permission_stream;plan jsonb;guard jsonb;policy jsonb;
 started timestamptz:=clock_timestamp();n timestamptz;until_at timestamptz;guard_digest bytea;keys text[];scope_until timestamptz;
BEGIN
 IF purpose NOT IN('capacity','capacity-capture') OR NOT public.capacity_role_ok(r,purpose) OR jsonb_typeof(o) IS DISTINCT FROM 'object' OR octet_length(o::text)>131072 THEN
  RAISE EXCEPTION 'capacity role or observation unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 -- Exclusive permission-root order also serializes absence/first enrollment
 -- and all supported consumers before any capacity or legacy child row lock.
 SELECT * INTO STRICT p FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 plan:=public.capacity_enrollment_plan(s,o,plan_bytes,pool_bytes,source_bytes);
 n:=clock_timestamp();
 IF plan IS NULL OR NOT public.capacity_json_fields(o->'Recovery',ARRAY['InstallationID','IssuerEpoch','Revision','ObservedAt','FreshUntil']) OR
  NOT public.capacity_json_fields(o->'Recovery'->'Revision',ARRAY['UID','Generation','Digest']) OR
  NOT public.capacity_json_text(o->'ObservedAt',1,64) OR NOT public.capacity_json_text(o->'FreshUntil',1,64) OR
  NOT public.capacity_json_text(o->'PermissionEpoch',36,36) OR NOT public.capacity_json_integer(o->'PermissionSequence',0,1152921504606846975) THEN
  RAISE EXCEPTION 'capacity closed current input unavailable' USING ERRCODE='23514';END IF;
 until_at:=LEAST(started+interval '5 seconds',(o->>'FreshUntil')::timestamptz,(o->'Recovery'->>'FreshUntil')::timestamptz,t.fresh_until,p.fresh_until,p.lease_until,s.fresh_until);
 IF NOT COALESCE(NOT s.suspended AND s.accepted_snapshot IS NOT NULL AND s.observed_at<=n AND n<s.fresh_until AND
  public.capacity_recovery_current(s,t,o->'Recovery',n) AND NOT p.suspended AND p.observed_at<=n AND p.fresh_until<=p.observed_at+interval '5 seconds' AND
  p.epoch=(o->>'PermissionEpoch')::uuid AND p.sequence=(o->>'PermissionSequence')::bigint AND p.trust_digest=public.connector_digest(o->'PermissionTrust') AND
  (o->>'ObservedAt')::timestamptz<=n AND (o->>'FreshUntil')::timestamptz>(o->>'ObservedAt')::timestamptz AND (o->>'FreshUntil')::timestamptz<=(o->>'ObservedAt')::timestamptz+interval '5 seconds' AND
  isfinite((o->>'ObservedAt')::timestamptz) AND isfinite((o->>'FreshUntil')::timestamptz) AND n<until_at,false) THEN
  RAISE EXCEPTION 'capacity current source or root unavailable' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.initial_audit_id AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.epoch AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'capacity root acknowledgement unavailable' USING ERRCODE='23514';END IF;
 -- The namespace guard is independently pinned by protected installation,
 -- not a digest picked by the budget author or read out of CRD status.
 IF jsonb_typeof(s.qualification->'NamespaceGuards') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'capacity namespace pins unavailable' USING ERRCODE='23514';END IF;
 SELECT value INTO STRICT guard FROM jsonb_array_elements(s.qualification->'NamespaceGuards') WHERE value->>'ClusterID'=o->'Key'->>'ClusterID';
 IF NOT public.capacity_json_fields(guard,ARRAY['ClusterID','Digest','Keys']) OR jsonb_typeof(guard->'Keys') IS DISTINCT FROM 'array' OR jsonb_array_length(guard->'Keys') NOT BETWEEN 1 AND 256 THEN
  RAISE EXCEPTION 'capacity namespace guard shape unavailable' USING ERRCODE='23514';END IF;
 guard_digest:=public.connector_digest(guard->'Digest');
 IF guard_digest IS NULL OR guard_digest=decode(repeat('00',32),'hex') OR guard_digest IS DISTINCT FROM public.connector_digest(o->'NamespaceGuardDigest') OR
  EXISTS(SELECT 1 FROM jsonb_array_elements(guard->'Keys') k WHERE NOT public.capacity_json_text(k,1,253)) THEN
  RAISE EXCEPTION 'capacity namespace guard changed' USING ERRCODE='23514';END IF;
 SELECT array_agg(value) INTO keys FROM jsonb_array_elements_text(guard->'Keys');
 IF cardinality(keys)<>(SELECT count(DISTINCT k) FROM unnest(keys) k) OR EXISTS(SELECT 1 FROM jsonb_object_keys(o->'NamespaceLabels') k WHERE NOT (k=ANY(keys))) THEN
  RAISE EXCEPTION 'capacity unprotected namespace labels' USING ERRCODE='23514';END IF;
 FOR policy IN SELECT value FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Policies') LOOP
  IF policy->'Scope'->>'ClusterID'=o->'Key'->>'ClusterID' AND EXISTS(SELECT 1 FROM jsonb_object_keys(policy->'Scope'->'NamespaceLabels') k WHERE NOT (k=ANY(keys))) THEN
   RAISE EXCEPTION 'capacity unprotected source selector' USING ERRCODE='23514';END IF;
 END LOOP;
 -- No human/group material enters the capacity account. This is only the
 -- current accepted collection-scope prerequisite for automatic enrollment.
 SELECT max(COALESCE(b.not_after,'infinity'::timestamptz)) INTO scope_until FROM public.permission_basis b
 WHERE b.stream_id=r AND b.effect='Allow' AND b.seen_sequence=p.sequence AND (b.not_after IS NULL OR b.not_after>n) AND
  b.cluster_id=(o->'Key'->>'ClusterID')::uuid AND b.namespace_uid=o->'Key'->>'NamespaceUID' AND
  (cardinality(b.workload_uids)=0 OR o->'Key'->>'WorkloadUID'=ANY(b.workload_uids)) AND
  EXISTS(SELECT 1 FROM public.permission_assignment a JOIN public.authority_audit proof ON proof.id=a.activation_audit_id
   WHERE a.stream_id=r AND a.basis_key=b.basis_key AND a.role='workload-maintainer' AND a.retired_at IS NULL AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL);
 n:=clock_timestamp();until_at:=LEAST(until_at,scope_until);
 IF scope_until IS NULL OR n>=until_at OR NOT public.capacity_recovery_current(s,t,o->'Recovery',n) THEN
  RAISE EXCEPTION 'capacity workload scope unavailable after locks' USING ERRCODE='23514';END IF;
 RETURN until_at;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_lock_observation(uuid,text,jsonb,bytea,bytea,bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_enrollment_receipt(w public.capacity_workload) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('Format','protected-capacity-enrollment/v1',
  'Key',jsonb_build_object('RootID',w.root_id,'ClusterID',w.cluster_id,'NamespaceUID',w.namespace_uid,'WorkloadUID',w.workload_uid),
  'ID',w.id,'AttemptID',w.attempt_id,'AllocationID',w.allocation_id,'DownloadAllocationID',w.download_allocation_id,
  'SourceDigest',to_jsonb(ARRAY(SELECT get_byte(w.source_digest,k) FROM generate_series(0,31) k)),
  'PlanDigest',to_jsonb(ARRAY(SELECT get_byte(w.plan_digest,k) FROM generate_series(0,31) k)),
  'Revision',w.revision,'InitialObservedAt',w.initial_observed_at,'InitialUntil',w.initial_until,'ReservedAt',w.reserved_at,
  'CaptureBackedAt',w.capture_backed_at,'ReadyAt',w.ready_at,'AccountVersion',w.account_version,
  'AccountDigest',to_jsonb(ARRAY(SELECT get_byte(w.account_digest,k) FROM generate_series(0,31) k)))
$$;

-- Both public RPCs below select a fixed purpose. No login receives this helper
-- or arbitrary table access. An absent row is observed only after the common
-- exclusive root prefix has joined any older reserve/continuation transaction.
CREATE FUNCTION capacity_read_enrollment(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE until_at timestamptz;s public.capacity_source;candidate public.capacity_workload;w public.capacity_workload;pool public.capacity_pool;body jsonb;
BEGIN
 until_at:=public.capacity_lock_observation(r,purpose,o,plan_bytes,pool_bytes,source_bytes);
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 IF public.capacity_managed_root_until(r,clock_timestamp()) IS NULL OR NOT public.capacity_root_general_exact(s) OR NOT public.capacity_root_capture_exact(s) THEN
  RAISE EXCEPTION 'capacity root is not fully backed' USING ERRCODE='23514';END IF;
 until_at:=LEAST(until_at,(s.root_configuration->>'PlannedUntil')::timestamptz);
 SELECT * INTO candidate FROM public.capacity_workload WHERE root_id=r AND cluster_id=(o->'Key'->>'ClusterID')::uuid AND namespace_uid=o->'Key'->>'NamespaceUID' AND workload_uid=o->'Key'->>'WorkloadUID';
 IF NOT FOUND THEN
  IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity absence expired' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Enrollment',NULL,'FreshUntil',until_at);
 END IF;
 -- The preliminary immutable locator is not a receipt. Lock every ancestor in
 -- the same order as reserve/renewal, then reread the exact original workload.
 SELECT * INTO STRICT pool FROM public.capacity_pool WHERE root_id=r AND id=candidate.pool_id FOR UPDATE;
 PERFORM 1 FROM public.capacity_cluster WHERE root_id=r AND pool_id=candidate.pool_id AND cluster_id=candidate.cluster_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'capacity cluster backing missing' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.capacity_namespace WHERE root_id=r AND pool_id=candidate.pool_id AND cluster_id=candidate.cluster_id AND namespace_uid=candidate.namespace_uid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'capacity namespace backing missing' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE id=candidate.id FOR UPDATE;
 body:=convert_from(plan_bytes,'UTF8')::jsonb;
 IF w IS DISTINCT FROM candidate OR w.mutation_xid IS NOT NULL OR w.root_id<>r OR w.source_digest IS DISTINCT FROM public.connector_digest(o->'SourceDigest') OR
  w.plan_digest IS DISTINCT FROM public.connector_digest(o->'PlanDigest') OR w.plan IS DISTINCT FROM body OR w.account_version IS DISTINCT FROM body->>'AccountVersion' OR
  pool.source_uid IS DISTINCT FROM body->>'PoolUID' OR pool.plan IS DISTINCT FROM convert_from(pool_bytes,'UTF8')::jsonb OR pool.plan_digest IS DISTINCT FROM public.connector_digest(body->'PoolDigest') THEN
  RAISE EXCEPTION 'capacity retained enrollment changed' USING ERRCODE='23514';END IF;
 IF NOT public.capacity_workload_general_exact(s,w,w.ready_at IS NOT NULL) OR w.capture_backed_at IS NOT NULL AND NOT public.capacity_workload_capture_exact(s,w) THEN RAISE EXCEPTION 'capacity child backing changed' USING ERRCODE='23514';END IF;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity retained read expired after locks' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt(w),'FreshUntil',until_at);
END $$;

CREATE FUNCTION read_capacity_enrollment(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.capacity_read_enrollment(r,'capacity',o,plan_bytes,pool_bytes,source_bytes)
$$;
CREATE FUNCTION read_capacity_capture_enrollment(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.capacity_read_enrollment(r,'capacity-capture',o,plan_bytes,pool_bytes,source_bytes)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_enrollment_receipt(capacity_workload),capacity_read_enrollment(uuid,text,jsonb,bytea,bytea,bytea),read_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea),read_capacity_capture_enrollment(uuid,jsonb,bytea,bytea,bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_capacity_workload() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE general_role boolean;capture_role boolean;s public.capacity_source;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'capacity account retirement requires qualified settlement' USING ERRCODE='23514';END IF;
 general_role:=public.capacity_role_ok(NEW.root_id,'capacity');capture_role:=public.capacity_role_ok(NEW.root_id,'capacity-capture');
 IF TG_OP='INSERT' THEN
  IF NOT general_role OR NEW.revision<>1 OR NEW.capture_backed_at IS NOT NULL OR NEW.capture_completion IS NOT NULL OR NEW.ready_at IS NOT NULL OR NEW.ready_completion IS NOT NULL OR NEW.mutation_xid IS DISTINCT FROM pg_current_xact_id() THEN
   RAISE EXCEPTION 'capacity first reservation must be incomplete and transaction owned' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=NEW.root_id;
  IF s.root_mutation_xid IS DISTINCT FROM pg_current_xact_id() OR s.root_plan IS NULL OR
   NOT public.capacity_root_configuration_valid(s.root_configuration) OR s.root_configuration->'ReadyAt'='null'::jsonb OR s.root_configuration->'ReconciledAt'<>'null'::jsonb OR
   clock_timestamp()>=(s.root_configuration->>'PlannedUntil')::timestamptz OR
   (SELECT count(*) FROM public.capacity_workload WHERE root_id=NEW.root_id)>=LEAST(16,(s.root_plan->'Totals'->>'Accounts')::bigint) THEN
   RAISE EXCEPTION 'capacity fixed root account backing unavailable' USING ERRCODE='23514';END IF;
 ELSE
  -- Only the three original facts may be set by this first enrollment path.
  -- An eventual explicit managed renewal gets its own exact branch; it cannot
  -- rewrite these identities/dates/debits or silently promote legacy children.
  IF NOT (general_role OR capture_role) OR
   (to_jsonb(NEW)-ARRAY['capture_backed_at','capture_completion','ready_at','ready_completion','mutation_xid']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['capture_backed_at','capture_completion','ready_at','ready_completion','mutation_xid']) OR
   OLD.capture_backed_at IS NOT NULL AND ROW(NEW.capture_backed_at,NEW.capture_completion) IS DISTINCT FROM ROW(OLD.capture_backed_at,OLD.capture_completion) OR
   OLD.ready_at IS NOT NULL AND ROW(NEW.ready_at,NEW.ready_completion) IS DISTINCT FROM ROW(OLD.ready_at,OLD.ready_completion) THEN
   RAISE EXCEPTION 'immutable capacity original enrollment' USING ERRCODE='23514';END IF;
  IF NEW.mutation_xid IS NOT NULL AND NEW.mutation_xid IS DISTINCT FROM pg_current_xact_id() OR OLD.mutation_xid IS NOT NULL AND OLD.mutation_xid IS DISTINCT FROM pg_current_xact_id() THEN
   RAISE EXCEPTION 'capacity mutation belongs to another transaction' USING ERRCODE='23514';END IF;
  IF ROW(NEW.capture_backed_at,NEW.capture_completion) IS DISTINCT FROM ROW(OLD.capture_backed_at,OLD.capture_completion) AND (NOT capture_role OR OLD.capture_backed_at IS NOT NULL OR NEW.capture_backed_at IS NULL OR NEW.mutation_xid IS DISTINCT FROM pg_current_xact_id()) THEN
   RAISE EXCEPTION 'capacity capture fact requires its distinct purpose' USING ERRCODE='23514';END IF;
  IF ROW(NEW.ready_at,NEW.ready_completion) IS DISTINCT FROM ROW(OLD.ready_at,OLD.ready_completion) AND (NOT general_role OR OLD.ready_at IS NOT NULL OR NEW.ready_at IS NULL OR NEW.capture_backed_at IS NULL OR NEW.mutation_xid IS DISTINCT FROM pg_current_xact_id()) THEN
   RAISE EXCEPTION 'capacity ready fact requires all prior backing' USING ERRCODE='23514';END IF;
  IF NEW.mutation_xid IS NULL AND OLD.mutation_xid IS NULL AND NEW IS DISTINCT FROM OLD THEN
   RAISE EXCEPTION 'capacity fact requires transaction marker' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_capacity_workload() FROM PUBLIC;
CREATE TRIGGER capacity_workload_guard BEFORE INSERT OR UPDATE OR DELETE ON capacity_workload FOR EACH ROW EXECUTE FUNCTION guard_capacity_workload();

-- +goose StatementBegin
CREATE FUNCTION capacity_json_uuid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE u uuid;
BEGIN
 IF NOT public.capacity_json_text(v,36,36) OR (v#>>'{}')!~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN RETURN false;END IF;
 u:=(v#>>'{}')::uuid;RETURN u<>'00000000-0000-0000-0000-000000000000'::uuid;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
CREATE FUNCTION capacity_json_digest(v jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(public.connector_digest(v)<>decode(repeat('00',32),'hex'),false)
$$;

-- Closed counterpart of CompileContextProtocolBacking. This computes only the
-- already bounded protocol quantities. No caller receives this helper; reserve
-- must select h from the independently pinned installation qualification and
-- additionally fund the parent/enrollment and ordinary record/refresh history.
CREATE FUNCTION capacity_context_protocol_backing(context_slice jsonb,h jsonb) RETURNS jsonb
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
  'Evidence',jsonb_build_object('Bytes',n*artifact_bytes,'Objects',n*4),
  'CaptureObjects',jsonb_build_object('Bytes',n*131072,'Objects',n*2),
  'VerificationObjects',jsonb_build_object('Bytes',n*131072,'Objects',n),
  'DeletionObjects',jsonb_build_object('Bytes',n*131072,'Objects',n),
  'PreparationObjects',jsonb_build_object('Bytes',n*262144,'Objects',n*2),
  'WindowObjects',jsonb_build_object('Bytes',n*524288,'Objects',n*4),
  'StopObjects',jsonb_build_object('Bytes',n*65536,'Objects',n),
  'ProtocolSystemObjects',jsonb_build_object('Bytes',n*1245184,'Objects',n*11),
  'Sessions',n,'OutputBytes',n*8192,'ReadBytes',n*12582912,'RequestsPerSession',3,'Responses',n*2,'Windows',n*2,
  'NativeRows',n,'NativeKeys',n*2,'NativeTransitionsPerRow',10,'CaptureKeyAttempts',n*13,'StopKeyAttempts',n*12,
  'ArtifactWraps',n*3,'PreparationUnwraps',n*3,'ContentUnwraps',n*6,
  'CaptureBackupBytes',capture_backup::bigint,'CaptureWALBytes',capture_wal::bigint,'NativeBackupBytes',native_backup::bigint,
  'NativeWALBytes',native_wal::bigint,'StopBackupBytes',stop_backup::bigint,'StopWALBytes',stop_wal::bigint);
EXCEPTION WHEN data_exception THEN RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_uuid(jsonb),capacity_json_digest(jsonb),capacity_context_protocol_backing(jsonb,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_root_audit_valid(v jsonb,r uuid,i uuid,l text,layout_name text) RETURNS boolean
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

CREATE FUNCTION capacity_processing_backing_valid(p jsonb,r uuid,i uuid,records bigint,release_policy jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE h jsonb:=p->'History';k text;rows numeric;transitions numeric;
BEGIN
 IF NOT public.capacity_json_fields(p,ARRAY['RootID','InstallationID','PolicyID','BackupIdentity','PolicyDigest','BackupDigest','History','MaxCaptures','MaxRules','MaxRootTransitions','BackupBytes','WALBytes','BackupHorizonSeconds','CleanupSeconds','ValidUntil','RetireBy']) OR
  NOT public.capacity_json_fields(h,ARRAY['Format','ID','Digest','RowBytes','TransitionWALBytes','BackupCopies','WALCopies']) OR
  h->>'Format' IS DISTINCT FROM 'context-processing-history/v1' OR p->>'RootID' IS DISTINCT FROM r::text OR p->>'InstallationID' IS DISTINCT FROM i::text OR
  NOT public.capacity_json_uuid(h->'ID') OR NOT public.capacity_json_digest(h->'Digest') OR
  NOT public.capacity_json_integer(h->'RowBytes',16384,16777216) OR NOT public.capacity_json_integer(h->'TransitionWALBytes',65536,67108864) OR
  NOT public.capacity_json_integer(h->'BackupCopies',1,64) OR NOT public.capacity_json_integer(h->'WALCopies',1,64) OR
  NOT public.capacity_json_integer(p->'MaxCaptures',records,1000000) OR NOT public.capacity_json_integer(p->'MaxRules',1,1024) OR
  NOT public.capacity_json_integer(p->'MaxRootTransitions',8,65536) OR NOT public.capacity_json_integer(p->'BackupBytes',1,9223372036854775807) OR
  NOT public.capacity_json_integer(p->'WALBytes',1,9223372036854775807) OR NOT public.capacity_json_integer(p->'BackupHorizonSeconds',0,316224000) OR
  NOT public.capacity_json_integer(p->'CleanupSeconds',1,86400) OR NOT public.capacity_json_text(p->'ValidUntil',20,40) OR NOT public.capacity_json_text(p->'RetireBy',20,40) OR
  NOT isfinite((p->>'ValidUntil')::timestamptz) OR NOT isfinite((p->>'RetireBy')::timestamptz) OR
  (p->>'ValidUntil')::timestamptz IS DISTINCT FROM (release_policy->>'ValidUntil')::timestamptz OR
  (p->>'RetireBy')::timestamptz IS DISTINCT FROM (p->>'ValidUntil')::timestamptz+make_interval(secs=>(2*(p->>'BackupHorizonSeconds')::bigint+(p->>'CleanupSeconds')::bigint)::double precision) OR
  (release_policy->>'MetadataSlots')::bigint<16*(p->>'MaxRules')::bigint THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['RootID','InstallationID','PolicyID','BackupIdentity'] LOOP IF NOT public.capacity_json_uuid(p->k) THEN RETURN false;END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['PolicyDigest','BackupDigest'] LOOP IF NOT public.capacity_json_digest(p->k) THEN RETURN false;END IF;END LOOP;
 rows:=1+(p->>'MaxRootTransitions')::numeric+(p->>'MaxCaptures')::numeric+17*(p->>'MaxRules')::numeric;
 transitions:=4*(p->>'MaxRootTransitions')::numeric+2*(p->>'MaxCaptures')::numeric+130*(p->>'MaxRules')::numeric;
 RETURN (p->>'BackupBytes')::numeric>=2*rows*(h->>'RowBytes')::numeric*(h->>'BackupCopies')::numeric AND
  (p->>'WALBytes')::numeric>=transitions*(h->>'TransitionWALBytes')::numeric*(h->>'WALCopies')::numeric;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

-- Identical closed quantities to CompileRootBacking. Numeric intermediates
-- reject overflow rather than wrapping into a smaller credit declaration.
-- This pure function cannot accept a backend; only a pinned installed source
-- may supply its input, and every effect recompiles the accepted system pool.
CREATE FUNCTION capacity_compile_root(input_value jsonb,system_pool jsonb) RETURNS jsonb
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
REVOKE ALL ON FUNCTION capacity_root_audit_valid(jsonb,uuid,uuid,text,text),capacity_processing_backing_valid(jsonb,uuid,uuid,bigint,jsonb),capacity_compile_root(jsonb,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_qualification_valid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE g jsonb;b jsonb;k text;key_value jsonb;previous_key text;clusters text[]:='{}';pools text[]:='{}';capacities text[]:='{}';ids text[]:='{}';stores text[]:='{}';system_found boolean:=false;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['ID','Digest','RootBacking','NamespaceGuards','Backends']) OR NOT public.capacity_json_uuid(v->'ID') OR
  NOT public.capacity_json_digest(v->'Digest') OR v->'RootBacking'->'QualificationID' IS DISTINCT FROM v->'ID' OR v->'RootBacking'->'QualificationDigest' IS DISTINCT FROM v->'Digest' OR
  jsonb_typeof(v->'NamespaceGuards') IS DISTINCT FROM 'array' OR jsonb_array_length(v->'NamespaceGuards') NOT BETWEEN 1 AND 16 OR
  jsonb_typeof(v->'Backends') IS DISTINCT FROM 'array' OR jsonb_array_length(v->'Backends') NOT BETWEEN 1 AND 16 THEN RETURN false;END IF;
 FOR g IN SELECT value FROM jsonb_array_elements(v->'NamespaceGuards') LOOP
  IF NOT public.capacity_json_fields(g,ARRAY['ClusterID','Digest','Keys']) OR NOT public.capacity_json_uuid(g->'ClusterID') OR NOT public.capacity_json_digest(g->'Digest') OR
   g->>'ClusterID'=ANY(clusters) OR jsonb_typeof(g->'Keys') IS DISTINCT FROM 'array' OR jsonb_array_length(g->'Keys') NOT BETWEEN 1 AND 256 THEN RETURN false;END IF;
  clusters:=array_append(clusters,g->>'ClusterID');previous_key:=NULL;
  FOR key_value IN SELECT value FROM jsonb_array_elements(g->'Keys') LOOP
   IF NOT public.capacity_json_text(key_value,1,253) OR previous_key IS NOT NULL AND (key_value#>>'{}') COLLATE "C"<=previous_key COLLATE "C" THEN RETURN false;END IF;
   previous_key:=key_value#>>'{}';
  END LOOP;
 END LOOP;
 FOR b IN SELECT value FROM jsonb_array_elements(v->'Backends') LOOP
  IF NOT public.capacity_json_fields(b,ARRAY['Layout','ID','Digest','PoolUID','StorageProfile','CapacityID','PoolID','EvidenceStoreID','AuditStoreID','Usable']) OR
   b->>'Layout' IS DISTINCT FROM 'dedicated-capacity-envelope/v1' OR NOT public.capacity_json_digest(b->'Digest') OR
   NOT public.capacity_json_text(b->'PoolUID',1,64) OR NOT public.capacity_json_text(b->'StorageProfile',1,63) OR NOT public.capacity_amount_valid(b->'Usable') OR
   b->>'PoolUID'=ANY(pools) OR b->>'CapacityID'=ANY(capacities) OR b->>'PoolID'=ANY(ids) OR b->>'EvidenceStoreID'=ANY(stores) THEN RETURN false;END IF;
  FOREACH k IN ARRAY ARRAY['ID','CapacityID','PoolID','EvidenceStoreID','AuditStoreID'] LOOP IF NOT public.capacity_json_uuid(b->k) THEN RETURN false;END IF;END LOOP;
  pools:=array_append(pools,b->>'PoolUID');capacities:=array_append(capacities,b->>'CapacityID');ids:=array_append(ids,b->>'PoolID');stores:=array_append(stores,b->>'EvidenceStoreID');
  IF b->>'PoolUID'=v->'RootBacking'->>'SystemPoolUID' THEN
   IF b->>'AuditStoreID' IS DISTINCT FROM v->'RootBacking'->'Capture'->'Policy'->>'StoreID' THEN RETURN false;END IF;system_found:=true;
  END IF;
 END LOOP;
 RETURN system_found;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

CREATE FUNCTION capacity_backend_for(s public.capacity_source,p jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE b jsonb;
BEGIN
 IF NOT public.capacity_qualification_valid(s.qualification) OR p->>'Format' IS DISTINCT FROM 'capacity-pool/v1' THEN RETURN NULL;END IF;
 SELECT value INTO STRICT b FROM jsonb_array_elements(s.qualification->'Backends') WHERE value->>'PoolUID'=p->>'UID';
 IF b->'StorageProfile' IS DISTINCT FROM p->'StorageProfile' OR NOT public.capacity_amount_valid(p->'Capacity') OR
  (b->'Usable'->>'Bytes')::bigint<(p->'Capacity'->>'Bytes')::bigint OR (b->'Usable'->>'Objects')::bigint<(p->'Capacity'->>'Objects')::bigint THEN RETURN NULL;END IF;
 RETURN b;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;

CREATE FUNCTION capacity_root_configuration_valid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE k text;item jsonb;d timestamptz;last_at timestamptz;first_at timestamptz;first_until timestamptz;revision_at timestamptz;revision_until timestamptz;planned timestamptz;revision bigint;zero jsonb:=to_jsonb(array_fill(0,ARRAY[32]));
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Format','RootID','AttemptID','PlanDigest','Revision','InitialObservedAt','InitialUntil','RevisionObservedAt','RevisionUntil','PlannedUntil','ReservedAt','CaptureBackedAt','ReadyAt','ReconciledAt','PreviousDigest','ReconciledDigest']) OR
  v->>'Format' IS DISTINCT FROM 'protected-capacity-configuration/v1' OR NOT public.capacity_json_uuid(v->'RootID') OR NOT public.capacity_json_uuid(v->'AttemptID') OR
  v->'RootID'=v->'AttemptID' OR NOT public.capacity_json_digest(v->'PlanDigest') OR NOT public.capacity_json_integer(v->'Revision',1,1152921504606846975) THEN RETURN false;END IF;
 -- These two state fields alone use the exact zero digest as an absent
 -- predecessor/disposition sentinel. Positive authority digests still use
 -- connector_digest, which must continue to reject zero.
 FOREACH k IN ARRAY ARRAY['PreviousDigest','ReconciledDigest'] LOOP
  IF jsonb_typeof(v->k) IS DISTINCT FROM 'array' THEN RETURN false;END IF;
  IF jsonb_array_length(v->k)<>32 THEN RETURN false;END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(v->k) LOOP
   IF NOT public.capacity_json_integer(item,0,255) THEN RETURN false;END IF;
  END LOOP;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['InitialObservedAt','InitialUntil','RevisionObservedAt','RevisionUntil','PlannedUntil','ReservedAt'] LOOP
  IF NOT public.capacity_json_text(v->k,20,40) THEN RETURN false;END IF;
  d:=(v->>k)::timestamptz;IF NOT isfinite(d) OR d='0001-01-01 00:00:00+00'::timestamptz THEN RETURN false;END IF;
 END LOOP;
 first_at:=(v->>'InitialObservedAt')::timestamptz;first_until:=(v->>'InitialUntil')::timestamptz;revision_at:=(v->>'RevisionObservedAt')::timestamptz;revision_until:=(v->>'RevisionUntil')::timestamptz;
 planned:=(v->>'PlannedUntil')::timestamptz;last_at:=(v->>'ReservedAt')::timestamptz;revision:=(v->>'Revision')::bigint;
 IF first_until<=first_at OR first_until>first_at+interval '5 seconds' OR revision_at<first_at OR revision_until<=revision_at OR revision_until>revision_at+interval '5 seconds' OR last_at<revision_at OR last_at>=revision_until OR planned<=last_at OR
  revision=1 AND (first_at<>revision_at OR first_until<>revision_until OR (v->'PreviousDigest')<>zero) OR
  revision>1 AND (v->'PreviousDigest')=zero THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['CaptureBackedAt','ReadyAt','ReconciledAt'] LOOP
  IF v->k='null'::jsonb THEN CONTINUE;END IF;
  IF NOT public.capacity_json_text(v->k,20,40) THEN RETURN false;END IF;
  d:=(v->>k)::timestamptz;
  IF NOT isfinite(d) OR d<last_at OR k<>'ReconciledAt' AND d>=planned OR k='ReadyAt' AND v->'CaptureBackedAt'='null'::jsonb THEN RETURN false;END IF;
  last_at:=d;
 END LOOP;
 RETURN (v->'ReconciledAt'='null'::jsonb)=((v->'ReconciledDigest')=zero);
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

-- Compare only qualified timestamp fields by instant. All other closed fields
-- remain exact; Go's UTC Z and PostgreSQL's +00:00 are not different receipts.
CREATE FUNCTION capacity_root_configuration_matches(a jsonb,b jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE dates text[]:=ARRAY['InitialObservedAt','InitialUntil','RevisionObservedAt','RevisionUntil','PlannedUntil','ReservedAt','CaptureBackedAt','ReadyAt','ReconciledAt'];k text;
BEGIN
 IF NOT public.capacity_root_configuration_valid(a) OR NOT public.capacity_root_configuration_valid(b) OR (a-dates) IS DISTINCT FROM (b-dates) THEN RETURN false;END IF;
 FOREACH k IN ARRAY dates LOOP
  IF (a->>k)::timestamptz IS DISTINCT FROM (b->>k)::timestamptz THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

CREATE FUNCTION capacity_root_transition_valid(old_row public.capacity_source,new_row public.capacity_source) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE old_value jsonb:=old_row.root_configuration;v jsonb:=new_row.root_configuration;k text;pool_name text;compiled jsonb;pool_plan jsonb;n timestamptz:=clock_timestamp();general boolean;capture boolean;opening boolean;
BEGIN
 general:=public.capacity_role_ok(old_row.root_id,'capacity');capture:=public.capacity_role_ok(old_row.root_id,'capacity-capture');
 IF NOT(general OR capture) OR new_row.suspended OR new_row.observed_at IS NULL OR new_row.observed_at>n OR n>=new_row.fresh_until OR
  NOT public.capacity_root_configuration_valid(v) OR v->>'RootID' IS DISTINCT FROM new_row.root_id::text OR
  new_row.root_plan IS DISTINCT FROM convert_from(new_row.root_plan_bytes,'UTF8')::jsonb OR
  new_row.root_plan_digest IS DISTINCT FROM sha256(convert_to('asservat-capacity-root/json-v1','UTF8')||decode('00','hex')||new_row.root_plan_bytes) OR
  public.connector_digest(v->'PlanDigest') IS DISTINCT FROM new_row.root_plan_digest OR
  new_row.root_plan->'Input' IS DISTINCT FROM new_row.qualification->'RootBacking' OR
  new_row.root_plan->'Input'->>'AccountVersion' IS DISTINCT FROM new_row.account_version OR
  new_row.root_plan->'Input'->>'RootID' IS DISTINCT FROM new_row.root_id::text OR
  new_row.root_plan->'Input'->>'InstallationID' IS DISTINCT FROM new_row.installation_id::text OR
  new_row.configuration_spent>(new_row.root_plan->'Totals'->>'ConfigurationTransitions')::bigint THEN RETURN false;END IF;
 -- A root-only refresh cannot pick a different system pool or treat malformed
 -- unrelated pools as this root's backing. The matching pool compiles fully.
 SELECT p->'Resource'->>'Name' INTO STRICT pool_name FROM jsonb_array_elements(new_row.accepted_snapshot->'Snapshot'->'Pools') p WHERE p->'Resource'->>'UID'=new_row.root_plan->'Input'->>'SystemPoolUID';
 pool_plan:=public.capacity_compile_pool(new_row.accepted_snapshot,pool_name);
 compiled:=public.capacity_compile_root(new_row.qualification->'RootBacking',pool_plan);
 IF compiled IS NULL OR compiled IS DISTINCT FROM new_row.root_plan OR public.capacity_backend_for(new_row,pool_plan) IS NULL THEN RETURN false;END IF;
 IF old_row.root_plan IS NOT NULL AND ROW(new_row.root_plan,new_row.root_plan_bytes,new_row.root_plan_digest) IS DISTINCT FROM ROW(old_row.root_plan,old_row.root_plan_bytes,old_row.root_plan_digest) THEN RETURN false;END IF;
 IF new_row.root_mutation_xid IS NULL THEN
  -- Closing the private transaction marker changes no receipt or debit.
  RETURN old_row.root_mutation_xid=pg_current_xact_id() AND v IS NOT DISTINCT FROM old_value AND new_row.configuration_spent=old_row.configuration_spent;
 END IF;
 IF new_row.root_mutation_xid<>pg_current_xact_id() OR old_row.root_mutation_xid IS NOT NULL AND old_row.root_mutation_xid<>pg_current_xact_id() THEN RETURN false;END IF;
 opening:=old_row.root_mutation_xid IS NULL;
 IF new_row.configuration_spent<>old_row.configuration_spent+(CASE WHEN opening THEN 1 ELSE 0 END) THEN RETURN false;END IF;
 IF old_value IS NULL THEN
  RETURN general AND (v->>'Revision')::bigint=1 AND v->'CaptureBackedAt'='null'::jsonb AND v->'ReadyAt'='null'::jsonb AND v->'ReconciledAt'='null'::jsonb AND
   (v->>'RevisionObservedAt')::timestamptz<=n AND n<(v->>'RevisionUntil')::timestamptz AND (v->>'ReservedAt')::timestamptz<=n AND
   (v->>'PlannedUntil')::timestamptz=(v->>'RevisionObservedAt')::timestamptz+make_interval(secs=>(new_row.root_plan->'Input'->>'AdmissionSeconds')::double precision);
 END IF;
 IF (v-ARRAY['CaptureBackedAt','ReadyAt','ReconciledAt','ReconciledDigest']) IS DISTINCT FROM (old_value-ARRAY['CaptureBackedAt','ReadyAt','ReconciledAt','ReconciledDigest']) THEN
  -- Revision selection additionally requires an exact all-child disposition
  -- from the previous revision. No external effect or missing receipt can be
  -- promoted by expiry or an unchanged GET. The private effect owns the proof.
  RETURN general AND old_value->'ReconciledAt'<>'null'::jsonb AND (v->>'Revision')::bigint=(old_value->>'Revision')::bigint+1 AND
   (v-ARRAY['Revision','RevisionObservedAt','RevisionUntil','PlannedUntil','ReservedAt','CaptureBackedAt','ReadyAt','ReconciledAt','PreviousDigest','ReconciledDigest']) IS NOT DISTINCT FROM
   (old_value-ARRAY['Revision','RevisionObservedAt','RevisionUntil','PlannedUntil','ReservedAt','CaptureBackedAt','ReadyAt','ReconciledAt','PreviousDigest','ReconciledDigest']) AND
   v->'PreviousDigest'=old_value->'ReconciledDigest' AND v->'CaptureBackedAt'='null'::jsonb AND v->'ReadyAt'='null'::jsonb AND v->'ReconciledAt'='null'::jsonb AND
   (v->>'RevisionObservedAt')::timestamptz<=(old_value->>'ReconciledAt')::timestamptz AND (old_value->>'ReconciledAt')::timestamptz<=(v->>'ReservedAt')::timestamptz AND (v->>'RevisionObservedAt')::timestamptz<=n AND n<(v->>'RevisionUntil')::timestamptz AND (v->>'ReservedAt')::timestamptz<=n AND
   (v->>'PlannedUntil')::timestamptz>(old_value->>'PlannedUntil')::timestamptz AND
   (v->>'PlannedUntil')::timestamptz=(v->>'RevisionObservedAt')::timestamptz+make_interval(secs=>(new_row.root_plan->'Input'->>'AdmissionSeconds')::double precision);
 END IF;
 IF old_value->'ReconciledAt'<>'null'::jsonb AND v IS DISTINCT FROM old_value THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['CaptureBackedAt','ReadyAt','ReconciledAt'] LOOP
  IF old_value->k<>'null'::jsonb AND v->k IS DISTINCT FROM old_value->k THEN RETURN false;END IF;
  IF v->k IS DISTINCT FROM old_value->k AND ((v->>k)::timestamptz>n OR k='CaptureBackedAt' AND NOT capture OR k<>'CaptureBackedAt' AND NOT general) THEN RETURN false;END IF;
 END LOOP;
 IF old_value->'ReconciledAt'<>'null'::jsonb AND v->'ReconciledDigest' IS DISTINCT FROM old_value->'ReconciledDigest' THEN RETURN false;END IF;
 RETURN true;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE FUNCTION require_capacity_root_marker_closed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.capacity_source'::regclass OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE') THEN RAISE EXCEPTION 'invalid capacity root marker source' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_source WHERE root_id=NEW.root_id AND root_mutation_xid IS NOT NULL) THEN RAISE EXCEPTION 'capacity root configuration remains open' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_qualification_valid(jsonb),capacity_backend_for(capacity_source,jsonb),capacity_root_configuration_valid(jsonb),capacity_root_configuration_matches(jsonb,jsonb),capacity_root_transition_valid(capacity_source,capacity_source),require_capacity_root_marker_closed() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER capacity_root_closed AFTER INSERT OR UPDATE ON capacity_source DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_capacity_root_marker_closed();

-- +goose StatementBegin
-- One fence for all managed new-admission readers. It says nothing about
-- existing session authority: those consume their original frozen snapshots
-- and current restrictive/recovery checks, even during configuration renewal.
-- No source means legacy behavior; a managed source never adopts an unknown
-- legacy allocation merely because it belongs to the same permission root.
CREATE FUNCTION capacity_managed_root_until(r uuid,n timestamptz) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;p public.permission_stream;c jsonb;until_at timestamptz;
BEGIN
 IF n IS NULL OR NOT isfinite(n) THEN RETURN NULL;END IF;
 SELECT * INTO s FROM public.capacity_source WHERE root_id=r;
 IF NOT FOUND THEN RETURN 'infinity'::timestamptz;END IF;
 c:=s.root_configuration;
 IF s.suspended OR s.observed_at IS NULL OR s.observed_at>n OR s.fresh_until IS NULL OR n>=s.fresh_until OR
  s.root_mutation_xid IS NOT NULL OR NOT public.capacity_root_configuration_valid(c) OR c->'ReadyAt'='null'::jsonb OR
  c->'ReconciledAt'<>'null'::jsonb OR (c->>'ReadyAt')::timestamptz>n OR n>=(c->>'PlannedUntil')::timestamptz THEN RETURN NULL;END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id;
 SELECT * INTO STRICT p FROM public.permission_stream WHERE id=r;
 IF t.suspended OR t.recovery_blocked OR t.observed_at IS NULL OR t.observed_at>n OR n>=t.fresh_until OR
  p.suspended OR p.observed_at IS NULL OR p.observed_at>n OR p.fresh_until IS NULL OR p.lease_until IS NULL OR n>=LEAST(p.fresh_until,p.lease_until) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.initial_audit_id AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.epoch AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) THEN RETURN NULL;END IF;
 IF NOT public.capacity_root_general_exact(s) OR NOT public.capacity_root_capture_exact(s) OR NOT public.capacity_retained_inventory_valid(s) THEN RETURN NULL;END IF;
 until_at:=LEAST(s.fresh_until,(c->>'PlannedUntil')::timestamptz,t.fresh_until,p.fresh_until,p.lease_until);
 IF clock_timestamp()>=until_at THEN RETURN NULL;END IF;
 RETURN until_at;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;

CREATE FUNCTION capacity_managed_admission_until(r uuid,allocation uuid,kind text,n timestamptz) RETURNS timestamptz
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
 IF compiled IS NULL OR compiled IS DISTINCT FROM p.plan OR p.plan_digest IS DISTINCT FROM public.connector_digest(w.plan->'PoolDigest') OR
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
CREATE FUNCTION capacity_managed_admission(r uuid,allocation uuid,kind text,n timestamptz) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(n<public.capacity_managed_admission_until(r,allocation,kind,n),false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_managed_root_until(uuid,timestamptz),capacity_managed_admission_until(uuid,uuid,text,timestamptz),capacity_managed_admission(uuid,uuid,text,timestamptz) FROM PUBLIC;

-- Fixed configuration read only. The separately provisioned audit-profile
-- credential receives EXECUTE on this function, no table or mutation grants.
-- These public backing facts grant neither operation replay nor capture rights.
-- All locks remain held by the caller's transaction through its bounded commit.
-- +goose StatementBegin
CREATE FUNCTION capacity_audit_reader_pin_valid(s public.capacity_source) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p pg_catalog.pg_roles;v jsonb:=s.audit_reader_provenance;comment_value jsonb;k text;name_value text;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['Format','InstallationID','InitialClaimID','OwnerConfigurationUID','RootUID','SetupID','Purpose','LayoutDigest','OperationID','DatabaseOID','PostmasterAt','ClaimedAt','Until']) OR
  v->>'Format' IS DISTINCT FROM 'asservat-public-runtime-role/v1' OR v->>'InstallationID' IS DISTINCT FROM s.installation_id::text OR v->>'Purpose' IS DISTINCT FROM 'capacity-profile-read' OR
  NOT public.capacity_json_text(v->'LayoutDigest',64,64) OR v->>'LayoutDigest' !~ '^[0-9a-f]{64}$' OR v->>'LayoutDigest'=repeat('0',64) OR
  NOT public.capacity_json_integer(v->'DatabaseOID',1,4294967295) OR (v->>'DatabaseOID')::oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR
  NOT public.incarnation_current((v->>'PostmasterAt')::timestamptz) OR NOT isfinite((v->>'ClaimedAt')::timestamptz) OR NOT isfinite((v->>'Until')::timestamptz) OR
  (v->>'Until')::timestamptz<=(v->>'ClaimedAt')::timestamptz OR (v->>'Until')::timestamptz>(v->>'ClaimedAt')::timestamptz+interval '5 seconds' THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['InitialClaimID','OwnerConfigurationUID','RootUID','SetupID','OperationID'] LOOP
  IF NOT public.capacity_json_uuid(v->k) THEN RETURN false;END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['PostmasterAt','ClaimedAt','Until'] LOOP
  IF NOT public.capacity_json_text(v->k,20,40) OR NOT isfinite((v->>k)::timestamptz) THEN RETURN false;END IF;
 END LOOP;
 name_value:='as_'||replace(s.installation_id::text,'-','')||'_pub_34';
 SELECT * INTO STRICT p FROM pg_roles WHERE oid=s.audit_reader_role AND rolname=name_value;
 IF NOT p.rolcanlogin OR p.rolinherit OR p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls OR p.rolconnlimit<>5 OR p.rolvaliduntil IS NOT NULL OR
  EXISTS(SELECT 1 FROM pg_auth_members WHERE member=p.oid OR roleid=p.oid) THEN RETURN false;END IF;
 comment_value:=shobj_description(p.oid,'pg_authid')::jsonb;
 RETURN comment_value IS NOT NULL AND comment_value=v;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE FUNCTION read_capacity_audit_profiles(r uuid,i uuid,q uuid,qd bytea,av text,observed timestamptz,original_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;p public.permission_stream;a public.operation_audit_pool;backing public.capacity_pool;
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
  p.suspended OR p.observed_at IS NULL OR p.observed_at>n OR p.fresh_until IS NULL OR p.lease_until IS NULL OR p.fresh_until>p.observed_at+interval '5 seconds' OR
  s.suspended OR s.observed_at IS NULL OR s.observed_at>n OR s.fresh_until IS NULL OR s.accepted_revision<1 OR s.accepted_snapshot IS NULL OR
  s.root_plan IS NULL OR s.root_mutation_xid IS NOT NULL OR NOT COALESCE(public.capacity_root_configuration_valid(c),false) OR c->'ReadyAt'='null'::jsonb OR c->'ReconciledAt'<>'null'::jsonb OR
  (c->>'ReadyAt')::timestamptz>n OR public.connector_digest(c->'PlanDigest') IS DISTINCT FROM s.root_plan_digest OR
  s.root_plan->'Input' IS DISTINCT FROM s.qualification->'RootBacking' OR n>=until_at OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.initial_audit_id AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit proof WHERE proof.id=p.epoch AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'current capacity audit profile unavailable' USING ERRCODE='23514';END IF;
 SELECT x->'Resource'->>'Name' INTO STRICT pool_name FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Pools') x
  WHERE x->'Resource'->>'UID'=s.root_plan->'Input'->>'SystemPoolUID';
 pool_plan:=public.capacity_compile_pool(s.accepted_snapshot,pool_name);
 SELECT * INTO STRICT backing FROM public.capacity_pool WHERE root_id=r AND source_uid=s.root_plan->'Input'->>'SystemPoolUID' FOR SHARE;
 IF pool_plan IS NULL OR backing.plan IS DISTINCT FROM pool_plan OR public.capacity_backend_for(s,pool_plan) IS NULL OR
  public.capacity_compile_root(s.qualification->'RootBacking',pool_plan) IS DISTINCT FROM s.root_plan THEN
  RAISE EXCEPTION 'capacity audit source backing mismatch' USING ERRCODE='23514';END IF;
 result:=jsonb_build_object('Format','accepted-capacity-audit-profiles/v1','RootID',r,'InstallationID',i,'QualificationID',q,'AccountVersion',av,
  'QualificationDigest',to_jsonb(ARRAY(SELECT get_byte(qd,k) FROM generate_series(0,31) k)),
  'PlanDigest',to_jsonb(ARRAY(SELECT get_byte(s.root_plan_digest,k) FROM generate_series(0,31) k)),
  'ConfigurationRevision',(c->>'Revision')::bigint,'SourceRevision',s.accepted_revision,'ObservedAt',observed);
 -- Stable sorted lock order, also used by the root producer.
 FOREACH lane_name IN ARRAY ARRAY['normal','resolution'] LOOP
  field_name:=CASE lane_name WHEN 'normal' THEN 'Normal' ELSE 'Resolution' END;
  v:=s.root_plan->'Input'->field_name;
  IF NOT public.capacity_root_audit_valid(v,r,i,lane_name,'operation-audit-history/v3') THEN
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
REVOKE ALL ON FUNCTION read_capacity_audit_profiles(uuid,uuid,uuid,bytea,text,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION capacity_audit_reader_pin_valid(capacity_source) FROM PUBLIC;
REVOKE ALL ON capacity_source,capacity_pool,capacity_cluster,capacity_namespace,capacity_workload FROM PUBLIC;

-- Remaining source acceptance, hierarchy/enrollment effects and the managed
-- child guards are added below before this isolated migration can be packaged.
-- No destructive down: original obligations and unknown results are retained.


-- Root configuration uses the same two fixed credentials as enrollment. This
-- observation contains no human identity and does not initialize processing.
-- +goose StatementBegin
CREATE FUNCTION capacity_lock_root_observation(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;p public.permission_stream;plan_value jsonb;pool_value jsonb;processing jsonb;recovery jsonb;n timestamptz;until_at timestamptz;pool_name text;
BEGIN
 IF NOT public.capacity_role_ok(r,purpose) OR purpose NOT IN ('capacity','capacity-capture') OR
  NOT public.capacity_json_fields(o,ARRAY['RootID','InstallationID','QualificationID','QualificationDigest','PlanDigest','SourceDigest','SourceRevision','Recovery','Processing','ObservedAt','FreshUntil']) OR
  octet_length(o::text)>16384 OR plan_bytes IS NULL OR pool_bytes IS NULL OR octet_length(plan_bytes) NOT BETWEEN 2 AND 65536 OR octet_length(pool_bytes) NOT BETWEEN 2 AND 65536 THEN
  RAISE EXCEPTION 'capacity root observation unavailable' USING ERRCODE='23514';END IF;
 plan_value:=convert_from(plan_bytes,'UTF8')::jsonb;pool_value:=convert_from(pool_bytes,'UTF8')::jsonb;
 processing:=o->'Processing';recovery:=o->'Recovery';
 IF NOT public.capacity_json_fields(processing,ARRAY['Revision','ProtectionDigest','ObservedAt','FreshUntil']) OR
  NOT public.capacity_json_fields(processing->'Revision',ARRAY['UID','Generation','Digest']) OR NOT public.capacity_json_integer(processing->'Revision'->'Generation',1,2147483647) OR
  NOT public.capacity_json_digest(processing->'Revision'->'Digest') OR NOT public.capacity_json_digest(processing->'ProtectionDigest') OR
  public.connector_digest(o->'PlanDigest') IS DISTINCT FROM sha256(convert_to('asservat-capacity-root/json-v1','UTF8')||decode('00','hex')||plan_bytes) THEN
  RAISE EXCEPTION 'capacity root protected input unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 SELECT * INTO STRICT p FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 until_at:=LEAST((o->>'FreshUntil')::timestamptz,(recovery->>'FreshUntil')::timestamptz,(processing->>'FreshUntil')::timestamptz,s.fresh_until,t.fresh_until,p.fresh_until,p.lease_until);
 IF NOT public.capacity_role_ok(r,purpose) OR NOT public.capacity_recovery_current(s,t,recovery,n) OR
  o->>'RootID' IS DISTINCT FROM r::text OR o->>'InstallationID' IS DISTINCT FROM s.installation_id::text OR o->>'QualificationID' IS DISTINCT FROM s.qualification->>'ID' OR
  public.connector_digest(o->'QualificationDigest') IS DISTINCT FROM s.qualification_digest OR public.connector_digest(o->'SourceDigest') IS DISTINCT FROM s.accepted_digest OR
  NOT public.capacity_json_integer(o->'SourceRevision',1,1152921504606846975) OR (o->>'SourceRevision')::bigint<>s.accepted_revision OR
  plan_value->'Input' IS DISTINCT FROM s.qualification->'RootBacking' OR s.suspended OR s.observed_at IS NULL OR s.observed_at>n OR s.fresh_until IS NULL OR
  p.suspended OR p.observed_at IS NULL OR p.observed_at>n OR p.fresh_until IS NULL OR p.lease_until IS NULL OR p.fresh_until>p.observed_at+interval '5 seconds' OR
  NOT COALESCE((o->>'ObservedAt')::timestamptz<=n AND (o->>'FreshUntil')::timestamptz>(o->>'ObservedAt')::timestamptz AND (o->>'FreshUntil')::timestamptz<=(o->>'ObservedAt')::timestamptz+interval '5 seconds' AND n<until_at,false) OR
  processing->'Revision'->>'UID' IS DISTINCT FROM plan_value->'Input'->>'ProcessingSourceUID' OR processing->'ProtectionDigest' IS DISTINCT FROM plan_value->'Input'->'ProcessingProtectionDigest' OR
  NOT COALESCE((processing->>'ObservedAt')::timestamptz<=n AND (processing->>'FreshUntil')::timestamptz>(processing->>'ObservedAt')::timestamptz AND (processing->>'FreshUntil')::timestamptz<=(processing->>'ObservedAt')::timestamptz+interval '5 seconds',false) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.initial_audit_id AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) OR
  NOT EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.epoch AND a.stream_id=r AND a.acknowledged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'capacity root current protection unavailable' USING ERRCODE='23514';END IF;
 SELECT x->'Resource'->>'Name' INTO STRICT pool_name FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Pools') x WHERE x->'Resource'->>'UID'=plan_value->'Input'->>'SystemPoolUID';
 IF public.capacity_compile_pool(s.accepted_snapshot,pool_name) IS DISTINCT FROM pool_value OR public.capacity_compile_root(s.qualification->'RootBacking',pool_value) IS DISTINCT FROM plan_value OR public.capacity_backend_for(s,pool_value) IS NULL OR
  s.root_plan IS NOT NULL AND ROW(s.root_plan,s.root_plan_bytes,s.root_plan_digest) IS DISTINCT FROM ROW(plan_value,plan_bytes,public.connector_digest(o->'PlanDigest')) OR clock_timestamp()>=until_at THEN
  RAISE EXCEPTION 'capacity root immutable plan mismatch' USING ERRCODE='23514';END IF;
 RETURN until_at;
END $$;

CREATE FUNCTION read_capacity_root(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE until_at timestamptz;s public.capacity_source;
BEGIN
 until_at:=public.capacity_lock_root_observation(r,'capacity',o,plan_bytes,pool_bytes);
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 IF s.root_mutation_xid IS NOT NULL OR s.root_configuration IS NOT NULL AND (NOT public.capacity_root_configuration_valid(s.root_configuration) OR
  NOT public.capacity_root_general_exact(s) OR s.root_configuration->'CaptureBackedAt'<>'null'::jsonb AND NOT public.capacity_root_capture_exact(s)) OR clock_timestamp()>=until_at THEN
  RAISE EXCEPTION 'capacity root disposition unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Configuration',s.root_configuration,'FreshUntil',until_at);
END $$;

-- Create the system/evidence envelope once. Its system debit is root-wide;
-- workload enrollments consume retained logical slots, never resize this plan.
CREATE FUNCTION reserve_capacity_root(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,attempt uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE until_at timestamptz;s public.capacity_source;plan_value jsonb;pool_value jsonb;input_value jsonb;totals jsonb;backend jsonb;c jsonb;lane_value jsonb;cluster_value jsonb;stop_value jsonb;work jsonb;
 pool_id uuid;n timestamptz;planned timestamptz;lane_name text;field_name text;records bigint;system_bytes bigint;system_objects bigint;zero_digest jsonb:=to_jsonb(array_fill(0,ARRAY[32]));
BEGIN
 until_at:=public.capacity_lock_root_observation(r,'capacity',o,plan_bytes,pool_bytes);
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 IF s.root_configuration IS NOT NULL THEN
  IF s.root_mutation_xid IS NOT NULL OR NOT public.capacity_root_general_exact(s) OR s.root_configuration->'CaptureBackedAt'<>'null'::jsonb AND NOT public.capacity_root_capture_exact(s) OR clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity root replay unavailable' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Configuration',s.root_configuration,'FreshUntil',until_at);
 END IF;
 plan_value:=convert_from(plan_bytes,'UTF8')::jsonb;pool_value:=convert_from(pool_bytes,'UTF8')::jsonb;input_value:=plan_value->'Input';totals:=plan_value->'Totals';
 backend:=public.capacity_backend_for(s,pool_value);pool_id:=(backend->>'PoolID')::uuid;
 PERFORM 1 FROM public.custody_pool WHERE id=pool_id FOR UPDATE;
 -- An existing configured or unconfigured legacy row is not silently adopted.
 IF FOUND OR EXISTS(SELECT 1 FROM public.custody_pool WHERE store_id=(backend->>'EvidenceStoreID')::uuid) OR
  EXISTS(SELECT 1 FROM public.capacity_pool WHERE root_id=r OR backend_capacity_id=(backend->>'CapacityID')::uuid) OR
  EXISTS(SELECT 1 FROM public.context_control_pool WHERE root_id=r) OR EXISTS(SELECT 1 FROM public.processing_root WHERE root_id=r) OR
  EXISTS(SELECT 1 FROM public.download_stop_pool WHERE root_id=r) OR EXISTS(SELECT 1 FROM public.operation_audit_pool WHERE root_id=r AND lane IN ('normal','resolution','processing','capture')) THEN
  RAISE EXCEPTION 'capacity root cannot adopt existing backing' USING ERRCODE='23514';END IF;
 -- A first configuration receives dates from this original protected
 -- observation, not from wall clock on replay or an expired packaging date.
 n:=clock_timestamp();planned:=(o->>'ObservedAt')::timestamptz+make_interval(secs=>(input_value->>'AdmissionSeconds')::double precision);records:=(totals->>'Records')::bigint;
 IF attempt IS NULL OR attempt=r OR n>=until_at OR n>=planned OR
  NOT EXISTS(SELECT 1 FROM public.capture_audit_root ar WHERE ar.root_id=r AND ar.installation_id=s.installation_id AND ar.source_role=s.capture_role) THEN
  RAISE EXCEPTION 'capacity first original interval unavailable' USING ERRCODE='23514';END IF;
 c:=jsonb_build_object('Format','protected-capacity-configuration/v1','RootID',r,'AttemptID',attempt,'PlanDigest',o->'PlanDigest','Revision',1,
  'InitialObservedAt',o->'ObservedAt','InitialUntil',until_at,'RevisionObservedAt',o->'ObservedAt','RevisionUntil',until_at,'PlannedUntil',planned,'ReservedAt',n,
  'CaptureBackedAt',NULL,'ReadyAt',NULL,'ReconciledAt',NULL,'PreviousDigest',zero_digest,'ReconciledDigest',zero_digest);
 UPDATE public.capacity_source SET root_plan=plan_value,root_plan_bytes=plan_bytes,root_plan_digest=public.connector_digest(o->'PlanDigest'),root_configuration=c,
  configuration_spent=configuration_spent+1,root_mutation_xid=pg_current_xact_id() WHERE root_id=r;
 INSERT INTO public.custody_pool(id,store_id,revision,valid_until,paused,byte_limit,object_limit)
 VALUES(pool_id,(backend->>'EvidenceStoreID')::uuid,1,planned,false,(pool_value->'Protected'->>'Bytes')::bigint+(pool_value->'Burst'->>'Bytes')::bigint,(pool_value->'Protected'->>'Objects')::bigint+(pool_value->'Burst'->>'Objects')::bigint);
 system_bytes:=(totals->'SystemObjects'->>'Bytes')::bigint;system_objects:=(totals->'SystemObjects'->>'Objects')::bigint;
 INSERT INTO public.capacity_pool(root_id,id,backend_capacity_id,backend_qualification_id,backend_qualification_digest,source_uid,source_name,source_generation,source_digest,revision,plan,plan_digest,
  protected_bytes,protected_objects,shared_bytes,shared_objects,system_bytes,system_objects,account_limit,namespace_limit,backed_system_bytes,backed_system_objects)
 VALUES(r,pool_id,(backend->>'CapacityID')::uuid,(backend->>'ID')::uuid,public.connector_digest(backend->'Digest'),pool_value->>'UID',pool_value->>'Name',(pool_value->>'Generation')::bigint,public.connector_digest(pool_value->'Digest'),1,pool_value,
  sha256(convert_to('asservat-capacity-pool/json-v1','UTF8')||decode('00','hex')||pool_bytes),(pool_value->'Protected'->>'Bytes')::bigint,(pool_value->'Protected'->>'Objects')::bigint,(pool_value->'Burst'->>'Bytes')::bigint,(pool_value->'Burst'->>'Objects')::bigint,
  (pool_value->'System'->>'Bytes')::bigint,(pool_value->'System'->>'Objects')::bigint,(pool_value->>'AccountLimit')::bigint,(pool_value->>'NamespaceLimit')::bigint,system_bytes,system_objects);
 FOR cluster_value IN SELECT x FROM jsonb_array_elements(pool_value->'Clusters') x ORDER BY x->>'ClusterID' LOOP
  INSERT INTO public.capacity_cluster(root_id,pool_id,cluster_id,protected_bytes,protected_objects,byte_limit,object_limit,account_limit,namespace_limit)
  VALUES(r,pool_id,(cluster_value->>'ClusterID')::uuid,(cluster_value->>'ProtectedBytes')::bigint,(cluster_value->>'ProtectedObjects')::bigint,(cluster_value->>'ByteLimit')::bigint,(cluster_value->>'ObjectLimit')::bigint,(cluster_value->>'AccountLimit')::bigint,(cluster_value->>'AccountLimit')::bigint);
 END LOOP;
 INSERT INTO public.context_control_pool(root_id,configured,paused,revision,valid_until,full_limit,replay_limit) VALUES(r,true,false,1,planned,records,records);
 FOREACH lane_name IN ARRAY ARRAY['normal','processing','resolution'] LOOP
  field_name:=CASE lane_name WHEN 'normal' THEN 'Normal' WHEN 'processing' THEN 'Processing' ELSE 'Resolution' END;lane_value:=input_value->field_name;
  INSERT INTO public.operation_audit_pool(root_id,lane,account_version,revision,paused,valid_until,account_limit,records_per_account,retained_seconds)
  VALUES(r,lane_name,s.account_version,1,false,planned,(lane_value->>'Accounts')::bigint,(lane_value->>'RecordsPerAccount')::bigint,(lane_value->>'RetainedSeconds')::bigint);
 END LOOP;
 INSERT INTO public.processing_root(root_id,installation_id,issuer_epoch,epoch,source_uid,protection_digest,backing,release_policy,backing_revision,valid_until,retire_by,max_captures,max_rules,max_root_transitions)
 VALUES(r,s.installation_id,(o->'Recovery'->>'IssuerEpoch')::uuid,(input_value->>'ProcessingEpoch')::uuid,(input_value->>'ProcessingSourceUID')::uuid,public.connector_digest(input_value->'ProcessingProtectionDigest'),
  (input_value->'ProcessingState')||jsonb_build_object('ValidUntil',planned,'RetireBy',planned+make_interval(secs=>(2*(input_value->'ProcessingState'->>'BackupHorizonSeconds')::bigint+(input_value->'ProcessingState'->>'CleanupSeconds')::bigint)::double precision)),
  (input_value->'Processing'->'Policy')||jsonb_build_object('ValidUntil',public.capacity_json_timestamp(planned)),1,planned,planned+make_interval(secs=>(2*(input_value->'ProcessingState'->>'BackupHorizonSeconds')::bigint+(input_value->'ProcessingState'->>'CleanupSeconds')::bigint)::double precision),(input_value->'ProcessingState'->>'MaxCaptures')::bigint,(input_value->'ProcessingState'->>'MaxRules')::bigint,(input_value->'ProcessingState'->>'MaxRootTransitions')::bigint);
 stop_value:=input_value->'ContextHistory'->'Stop';
 -- The per-workload helper caps at 512 sessions. Root multiplication uses the
 -- exact already compiled account count, rather than truncating the root count.
 work:=public.capacity_context_protocol_backing(jsonb_build_object('Bytes',1544192*(input_value->>'RecordsPerAccount')::bigint,'Objects',4*(input_value->>'RecordsPerAccount')::bigint),input_value->'ContextHistory');
 INSERT INTO public.download_stop_pool(root_id,installation_id,store_id,policy_id,backup_profile_id,policy_digest,backup_profile_digest,slots,cipher_bytes,key_attempts,backup_bytes,wal_bytes,retained_seconds,backup_horizon_seconds,valid_until,lifecycle_policy)
 VALUES(r,s.installation_id,(stop_value->>'StoreID')::uuid,(stop_value->>'PolicyID')::uuid,(stop_value->>'BackupProfileID')::uuid,public.connector_digest(stop_value->'PolicyDigest'),public.connector_digest(stop_value->'BackupProfileDigest'),records,records*65536,
  (work->>'StopKeyAttempts')::bigint*(input_value->>'Accounts')::bigint,(work->>'StopBackupBytes')::bigint*(input_value->>'Accounts')::bigint,(work->>'StopWALBytes')::bigint*(input_value->>'Accounts')::bigint,
  (input_value->>'StopRetainedSeconds')::bigint,(stop_value->>'BackupHorizonSeconds')::bigint,planned,stop_value);
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity root reservation expired after effects' USING ERRCODE='23514';END IF;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity root reservation expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Configuration',c,'FreshUntil',until_at);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_lock_root_observation(uuid,text,jsonb,bytea,bytea),read_capacity_root(uuid,jsonb,bytea,bytea),reserve_capacity_root(uuid,jsonb,bytea,bytea,uuid) FROM PUBLIC;


-- +goose StatementBegin
CREATE FUNCTION capacity_root_general_exact(s public.capacity_source) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c jsonb:=s.root_configuration;v jsonb:=s.root_plan->'Input';totals jsonb:=s.root_plan->'Totals';p public.capacity_pool;custody public.custody_pool;control public.context_control_pool;processing public.processing_root;stop_pool public.download_stop_pool;a public.operation_audit_pool;
 lane_name text;field_name text;lane_value jsonb;policy jsonb;backing jsonb;stop_value jsonb;work jsonb;planned timestamptz;revision bigint;records bigint;pool_name text;current_pool jsonb;backend jsonb;
BEGIN
 IF NOT public.capacity_root_configuration_valid(c) OR public.connector_digest(c->'PlanDigest') IS DISTINCT FROM s.root_plan_digest THEN RETURN false;END IF;
 planned:=(c->>'PlannedUntil')::timestamptz;revision:=(c->>'Revision')::bigint;records:=(totals->>'Records')::bigint;
 SELECT x->'Resource'->>'Name' INTO STRICT pool_name FROM jsonb_array_elements(s.accepted_snapshot->'Snapshot'->'Pools') x WHERE x->'Resource'->>'UID'=v->>'SystemPoolUID';
 current_pool:=public.capacity_compile_pool(s.accepted_snapshot,pool_name);backend:=public.capacity_backend_for(s,current_pool);
 SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=s.root_id AND source_uid=v->>'SystemPoolUID';
 SELECT * INTO STRICT custody FROM public.custody_pool WHERE id=p.id;
 IF current_pool IS NULL OR backend IS NULL OR p.plan IS DISTINCT FROM current_pool OR p.id<>(backend->>'PoolID')::uuid OR p.backend_capacity_id<>(backend->>'CapacityID')::uuid OR
  p.backend_qualification_id<>(backend->>'ID')::uuid OR p.backend_qualification_digest IS DISTINCT FROM public.connector_digest(backend->'Digest') OR
  p.backed_system_bytes<>(totals->'SystemObjects'->>'Bytes')::bigint OR p.backed_system_objects<>(totals->'SystemObjects'->>'Objects')::bigint OR
  custody.store_id<>(backend->>'EvidenceStoreID')::uuid OR custody.paused OR custody.valid_until<>planned OR custody.revision<>revision OR
  custody.byte_limit<>(current_pool->'Protected'->>'Bytes')::bigint+(current_pool->'Burst'->>'Bytes')::bigint OR custody.object_limit<>(current_pool->'Protected'->>'Objects')::bigint+(current_pool->'Burst'->>'Objects')::bigint THEN RETURN false;END IF;
 SELECT * INTO STRICT control FROM public.context_control_pool WHERE root_id=s.root_id;
 IF NOT control.configured OR control.paused OR control.revision<>revision OR control.valid_until<>planned OR control.full_limit<>records OR control.replay_limit<>records THEN RETURN false;END IF;
 FOREACH lane_name IN ARRAY ARRAY['normal','processing','resolution'] LOOP
  field_name:=CASE lane_name WHEN 'normal' THEN 'Normal' WHEN 'processing' THEN 'Processing' ELSE 'Resolution' END;lane_value:=v->field_name;
  SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=s.root_id AND lane=lane_name;
  policy:=lane_value->'Policy';
  IF a.account_version<>s.account_version OR a.revision<>revision OR a.paused OR a.valid_until<>planned OR a.account_limit<>(lane_value->>'Accounts')::bigint OR a.records_per_account<>(lane_value->>'RecordsPerAccount')::bigint OR a.retained_seconds<>(lane_value->>'RetainedSeconds')::bigint OR
   a.history_profile IS NOT NULL AND a.history_profile IS DISTINCT FROM (policy-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']) THEN RETURN false;END IF;
 END LOOP;
 backing:=(v->'ProcessingState')||jsonb_build_object('ValidUntil',planned,'RetireBy',planned+make_interval(secs=>(2*(v->'ProcessingState'->>'BackupHorizonSeconds')::bigint+(v->'ProcessingState'->>'CleanupSeconds')::bigint)::double precision));
 policy:=(v->'Processing'->'Policy')||jsonb_build_object('BackingRevision',revision,'ValidUntil',public.capacity_json_timestamp(planned));
 SELECT * INTO STRICT processing FROM public.processing_root WHERE root_id=s.root_id;
 IF processing.installation_id<>s.installation_id OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust t WHERE t.installation_id=s.installation_id AND t.issuer_epoch=processing.issuer_epoch AND NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until) OR processing.epoch<>(v->>'ProcessingEpoch')::uuid OR processing.source_uid<>(v->>'ProcessingSourceUID')::uuid OR processing.protection_digest IS DISTINCT FROM public.connector_digest(v->'ProcessingProtectionDigest') OR
  (processing.backing-ARRAY['ValidUntil','RetireBy']) IS DISTINCT FROM (backing-ARRAY['ValidUntil','RetireBy']) OR
  (processing.backing->>'ValidUntil')::timestamptz<>planned OR (processing.backing->>'RetireBy')::timestamptz<>(backing->>'RetireBy')::timestamptz OR
  (processing.release_policy-ARRAY['BackingRevision','ValidUntil']) IS DISTINCT FROM (policy-ARRAY['BackingRevision','ValidUntil']) OR
  (processing.release_policy->>'BackingRevision')::bigint<>revision OR (processing.release_policy->>'ValidUntil')::timestamptz<>planned OR
  processing.backing_revision<>revision OR processing.valid_until<>planned OR processing.retire_by<>(backing->>'RetireBy')::timestamptz OR
  processing.max_captures<>(backing->>'MaxCaptures')::bigint OR processing.max_rules<>(backing->>'MaxRules')::bigint OR processing.max_root_transitions<>(backing->>'MaxRootTransitions')::bigint THEN RETURN false;END IF;
 stop_value:=v->'ContextHistory'->'Stop';
 work:=public.capacity_context_protocol_backing(jsonb_build_object('Bytes',1544192*(v->>'RecordsPerAccount')::bigint,'Objects',4*(v->>'RecordsPerAccount')::bigint),v->'ContextHistory');
 SELECT * INTO STRICT stop_pool FROM public.download_stop_pool WHERE root_id=s.root_id;
 RETURN stop_pool.installation_id=s.installation_id AND stop_pool.store_id=(stop_value->>'StoreID')::uuid AND stop_pool.policy_id=(stop_value->>'PolicyID')::uuid AND stop_pool.backup_profile_id=(stop_value->>'BackupProfileID')::uuid AND
  stop_pool.policy_digest=public.connector_digest(stop_value->'PolicyDigest') AND stop_pool.backup_profile_digest=public.connector_digest(stop_value->'BackupProfileDigest') AND stop_pool.lifecycle_policy=stop_value AND
  stop_pool.slots=records AND stop_pool.cipher_bytes=records*65536 AND stop_pool.key_attempts=(work->>'StopKeyAttempts')::bigint*(v->>'Accounts')::bigint AND stop_pool.backup_bytes=(work->>'StopBackupBytes')::bigint*(v->>'Accounts')::bigint AND stop_pool.wal_bytes=(work->>'StopWALBytes')::bigint*(v->>'Accounts')::bigint AND
  stop_pool.retained_seconds=(v->>'StopRetainedSeconds')::bigint AND stop_pool.backup_horizon_seconds=(stop_value->>'BackupHorizonSeconds')::bigint AND stop_pool.valid_until=planned AND stop_pool.revision=revision;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE FUNCTION capacity_root_capture_exact(s public.capacity_source) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c jsonb:=s.root_configuration;v jsonb:=s.root_plan->'Input'->'Capture';a public.operation_audit_pool;r public.capture_audit_root;
BEGIN
 SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=s.root_id AND lane='capture';
 SELECT * INTO STRICT r FROM public.capture_audit_root WHERE root_id=s.root_id AND installation_id=s.installation_id AND source_role=s.capture_role;
 RETURN NOT r.paused AND r.valid_until=(c->>'PlannedUntil')::timestamptz AND a.account_version=s.account_version AND a.revision=(c->>'Revision')::bigint AND NOT a.paused AND a.valid_until=(c->>'PlannedUntil')::timestamptz AND
  a.account_limit=(v->>'Accounts')::bigint AND a.records_per_account=(v->>'RecordsPerAccount')::bigint AND a.retained_seconds=(v->>'RetainedSeconds')::bigint AND
  (a.history_profile IS NULL OR a.history_profile=((v->'Policy')-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']));
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;



CREATE FUNCTION publish_capacity_root(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,expected jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE until_at timestamptz;s public.capacity_source;c jsonb;n timestamptz;
BEGIN
 until_at:=public.capacity_lock_root_observation(r,'capacity',o,plan_bytes,pool_bytes);
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;c:=s.root_configuration;
 IF c IS NULL OR NOT public.capacity_root_configuration_matches(c,expected) OR NOT public.capacity_root_configuration_valid(c) OR s.root_mutation_xid IS NOT NULL OR c->'ReconciledAt'<>'null'::jsonb OR c->'CaptureBackedAt'='null'::jsonb THEN
  RAISE EXCEPTION 'capacity root completion state unavailable' USING ERRCODE='23514';END IF;
 -- Root admission remains closed until all purpose-separated rows agree.
 PERFORM 1 FROM public.custody_pool WHERE id IN(SELECT id FROM public.capacity_pool WHERE root_id=r) ORDER BY id FOR SHARE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane IN('capture','normal','processing','resolution') ORDER BY lane FOR SHARE;
 n:=clock_timestamp();until_at:=LEAST(until_at,(c->>'PlannedUntil')::timestamptz);
 IF n>=until_at OR NOT public.capacity_root_general_exact(s) OR NOT public.capacity_root_capture_exact(s) OR NOT public.capacity_retained_inventory_valid(s) THEN RAISE EXCEPTION 'capacity root backing incomplete' USING ERRCODE='23514';END IF;
 IF c->'ReadyAt'<>'null'::jsonb THEN RETURN jsonb_build_object('Configuration',c,'FreshUntil',until_at);END IF;
 UPDATE public.capacity_source SET root_mutation_xid=pg_current_xact_id(),configuration_spent=configuration_spent+1 WHERE root_id=r;
 c:=jsonb_set(c,'{ReadyAt}',to_jsonb(clock_timestamp()));
 UPDATE public.capacity_source SET root_configuration=c WHERE root_id=r;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity root completion expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Configuration',c,'FreshUntil',until_at);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_root_general_exact(capacity_source),capacity_root_capture_exact(capacity_source),publish_capacity_root(uuid,jsonb,bytea,bytea,jsonb) FROM PUBLIC;

-- +goose StatementBegin
-- Existing effect triggers still own their original locks, spend and dates.
-- These final new-row checks additionally prevent every supported legacy or
-- current path from admitting a managed child while configuration is partial.
-- Historical updates and deletion/settlement do not pass through this gate.
CREATE FUNCTION require_capacity_new_admission() RETURNS trigger
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
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_capacity_new_admission() FROM PUBLIC;
CREATE TRIGGER zzz_capacity_new_admission AFTER INSERT ON custody_attempt FOR EACH ROW EXECUTE FUNCTION require_capacity_new_admission();
CREATE TRIGGER zzz_capacity_new_admission AFTER INSERT ON context_capture FOR EACH ROW EXECUTE FUNCTION require_capacity_new_admission();
CREATE TRIGGER zzz_capacity_new_admission AFTER INSERT ON artifact_download FOR EACH ROW EXECUTE FUNCTION require_capacity_new_admission();
CREATE TRIGGER zzz_capacity_new_admission AFTER INSERT ON operation_audit FOR EACH ROW EXECUTE FUNCTION require_capacity_new_admission();

-- +goose StatementBegin
-- Called only after the recovery / exclusive permission / source prefix.
-- A new pool is the exact dedicated backend already accepted by the installer;
-- an occupied legacy name/store/ID is never adopted into managed capacity.
CREATE FUNCTION capacity_ensure_pool(s public.capacity_source,pool_value jsonb,pool_bytes bytea) RETURNS public.capacity_pool
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE backend jsonb;p public.capacity_pool;c public.custody_pool;cluster_value jsonb;pool_id uuid;planned timestamptz;revision bigint;
BEGIN
 IF NOT public.capacity_role_ok(s.root_id,'capacity') OR public.capacity_compile_pool(s.accepted_snapshot,pool_value->>'Name') IS DISTINCT FROM pool_value THEN RAISE EXCEPTION 'capacity pool source unavailable' USING ERRCODE='23514';END IF;
 backend:=public.capacity_backend_for(s,pool_value);pool_id:=(backend->>'PoolID')::uuid;
 planned:=(s.root_configuration->>'PlannedUntil')::timestamptz;revision:=(s.root_configuration->>'Revision')::bigint;
 IF backend IS NULL OR clock_timestamp()>=planned THEN RAISE EXCEPTION 'capacity backend unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO c FROM public.custody_pool WHERE id=pool_id FOR UPDATE;
 IF FOUND THEN
  SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=s.root_id AND id=pool_id FOR UPDATE;
  IF p.plan IS DISTINCT FROM pool_value OR p.plan_digest IS DISTINCT FROM sha256(convert_to('asservat-capacity-pool/json-v1','UTF8')||decode('00','hex')||pool_bytes) OR
   p.source_uid IS DISTINCT FROM pool_value->>'UID' OR p.backend_capacity_id<>(backend->>'CapacityID')::uuid OR p.backend_qualification_id<>(backend->>'ID')::uuid OR
   p.backend_qualification_digest IS DISTINCT FROM public.connector_digest(backend->'Digest') OR c.store_id<>(backend->>'EvidenceStoreID')::uuid OR c.paused OR c.revision<>revision OR c.valid_until<>planned OR
   c.byte_limit<>(pool_value->'Protected'->>'Bytes')::bigint+(pool_value->'Burst'->>'Bytes')::bigint OR c.object_limit<>(pool_value->'Protected'->>'Objects')::bigint+(pool_value->'Burst'->>'Objects')::bigint THEN
   RAISE EXCEPTION 'capacity original pool changed' USING ERRCODE='23514';END IF;
  RETURN p;
 END IF;
 IF EXISTS(SELECT 1 FROM public.custody_pool WHERE store_id=(backend->>'EvidenceStoreID')::uuid) OR EXISTS(SELECT 1 FROM public.capacity_pool WHERE backend_capacity_id=(backend->>'CapacityID')::uuid) THEN
  RAISE EXCEPTION 'capacity dedicated backend already occupied' USING ERRCODE='23514';END IF;
 INSERT INTO public.custody_pool(id,store_id,revision,valid_until,paused,byte_limit,object_limit)
 VALUES(pool_id,(backend->>'EvidenceStoreID')::uuid,revision,planned,false,(pool_value->'Protected'->>'Bytes')::bigint+(pool_value->'Burst'->>'Bytes')::bigint,(pool_value->'Protected'->>'Objects')::bigint+(pool_value->'Burst'->>'Objects')::bigint);
 INSERT INTO public.capacity_pool(root_id,id,backend_capacity_id,backend_qualification_id,backend_qualification_digest,source_uid,source_name,source_generation,source_digest,revision,plan,plan_digest,
  protected_bytes,protected_objects,shared_bytes,shared_objects,system_bytes,system_objects,account_limit,namespace_limit)
 VALUES(s.root_id,pool_id,(backend->>'CapacityID')::uuid,(backend->>'ID')::uuid,public.connector_digest(backend->'Digest'),pool_value->>'UID',pool_value->>'Name',(pool_value->>'Generation')::bigint,public.connector_digest(pool_value->'Digest'),revision,pool_value,
  sha256(convert_to('asservat-capacity-pool/json-v1','UTF8')||decode('00','hex')||pool_bytes),(pool_value->'Protected'->>'Bytes')::bigint,(pool_value->'Protected'->>'Objects')::bigint,(pool_value->'Burst'->>'Bytes')::bigint,(pool_value->'Burst'->>'Objects')::bigint,
  (pool_value->'System'->>'Bytes')::bigint,(pool_value->'System'->>'Objects')::bigint,(pool_value->>'AccountLimit')::bigint,(pool_value->>'NamespaceLimit')::bigint) RETURNING * INTO p;
 FOR cluster_value IN SELECT x FROM jsonb_array_elements(pool_value->'Clusters') x ORDER BY x->>'ClusterID' LOOP
  INSERT INTO public.capacity_cluster(root_id,pool_id,cluster_id,protected_bytes,protected_objects,byte_limit,object_limit,account_limit,namespace_limit)
  VALUES(s.root_id,pool_id,(cluster_value->>'ClusterID')::uuid,(cluster_value->>'ProtectedBytes')::bigint,(cluster_value->>'ProtectedObjects')::bigint,(cluster_value->>'ByteLimit')::bigint,(cluster_value->>'ObjectLimit')::bigint,(cluster_value->>'AccountLimit')::bigint,(cluster_value->>'AccountLimit')::bigint);
 END LOOP;
 RETURN p;
END $$;

CREATE FUNCTION capacity_native_plan(s public.capacity_source,allocation uuid,work jsonb) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('AllocationID',allocation,'RootID',s.root_id,'PolicyID',s.qualification->'ID','PolicyDigest',s.qualification->'Digest',
  'Rows',work->'NativeRows','Keys',work->'NativeKeys','TransitionsPerRow',work->'NativeTransitionsPerRow','BackupBytes',work->'NativeBackupBytes','WALBytes',work->'NativeWALBytes',
  'BackupHorizonSeconds',s.root_plan#>'{Input,Capture,Policy,BackupHorizonSeconds}','CleanupSeconds',s.root_plan#>'{Input,Capture,Policy,CleanupBudgetSeconds}',
  'ValidUntil',s.root_configuration->'PlannedUntil',
  'RetireBy',(s.root_configuration->>'PlannedUntil')::timestamptz+make_interval(secs=>(2*(s.root_plan#>>'{Input,Capture,Policy,BackupHorizonSeconds}')::bigint+(s.root_plan#>>'{Input,Capture,Policy,CleanupBudgetSeconds}')::bigint)::double precision),
  'History',s.root_plan#>'{Input,ContextHistory,Native}')
$$;

CREATE FUNCTION reserve_capacity_enrollment(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,account_id uuid,attempt uuid,allocation uuid,download_allocation uuid,account_digest bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE until_at timestamptz;s public.capacity_source;p public.capacity_pool;c public.capacity_cluster;ns public.capacity_namespace;w public.capacity_workload;
 body jsonb;pool_value jsonb;budget jsonb;work jsonb;native jsonb;planned timestamptz;n timestamptz;cluster uuid;namespace text;workload text;new_namespace boolean;
 request_bytes bigint;request_objects bigint;records bigint;
BEGIN
 until_at:=public.capacity_lock_observation(r,'capacity',o,plan_bytes,pool_bytes,source_bytes);
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 body:=convert_from(plan_bytes,'UTF8')::jsonb;pool_value:=convert_from(pool_bytes,'UTF8')::jsonb;budget:=body->'Budget';
 cluster:=(o->'Key'->>'ClusterID')::uuid;namespace:=o->'Key'->>'NamespaceUID';workload:=o->'Key'->>'WorkloadUID';
 -- The current root observation cannot overwrite the original enrollment.
 -- Every later invocation starts with this exact absence/winner check.
 SELECT * INTO w FROM public.capacity_workload WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace AND workload_uid=workload;
 IF FOUND THEN RETURN public.capacity_read_enrollment(r,'capacity',o,plan_bytes,pool_bytes,source_bytes);END IF;
 IF account_id IS NULL OR attempt IS NULL OR allocation IS NULL OR download_allocation IS NULL OR
  (SELECT count(DISTINCT x) FROM unnest(ARRAY[account_id,attempt,allocation,download_allocation]) x)<>4 OR octet_length(account_digest)<>32 OR account_digest=decode(repeat('00',32),'hex') OR
  s.root_mutation_xid IS NOT NULL OR public.capacity_managed_root_until(r,clock_timestamp()) IS NULL OR NOT public.capacity_root_general_exact(s) OR NOT public.capacity_root_capture_exact(s) THEN
  RAISE EXCEPTION 'capacity original root backing unavailable' USING ERRCODE='23514';END IF;
 planned:=(s.root_configuration->>'PlannedUntil')::timestamptz;until_at:=LEAST(until_at,planned);
 work:=public.capacity_context_protocol_backing(budget->'Context',s.root_plan#>'{Input,ContextHistory}');records:=(work->>'Records')::bigint;
 IF work IS NULL OR records>(s.root_plan->'Input'->>'RecordsPerAccount')::bigint OR
  (SELECT count(*) FROM public.capacity_workload WHERE root_id=r)>=LEAST(16,(s.root_plan->'Input'->>'Accounts')::bigint) OR
  (SELECT count(*) FROM public.capacity_workload WHERE root_id=r AND policy_uid=body->>'PolicyUID')>=(body->>'PolicySlots')::bigint THEN
  RAISE EXCEPTION 'capacity qualified account or protocol ceiling reached' USING ERRCODE='23514';END IF;
 -- This marker spends one prepaid configuration transaction. It is private
 -- to this transaction and must close before commit, including rollback tests.
 UPDATE public.capacity_source SET configuration_spent=configuration_spent+1,root_mutation_xid=pg_current_xact_id() WHERE root_id=r;
 p:=public.capacity_ensure_pool(s,pool_value,pool_bytes);
 SELECT * INTO STRICT c FROM public.capacity_cluster WHERE root_id=r AND pool_id=p.id AND cluster_id=cluster FOR UPDATE;
 SELECT * INTO ns FROM public.capacity_namespace WHERE root_id=r AND pool_id=p.id AND cluster_id=cluster AND namespace_uid=namespace FOR UPDATE;
 new_namespace:=NOT FOUND;
 request_bytes:=(budget->'Protected'->>'Bytes')::bigint;request_objects:=(budget->'Protected'->>'Objects')::bigint;
 IF p.accounts>=p.account_limit OR c.accounts>=c.account_limit OR p.protected_bytes-p.backed_bytes<request_bytes OR p.protected_objects-p.backed_objects<request_objects OR
  c.protected_bytes-c.backed_bytes<request_bytes OR c.protected_objects-c.backed_objects<request_objects OR
  new_namespace AND (p.namespaces>=p.namespace_limit OR c.namespaces>=c.namespace_limit) THEN RAISE EXCEPTION 'capacity protected hierarchy exhausted' USING ERRCODE='23514';END IF;
 IF new_namespace THEN
  INSERT INTO public.capacity_namespace(root_id,pool_id,cluster_id,namespace_uid,byte_limit,object_limit,account_limit)
  VALUES(r,p.id,cluster,namespace,(budget->'NamespaceMaximum'->>'Bytes')::bigint,(budget->'NamespaceMaximum'->>'Objects')::bigint,(budget->>'NamespaceAccounts')::bigint) RETURNING * INTO ns;
 END IF;
 IF ns.byte_limit<>(budget->'NamespaceMaximum'->>'Bytes')::bigint OR ns.object_limit<>(budget->'NamespaceMaximum'->>'Objects')::bigint OR ns.account_limit<>(budget->>'NamespaceAccounts')::bigint OR
  ns.accounts>=ns.account_limit OR ns.byte_limit-ns.backed_bytes<request_bytes OR ns.object_limit-ns.backed_objects<request_objects THEN RAISE EXCEPTION 'capacity namespace commitment unavailable' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM public.context_storage_binding WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace AND workload_uid=workload) OR
  EXISTS(SELECT 1 FROM public.download_allocation WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace AND workload_uid=workload) THEN
  RAISE EXCEPTION 'capacity cannot adopt legacy workload backing' USING ERRCODE='23514';END IF;
 UPDATE public.capacity_pool SET accounts=accounts+1,namespaces=namespaces+CASE WHEN new_namespace THEN 1 ELSE 0 END,backed_bytes=backed_bytes+request_bytes,backed_objects=backed_objects+request_objects WHERE root_id=r AND id=p.id;
 UPDATE public.capacity_cluster SET accounts=accounts+1,namespaces=namespaces+CASE WHEN new_namespace THEN 1 ELSE 0 END,backed_bytes=backed_bytes+request_bytes,backed_objects=backed_objects+request_objects WHERE root_id=r AND pool_id=p.id AND cluster_id=cluster;
 UPDATE public.capacity_namespace SET accounts=accounts+1,backed_bytes=backed_bytes+request_bytes,backed_objects=backed_objects+request_objects WHERE root_id=r AND pool_id=p.id AND cluster_id=cluster AND namespace_uid=namespace;
 UPDATE public.custody_pool SET allocated_bytes=allocated_bytes+(work->'Evidence'->>'Bytes')::bigint,allocated_objects=allocated_objects+(work->'Evidence'->>'Objects')::bigint WHERE id=p.id;
 INSERT INTO public.custody_allocation(id,pool_id,scope_id,service_class,revision,valid_until,paused,byte_limit,object_limit)
 VALUES(allocation,p.id,account_id,'context',1,planned,true,(work->'Evidence'->>'Bytes')::bigint,(work->'Evidence'->>'Objects')::bigint);
 -- SQL37 requires the truthful physical binding before control backing. It is
 -- unusable while paused/incomplete; no temporary unpause or fake binding.
 INSERT INTO public.context_storage_binding(root_id,cluster_id,namespace_uid,workload_uid,allocation_id,source_uid,source_generation,source_digest,observed_at,fresh_until)
 VALUES(r,cluster,namespace,workload,allocation,body->>'PolicyUID',(body->>'PolicyGeneration')::bigint,public.connector_digest(body->'PolicyDigest'),(o->>'ObservedAt')::timestamptz,until_at);
 INSERT INTO public.context_control_account(root_id,allocation_id,configured,revision,valid_until,full_limit,replay_limit,paused)
 VALUES(r,allocation,true,1,planned,records,records,true);
 INSERT INTO public.download_allocation(id,root_id,cluster_id,namespace_uid,workload_uid,output_limit,read_limit,session_limit,valid_until)
 VALUES(download_allocation,r,cluster,namespace,workload,(work->>'OutputBytes')::bigint,(work->>'ReadBytes')::bigint,(work->>'Sessions')::bigint,planned);
 INSERT INTO public.download_control_allocation(id,root_id,audit_store_id,response_limit,window_limit,audit_byte_limit,valid_until,audit_write_until)
 VALUES(download_allocation,r,(s.root_plan#>>'{Input,Capture,Policy,StoreID}')::uuid,(work->>'Responses')::bigint,(work->>'Windows')::bigint,(work->'WindowObjects'->>'Bytes')::bigint,planned,planned+interval '30 seconds');
 native:=public.capacity_native_plan(s,download_allocation,work);
 INSERT INTO public.download_native_backing(allocation_id,root_id,policy_json,rows_limit,keys_limit,transitions_per_row,backup_horizon_seconds,cleanup_seconds,valid_until,retire_by,residual_until)
 VALUES(download_allocation,r,native,(work->>'NativeRows')::bigint,(work->>'NativeKeys')::bigint,(work->>'NativeTransitionsPerRow')::bigint,(native->>'BackupHorizonSeconds')::bigint,(native->>'CleanupSeconds')::bigint,planned,(native->>'RetireBy')::timestamptz,(native->>'RetireBy')::timestamptz);
 INSERT INTO public.download_stop_backing(allocation_id,root_id,slots) VALUES(download_allocation,r,(work->>'Sessions')::bigint);
 n:=clock_timestamp();IF n>=until_at THEN RAISE EXCEPTION 'capacity reservation expired after child locks' USING ERRCODE='23514';END IF;
 INSERT INTO public.capacity_workload(root_id,pool_id,cluster_id,namespace_uid,workload_uid,id,attempt_id,allocation_id,download_allocation_id,revision,policy_uid,source_digest,plan,plan_digest,account_version,account_digest,
  protected_bytes,protected_objects,system_bytes,system_objects,initial_observed_at,initial_until,reserved_at,mutation_xid)
 VALUES(r,p.id,cluster,namespace,workload,account_id,attempt,allocation,download_allocation,1,body->>'PolicyUID',public.connector_digest(o->'SourceDigest'),body,public.connector_digest(o->'PlanDigest'),s.account_version,account_digest,
  request_bytes,request_objects,(work->'ProtocolSystemObjects'->>'Bytes')::bigint,(work->'ProtocolSystemObjects'->>'Objects')::bigint,(o->>'ObservedAt')::timestamptz,until_at,n,pg_current_xact_id());
 UPDATE public.capacity_workload SET mutation_xid=NULL WHERE id=account_id RETURNING * INTO w;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity reservation expired at completion' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt(w),'FreshUntil',until_at);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_ensure_pool(capacity_source,jsonb,bytea),capacity_native_plan(capacity_source,uuid,jsonb),reserve_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea,uuid,uuid,uuid,uuid,bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_enrollment_matches(w public.capacity_workload,expected jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=public.capacity_enrollment_receipt(w);k text;fields text[]:=ARRAY['InitialObservedAt','InitialUntil','ReservedAt','CaptureBackedAt','ReadyAt'];
BEGIN
 IF expected IS NULL OR octet_length(expected::text)>8192 OR NOT public.capacity_json_fields(expected,ARRAY['Format','Key','ID','AttemptID','AllocationID','DownloadAllocationID','SourceDigest','PlanDigest','Revision','InitialObservedAt','InitialUntil','ReservedAt','CaptureBackedAt','ReadyAt','AccountVersion','AccountDigest']) OR (v-fields) IS DISTINCT FROM (expected-fields) THEN RETURN false;END IF;
 FOREACH k IN ARRAY fields LOOP
  IF (v->k='null'::jsonb) IS DISTINCT FROM (expected->k='null'::jsonb) THEN RETURN false;END IF;
  IF v->k<>'null'::jsonb AND (NOT public.capacity_json_text(expected->k,20,40) OR (v->>k)::timestamptz IS DISTINCT FROM (expected->>k)::timestamptz) THEN RETURN false;END IF;
 END LOOP;RETURN true;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

-- Fixed non-capture children. Counters may grow under their own spend guards;
-- configuration identity, cutoffs and guarantees may not be silently replaced.
CREATE FUNCTION capacity_workload_general_exact(s public.capacity_source,w public.capacity_workload,ready boolean) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE work jsonb;native jsonb;planned timestamptz;a public.custody_allocation;b public.context_storage_binding;control public.context_control_account;
 d public.download_allocation;dc public.download_control_allocation;dn public.download_native_backing;stop_backing public.download_stop_backing;
BEGIN
 work:=public.capacity_context_protocol_backing(w.plan->'Budget'->'Context',s.root_plan#>'{Input,ContextHistory}');planned:=(s.root_configuration->>'PlannedUntil')::timestamptz;
 IF work IS NULL OR w.protected_bytes<>(w.plan#>>'{Budget,Protected,Bytes}')::bigint OR w.protected_objects<>(w.plan#>>'{Budget,Protected,Objects}')::bigint OR
  w.system_bytes<>(work#>>'{ProtocolSystemObjects,Bytes}')::bigint OR w.system_objects<>(work#>>'{ProtocolSystemObjects,Objects}')::bigint THEN RETURN false;END IF;
 SELECT * INTO STRICT a FROM public.custody_allocation WHERE id=w.allocation_id;
 SELECT * INTO STRICT b FROM public.context_storage_binding WHERE root_id=s.root_id AND allocation_id=w.allocation_id;
 SELECT * INTO STRICT control FROM public.context_control_account WHERE root_id=s.root_id AND allocation_id=w.allocation_id;
 IF a.pool_id<>w.pool_id OR a.scope_id<>w.id OR a.service_class<>'context' OR a.paused=ready OR a.valid_until<>planned OR
  a.byte_limit<>(work#>>'{Evidence,Bytes}')::bigint OR a.object_limit<>(work#>>'{Evidence,Objects}')::bigint OR
  b.cluster_id<>w.cluster_id OR b.namespace_uid<>w.namespace_uid OR b.workload_uid<>w.workload_uid OR b.source_uid<>w.plan->>'PolicyUID' OR
  b.source_generation<>(w.plan->>'PolicyGeneration')::bigint OR b.source_digest IS DISTINCT FROM public.connector_digest(w.plan->'PolicyDigest') OR
  NOT control.configured OR control.paused=ready OR control.valid_until<>planned OR control.full_limit<>(work->>'Records')::bigint OR control.replay_limit<>(work->>'ReplayRecords')::bigint THEN RETURN false;END IF;
 SELECT * INTO STRICT d FROM public.download_allocation WHERE root_id=s.root_id AND id=w.download_allocation_id;
 SELECT * INTO STRICT dc FROM public.download_control_allocation WHERE root_id=s.root_id AND id=w.download_allocation_id;
 SELECT * INTO STRICT dn FROM public.download_native_backing WHERE root_id=s.root_id AND allocation_id=w.download_allocation_id;
 SELECT * INTO STRICT stop_backing FROM public.download_stop_backing WHERE root_id=s.root_id AND allocation_id=w.download_allocation_id;
 native:=public.capacity_native_plan(s,w.download_allocation_id,work);
 RETURN d.cluster_id=w.cluster_id AND d.namespace_uid=w.namespace_uid AND d.workload_uid=w.workload_uid AND d.output_limit=(work->>'OutputBytes')::bigint AND d.read_limit=(work->>'ReadBytes')::bigint AND d.session_limit=(work->>'Sessions')::bigint AND d.valid_until=planned AND
  dc.audit_store_id=(s.root_plan#>>'{Input,Capture,Policy,StoreID}')::uuid AND dc.response_limit=(work->>'Responses')::bigint AND dc.window_limit=(work->>'Windows')::bigint AND dc.audit_byte_limit=(work#>>'{WindowObjects,Bytes}')::bigint AND dc.valid_until=planned AND dc.audit_write_until=planned+interval '30 seconds' AND
  (dn.policy_json-ARRAY['ValidUntil','RetireBy'])=(native-ARRAY['ValidUntil','RetireBy']) AND (dn.policy_json->>'ValidUntil')::timestamptz=planned AND (dn.policy_json->>'RetireBy')::timestamptz=(native->>'RetireBy')::timestamptz AND
  dn.rows_limit=(work->>'NativeRows')::bigint AND dn.keys_limit=(work->>'NativeKeys')::bigint AND dn.transitions_per_row=(work->>'NativeTransitionsPerRow')::bigint AND
  dn.backup_horizon_seconds=(native->>'BackupHorizonSeconds')::bigint AND dn.cleanup_seconds=(native->>'CleanupSeconds')::bigint AND dn.valid_until=planned AND dn.retire_by=(native->>'RetireBy')::timestamptz AND dn.residual_until>=dn.retire_by AND
  stop_backing.slots=(work->>'Sessions')::bigint;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE FUNCTION capacity_workload_capture_exact(s public.capacity_source,w public.capacity_workload) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.capture_audit_allocation;policy jsonb;work jsonb;
BEGIN
 SELECT * INTO STRICT a FROM public.capture_audit_allocation WHERE root_id=s.root_id AND allocation_id=w.allocation_id;
 work:=public.capacity_context_protocol_backing(w.plan->'Budget'->'Context',s.root_plan#>'{Input,ContextHistory}');
 policy:=(s.root_plan#>'{Input,Capture,Policy}')||jsonb_build_object('BackingRevision',s.root_configuration->'Revision','ValidUntil',public.capacity_json_timestamp((s.root_configuration->>'PlannedUntil')::timestamptz));
 RETURN NOT a.paused AND a.account_version=s.account_version AND a.account_digest=w.account_digest AND a.guaranteed_records=(work->>'Records')::bigint AND
  a.valid_until=(s.root_configuration->>'PlannedUntil')::timestamptz AND (a.policy-ARRAY['ValidUntil'])=(policy-ARRAY['ValidUntil']) AND (a.policy->>'ValidUntil')::timestamptz=(policy->>'ValidUntil')::timestamptz;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE FUNCTION capacity_phase_fact(s public.capacity_source,o jsonb,until_at timestamptz) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('ObservedAt',o->'ObservedAt','Until',until_at,'SourceRevision',s.accepted_revision,'SourceDigest',o->'SourceDigest','RecoveryEpoch',o#>'{Recovery,IssuerEpoch}','RootRevision',s.root_configuration->'Revision','PlanDigest',o->'PlanDigest')
$$;

CREATE FUNCTION capacity_finish_enrollment(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb,continuation boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE until_at timestamptz;read_value jsonb;s public.capacity_source;w public.capacity_workload;pol jsonb;pool_input jsonb;account_input jsonb;work jsonb;capture_revision bigint;n timestamptz;planned timestamptz;
BEGIN
 IF purpose NOT IN ('capacity','capacity-capture') THEN RAISE EXCEPTION 'capacity phase unavailable' USING ERRCODE='23514';END IF;
 -- This exact read joins any older transaction and locks all ancestors. A
 -- fresh observation can complete SQL configuration, never revive an old permit.
 read_value:=public.capacity_read_enrollment(r,purpose,o,plan_bytes,pool_bytes,source_bytes);until_at:=(read_value->>'FreshUntil')::timestamptz;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE id=(expected->>'ID')::uuid AND root_id=r FOR UPDATE;
 n:=clock_timestamp();planned:=(s.root_configuration->>'PlannedUntil')::timestamptz;until_at:=LEAST(until_at,planned);
 IF read_value->'Enrollment'='null'::jsonb OR NOT public.capacity_enrollment_matches(w,expected) OR w.mutation_xid IS NOT NULL OR s.root_mutation_xid IS NOT NULL OR
  public.capacity_managed_root_until(r,n) IS NULL OR NOT public.capacity_root_general_exact(s) OR NOT public.capacity_root_capture_exact(s) OR
  NOT public.capacity_workload_general_exact(s,w,w.ready_at IS NOT NULL) OR w.capture_backed_at IS NOT NULL AND NOT public.capacity_workload_capture_exact(s,w) OR n>=until_at THEN
  RAISE EXCEPTION 'capacity exact original backing unavailable' USING ERRCODE='23514';END IF;
 IF (purpose='capacity-capture' AND w.capture_backed_at IS NOT NULL) OR (purpose='capacity' AND w.ready_at IS NOT NULL) THEN
  RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt(w),'FreshUntil',until_at);
 END IF;
 IF NOT continuation THEN until_at:=LEAST(until_at,w.initial_until);END IF;
 IF clock_timestamp()>=until_at OR purpose='capacity' AND w.capture_backed_at IS NULL THEN RAISE EXCEPTION 'capacity original phase unavailable' USING ERRCODE='23514';END IF;
 -- A current continuation has exact source/backing compatibility above and no
 -- new account/child ID or debit. Unknown prior outcomes stay joined/lookup-only
 -- until this transaction has observed their actual committed disposition.
 UPDATE public.capacity_source SET configuration_spent=configuration_spent+1,root_mutation_xid=pg_current_xact_id() WHERE root_id=r;
 UPDATE public.capacity_workload SET mutation_xid=pg_current_xact_id() WHERE id=w.id;
 IF purpose='capacity-capture' THEN
  IF EXISTS(SELECT 1 FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=w.allocation_id) THEN RAISE EXCEPTION 'unacknowledged foreign capture account' USING ERRCODE='23514';END IF;
  capture_revision:=(s.root_configuration->>'Revision')::bigint;work:=public.capacity_context_protocol_backing(w.plan->'Budget'->'Context',s.root_plan#>'{Input,ContextHistory}');
  pol:=(s.root_plan#>'{Input,Capture,Policy}')||jsonb_build_object('BackingRevision',capture_revision,'ValidUntil',public.capacity_json_timestamp(planned));
  -- Exact replay of the one prepaid pool: adding this account does not revise
  -- the shared pool, invalidate older accounts or duplicate root backing.
  pool_input:=jsonb_build_object('RootID',r,'Lane','capture','ExpectedRevision',capture_revision-1,'AccountVersion',s.account_version,'Paused',false,'ValidUntil',planned,
   'Accounts',s.root_plan#>'{Input,Capture,Accounts}','RecordsPerAccount',s.root_plan#>'{Input,Capture,RecordsPerAccount}','RetainedSeconds',s.root_plan#>'{Input,Capture,RetainedSeconds}');
  account_input:=jsonb_build_object('ExpectedRevision',0,'Paused',false,'ValidUntil',planned,'Account',jsonb_build_object('RootID',r,'AllocationID',w.allocation_id,
   'AccountVersion',w.account_version,'AccountDigest',to_jsonb(ARRAY(SELECT get_byte(w.account_digest,k) FROM generate_series(0,31) k)),'Revision',1,'Records',work->'Records',
   'RetainedSeconds',s.root_plan#>'{Input,Capture,RetainedSeconds}','Policy',pol));
  until_at:=LEAST(until_at,public.configure_capture_audit_backing(r,pool_input,account_input,(o->>'ObservedAt')::timestamptz,until_at));
  n:=clock_timestamp();IF n>=until_at OR NOT public.capacity_workload_capture_exact(s,w) THEN RAISE EXCEPTION 'capacity capture phase expired or changed' USING ERRCODE='23514';END IF;
  UPDATE public.capacity_workload SET capture_backed_at=n,capture_completion=public.capacity_phase_fact(s,o,until_at) WHERE id=w.id;
 ELSE
  -- Publish only after both purpose-specific backing sets are exact. Retain
  -- all spent counters and original identities while unpausing in one commit.
  UPDATE public.custody_allocation SET paused=false,revision=revision+1 WHERE id=w.allocation_id AND paused;
  UPDATE public.context_control_account SET paused=false,revision=revision+1 WHERE root_id=r AND allocation_id=w.allocation_id AND paused;
  UPDATE public.context_storage_binding SET observed_at=(o->>'ObservedAt')::timestamptz,fresh_until=until_at WHERE root_id=r AND allocation_id=w.allocation_id;
  n:=clock_timestamp();IF n>=until_at OR NOT public.capacity_workload_general_exact(s,w,true) OR NOT public.capacity_workload_capture_exact(s,w) THEN RAISE EXCEPTION 'capacity Ready phase expired or changed' USING ERRCODE='23514';END IF;
  UPDATE public.capacity_workload SET ready_at=n,ready_completion=public.capacity_phase_fact(s,o,until_at) WHERE id=w.id;
 END IF;
 UPDATE public.capacity_workload SET mutation_xid=NULL WHERE id=w.id RETURNING * INTO w;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity phase expired at completion' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt(w),'FreshUntil',until_at);
END $$;
CREATE FUNCTION back_capacity_enrollment(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.capacity_finish_enrollment(r,'capacity-capture',o,plan_bytes,pool_bytes,source_bytes,expected,false)
$$;
CREATE FUNCTION continue_capacity_capture(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.capacity_finish_enrollment(r,'capacity-capture',o,plan_bytes,pool_bytes,source_bytes,expected,true)
$$;
CREATE FUNCTION publish_capacity_enrollment(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.capacity_finish_enrollment(r,'capacity',o,plan_bytes,pool_bytes,source_bytes,expected,false)
$$;
CREATE FUNCTION continue_capacity_publication(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.capacity_finish_enrollment(r,'capacity',o,plan_bytes,pool_bytes,source_bytes,expected,true)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_enrollment_matches(capacity_workload,jsonb),capacity_workload_general_exact(capacity_source,capacity_workload,boolean),capacity_workload_capture_exact(capacity_source,capacity_workload),capacity_phase_fact(capacity_source,jsonb,timestamptz),capacity_finish_enrollment(uuid,text,jsonb,bytea,bytea,bytea,jsonb,boolean),back_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea,jsonb),continue_capacity_capture(uuid,jsonb,bytea,bytea,bytea,jsonb),publish_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea,jsonb),continue_capacity_publication(uuid,jsonb,bytea,bytea,bytea,jsonb) FROM PUBLIC;

-- +goose StatementBegin
-- Managed configuration is writable only inside one of the purpose-fixed
-- producer transactions. Existing protocol counters/history overlays still go
-- through their original guards; this marker never authorizes those effects.
CREATE FUNCTION require_capacity_configuration_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb;old_value jsonb;r uuid;s public.capacity_source;ignored text[];purpose text:='capacity';
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN('INSERT','UPDATE','DELETE') THEN RAISE EXCEPTION 'invalid managed configuration source' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN v:=to_jsonb(OLD);ELSE v:=to_jsonb(NEW);END IF;
 IF TG_RELID='public.custody_pool'::regclass THEN
  SELECT root_id INTO r FROM public.capacity_pool WHERE id=(v->>'id')::uuid;
  IF NOT FOUND THEN
   SELECT root_id INTO r FROM public.capacity_source source WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(source.qualification->'Backends') b WHERE b->>'PoolID'=v->>'id');
  END IF;
  ignored:=ARRAY['allocated_bytes','allocated_objects'];
 ELSIF TG_RELID='public.custody_allocation'::regclass THEN
  SELECT root_id INTO r FROM public.capacity_pool WHERE id=(v->>'pool_id')::uuid;ignored:=ARRAY['charged_bytes','charged_objects'];
 ELSIF TG_RELID='public.context_storage_binding'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY[]::text[];
 ELSIF TG_RELID='public.context_control_pool'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY['backed_full','backed_replay'];
 ELSIF TG_RELID='public.context_control_account'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY['charged_full','charged_replay'];
 ELSIF TG_RELID='public.download_allocation'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY['reserved_output','reserved_read','reserved_sessions'];
 ELSIF TG_RELID='public.download_control_allocation'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY['reserved_responses','reserved_windows','reserved_audit_bytes'];
 ELSIF TG_RELID='public.download_native_backing'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY['charged_rows','charged_keys','residual_until','overdue'];
 ELSIF TG_RELID='public.download_stop_backing'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY['charged'];
 ELSIF TG_RELID='public.processing_root'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY['captures','rules','root_transitions','sequence','initialized_at','initialization_id'];
 ELSIF TG_RELID='public.download_stop_pool'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY['allocated','history_backing_until'];
 ELSIF TG_RELID='public.operation_audit_pool'::regclass THEN
  IF v->>'lane' NOT IN('normal','resolution','processing','capture') THEN IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
  r:=(v->>'root_id')::uuid;ignored:=ARRAY['accounts','history_profile','history_backing_until','proof_window_missed'];
  IF v->>'lane'='capture' THEN purpose:='capacity-capture';END IF;
 ELSIF TG_RELID='public.capture_audit_allocation'::regclass THEN r:=(v->>'root_id')::uuid;ignored:=ARRAY[]::text[];purpose:='capacity-capture';
 ELSE RAISE EXCEPTION 'invalid managed configuration table' USING ERRCODE='23514';END IF;
 SELECT * INTO s FROM public.capacity_source WHERE root_id=r;
 IF NOT FOUND THEN IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'managed configuration retains unsettled backing' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' THEN
  old_value:=to_jsonb(OLD);
  IF (v-ignored) IS NOT DISTINCT FROM (old_value-ignored) THEN RETURN NEW;END IF;
 END IF;
 IF s.root_mutation_xid IS DISTINCT FROM pg_current_xact_id() OR NOT public.capacity_role_ok(r,purpose) OR s.suspended OR s.observed_at IS NULL OR s.observed_at>clock_timestamp() OR clock_timestamp()>=s.fresh_until THEN
  RAISE EXCEPTION 'managed configuration requires original producer transaction' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_capacity_configuration_owner() FROM PUBLIC;
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON custody_pool FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON custody_allocation FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON context_storage_binding FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON context_control_pool FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON context_control_account FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON download_allocation FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON download_control_allocation FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON download_native_backing FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON download_stop_backing FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON processing_root FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON download_stop_pool FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON operation_audit_pool FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();
CREATE TRIGGER aaa_capacity_configuration BEFORE INSERT OR UPDATE OR DELETE ON capture_audit_allocation FOR EACH ROW EXECUTE FUNCTION require_capacity_configuration_owner();

-- +goose StatementBegin
-- The capture purpose alone may advance its managed root. Partial setup and
-- previous expired dates are not authority: the private current transaction
-- marker and exact pending configuration must both exist. Legacy roots retain
-- their original SQL52 guard unchanged.
CREATE FUNCTION require_capacity_capture_root_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;c jsonb;n timestamptz;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.capture_audit_root'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('UPDATE','DELETE') THEN RAISE EXCEPTION 'invalid managed capture root source' USING ERRCODE='23514';END IF;
 SELECT * INTO s FROM public.capacity_source WHERE root_id=OLD.root_id;
 IF NOT FOUND THEN IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'managed capture root retains obligations' USING ERRCODE='23514';END IF;
 c:=s.root_configuration;n:=clock_timestamp();
 IF NOT public.capacity_role_ok(s.root_id,'capacity-capture') OR NOT public.capture_audit_role_ok(s.root_id,'source') OR
  s.root_mutation_xid IS DISTINCT FROM pg_current_xact_id() OR s.suspended OR s.observed_at IS NULL OR s.observed_at>n OR s.fresh_until IS NULL OR n>=s.fresh_until OR
  NOT COALESCE(public.capacity_root_configuration_valid(c),false) OR c->'CaptureBackedAt'<>'null'::jsonb OR c->'ReadyAt'<>'null'::jsonb OR c->'ReconciledAt'<>'null'::jsonb OR
  NEW.source_role<>s.capture_role OR NEW.installation_id<>s.installation_id OR NEW.paused OR NEW.valid_until IS DISTINCT FROM (c->>'PlannedUntil')::timestamptz OR n>=NEW.valid_until OR
  (to_jsonb(NEW)-ARRAY['revision','paused','valid_until']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['revision','paused','valid_until']) OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'managed capture root requires original capture producer phase' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

-- This is a transaction-local predicate, never a caller-set GUC or a granted
-- RPC. Exact managed parent/workload identity and private markers are required.
-- It authorizes changing future backing dates only; session snapshots are not
-- updated, and each row guard additionally retains every counter/other field.
CREATE FUNCTION capacity_download_renewal(r uuid,a uuid,old_until timestamptz,new_until timestamptz) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;w public.capacity_workload;c jsonb;n timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=r AND download_allocation_id=a;
 c:=s.root_configuration;
 RETURN COALESCE(public.capacity_role_ok(r,'capacity') AND s.root_mutation_xid=pg_current_xact_id() AND w.mutation_xid=pg_current_xact_id() AND
  NOT s.suspended AND s.observed_at<=n AND n<s.fresh_until AND public.capacity_root_configuration_valid(c) AND
  (c->>'Revision')::bigint>1 AND c->'CaptureBackedAt'='null'::jsonb AND c->'ReadyAt'='null'::jsonb AND c->'ReconciledAt'='null'::jsonb AND
  new_until=(c->>'PlannedUntil')::timestamptz AND new_until>old_until AND n<new_until,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_capacity_capture_root_owner(),capacity_download_renewal(uuid,uuid,timestamptz,timestamptz) FROM PUBLIC;
CREATE TRIGGER aaa_capacity_capture_root BEFORE UPDATE OR DELETE ON capture_audit_root FOR EACH ROW EXECUTE FUNCTION require_capacity_capture_root_owner();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_download_allocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.valid_until IS DISTINCT FROM OLD.valid_until THEN
 IF (to_jsonb(NEW)-'valid_until') IS NOT DISTINCT FROM (to_jsonb(OLD)-'valid_until') AND
  public.capacity_download_renewal(OLD.root_id,OLD.id,OLD.valid_until,NEW.valid_until) THEN RETURN NEW;END IF;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['reserved_output','reserved_read','reserved_sessions']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['reserved_output','reserved_read','reserved_sessions']) OR NEW.reserved_output<OLD.reserved_output OR NEW.reserved_read<OLD.reserved_read OR NEW.reserved_sessions<OLD.reserved_sessions THEN
  RAISE EXCEPTION 'immutable download allocation; reservations cannot be refunded' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION guard_download_control_allocation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.download_allocation;
BEGIN
 IF TG_OP='UPDATE' AND NEW.valid_until IS DISTINCT FROM OLD.valid_until THEN
 IF   (to_jsonb(NEW)-ARRAY['valid_until','audit_write_until']) IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['valid_until','audit_write_until']) AND
  OLD.audit_write_until=OLD.valid_until+interval '30 seconds' AND NEW.audit_write_until=NEW.valid_until+interval '30 seconds' AND
  public.capacity_download_renewal(OLD.root_id,OLD.id,OLD.valid_until,NEW.valid_until) THEN
  SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.id AND root_id=NEW.root_id;
  IF NEW.valid_until IS DISTINCT FROM a.valid_until THEN RAISE EXCEPTION 'managed download parent cutoff mismatch' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download control lifecycle unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.id AND root_id=NEW.root_id;
  IF NEW.reserved_responses<>0 OR NEW.reserved_windows<>0 OR NEW.reserved_audit_bytes<>0 OR NEW.valid_until>a.valid_until OR NEW.window_limit>((a.output_limit-1)/67108864+1)+NEW.response_limit THEN RAISE EXCEPTION 'invalid download control backing' USING ERRCODE='23514';END IF;
 ELSIF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['reserved_responses','reserved_windows','reserved_audit_bytes']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['reserved_responses','reserved_windows','reserved_audit_bytes']) OR NEW.reserved_responses<>OLD.reserved_responses+1 OR NEW.reserved_windows<=OLD.reserved_windows OR NEW.reserved_audit_bytes<>OLD.reserved_audit_bytes+(NEW.reserved_windows-OLD.reserved_windows)*262144 THEN
  RAISE EXCEPTION 'immutable source-managed download control backing' USING ERRCODE='23514';
 END IF;RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION guard_download_native_backing() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb;q jsonb;need_backup numeric;need_wal numeric;a public.download_allocation;
BEGIN
 IF TG_OP='UPDATE' AND NEW.valid_until IS DISTINCT FROM OLD.valid_until THEN
 IF   (to_jsonb(NEW)-ARRAY['policy_json','valid_until','retire_by','residual_until']) IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['policy_json','valid_until','retire_by','residual_until']) AND
  (NEW.policy_json-ARRAY['ValidUntil','RetireBy']) IS NOT DISTINCT FROM (OLD.policy_json-ARRAY['ValidUntil','RetireBy']) AND
  public.capacity_native_snapshot_valid(OLD.policy_json) AND public.capacity_native_snapshot_valid(NEW.policy_json) AND
  (NEW.policy_json->>'ValidUntil')::timestamptz=NEW.valid_until AND (NEW.policy_json->>'RetireBy')::timestamptz=NEW.retire_by AND
  NEW.residual_until=GREATEST(OLD.residual_until,NEW.retire_by) AND
  public.capacity_download_renewal(OLD.root_id,OLD.allocation_id,OLD.valid_until,NEW.valid_until) THEN
  SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id;
  IF NEW.valid_until IS DISTINCT FROM a.valid_until THEN RAISE EXCEPTION 'managed native parent cutoff mismatch' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 END IF;
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

-- Every managed session retains its original configuration. Neither a nullable
-- legacy row nor a missing/malformed managed snapshot chooses current backing.
ALTER TABLE artifact_download ADD COLUMN capacity_account_id uuid REFERENCES capacity_workload(id);
ALTER TABLE artifact_download ADD COLUMN capacity_backing jsonb;
ALTER TABLE artifact_download ADD COLUMN capacity_backing_digest bytea;
ALTER TABLE artifact_download ADD CONSTRAINT capacity_download_snapshot_present CHECK(
 (capacity_account_id IS NULL AND capacity_backing IS NULL AND capacity_backing_digest IS NULL) OR
 (capacity_account_id IS NOT NULL AND capacity_backing IS NOT NULL AND capacity_backing_digest IS NOT NULL AND
 jsonb_typeof(capacity_backing)='object' AND octet_length(capacity_backing::text)<=8192 AND octet_length(capacity_backing_digest)=32));

-- +goose StatementBegin
CREATE FUNCTION capacity_json_time(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE t timestamptz;
BEGIN
 IF NOT public.capacity_json_text(v,20,40) OR (v#>>'{}')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})$' THEN RETURN false;END IF;
 t:=(v#>>'{}')::timestamptz;RETURN isfinite(t) AND t<>'0001-01-01 00:00:00+00'::timestamptz;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
CREATE FUNCTION capacity_revision_valid(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.capacity_json_fields(v,ARRAY['UID','Generation','Digest']) AND public.capacity_json_text(v->'UID',1,64) AND
 (v->>'UID')!~'[[:cntrl:]]' AND public.capacity_json_integer(v->'Generation',1,2147483647) AND public.capacity_json_digest(v->'Digest')
$$;
CREATE FUNCTION capacity_native_snapshot_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE q jsonb:=p->'History';backup numeric;wal numeric;k text;
BEGIN
 IF NOT public.capacity_json_fields(p,ARRAY['AllocationID','RootID','PolicyID','PolicyDigest','Rows','Keys','TransitionsPerRow','BackupBytes','WALBytes','BackupHorizonSeconds','CleanupSeconds','ValidUntil','RetireBy','History']) OR
  NOT public.capacity_json_fields(q,ARRAY['ID','Digest','RowBytes','TransitionWALBytes','BackupCopies','WALCopies']) THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['AllocationID','RootID','PolicyID'] LOOP IF NOT public.capacity_json_uuid(p->k) THEN RETURN false;END IF;END LOOP;
 IF NOT public.capacity_json_digest(p->'PolicyDigest') OR NOT public.capacity_json_uuid(q->'ID') OR NOT public.capacity_json_digest(q->'Digest') OR
  NOT public.capacity_json_integer(p->'Rows',1,100000) OR NOT public.capacity_json_integer(p->'Keys',1,263168) OR
  NOT public.capacity_json_integer(p->'TransitionsPerRow',8,65536) OR NOT public.capacity_json_integer(p->'BackupBytes',1,9223372036854775807) OR NOT public.capacity_json_integer(p->'WALBytes',1,9223372036854775807) OR
  NOT public.capacity_json_integer(p->'BackupHorizonSeconds',0,316224000) OR NOT public.capacity_json_integer(p->'CleanupSeconds',1,86400) OR
  NOT public.capacity_json_integer(q->'RowBytes',65536,16777216) OR NOT public.capacity_json_integer(q->'TransitionWALBytes',65536,67108864) OR
  NOT public.capacity_json_integer(q->'BackupCopies',1,64) OR NOT public.capacity_json_integer(q->'WALCopies',1,64) OR
  NOT public.capacity_json_time(p->'ValidUntil') OR NOT public.capacity_json_time(p->'RetireBy') OR
  (p->>'RetireBy')::timestamptz<>(p->>'ValidUntil')::timestamptz+make_interval(secs=>(2*(p->>'BackupHorizonSeconds')::bigint+(p->>'CleanupSeconds')::bigint)::double precision) THEN RETURN false;END IF;
 backup:=2*(q->>'RowBytes')::numeric*(q->>'BackupCopies')::numeric*((p->>'Rows')::numeric+(p->>'Keys')::numeric);
 wal:=(q->>'TransitionWALBytes')::numeric*(q->>'WALCopies')::numeric*(((p->>'TransitionsPerRow')::numeric+4)*(p->>'Rows')::numeric+8*(p->>'Keys')::numeric);
 RETURN (p->>'BackupBytes')::numeric>=backup AND (p->>'WALBytes')::numeric>=wal;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
CREATE FUNCTION capacity_session_snapshot_valid(p jsonb,account uuid,allocation uuid,r uuid,deadline timestamptz) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE k text;
BEGIN
 IF account IS NULL OR allocation IS NULL OR r IS NULL OR deadline IS NULL OR NOT isfinite(deadline) OR
  NOT public.capacity_json_fields(p,ARRAY['Format','AccountID','AttemptID','AllocationID','Revision','PoolSource','PolicySource','AllocationUntil','ControlUntil','AuditStoreID','AuditWriteUntil','Native']) OR
  octet_length(p::text)>8192 OR p->>'Format' IS DISTINCT FROM 'protected-capacity/v1' OR
  NOT public.capacity_json_integer(p->'Revision',1,1152921504606846976) OR NOT public.capacity_revision_valid(p->'PoolSource') OR NOT public.capacity_revision_valid(p->'PolicySource') OR NOT public.capacity_native_snapshot_valid(p->'Native') THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['AccountID','AttemptID','AllocationID','AuditStoreID'] LOOP IF NOT public.capacity_json_uuid(p->k) THEN RETURN false;END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['AllocationUntil','ControlUntil','AuditWriteUntil'] LOOP IF NOT public.capacity_json_time(p->k) THEN RETURN false;END IF;END LOOP;
 RETURN (p->>'AccountID')::uuid=account AND (p->>'AllocationID')::uuid=allocation AND (p#>>'{Native,AllocationID}')::uuid=allocation AND (p#>>'{Native,RootID}')::uuid=r AND
  (p->>'AuditWriteUntil')::timestamptz>=(p->>'ControlUntil')::timestamptz AND (p->>'AuditWriteUntil')::timestamptz<=(p->>'ControlUntil')::timestamptz+interval '5 minutes' AND
  deadline<=LEAST((p->>'AllocationUntil')::timestamptz,(p->>'ControlUntil')::timestamptz,(p#>>'{Native,ValidUntil}')::timestamptz);
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
CREATE FUNCTION capacity_session_snapshot_digest(p jsonb) RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT sha256(convert_to('asservat-capacity-session/jsonb-v1','UTF8')||decode('00','hex')||convert_to(p::text,'UTF8'))
$$;
CREATE FUNCTION require_capacity_download_snapshot() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
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
CREATE TRIGGER aaa_capacity_session_snapshot BEFORE INSERT ON artifact_download FOR EACH ROW EXECUTE FUNCTION require_capacity_download_snapshot();

CREATE FUNCTION capacity_original_session_backing(s public.artifact_download) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF s.capacity_account_id IS NULL THEN
  IF s.capacity_backing IS NOT NULL OR s.capacity_backing_digest IS NOT NULL THEN RAISE EXCEPTION 'unmanaged session snapshot invalid' USING ERRCODE='23514';END IF;
  RETURN NULL;
 END IF;
 IF NOT public.capacity_session_snapshot_valid(s.capacity_backing,s.capacity_account_id,s.allocation_id,s.root_id,s.deadline) OR
  s.capacity_backing_digest IS NULL OR s.capacity_backing_digest IS DISTINCT FROM public.capacity_session_snapshot_digest(s.capacity_backing) THEN RAISE EXCEPTION 'managed session snapshot invalid' USING ERRCODE='23514';END IF;
 RETURN s.capacity_backing;
END $$;

-- Effective copies preserve current aggregate counters. Only the independently
-- stored original cutoff/policy fields are substituted for this exact session.
CREATE FUNCTION capacity_session_control(s public.artifact_download,c public.download_control_allocation) RETURNS public.download_control_allocation
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb;
BEGIN
 IF s.allocation_id IS DISTINCT FROM c.id OR s.root_id IS DISTINCT FROM c.root_id THEN RAISE EXCEPTION 'session control identity invalid' USING ERRCODE='23514';END IF;
 p:=public.capacity_original_session_backing(s);
 IF p IS NOT NULL THEN
  IF c.audit_store_id IS DISTINCT FROM (p->>'AuditStoreID')::uuid THEN RAISE EXCEPTION 'session audit store changed' USING ERRCODE='23514';END IF;
  c.valid_until:=(p->>'ControlUntil')::timestamptz;c.audit_write_until:=(p->>'AuditWriteUntil')::timestamptz;
 END IF;RETURN c;
END $$;
CREATE FUNCTION capacity_session_native(s public.artifact_download,b public.download_native_backing) RETURNS public.download_native_backing
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb;
BEGIN
 IF s.allocation_id IS DISTINCT FROM b.allocation_id OR s.root_id IS DISTINCT FROM b.root_id THEN RAISE EXCEPTION 'session native identity invalid' USING ERRCODE='23514';END IF;
 p:=public.capacity_original_session_backing(s);
 IF p IS NOT NULL THEN
  p:=p->'Native';b.policy_json:=p;
  b.rows_limit:=(p->>'Rows')::bigint;b.keys_limit:=(p->>'Keys')::bigint;b.transitions_per_row:=(p->>'TransitionsPerRow')::bigint;
  b.backup_horizon_seconds:=(p->>'BackupHorizonSeconds')::bigint;b.cleanup_seconds:=(p->>'CleanupSeconds')::bigint;
  b.valid_until:=(p->>'ValidUntil')::timestamptz;b.retire_by:=(p->>'RetireBy')::timestamptz;
 END IF;RETURN b;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_time(jsonb),capacity_revision_valid(jsonb),capacity_native_snapshot_valid(jsonb),capacity_session_snapshot_valid(jsonb,uuid,uuid,uuid,timestamptz),capacity_session_snapshot_digest(jsonb),require_capacity_download_snapshot(),capacity_original_session_backing(artifact_download),capacity_session_control(artifact_download,download_control_allocation),capacity_session_native(artifact_download,download_native_backing) FROM PUBLIC;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_response() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.artifact_download;c public.download_control_allocation;n timestamptz;used bigint;responses bigint;length bigint;off bigint;read_each bigint;win bigint;
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
  SELECT coalesce(sum(reserved_windows),0),count(*) INTO used,responses FROM public.download_response WHERE session_id=s.id;
  IF n>=c.valid_until OR n>=NEW.lease_until OR n>=NEW.until_at OR NEW.until_at>s.deadline OR NEW.until_at>c.valid_until OR NEW.started_at>n OR NEW.lease_until>NEW.started_at+interval '5 seconds' OR NEW.generation<>s.generation+1 OR s.state NOT IN ('Ready','Streaming','Interrupted') OR NEW.window_count<>0 OR NEW.completed_windows<>0 OR NEW.emitted_bytes<>0 OR NEW.active_window IS NOT NULL OR NEW.closed OR NEW.lease_sequence<>0 OR NEW.reserved_windows<>win OR read_each>70368744177664/win OR read_each*win>s.read_limit-s.charged_read OR length>s.output_limit-s.charged_output OR responses>=c.response_limit OR used+win>((s.output_limit-1)/67108864+1)+c.response_limit THEN RAISE EXCEPTION 'download response unavailable' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM public.download_response WHERE session_id=s.id AND generation=s.generation AND NOT closed AND lease_until>n) OR EXISTS(SELECT 1 FROM public.download_batch WHERE id=s.active_batch AND lease_until>n AND outcome_json IS NULL) THEN RAISE EXCEPTION 'download response busy' USING ERRCODE='23514';END IF;
  UPDATE public.download_control_allocation SET reserved_responses=reserved_responses+1,reserved_windows=reserved_windows+win,reserved_audit_bytes=reserved_audit_bytes+win*262144 WHERE id=c.id;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.session_id,NEW.owner_id,NEW.generation,NEW.plan_json,NEW.reserved_windows,NEW.started_at,NEW.until_at) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.session_id,OLD.owner_id,OLD.generation,OLD.plan_json,OLD.reserved_windows,OLD.started_at,OLD.until_at) OR NEW.window_count<OLD.window_count OR NEW.completed_windows<OLD.completed_windows OR NEW.emitted_bytes<OLD.emitted_bytes OR NEW.lease_sequence<OLD.lease_sequence OR OLD.closed AND NOT NEW.closed THEN RAISE EXCEPTION 'immutable native response' USING ERRCODE='23514';END IF;
  IF NEW.lease_sequence<>OLD.lease_sequence AND (NEW.lease_sequence<>OLD.lease_sequence+1 OR NEW.lease_until>clock_timestamp()+interval '5 seconds' OR OLD.closed) OR pg_trigger_depth()<2 AND NEW.lease_sequence=OLD.lease_sequence AND NEW.lease_until IS DISTINCT FROM OLD.lease_until THEN RAISE EXCEPTION 'invalid response lease transition' USING ERRCODE='23514';END IF;
  IF pg_trigger_depth()<2 AND ROW(NEW.window_count,NEW.completed_windows,NEW.emitted_bytes,NEW.active_window) IS DISTINCT FROM ROW(OLD.window_count,OLD.completed_windows,OLD.emitted_bytes,OLD.active_window) THEN RAISE EXCEPTION 'window-managed response accounting' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_window() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.download_response;s public.artifact_download;c public.download_control_allocation;w jsonb;n timestamptz;amount bigint;read_bytes bigint;emitted bigint;success boolean;verified boolean;final boolean;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download window lifecycle unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.artifact_download WHERE id=NEW.session_id FOR UPDATE;
 SELECT * INTO STRICT r FROM public.download_response WHERE id=NEW.response_id AND session_id=NEW.session_id FOR UPDATE;
 n:=clock_timestamp();w:=NEW.intent_json->'Window';
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT c FROM public.download_control_allocation WHERE id=s.allocation_id AND root_id=s.root_id;
  c:=public.capacity_session_control(s,c);
  IF jsonb_typeof(w) IS DISTINCT FROM 'object' OR NOT (w ?& ARRAY['ID','ResponseID','SessionID','OwnerID','AuditStoreID','Generation','Ordinal','Offset','Length','ReadLimit','StartedAt','WriteUntil','Authority','IntentAcknowledged','Outcome','OutcomeAcknowledged']) OR w->'IntentAcknowledged' IS DISTINCT FROM 'false'::jsonb OR w->'OutcomeAcknowledged' IS DISTINCT FROM 'false'::jsonb OR w->'Outcome' IS DISTINCT FROM 'null'::jsonb OR jsonb_typeof(w->'Authority') IS DISTINCT FROM 'object' OR NOT ((w->'Authority') ?& ARRAY['CheckedAt','ValidUntil','Scope']) OR NEW.intent_json#>'{Response,Plan}' IS DISTINCT FROM r.plan_json OR (NEW.intent_json#>>'{Response,ID}') IS DISTINCT FROM r.id::text OR (NEW.intent_json#>>'{Response,OwnerID}') IS DISTINCT FROM r.owner_id::text THEN RAISE EXCEPTION 'closed original window required' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_each(w-'Outcome') AS v WHERE v.value='null'::jsonb) OR (w#>>'{Authority,CheckedAt}') IS NULL OR (w#>>'{Authority,ValidUntil}') IS NULL OR (w->>'StartedAt')::timestamptz>n OR (w#>>'{Authority,ValidUntil}')::timestamptz>(w#>>'{Authority,CheckedAt}')::timestamptz+interval '5 seconds' OR (w#>>'{Authority,Scope,RootID}') IS DISTINCT FROM s.root_id::text OR (w#>'{Authority,Scope}') IS DISTINCT FROM s.scope_json THEN RAISE EXCEPTION 'window scope/interval mismatch' USING ERRCODE='23514';END IF;
  amount:=(w->>'Length')::bigint;read_bytes:=(w->>'ReadLimit')::bigint;
  IF s.generation<>r.generation OR s.state NOT IN ('Ready','Streaming','Interrupted') OR r.closed OR r.active_window IS NOT NULL OR r.window_count<>r.completed_windows OR r.window_count>=r.reserved_windows OR NEW.ordinal<>r.window_count+1 OR (w->>'ID')::uuid<>NEW.id OR (w->>'ResponseID')::uuid<>r.id OR (w->>'SessionID')::uuid<>s.id OR (w->>'OwnerID')::uuid<>r.owner_id OR (w->>'Generation')::bigint<>r.generation OR (w->>'Ordinal')::bigint<>NEW.ordinal OR (w->>'AuditStoreID')::uuid<>c.audit_store_id OR (w->>'WriteUntil')::timestamptz<>c.audit_write_until OR (w->>'Offset')::bigint<>(r.plan_json#>>'{Selection,Offset}')::bigint+r.emitted_bytes OR amount<>least(67108864,(r.plan_json#>>'{Selection,Length}')::bigint-r.emitted_bytes) OR read_bytes<>(r.plan_json->>'WindowReadLimit')::bigint OR n>=r.until_at OR n>=(w#>>'{Authority,ValidUntil}')::timestamptz OR NEW.intent_receipt IS NOT NULL OR NEW.intent_completion IS NOT NULL OR NEW.outcome_completion IS NOT NULL OR NEW.outcome_json IS NOT NULL OR NEW.outcome_receipt IS NOT NULL THEN RAISE EXCEPTION 'download window unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.artifact_download SET charged_output=charged_output+amount,charged_read=charged_read+read_bytes WHERE id=s.id;
  UPDATE public.download_response SET window_count=window_count+1,active_window=NEW.id,lease_until=least(until_at,(w#>>'{Authority,ValidUntil}')::timestamptz) WHERE id=r.id;
 ELSE
  IF ROW(NEW.id,NEW.response_id,NEW.session_id,NEW.ordinal,NEW.intent_json) IS DISTINCT FROM ROW(OLD.id,OLD.response_id,OLD.session_id,OLD.ordinal,OLD.intent_json) OR OLD.intent_receipt IS NOT NULL AND ROW(NEW.intent_receipt,NEW.intent_completion) IS DISTINCT FROM ROW(OLD.intent_receipt,OLD.intent_completion) OR OLD.outcome_json IS NOT NULL AND NEW.outcome_json IS DISTINCT FROM OLD.outcome_json OR OLD.outcome_receipt IS NOT NULL AND ROW(NEW.outcome_receipt,NEW.outcome_completion) IS DISTINCT FROM ROW(OLD.outcome_receipt,OLD.outcome_completion) THEN RAISE EXCEPTION 'immutable window/audit' USING ERRCODE='23514';END IF;
  IF OLD.outcome_json IS NULL AND NEW.outcome_json IS NOT NULL THEN
   emitted:=(NEW.outcome_json->>'EmittedBytes')::bigint;success:=(NEW.outcome_json->>'Success')::boolean;verified:=(NEW.outcome_json->>'VerifiedFinal')::boolean;
   IF NEW.intent_receipt IS NULL OR emitted IS NULL OR success IS NULL OR verified IS NULL OR emitted<0 OR emitted>(w->>'Length')::bigint OR success AND emitted<>(w->>'Length')::bigint OR verified AND (NOT success OR NEW.ordinal<>r.reserved_windows) THEN RAISE EXCEPTION 'invalid window outcome' USING ERRCODE='23514';END IF;
   UPDATE public.artifact_download SET emitted_bytes=emitted_bytes+emitted WHERE id=s.id;
  END IF;
  IF OLD.outcome_receipt IS NULL AND NEW.outcome_receipt IS NOT NULL THEN
   emitted:=(NEW.outcome_json->>'EmittedBytes')::bigint;success:=(NEW.outcome_json->>'Success')::boolean;verified:=(NEW.outcome_json->>'VerifiedFinal')::boolean;final:=NEW.ordinal=r.reserved_windows;
   IF r.active_window IS DISTINCT FROM NEW.id OR r.completed_windows+1<>NEW.ordinal OR (w->>'Offset')::bigint<>(r.plan_json#>>'{Selection,Offset}')::bigint+r.emitted_bytes THEN RAISE EXCEPTION 'noncontiguous outcome acknowledgement' USING ERRCODE='23514';END IF;
   UPDATE public.download_response SET completed_windows=completed_windows+1,emitted_bytes=emitted_bytes+emitted,active_window=NULL,closed=closed OR NOT success OR final OR n>=until_at WHERE id=r.id;
   IF s.generation=r.generation AND s.state NOT IN ('Completed','Cancelled','Expired','Denied','Failed') THEN
    IF n>=s.deadline OR n>=r.until_at THEN UPDATE public.artifact_download SET state='Expired' WHERE id=s.id;
    ELSIF NOT success OR final THEN UPDATE public.artifact_download SET state=CASE WHEN final AND success AND verified AND (r.plan_json->>'WholeFile')::boolean AND r.emitted_bytes+emitted=(r.plan_json#>>'{Selection,Length}')::bigint THEN 'Completed' ELSE 'Interrupted' END WHERE id=s.id;
    END IF;
   END IF;
  END IF;
 END IF;RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_native_owner() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w public.download_worker;s public.artifact_download;b public.download_native_backing;e public.download_worker_enrollment;n timestamptz;o jsonb;ref jsonb;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=OLD.allocation_id;
  SELECT * INTO STRICT w FROM public.download_worker WHERE id=OLD.worker_id;
  SELECT * INTO STRICT s FROM public.artifact_download WHERE id=w.session_id;
  b:=public.capacity_session_native(s,b);
  n:=clock_timestamp();
  IF OLD.retired_at IS NULL OR w.retired_proof_json IS NULL OR n<OLD.retired_at+make_interval(secs=>b.backup_horizon_seconds::double precision) OR EXISTS(SELECT 1 FROM public.download_native_key WHERE worker_id=OLD.worker_id) THEN RAISE EXCEPTION 'native owner history not quiescent' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET residual_until=GREATEST(residual_until,n+make_interval(secs=>b.backup_horizon_seconds::double precision)),overdue=overdue OR n+make_interval(secs=>b.backup_horizon_seconds::double precision)>b.retire_by WHERE allocation_id=b.allocation_id;RETURN OLD;
 END IF;
 SELECT * INTO STRICT w FROM public.download_worker WHERE id=NEW.worker_id;
 SELECT * INTO STRICT s FROM public.artifact_download WHERE id=w.session_id;
 SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=NEW.allocation_id FOR UPDATE;
 b:=public.capacity_session_native(s,b);
 n:=clock_timestamp();o:=NEW.operation_json;ref:=o->'Reference';
 IF TG_OP='UPDATE' AND NEW.retired_at IS NOT NULL THEN
  IF OLD.retired_at IS NOT NULL OR w.retired_proof_json IS NULL OR NOT NEW.closed OR NEW.retired_at<>NEW.updated_at OR NEW.updated_at>n OR NEW.updates<>OLD.updates+1 OR (to_jsonb(NEW)-ARRAY['closed','retired_at','updated_at','updates']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['closed','retired_at','updated_at','updates']) OR NEW.updates>b.transitions_per_row THEN RAISE EXCEPTION 'invalid native owner retirement' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND NEW.closed THEN
  IF OLD.retired_at IS NOT NULL OR OLD.closed OR NEW.updates<>OLD.updates+1 OR NEW.updated_at>n OR (to_jsonb(NEW)-ARRAY['closed','updated_at','updates']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['closed','updated_at','updates']) OR NEW.updates>b.transitions_per_row-1 THEN RAISE EXCEPTION 'invalid native owner close' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 SELECT * INTO STRICT e FROM public.download_worker_enrollment WHERE worker_id=NEW.worker_id;
 IF jsonb_typeof(o->'StartedAt') IS DISTINCT FROM 'string' OR jsonb_typeof(o->'Until') IS DISTINCT FROM 'string' OR jsonb_typeof(NEW.authority_json->'ValidUntil') IS DISTINCT FROM 'string' OR n>=b.valid_until OR n>=NEW.lease_until OR NEW.lease_started>n OR NEW.updated_at<>NEW.lease_started OR NEW.updates>b.transitions_per_row-2 OR NEW.closed OR NEW.retired_at IS NOT NULL OR w.termination_json IS NOT NULL OR w.retired_proof_json IS NOT NULL OR w.audit_receipt_json IS NULL OR NEW.root_id<>w.root_id OR NEW.allocation_id<>w.allocation_id OR NEW.lease_until>w.run_until OR NEW.lease_until>s.deadline OR (ref->>'WorkerID')::uuid IS DISTINCT FROM NEW.worker_id OR (ref->>'SessionID')::uuid IS DISTINCT FROM s.id OR (ref->>'InstallationID')::uuid IS DISTINCT FROM w.installation_id OR (ref->>'OperationID')::uuid IS DISTINCT FROM NEW.operation_id OR (ref->>'Fence')::bigint IS DISTINCT FROM NEW.fence OR o->'SourceVersion' IS DISTINCT FROM NEW.authority_json#>'{Scope,Version}' OR NEW.authority_json->'Scope' IS DISTINCT FROM s.scope_json OR (NEW.authority_json->>'ValidUntil')::timestamptz<NEW.lease_until OR (o->>'Until')::timestamptz<NEW.lease_until OR (o->>'Until')::timestamptz>w.run_until OR (o->>'WorkerPodUID') IS DISTINCT FROM (convert_from(w.binding_json,'UTF8')::jsonb)->>'PodUID' OR o->'WorkerPublicKey' IS DISTINCT FROM (convert_from(e.enrollment_json,'UTF8')::jsonb)->'PublicKeyDigest' OR e.audit_receipt_json IS NULL THEN RAISE EXCEPTION 'native operation binding mismatch' USING ERRCODE='23514';END IF;
 IF o->>'Kind' IN ('prepare-context','observe-prepared-context') THEN
  IF NEW.lease_sequence<>1 OR (o->>'Until')::timestamptz>(o->>'StartedAt')::timestamptz+interval '5 seconds' OR NOT EXISTS(SELECT 1 FROM public.download_batch p WHERE p.id=(o->>'ParentID')::uuid AND p.session_id=s.id AND p.generation=(o->>'Generation')::bigint AND p.intent_json#>>'{Batch,Purpose}'='prepare' AND p.audit_receipt_json IS NOT NULL) THEN RAISE EXCEPTION 'native preparation parent unavailable' USING ERRCODE='23514';END IF;
 ELSIF o->>'Kind'='read-context-response' THEN
  IF NOT EXISTS(SELECT 1 FROM public.download_response r WHERE r.id=(o->>'ParentID')::uuid AND r.session_id=s.id AND r.generation=(o->>'Generation')::bigint AND r.generation=s.generation AND NOT r.closed AND r.lease_sequence=NEW.lease_sequence AND r.lease_until>=NEW.lease_until AND r.until_at>n) THEN RAISE EXCEPTION 'native response parent unavailable' USING ERRCODE='23514';END IF;
 ELSE RAISE EXCEPTION 'unknown native operation' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.fence<>1 OR NEW.updates<>1 THEN RAISE EXCEPTION 'native initial fence' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET charged_rows=charged_rows+1 WHERE allocation_id=b.allocation_id;
 ELSE
  IF OLD.retired_at IS NOT NULL OR NEW.updates<>OLD.updates+1 OR ROW(NEW.worker_id,NEW.root_id,NEW.allocation_id) IS DISTINCT FROM ROW(OLD.worker_id,OLD.root_id,OLD.allocation_id) THEN RAISE EXCEPTION 'native immutable owner' USING ERRCODE='23514';END IF;
  IF NEW.operation_id=OLD.operation_id THEN
   IF OLD.closed OR NEW.operation_json IS DISTINCT FROM OLD.operation_json OR NEW.fence<>OLD.fence OR o->>'Kind'<>'read-context-response' OR NEW.lease_sequence<=OLD.lease_sequence THEN RAISE EXCEPTION 'native operation replay cannot renew' USING ERRCODE='23514';END IF;
  ELSIF NOT OLD.closed OR NEW.fence<>OLD.fence+1 THEN RAISE EXCEPTION 'native previous owner not closed' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_native_key() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.download_native_backing;o public.download_native_owner;w public.download_worker;s public.artifact_download;n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=OLD.allocation_id;
  SELECT * INTO STRICT o FROM public.download_native_owner WHERE worker_id=OLD.worker_id;
  SELECT * INTO STRICT w FROM public.download_worker WHERE id=OLD.worker_id;
  SELECT * INTO STRICT s FROM public.artifact_download WHERE id=w.session_id;
  b:=public.capacity_session_native(s,b);
  n:=clock_timestamp();
  IF o.retired_at IS NULL OR w.retired_proof_json IS NULL OR n<o.retired_at+make_interval(secs=>b.backup_horizon_seconds::double precision) THEN RAISE EXCEPTION 'native key history not quiescent' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET residual_until=GREATEST(residual_until,n+make_interval(secs=>b.backup_horizon_seconds::double precision)),overdue=overdue OR n+make_interval(secs=>b.backup_horizon_seconds::double precision)>b.retire_by WHERE allocation_id=b.allocation_id;RETURN OLD;
 END IF;
 SELECT * INTO STRICT o FROM public.download_native_owner WHERE worker_id=NEW.worker_id;
 SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=NEW.allocation_id FOR UPDATE;
 SELECT * INTO STRICT w FROM public.download_worker WHERE id=NEW.worker_id;
 SELECT * INTO STRICT s FROM public.artifact_download WHERE id=w.session_id;
 b:=public.capacity_session_native(s,b);
 n:=clock_timestamp();
 IF o.closed OR o.retired_at IS NOT NULL OR o.root_id<>NEW.root_id OR o.allocation_id<>NEW.allocation_id OR o.operation_id<>NEW.operation_id OR o.fence<>NEW.operation_fence OR NEW.valid_until>o.lease_until OR n>=NEW.valid_until OR NOT EXISTS(SELECT 1 FROM public.download_window win JOIN public.download_response r ON r.id=win.response_id JOIN public.artifact_download s ON s.id=r.session_id WHERE win.id=NEW.window_id AND r.id=(o.operation_json->>'ParentID')::uuid AND r.generation=(o.operation_json->>'Generation')::bigint AND r.generation=s.generation AND r.active_window=win.id AND NOT r.closed AND r.lease_until>=NEW.valid_until AND win.intent_receipt IS NOT NULL AND win.intent_completion IS NOT NULL AND win.outcome_json IS NULL AND NEW.authority_json->'Scope'=s.scope_json) THEN RAISE EXCEPTION 'native key current window unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF jsonb_typeof(NEW.authority_json->'ValidUntil') IS DISTINCT FROM 'string' OR jsonb_typeof(NEW.proof_json->'FreshUntil') IS DISTINCT FROM 'string' OR NEW.used_roles<>0 OR NEW.created_at>n OR NEW.valid_until>(NEW.authority_json->>'ValidUntil')::timestamptz OR NEW.valid_until>(NEW.proof_json->>'FreshUntil')::timestamptz OR NEW.installation_id IS DISTINCT FROM (o.operation_json#>>'{Reference,InstallationID}')::uuid OR NEW.peer_id IS DISTINCT FROM (o.operation_json->>'WorkerPodUID')::uuid THEN RAISE EXCEPTION 'native key identity mismatch' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET charged_keys=charged_keys+1 WHERE allocation_id=b.allocation_id;
 ELSIF (to_jsonb(NEW)-'used_roles') IS DISTINCT FROM (to_jsonb(OLD)-'used_roles') OR NEW.used_roles=OLD.used_roles OR NEW.used_roles|OLD.used_roles<>NEW.used_roles OR (NEW.used_roles#OLD.used_roles) NOT IN (1,2,4) THEN RAISE EXCEPTION 'native key slots immutable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- This is immutable installer provenance, not runtime source acceptance. The
-- SQL administrator's exact compiled-ACL verification occurs in the paired
-- transaction; the row independently retains/matches the original identities.
CREATE FUNCTION capacity_setup_original_valid(s public.capacity_source) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=s.setup_receipt;i jsonb:=s.setup_input;x jsonb;p jsonb;receipt jsonb;k text;
 purposes text[]:=ARRAY['capacity','capacity-capture','capacity-profile-read','capture-admit','capture-journal','capture-ack','capture-cleanup','capture-verifier','capture-finalizer','capture-intent-read'];
 ordinals integer[]:=ARRAY[70,71,34,40,41,42,43,44,45,16];
 a public.capture_audit_root;u pg_catalog.pg_roles;actual oid[]:='{}';at integer:=0;limit_value integer;
BEGIN
 IF NOT public.capacity_json_fields(v,ARRAY['format','operationID','installationID','initialClaimID','permissionRootID','roleRootUID','roleSetupID','inputDigest','databaseOID','postmasterAt','claimedAt','until']) OR
  NOT public.capacity_json_fields(i,ARRAY['format','installationID','initialClaimID','permissionRootID','roleRootUID','roleSetupID','controlClusterID','controlNamespaceUID','sourceGuardDigest','accountVersion','qualification']) OR
  v->>'format' IS DISTINCT FROM 'asservat-capacity-root-setup/v1' OR i->'format' IS DISTINCT FROM v->'format' OR
  NOT public.capacity_json_text(v->'inputDigest',64,64) OR v->>'inputDigest' !~ '^[0-9a-f]{64}$' OR v->>'inputDigest'=repeat('0',64) OR
  NOT public.capacity_json_integer(v->'databaseOID',1,4294967295) OR (v->>'databaseOID')::oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR
  NOT public.capacity_json_time(v->'postmasterAt') OR NOT public.incarnation_current((v->>'postmasterAt')::timestamptz) OR
  NOT public.capacity_json_time(v->'claimedAt') OR NOT public.capacity_json_time(v->'until') OR
  (v->>'postmasterAt')::timestamptz>(v->>'claimedAt')::timestamptz OR (v->>'until')::timestamptz<=(v->>'claimedAt')::timestamptz OR (v->>'until')::timestamptz>(v->>'claimedAt')::timestamptz+interval '5 seconds' OR
  jsonb_typeof(s.setup_roles) IS DISTINCT FROM 'array' OR jsonb_array_length(s.setup_roles)<>10 THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['operationID','installationID','initialClaimID','permissionRootID','roleRootUID','roleSetupID'] LOOP
  IF NOT public.capacity_json_uuid(v->k) THEN RETURN false;END IF;
  IF k<>'operationID' AND i->k IS DISTINCT FROM v->k THEN RETURN false;END IF;
 END LOOP;
 IF v->>'installationID' IS DISTINCT FROM s.installation_id::text OR v->>'permissionRootID' IS DISTINCT FROM s.root_id::text OR
  i->>'controlClusterID' IS DISTINCT FROM s.control_cluster_id::text OR i->>'controlNamespaceUID' IS DISTINCT FROM s.control_namespace_uid OR
  i->>'sourceGuardDigest' IS DISTINCT FROM encode(s.source_guard_digest,'hex') OR i->>'accountVersion' IS DISTINCT FROM s.account_version OR i->'qualification' IS DISTINCT FROM s.qualification OR
  NOT EXISTS(SELECT 1 FROM public.fleet_initial_activation f WHERE f.installation_id=s.installation_id AND f.claim_id=(v->>'initialClaimID')::uuid AND f.audit_receipt_json IS NOT NULL AND f.activated_at IS NOT NULL) THEN RETURN false;END IF;
 SELECT * INTO STRICT a FROM public.capture_audit_root WHERE root_id=s.root_id;
 IF a.installation_id<>s.installation_id THEN RETURN false;END IF;
 FOR x IN SELECT value FROM jsonb_array_elements(s.setup_roles) LOOP
  at:=at+1;receipt:=x->'Receipt';p:=x->'Provenance';
  IF NOT public.capacity_json_fields(x,ARRAY['Purpose','Receipt','Provenance']) OR x->>'Purpose' IS DISTINCT FROM purposes[at] OR
   NOT public.capacity_json_fields(receipt,ARRAY['roleName','roleOID','layoutDigest']) OR NOT public.capacity_json_integer(receipt->'roleOID',1,4294967295) OR
   receipt->>'roleName' IS DISTINCT FROM 'as_'||replace(s.installation_id::text,'-','')||'_pub_'||lpad(ordinals[at]::text,2,'0') OR
   NOT public.capacity_json_text(receipt->'layoutDigest',64,64) OR receipt->>'layoutDigest' !~ '^[0-9a-f]{64}$' OR receipt->>'layoutDigest'=repeat('0',64) OR
   NOT public.capacity_json_fields(p,ARRAY['Format','InstallationID','InitialClaimID','OwnerConfigurationUID','RootUID','SetupID','Purpose','LayoutDigest','OperationID','DatabaseOID','PostmasterAt','ClaimedAt','Until']) OR
   p->>'Format' IS DISTINCT FROM 'asservat-public-runtime-role/v1' OR p->'InstallationID' IS DISTINCT FROM v->'installationID' OR p->'InitialClaimID' IS DISTINCT FROM v->'initialClaimID' OR
   p->'RootUID' IS DISTINCT FROM v->'roleRootUID' OR p->'SetupID' IS DISTINCT FROM v->'roleSetupID' OR p->'DatabaseOID' IS DISTINCT FROM v->'databaseOID' OR
   p->'LayoutDigest' IS DISTINCT FROM receipt->'layoutDigest' OR p->>'Purpose' IS DISTINCT FROM purposes[at] OR
   NOT public.capacity_json_time(p->'PostmasterAt') OR (p->>'PostmasterAt')::timestamptz<>(v->>'postmasterAt')::timestamptz OR
   NOT public.capacity_json_time(p->'ClaimedAt') OR NOT public.capacity_json_time(p->'Until') OR
   (p->>'ClaimedAt')::timestamptz>(v->>'claimedAt')::timestamptz OR (p->>'Until')::timestamptz<=(p->>'ClaimedAt')::timestamptz OR (p->>'Until')::timestamptz>(p->>'ClaimedAt')::timestamptz+interval '5 seconds' THEN RETURN false;END IF;
  FOREACH k IN ARRAY ARRAY['OwnerConfigurationUID','OperationID'] LOOP IF NOT public.capacity_json_uuid(p->k) THEN RETURN false;END IF;END LOOP;
  limit_value:=CASE WHEN ordinals[at] IN(70,71,43,44,45) THEN 3 ELSE 5 END;
  SELECT * INTO STRICT u FROM pg_roles WHERE oid=(receipt->>'roleOID')::oid AND rolname=receipt->>'roleName';
  IF u.oid=ANY(actual) OR u.oid=10 OR NOT u.rolcanlogin OR u.rolinherit OR u.rolsuper OR u.rolcreatedb OR u.rolcreaterole OR u.rolreplication OR u.rolbypassrls OR u.rolconnlimit<>limit_value OR u.rolvaliduntil IS NOT NULL OR
   EXISTS(SELECT 1 FROM pg_auth_members WHERE member=u.oid OR roleid=u.oid) OR shobj_description(u.oid,'pg_authid')::jsonb IS DISTINCT FROM p THEN RETURN false;END IF;
  actual:=array_append(actual,u.oid);
 END LOOP;
 RETURN actual=ARRAY[s.writer_role,s.capture_role,s.audit_reader_role,a.admission_role,a.journal_role,a.acknowledge_role,a.cleanup_role,a.verifier_role,a.finalizer_role,a.reader_role] AND a.source_role=s.capture_role AND
  s.audit_reader_provenance=s.setup_roles#>'{2,Provenance}';
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_setup_original_valid(capacity_source) FROM PUBLIC;


-- +goose StatementBegin
-- These retained-row checks do not grant admission. They qualify the bounded
-- complete old configuration, including incompatible scopes, before selecting
-- a new revision. Every row/counter remains present and charged.
CREATE FUNCTION capacity_retained_workload_exact(s public.capacity_source,w public.capacity_workload) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE old_s public.capacity_source:=s;a public.custody_allocation;ca public.capture_audit_allocation;
BEGIN
 SELECT * INTO STRICT a FROM public.custody_allocation WHERE id=w.allocation_id;
 IF w.mutation_xid IS NOT NULL OR w.plan->>'RootID' IS DISTINCT FROM s.root_id::text OR w.plan->>'InstallationID' IS DISTINCT FROM s.installation_id::text OR
  w.plan->>'QualificationID' IS DISTINCT FROM s.qualification->>'ID' OR public.connector_digest(w.plan->'QualificationDigest') IS DISTINCT FROM s.qualification_digest OR
  a.valid_until>(s.root_configuration->>'PlannedUntil')::timestamptz THEN RETURN false;END IF;
 old_s.root_configuration:=jsonb_set(old_s.root_configuration,'{PlannedUntil}',to_jsonb(a.valid_until));
 IF NOT public.capacity_workload_general_exact(old_s,w,w.ready_at IS NOT NULL) THEN RETURN false;END IF;
 SELECT * INTO ca FROM public.capture_audit_allocation WHERE root_id=s.root_id AND allocation_id=w.allocation_id;
 IF w.capture_backed_at IS NULL THEN RETURN NOT FOUND;END IF;
 IF NOT FOUND OR ca.valid_until>a.valid_until OR (ca.policy->>'BackingRevision')::bigint>(s.root_configuration->>'Revision')::bigint THEN RETURN false;END IF;
 old_s.root_configuration:=old_s.root_configuration||jsonb_build_object('PlannedUntil',ca.valid_until,'Revision',ca.policy->'BackingRevision');
 RETURN public.capacity_workload_capture_exact(old_s,w);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

CREATE FUNCTION capacity_retained_inventory_valid(s public.capacity_source) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.capacity_pool;c public.capacity_cluster;ns public.capacity_namespace;w public.capacity_workload;count_work bigint;cluster_plan jsonb;namespace_plan jsonb;
BEGIN
 SELECT count(*) INTO count_work FROM public.capacity_workload WHERE root_id=s.root_id;
 IF count_work>LEAST(16,(s.root_plan#>>'{Input,Accounts}')::bigint) OR
  (SELECT count(*) FROM public.capacity_pool WHERE root_id=s.root_id)>jsonb_array_length(s.qualification->'Backends') OR
  (SELECT count(*) FROM public.context_control_account WHERE root_id=s.root_id)<>count_work OR
  (SELECT count(*) FROM public.context_storage_binding WHERE root_id=s.root_id)<>count_work OR
  (SELECT count(*) FROM public.download_allocation WHERE root_id=s.root_id)<>count_work OR
  (SELECT count(*) FROM public.download_control_allocation WHERE root_id=s.root_id)<>count_work OR
  (SELECT count(*) FROM public.download_native_backing WHERE root_id=s.root_id)<>count_work OR
  (SELECT count(*) FROM public.download_stop_backing WHERE root_id=s.root_id)<>count_work OR
  (SELECT count(*) FROM public.capture_audit_allocation WHERE root_id=s.root_id)<>(SELECT count(*) FROM public.capacity_workload WHERE root_id=s.root_id AND capture_backed_at IS NOT NULL) THEN RETURN false;END IF;
 FOR p IN SELECT * FROM public.capacity_pool WHERE root_id=s.root_id ORDER BY id LOOP
  IF p.protected_bytes IS DISTINCT FROM (p.plan#>>'{Protected,Bytes}')::bigint OR p.protected_objects IS DISTINCT FROM (p.plan#>>'{Protected,Objects}')::bigint OR
   p.shared_bytes IS DISTINCT FROM (p.plan#>>'{Burst,Bytes}')::bigint OR p.shared_objects IS DISTINCT FROM (p.plan#>>'{Burst,Objects}')::bigint OR
   p.system_bytes IS DISTINCT FROM (p.plan#>>'{System,Bytes}')::bigint OR p.system_objects IS DISTINCT FROM (p.plan#>>'{System,Objects}')::bigint OR
   p.account_limit IS DISTINCT FROM (p.plan->>'AccountLimit')::bigint OR p.namespace_limit IS DISTINCT FROM (p.plan->>'NamespaceLimit')::bigint OR
   p.source_uid IS DISTINCT FROM p.plan->>'UID' OR p.source_name IS DISTINCT FROM p.plan->>'Name' OR p.source_generation IS DISTINCT FROM (p.plan->>'Generation')::bigint OR p.source_digest IS DISTINCT FROM public.connector_digest(p.plan->'Digest') OR
   NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s.qualification->'Backends') b JOIN public.custody_pool cp ON cp.id=p.id
    WHERE b->>'ID'=p.backend_qualification_id::text AND public.connector_digest(b->'Digest')=p.backend_qualification_digest AND b->>'CapacityID'=p.backend_capacity_id::text AND b->>'PoolID'=p.id::text AND b->>'EvidenceStoreID'=cp.store_id::text AND
     cp.byte_limit=p.protected_bytes+p.shared_bytes AND cp.object_limit=p.protected_objects+p.shared_objects AND cp.valid_until<=(s.root_configuration->>'PlannedUntil')::timestamptz) THEN RETURN false;END IF;
  IF p.accounts<>(SELECT count(*) FROM public.capacity_workload WHERE root_id=s.root_id AND pool_id=p.id) OR
   jsonb_array_length(p.plan->'Clusters')<>(SELECT count(*) FROM public.capacity_cluster WHERE root_id=s.root_id AND pool_id=p.id) OR
   p.namespaces<>(SELECT count(*) FROM public.capacity_namespace WHERE root_id=s.root_id AND pool_id=p.id) OR
   p.backed_bytes<>(SELECT COALESCE(sum(protected_bytes),0) FROM public.capacity_workload WHERE root_id=s.root_id AND pool_id=p.id) OR
   p.backed_objects<>(SELECT COALESCE(sum(protected_objects),0) FROM public.capacity_workload WHERE root_id=s.root_id AND pool_id=p.id) OR
   (SELECT count(*) FROM public.custody_allocation WHERE pool_id=p.id)<>p.accounts OR
   NOT EXISTS(SELECT 1 FROM public.custody_pool cp WHERE cp.id=p.id AND cp.allocated_bytes=(SELECT COALESCE(sum(byte_limit),0) FROM public.custody_allocation WHERE pool_id=p.id) AND cp.allocated_objects=(SELECT COALESCE(sum(object_limit),0) FROM public.custody_allocation WHERE pool_id=p.id)) THEN RETURN false;END IF;
  IF p.source_uid=s.root_plan#>>'{Input,SystemPoolUID}' THEN
   IF p.backed_system_bytes IS DISTINCT FROM (s.root_plan#>>'{Totals,SystemObjects,Bytes}')::bigint OR
    p.backed_system_objects IS DISTINCT FROM (s.root_plan#>>'{Totals,SystemObjects,Objects}')::bigint THEN RETURN false;END IF;
  ELSIF p.backed_system_bytes<>0 OR p.backed_system_objects<>0 THEN RETURN false;END IF;
 END LOOP;
 FOR c IN SELECT * FROM public.capacity_cluster WHERE root_id=s.root_id ORDER BY pool_id,cluster_id LOOP
  SELECT entry INTO STRICT cluster_plan FROM public.capacity_pool stored_pool CROSS JOIN LATERAL jsonb_array_elements(stored_pool.plan->'Clusters') entry
   WHERE stored_pool.root_id=s.root_id AND stored_pool.id=c.pool_id AND entry->>'ClusterID'=c.cluster_id::text;
  IF c.protected_bytes IS DISTINCT FROM (cluster_plan->>'ProtectedBytes')::bigint OR c.protected_objects IS DISTINCT FROM (cluster_plan->>'ProtectedObjects')::bigint OR
   c.byte_limit IS DISTINCT FROM (cluster_plan->>'ByteLimit')::bigint OR c.object_limit IS DISTINCT FROM (cluster_plan->>'ObjectLimit')::bigint OR
   c.account_limit IS DISTINCT FROM (cluster_plan->>'AccountLimit')::bigint OR c.namespace_limit<>c.account_limit OR
   c.accounts<>(SELECT count(*) FROM public.capacity_workload WHERE root_id=s.root_id AND pool_id=c.pool_id AND cluster_id=c.cluster_id) OR
   c.namespaces<>(SELECT count(*) FROM public.capacity_namespace WHERE root_id=s.root_id AND pool_id=c.pool_id AND cluster_id=c.cluster_id) OR
   c.backed_bytes<>(SELECT COALESCE(sum(protected_bytes),0) FROM public.capacity_workload WHERE root_id=s.root_id AND pool_id=c.pool_id AND cluster_id=c.cluster_id) OR
   c.backed_objects<>(SELECT COALESCE(sum(protected_objects),0) FROM public.capacity_workload WHERE root_id=s.root_id AND pool_id=c.pool_id AND cluster_id=c.cluster_id) THEN RETURN false;END IF;
 END LOOP;
 FOR ns IN SELECT * FROM public.capacity_namespace WHERE root_id=s.root_id ORDER BY pool_id,cluster_id,namespace_uid LOOP
  SELECT plan->'Budget' INTO STRICT namespace_plan FROM public.capacity_workload
   WHERE root_id=s.root_id AND pool_id=ns.pool_id AND cluster_id=ns.cluster_id AND namespace_uid=ns.namespace_uid ORDER BY id LIMIT 1;
  IF ns.accounts<1 OR ns.byte_limit IS DISTINCT FROM (namespace_plan#>>'{NamespaceMaximum,Bytes}')::bigint OR ns.object_limit IS DISTINCT FROM (namespace_plan#>>'{NamespaceMaximum,Objects}')::bigint OR
   ns.account_limit IS DISTINCT FROM (namespace_plan->>'NamespaceAccounts')::bigint OR
   EXISTS(SELECT 1 FROM public.capacity_workload child WHERE child.root_id=s.root_id AND child.pool_id=ns.pool_id AND child.cluster_id=ns.cluster_id AND child.namespace_uid=ns.namespace_uid AND
    (child.plan#>'{Budget,NamespaceMaximum}' IS DISTINCT FROM namespace_plan->'NamespaceMaximum' OR child.plan#>'{Budget,NamespaceAccounts}' IS DISTINCT FROM namespace_plan->'NamespaceAccounts')) OR
   ns.accounts<>(SELECT count(*) FROM public.capacity_workload WHERE root_id=s.root_id AND pool_id=ns.pool_id AND cluster_id=ns.cluster_id AND namespace_uid=ns.namespace_uid) OR
   ns.backed_bytes<>(SELECT COALESCE(sum(protected_bytes),0) FROM public.capacity_workload WHERE root_id=s.root_id AND pool_id=ns.pool_id AND cluster_id=ns.cluster_id AND namespace_uid=ns.namespace_uid) OR
   ns.backed_objects<>(SELECT COALESCE(sum(protected_objects),0) FROM public.capacity_workload WHERE root_id=s.root_id AND pool_id=ns.pool_id AND cluster_id=ns.cluster_id AND namespace_uid=ns.namespace_uid) THEN RETURN false;END IF;
 END LOOP;
 FOR w IN SELECT * FROM public.capacity_workload WHERE root_id=s.root_id ORDER BY id LOOP
  IF NOT public.capacity_retained_workload_exact(s,w) THEN RETURN false;END IF;
 END LOOP;
 RETURN EXISTS(SELECT 1 FROM public.context_control_pool cp WHERE cp.root_id=s.root_id AND
  cp.backed_full=(SELECT COALESCE(sum(full_limit),0) FROM public.context_control_account WHERE root_id=s.root_id) AND cp.backed_replay=(SELECT COALESCE(sum(replay_limit),0) FROM public.context_control_account WHERE root_id=s.root_id));
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

-- Recovery and permission are already held before this fixed lock order.
-- This joins prior SQL configuration, including unknown client replies. It
-- does not join any external evidence writer, release spend or close sessions.
CREATE FUNCTION capacity_lock_retained_configuration(s public.capacity_source) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF s.root_mutation_xid IS NOT NULL OR (SELECT count(*) FROM public.capacity_workload WHERE root_id=s.root_id)>16 THEN RAISE EXCEPTION 'capacity retained inventory unavailable' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.capacity_pool WHERE root_id=s.root_id ORDER BY id FOR UPDATE;
 PERFORM 1 FROM public.capacity_cluster WHERE root_id=s.root_id ORDER BY pool_id,cluster_id FOR UPDATE;
 PERFORM 1 FROM public.capacity_namespace WHERE root_id=s.root_id ORDER BY pool_id,cluster_id,namespace_uid FOR UPDATE;
 PERFORM 1 FROM public.capacity_workload WHERE root_id=s.root_id ORDER BY id FOR UPDATE;
 PERFORM 1 FROM public.custody_pool WHERE id IN(SELECT id FROM public.capacity_pool WHERE root_id=s.root_id) ORDER BY id FOR UPDATE;
 PERFORM 1 FROM public.context_control_pool WHERE root_id=s.root_id FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=s.root_id AND lane IN('normal','processing','resolution','capture') ORDER BY lane FOR UPDATE;
 PERFORM 1 FROM public.processing_root WHERE root_id=s.root_id FOR UPDATE;
 PERFORM 1 FROM public.download_stop_pool WHERE root_id=s.root_id FOR UPDATE;
 PERFORM 1 FROM public.custody_allocation WHERE id IN(SELECT allocation_id FROM public.capacity_workload WHERE root_id=s.root_id) ORDER BY id FOR UPDATE;
 PERFORM 1 FROM public.context_control_account WHERE root_id=s.root_id ORDER BY allocation_id FOR UPDATE;
 PERFORM 1 FROM public.download_allocation WHERE root_id=s.root_id ORDER BY id FOR UPDATE;
 PERFORM 1 FROM public.download_control_allocation WHERE root_id=s.root_id ORDER BY id FOR UPDATE;
 PERFORM 1 FROM public.download_native_backing WHERE root_id=s.root_id ORDER BY allocation_id FOR UPDATE;
 PERFORM 1 FROM public.download_stop_backing WHERE root_id=s.root_id ORDER BY allocation_id FOR UPDATE;
 PERFORM 1 FROM public.capture_audit_root WHERE root_id=s.root_id FOR UPDATE;
 PERFORM 1 FROM public.capture_audit_allocation WHERE root_id=s.root_id ORDER BY allocation_id FOR UPDATE;
END $$;

CREATE FUNCTION renew_capacity_root(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,expected jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;c jsonb;previous jsonb;reconciled bytea;receipts jsonb;n timestamptz;until_at timestamptz;planned timestamptz;
 p public.capacity_pool;w public.capacity_workload;input_value jsonb;native jsonb;work jsonb;backing_value jsonb;policy jsonb;zero_digest jsonb:=to_jsonb(array_fill(0,ARRAY[32]));
BEGIN
 until_at:=public.capacity_lock_root_observation(r,'capacity',o,plan_bytes,pool_bytes);
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;c:=s.root_configuration;
 IF c IS NULL OR NOT public.capacity_root_configuration_matches(c,expected) OR c->'ReconciledAt'<>'null'::jsonb OR NOT public.capacity_root_general_exact(s) OR
  c->'CaptureBackedAt'<>'null'::jsonb AND NOT public.capacity_root_capture_exact(s) THEN RAISE EXCEPTION 'capacity renewal predecessor unavailable' USING ERRCODE='23514';END IF;
 PERFORM public.capacity_lock_retained_configuration(s);
 n:=clock_timestamp();
 IF n>=until_at OR NOT public.capacity_retained_inventory_valid(s) THEN RAISE EXCEPTION 'capacity renewal inventory or original interval unavailable' USING ERRCODE='23514';END IF;
 -- Renewal is bounded maintenance near the original end, not a high-rate
 -- caller-controlled configuration bump. Exact early replay is read-only.
 IF n+interval '10 seconds'<(c->>'PlannedUntil')::timestamptz THEN RETURN jsonb_build_object('Configuration',c,'FreshUntil',until_at);END IF;
 input_value:=s.root_plan->'Input';planned:=(o->>'ObservedAt')::timestamptz+make_interval(secs=>(input_value->>'AdmissionSeconds')::double precision);
 IF planned<=(c->>'PlannedUntil')::timestamptz OR n>=planned THEN RAISE EXCEPTION 'capacity renewal cannot reset an interval' USING ERRCODE='23514';END IF;
 SELECT COALESCE(jsonb_agg(public.capacity_enrollment_receipt(x) ORDER BY x.id),'[]'::jsonb) INTO receipts FROM public.capacity_workload x WHERE root_id=r;
 reconciled:=sha256(convert_to('asservat-capacity-reconciliation/jsonb-v1','UTF8')||decode('00','hex')||convert_to(jsonb_build_object('Configuration',c,'PlanDigest',c->'PlanDigest','Enrollments',receipts)::text,'UTF8'));
 UPDATE public.capacity_source SET root_mutation_xid=pg_current_xact_id(),configuration_spent=configuration_spent+1 WHERE root_id=r;
 previous:=c||jsonb_build_object('ReconciledAt',n,'ReconciledDigest',to_jsonb(ARRAY(SELECT get_byte(reconciled,k) FROM generate_series(0,31) k)));
 UPDATE public.capacity_source SET root_configuration=previous WHERE root_id=r;
 c:=c||jsonb_build_object('Revision',(c->>'Revision')::bigint+1,'RevisionObservedAt',o->'ObservedAt','RevisionUntil',until_at,'PlannedUntil',planned,'ReservedAt',clock_timestamp(),
  'CaptureBackedAt',NULL,'ReadyAt',NULL,'ReconciledAt',NULL,'PreviousDigest',previous->'ReconciledDigest','ReconciledDigest',zero_digest);
 UPDATE public.capacity_source SET root_configuration=c WHERE root_id=r RETURNING * INTO s;
 -- Funding is retained for every scope. Only exactly compatible pools acquire
 -- future dates; malformed root accounting above is never skipped as a policy
 -- incompatibility. An incompatible child remains in the inventory/charges.
 FOR p IN SELECT * FROM public.capacity_pool WHERE root_id=r ORDER BY id LOOP
  IF public.capacity_compile_pool(s.accepted_snapshot,p.source_name) IS DISTINCT FROM p.plan OR public.capacity_backend_for(s,p.plan) IS NULL THEN CONTINUE;END IF;
  UPDATE public.custody_pool SET revision=(c->>'Revision')::bigint,valid_until=planned WHERE id=p.id;
 END LOOP;
 UPDATE public.context_control_pool SET revision=revision+1,valid_until=planned WHERE root_id=r;
 UPDATE public.operation_audit_pool SET revision=revision+1,valid_until=planned WHERE root_id=r AND lane IN('normal','processing','resolution');
 backing_value:=(input_value->'ProcessingState')||jsonb_build_object('ValidUntil',planned,'RetireBy',planned+make_interval(secs=>(2*(input_value->'ProcessingState'->>'BackupHorizonSeconds')::bigint+(input_value->'ProcessingState'->>'CleanupSeconds')::bigint)::double precision));
 policy:=(input_value->'Processing'->'Policy')||jsonb_build_object('BackingRevision',c->'Revision','ValidUntil',public.capacity_json_timestamp(planned));
 UPDATE public.processing_root SET backing=backing_value,release_policy=policy,valid_until=planned,retire_by=(backing_value->>'RetireBy')::timestamptz,backing_revision=backing_revision+1,root_transitions=root_transitions+1,sequence=sequence+1 WHERE root_id=r;
 UPDATE public.download_stop_pool SET revision=revision+1,valid_until=planned WHERE root_id=r;
 FOR w IN SELECT * FROM public.capacity_workload WHERE root_id=r ORDER BY id LOOP
  SELECT * INTO STRICT p FROM public.capacity_pool WHERE root_id=r AND id=w.pool_id;
  IF public.capacity_compile_pool(s.accepted_snapshot,p.source_name) IS DISTINCT FROM p.plan OR public.capacity_backend_for(s,p.plan) IS NULL THEN CONTINUE;END IF;
  UPDATE public.capacity_workload SET mutation_xid=pg_current_xact_id() WHERE id=w.id;
  UPDATE public.custody_allocation SET revision=revision+1,valid_until=planned WHERE id=w.allocation_id;
  UPDATE public.context_control_account SET revision=revision+1,valid_until=planned WHERE root_id=r AND allocation_id=w.allocation_id;
  UPDATE public.download_allocation SET valid_until=planned WHERE id=w.download_allocation_id;
  UPDATE public.download_control_allocation SET valid_until=planned,audit_write_until=planned+interval '30 seconds' WHERE id=w.download_allocation_id;
  work:=public.capacity_context_protocol_backing(w.plan#>'{Budget,Context}',s.root_plan#>'{Input,ContextHistory}');native:=public.capacity_native_plan(s,w.download_allocation_id,work);
  UPDATE public.download_native_backing SET policy_json=native,valid_until=planned,retire_by=(native->>'RetireBy')::timestamptz,residual_until=GREATEST(residual_until,(native->>'RetireBy')::timestamptz) WHERE allocation_id=w.download_allocation_id;
  UPDATE public.capacity_workload SET mutation_xid=NULL WHERE id=w.id;
  IF clock_timestamp()>=until_at OR NOT public.capacity_workload_general_exact(s,w,w.ready_at IS NOT NULL) THEN RAISE EXCEPTION 'capacity child renewal changed or expired' USING ERRCODE='23514';END IF;
 END LOOP;
 IF clock_timestamp()>=until_at OR NOT public.capacity_root_general_exact(s) OR NOT public.capacity_retained_inventory_valid(s) THEN RAISE EXCEPTION 'capacity renewal changed or expired after effects' USING ERRCODE='23514';END IF;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity renewal expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Configuration',c,'FreshUntil',until_at);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_retained_workload_exact(capacity_source,capacity_workload),capacity_retained_inventory_valid(capacity_source),capacity_lock_retained_configuration(capacity_source),renew_capacity_root(uuid,jsonb,bytea,bytea,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_previous_capture_exact(s public.capacity_source) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE old_s public.capacity_source:=s;p public.operation_audit_pool;
BEGIN
 SELECT * INTO p FROM public.operation_audit_pool WHERE root_id=s.root_id AND lane='capture';
 IF NOT FOUND THEN RETURN NOT EXISTS(SELECT 1 FROM public.capture_audit_allocation WHERE root_id=s.root_id);END IF;
 IF p.revision>(s.root_configuration->>'Revision')::bigint OR p.valid_until>(s.root_configuration->>'PlannedUntil')::timestamptz THEN RETURN false;END IF;
 old_s.root_configuration:=old_s.root_configuration||jsonb_build_object('Revision',p.revision,'PlannedUntil',p.valid_until);
 RETURN public.capacity_root_capture_exact(old_s);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;

-- Only this closed source71 phase may skip unused *configuration* revision
-- numbers after a partially completed revision expired. No audit record, old
-- policy binding, original receipt or account spend is rewritten by it.
CREATE FUNCTION capacity_capture_pool_revision(v public.operation_audit_pool) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;c jsonb;p jsonb;n timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=v.root_id;c:=s.root_configuration;p:=s.root_plan#>'{Input,Capture}';
 RETURN COALESCE(v.lane='capture' AND public.capacity_role_ok(v.root_id,'capacity-capture') AND public.capture_audit_role_ok(v.root_id,'source') AND
  s.root_mutation_xid=pg_current_xact_id() AND NOT s.suspended AND s.observed_at<=n AND n<s.fresh_until AND public.capacity_root_configuration_valid(c) AND
  c->'CaptureBackedAt'='null'::jsonb AND c->'ReadyAt'='null'::jsonb AND c->'ReconciledAt'='null'::jsonb AND
  v.revision=(c->>'Revision')::bigint AND NOT v.paused AND v.valid_until=(c->>'PlannedUntil')::timestamptz AND n<v.valid_until AND v.account_version=s.account_version AND
  v.account_limit=(p->>'Accounts')::bigint AND v.records_per_account=(p->>'RecordsPerAccount')::bigint AND v.retained_seconds=(p->>'RetainedSeconds')::bigint,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_previous_capture_exact(capacity_source),capacity_capture_pool_revision(operation_audit_pool) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION back_capacity_root(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,expected jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE until_at timestamptz;s public.capacity_source;c jsonb;v jsonb;n timestamptz;p public.operation_audit_pool;w public.capacity_workload;policy_value jsonb;pool_exists boolean;
BEGIN
 until_at:=public.capacity_lock_root_observation(r,'capacity-capture',o,plan_bytes,pool_bytes);
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;c:=s.root_configuration;v:=s.root_plan#>'{Input,Capture}';
 IF c IS NULL OR NOT public.capacity_root_configuration_matches(c,expected) OR c->'ReconciledAt'<>'null'::jsonb OR NOT public.capture_audit_role_ok(r,'source') OR NOT public.capacity_root_general_exact(s) THEN
  RAISE EXCEPTION 'capacity capture root original state unavailable' USING ERRCODE='23514';END IF;
 PERFORM public.capacity_lock_retained_configuration(s);
 n:=clock_timestamp();until_at:=LEAST(until_at,(c->>'PlannedUntil')::timestamptz);
 IF n>=until_at OR NOT public.capacity_retained_inventory_valid(s) OR NOT public.capacity_previous_capture_exact(s) THEN RAISE EXCEPTION 'capacity capture root retained backing unavailable' USING ERRCODE='23514';END IF;
 IF c->'CaptureBackedAt'<>'null'::jsonb THEN
  IF NOT public.capacity_root_capture_exact(s) THEN RAISE EXCEPTION 'capacity capture root replay mismatch' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('Configuration',c,'FreshUntil',until_at);
 END IF;
 SELECT * INTO p FROM public.operation_audit_pool WHERE root_id=r AND lane='capture';pool_exists:=FOUND;
 IF pool_exists AND (p.revision>=(c->>'Revision')::bigint OR p.valid_until>=(c->>'PlannedUntil')::timestamptz) THEN RAISE EXCEPTION 'capacity capture root unknown revision' USING ERRCODE='23514';END IF;
 UPDATE public.capacity_source SET root_mutation_xid=pg_current_xact_id(),configuration_spent=configuration_spent+1 WHERE root_id=r;
 UPDATE public.capture_audit_root SET valid_until=(c->>'PlannedUntil')::timestamptz,paused=false,revision=revision+1 WHERE root_id=r;
 IF NOT pool_exists THEN
  INSERT INTO public.operation_audit_pool(root_id,lane,account_version,revision,paused,valid_until,account_limit,records_per_account,retained_seconds)
  VALUES(r,'capture',s.account_version,(c->>'Revision')::bigint,false,(c->>'PlannedUntil')::timestamptz,(v->>'Accounts')::bigint,(v->>'RecordsPerAccount')::bigint,(v->>'RetainedSeconds')::bigint);
 ELSE
  UPDATE public.operation_audit_pool SET revision=(c->>'Revision')::bigint,valid_until=(c->>'PlannedUntil')::timestamptz WHERE root_id=r AND lane='capture';
 END IF;
 policy_value:=(v->'Policy')||jsonb_build_object('BackingRevision',c->'Revision','ValidUntil',public.capacity_json_timestamp((c->>'PlannedUntil')::timestamptz));
 FOR w IN SELECT * FROM public.capacity_workload WHERE root_id=r AND capture_backed_at IS NOT NULL ORDER BY id LOOP
  -- A preceding general phase selected exactly compatible scopes. Others keep
  -- their old dates/charges and fail the shared current-revision admission gate.
  IF NOT public.capacity_workload_general_exact(s,w,w.ready_at IS NOT NULL) THEN CONTINUE;END IF;
  UPDATE public.capture_audit_allocation SET revision=revision+1,valid_until=(c->>'PlannedUntil')::timestamptz,policy=policy_value WHERE root_id=r AND allocation_id=w.allocation_id;
  IF clock_timestamp()>=until_at OR NOT public.capacity_workload_capture_exact(s,w) THEN RAISE EXCEPTION 'capacity capture child renewal unavailable' USING ERRCODE='23514';END IF;
 END LOOP;
 n:=clock_timestamp();IF n>=until_at OR NOT public.capacity_root_capture_exact(s) OR NOT public.capacity_retained_inventory_valid(s) THEN RAISE EXCEPTION 'capacity capture root expired after effect' USING ERRCODE='23514';END IF;
 c:=jsonb_set(c,'{CaptureBackedAt}',to_jsonb(n));
 UPDATE public.capacity_source SET root_configuration=c WHERE root_id=r;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity capture root expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Configuration',c,'FreshUntil',until_at);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit_pool() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.lane='capture' AND NEW.proof_window_missed=0 AND NEW.accounts=0 AND NEW.history_profile IS NULL AND NEW.history_backing_until IS NULL AND public.capacity_capture_pool_revision(NEW) THEN RETURN NEW;END IF;
 IF TG_OP='UPDATE' AND NEW.lane='capture' AND (to_jsonb(NEW)-ARRAY['revision','valid_until']) IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['revision','valid_until']) AND
  NEW.revision>OLD.revision AND NEW.valid_until>OLD.valid_until AND public.capacity_capture_pool_revision(NEW) THEN RETURN NEW;END IF;
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
 IF EXISTS(SELECT 1 FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND charged>NEW.records_per_account) THEN
  RAISE EXCEPTION 'audit backing below retained spend' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION back_capacity_root(uuid,jsonb,bytea,bytea,jsonb) FROM PUBLIC;

-- +goose StatementBegin
-- A Ready receipt never refreshes workload metadata by itself. This fixed
-- source70 operation consumes an independently current exact observation and
-- changes only the existing binding's observation dates. It cannot recreate
-- missing enrollment, move scope, clear spend, or edit original phase facts.
CREATE FUNCTION refresh_capacity_enrollment(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb;s public.capacity_source;w public.capacity_workload;b public.context_storage_binding;until_at timestamptz;n timestamptz;observed timestamptz;
BEGIN
 result:=public.capacity_read_enrollment(r,'capacity',o,plan_bytes,pool_bytes,source_bytes);until_at:=(result->>'FreshUntil')::timestamptz;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT w FROM public.capacity_workload WHERE root_id=r AND id=(expected->>'ID')::uuid FOR UPDATE;
 IF w.ready_at IS NULL OR w.mutation_xid IS NOT NULL OR s.root_mutation_xid IS NOT NULL OR NOT public.capacity_enrollment_matches(w,expected) OR
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
  RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt(w),'FreshUntil',until_at);
 END IF;
 UPDATE public.capacity_source SET configuration_spent=configuration_spent+1,root_mutation_xid=pg_current_xact_id() WHERE root_id=r;
 UPDATE public.context_storage_binding SET observed_at=observed,fresh_until=until_at WHERE root_id=r AND allocation_id=w.allocation_id;
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity observation expired before commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt(w),'FreshUntil',until_at);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION refresh_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_capacity_recovery(r uuid,observed timestamptz,original_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;until_at timestamptz;n timestamptz;result jsonb;
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') OR NOT isfinite(observed) OR NOT isfinite(original_until) OR
  original_until<=observed OR original_until>observed+interval '5 seconds' THEN
  RAISE EXCEPTION 'capacity recovery observation unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 until_at:=LEAST(original_until,t.fresh_until);n:=clock_timestamp();
 IF observed>n OR n>=until_at OR t.suspended OR t.recovery_blocked OR t.observed_at>n OR t.fresh_until<=t.observed_at OR
  t.fresh_until>t.observed_at+interval '30 seconds' OR NOT public.capacity_setup_original_valid(s) THEN
  RAISE EXCEPTION 'capacity recovery unavailable after locks' USING ERRCODE='23514';END IF;
 result:=jsonb_build_object('InstallationID',s.installation_id,'IssuerEpoch',t.issuer_epoch,
  'Revision',jsonb_build_object('UID',t.source_uid,'Generation',t.source_generation,
   'Digest',to_jsonb(ARRAY(SELECT get_byte(t.source_digest,k) FROM generate_series(0,31) k))),
  'ObservedAt',observed,'FreshUntil',until_at);
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity recovery expired after read' USING ERRCODE='23514';END IF;
 RETURN result;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_capacity_recovery(uuid,timestamptz,timestamptz) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_capacity_runtime_scope(r uuid,expected jsonb,qualified jsonb,observed timestamptz,original_until timestamptz) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;t public.fleet_current_trust;until_at timestamptz;n timestamptz;
BEGIN
 IF NOT (public.capacity_role_ok(r,'capacity') OR public.capacity_role_ok(r,'capacity-capture')) OR
  NOT isfinite(observed) OR NOT isfinite(original_until) OR original_until<=observed OR original_until>observed+interval '5 seconds' OR
  octet_length(expected::text)>4096 OR octet_length(qualified::text)>131072 THEN
  RAISE EXCEPTION 'capacity runtime original scope unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR SHARE;
 until_at:=LEAST(original_until,t.fresh_until);n:=clock_timestamp();
 IF observed>n OR n>=until_at OR t.suspended OR t.recovery_blocked OR t.observed_at>n OR t.fresh_until<=t.observed_at OR
  t.fresh_until>t.observed_at+interval '30 seconds' OR s.setup_receipt IS DISTINCT FROM expected OR s.qualification IS DISTINCT FROM qualified OR
  NOT public.capacity_setup_original_valid(s) THEN
  RAISE EXCEPTION 'capacity runtime original scope changed' USING ERRCODE='23514';END IF;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity runtime scope expired after read' USING ERRCODE='23514';END IF;
 RETURN until_at;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_capacity_runtime_scope(uuid,jsonb,jsonb,timestamptz,timestamptz) FROM PUBLIC;
