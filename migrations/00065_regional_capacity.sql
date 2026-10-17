-- +goose Up
-- ADR-197: regional capacity. Write-once cluster qualifications extend the
-- immutable capacity qualification's namespace guards for regional clusters,
-- and an additive pool revision lets a regional budget policy extend the
-- system pool while every existing policy and cluster entry stays
-- byte-identical. Existing enrollments keep their original plans; the
-- revision chain proves they are unchanged under the extended pool.

-- One row per regional cluster, written by the hub-api from the guarded
-- cluster catalog. The digest is the region's assertion; runtime observation
-- compares it with the live guard (ADR-197 decision 6).
CREATE TABLE capacity_cluster_qualification (
 root_id uuid NOT NULL REFERENCES capacity_source(root_id),
 cluster_id uuid NOT NULL,
 peer_id uuid NOT NULL, issuer_epoch uuid NOT NULL,
 guard_digest bytea NOT NULL CHECK(octet_length(guard_digest)=32 AND guard_digest<>decode(repeat('00',32),'hex')),
 guard_keys jsonb NOT NULL CHECK(jsonb_typeof(guard_keys)='array' AND jsonb_array_length(guard_keys) BETWEEN 1 AND 256 AND octet_length(guard_keys::text)<=131072),
 qualified_at timestamptz NOT NULL,
 PRIMARY KEY(root_id,cluster_id), UNIQUE(root_id,peer_id)
);
-- Every superseded plan of an extended pool; at most 16 revisions.
CREATE TABLE capacity_pool_revision (
 root_id uuid NOT NULL, pool_id uuid NOT NULL,
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 16),
 plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object' AND octet_length(plan::text)<=65536),
 plan_digest bytea NOT NULL CHECK(octet_length(plan_digest)=32),
 superseded_at timestamptz NOT NULL,
 PRIMARY KEY(root_id,pool_id,revision), UNIQUE(root_id,pool_id,plan_digest),
 FOREIGN KEY(root_id,pool_id) REFERENCES capacity_pool(root_id,id)
);
REVOKE ALL ON capacity_cluster_qualification,capacity_pool_revision FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_capacity_append_only() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'capacity regional qualification and pool revisions are write-once' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_capacity_append_only() FROM PUBLIC;
CREATE TRIGGER guard_capacity_append_only BEFORE UPDATE OR DELETE ON capacity_cluster_qualification FOR EACH ROW EXECUTE FUNCTION guard_capacity_append_only();
CREATE TRIGGER guard_capacity_append_only BEFORE UPDATE OR DELETE ON capacity_pool_revision FOR EACH ROW EXECUTE FUNCTION guard_capacity_append_only();

-- +goose StatementBegin
-- The hub-api's narrow writer (purpose regional-capacity). An existing row
-- is replayed exactly or refused; the hub cluster's original pin is never
-- shadowed and the root keeps at most sixteen guarded clusters.
CREATE FUNCTION qualify_capacity_cluster(r uuid,cluster uuid,peer uuid,epoch uuid,digest bytea,keys jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;q public.capacity_cluster_qualification;k jsonb;previous text;
BEGIN
 IF r IS NULL OR cluster IS NULL OR peer IS NULL OR epoch IS NULL OR digest IS NULL OR octet_length(digest)<>32 OR digest=decode(repeat('00',32),'hex') OR
  jsonb_typeof(keys) IS DISTINCT FROM 'array' OR jsonb_array_length(keys) NOT BETWEEN 1 AND 256 OR octet_length(keys::text)>131072 THEN
  RAISE EXCEPTION 'capacity cluster qualification invalid' USING ERRCODE='23514';END IF;
 FOR k IN SELECT value FROM jsonb_array_elements(keys) LOOP
  IF NOT public.capacity_json_text(k,1,253) OR previous IS NOT NULL AND (k#>>'{}') COLLATE "C"<=previous COLLATE "C" THEN
   RAISE EXCEPTION 'capacity cluster qualification keys invalid' USING ERRCODE='23514';END IF;
  previous:=k#>>'{}';
 END LOOP;
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r FOR UPDATE;
 SELECT * INTO q FROM public.capacity_cluster_qualification WHERE root_id=r AND cluster_id=cluster;
 IF FOUND THEN
  IF ROW(q.peer_id,q.issuer_epoch,q.guard_digest,q.guard_keys) IS DISTINCT FROM ROW(peer,epoch,digest,keys) THEN
   RAISE EXCEPTION 'capacity cluster qualification is write-once' USING ERRCODE='23514';END IF;
  RETURN false;
 END IF;
 IF cluster=s.control_cluster_id OR jsonb_typeof(s.qualification->'NamespaceGuards') IS DISTINCT FROM 'array' OR
  EXISTS(SELECT 1 FROM jsonb_array_elements(s.qualification->'NamespaceGuards') g WHERE g->>'ClusterID'=cluster::text) OR
  (SELECT count(*) FROM public.capacity_cluster_qualification WHERE root_id=r)+jsonb_array_length(s.qualification->'NamespaceGuards')>=16 THEN
  RAISE EXCEPTION 'capacity cluster qualification unavailable' USING ERRCODE='23514';END IF;
 INSERT INTO public.capacity_cluster_qualification(root_id,cluster_id,peer_id,issuer_epoch,guard_digest,guard_keys,qualified_at)
 VALUES(r,cluster,peer,epoch,digest,keys,clock_timestamp());
 RETURN true;
END $$;

-- The hub-worker's effective cluster set: its projection's hub cluster plus
-- these rows (ADR-197 decision 6).
CREATE FUNCTION read_capacity_cluster_qualifications(r uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT public.capacity_role_ok(r,'capacity') THEN RAISE EXCEPTION 'capacity cluster qualification role unavailable' USING ERRCODE='23514';END IF;
 RETURN COALESCE((SELECT jsonb_agg(jsonb_build_object('ClusterID',q.cluster_id,'PeerID',q.peer_id,'IssuerEpoch',q.issuer_epoch,
  'Digest',to_jsonb(ARRAY(SELECT get_byte(q.guard_digest,i) FROM generate_series(0,31) i)),'Keys',q.guard_keys) ORDER BY q.cluster_id)
  FROM public.capacity_cluster_qualification q WHERE q.root_id=r),'[]'::jsonb);
END $$;

-- The original namespace pin for a cluster, else its write-once regional
-- qualification, in the original pin's shape; NULL for an unknown cluster.
CREATE FUNCTION capacity_cluster_guard(s public.capacity_source,cluster text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g jsonb;q public.capacity_cluster_qualification;
BEGIN
 IF jsonb_typeof(s.qualification->'NamespaceGuards') IS DISTINCT FROM 'array' THEN RETURN NULL;END IF;
 SELECT value INTO g FROM jsonb_array_elements(s.qualification->'NamespaceGuards') WHERE value->>'ClusterID'=cluster;
 IF FOUND THEN RETURN g;END IF;
 SELECT * INTO q FROM public.capacity_cluster_qualification WHERE root_id=s.root_id AND cluster_id::text=cluster;
 IF NOT FOUND THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('ClusterID',q.cluster_id,'Digest',to_jsonb(ARRAY(SELECT get_byte(q.guard_digest,i) FROM generate_series(0,31) i)),'Keys',q.guard_keys);
END $$;

-- An additive pool revision: the same pool, backend and fixed amounts; a
-- later generation; every existing policy and cluster entry byte-identical;
-- only new clusters and their policies added. Capacity may only grow.
CREATE FUNCTION capacity_pool_extends(old_value jsonb,new_value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE e jsonb;
BEGIN
 IF old_value IS NULL OR new_value IS NULL OR old_value->>'Format' IS DISTINCT FROM 'capacity-pool/v1' OR new_value->>'Format' IS DISTINCT FROM 'capacity-pool/v1' OR
  ROW(new_value->'Name',new_value->'UID',new_value->'StorageProfile',new_value->'Safety',new_value->'System',new_value->'Burst') IS DISTINCT FROM
  ROW(old_value->'Name',old_value->'UID',old_value->'StorageProfile',old_value->'Safety',old_value->'System',old_value->'Burst') OR
  (new_value->>'Generation')::bigint<=(old_value->>'Generation')::bigint OR
  (new_value->'Capacity'->>'Bytes')::bigint<(old_value->'Capacity'->>'Bytes')::bigint OR (new_value->'Capacity'->>'Objects')::bigint<(old_value->'Capacity'->>'Objects')::bigint OR
  jsonb_array_length(new_value->'Policies')<=jsonb_array_length(old_value->'Policies') OR jsonb_array_length(new_value->'Clusters')<=jsonb_array_length(old_value->'Clusters') THEN RETURN false;END IF;
 FOR e IN SELECT value FROM jsonb_array_elements(old_value->'Policies') LOOP
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(new_value->'Policies') x WHERE x.value=e) THEN RETURN false;END IF;
 END LOOP;
 FOR e IN SELECT value FROM jsonb_array_elements(old_value->'Clusters') LOOP
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(new_value->'Clusters') x WHERE x.value=e) THEN RETURN false;END IF;
 END LOOP;
 -- A new policy in an existing cluster would have changed that entry.
 RETURN NOT EXISTS(SELECT 1 FROM jsonb_array_elements(new_value->'Policies') x WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(old_value->'Policies') y WHERE y.value=x.value) AND
  EXISTS(SELECT 1 FROM jsonb_array_elements(old_value->'Clusters') c WHERE c.value->>'ClusterID'=x.value->'Budget'->>'Cluster'));
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;

-- Applies one additive revision inside the caller's open root transaction:
-- retains the superseded plan, adopts the new one, adds its new clusters and
-- resizes the dedicated custody pool. Existing children are unchanged.
CREATE FUNCTION capacity_apply_pool_extension(s public.capacity_source,p public.capacity_pool,pool_value jsonb,pool_bytes bytea) RETURNS public.capacity_pool
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cluster_value jsonb;out public.capacity_pool;revisions bigint;marker xid8;
BEGIN
 SELECT root_mutation_xid INTO STRICT marker FROM public.capacity_source WHERE root_id=s.root_id;
 IF marker IS DISTINCT FROM pg_current_xact_id() OR NOT public.capacity_role_ok(s.root_id,'capacity') OR NOT public.capacity_pool_extends(p.plan,pool_value) OR
  public.capacity_compile_pool(s.accepted_snapshot,p.source_name) IS DISTINCT FROM pool_value OR public.capacity_backend_for(s,pool_value) IS NULL OR
  octet_length(pool_bytes) NOT BETWEEN 2 AND 65536 OR convert_from(pool_bytes,'UTF8')::jsonb IS DISTINCT FROM pool_value THEN
  RAISE EXCEPTION 'capacity pool extension unavailable' USING ERRCODE='23514';END IF;
 SELECT count(*) INTO revisions FROM public.capacity_pool_revision WHERE root_id=p.root_id AND pool_id=p.id;
 INSERT INTO public.capacity_pool_revision(root_id,pool_id,revision,plan,plan_digest,superseded_at) VALUES(p.root_id,p.id,revisions+1,p.plan,p.plan_digest,clock_timestamp());
 UPDATE public.capacity_pool SET source_generation=(pool_value->>'Generation')::bigint,source_digest=public.connector_digest(pool_value->'Digest'),plan=pool_value,
  plan_digest=sha256(convert_to('asservat-capacity-pool/json-v1','UTF8')||decode('00','hex')||pool_bytes),
  protected_bytes=(pool_value->'Protected'->>'Bytes')::bigint,protected_objects=(pool_value->'Protected'->>'Objects')::bigint,
  account_limit=(pool_value->>'AccountLimit')::bigint,namespace_limit=(pool_value->>'NamespaceLimit')::bigint
 WHERE root_id=p.root_id AND id=p.id RETURNING * INTO out;
 FOR cluster_value IN SELECT x.value FROM jsonb_array_elements(pool_value->'Clusters') x
  WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p.plan->'Clusters') y WHERE y.value->>'ClusterID'=x.value->>'ClusterID') ORDER BY x.value->>'ClusterID' LOOP
  INSERT INTO public.capacity_cluster(root_id,pool_id,cluster_id,protected_bytes,protected_objects,byte_limit,object_limit,account_limit,namespace_limit)
  VALUES(p.root_id,p.id,(cluster_value->>'ClusterID')::uuid,(cluster_value->>'ProtectedBytes')::bigint,(cluster_value->>'ProtectedObjects')::bigint,(cluster_value->>'ByteLimit')::bigint,(cluster_value->>'ObjectLimit')::bigint,(cluster_value->>'AccountLimit')::bigint,(cluster_value->>'AccountLimit')::bigint);
 END LOOP;
 UPDATE public.custody_pool SET byte_limit=out.protected_bytes+out.shared_bytes,object_limit=out.protected_objects+out.shared_objects WHERE id=p.id;
 RETURN out;
END $$;

-- read_capacity_root catches up a pending extension of the system pool under
-- its exclusive root locks, spending one prepaid configuration transaction.
CREATE FUNCTION capacity_extend_system_pool(r uuid,pool_value jsonb,pool_bytes bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s public.capacity_source;p public.capacity_pool;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 IF s.root_plan IS NULL OR s.root_mutation_xid IS NOT NULL THEN RETURN;END IF;
 SELECT * INTO p FROM public.capacity_pool WHERE root_id=r AND source_uid=s.root_plan#>>'{Input,SystemPoolUID}' FOR UPDATE;
 IF NOT FOUND OR p.plan IS NOT DISTINCT FROM pool_value OR NOT public.capacity_pool_extends(p.plan,pool_value) THEN RETURN;END IF;
 UPDATE public.capacity_source SET configuration_spent=configuration_spent+1,root_mutation_xid=pg_current_xact_id() WHERE root_id=r;
 PERFORM public.capacity_apply_pool_extension(s,p,pool_value,pool_bytes);
 UPDATE public.capacity_source SET root_mutation_xid=NULL WHERE root_id=r;
END $$;

-- An enrollment made under an earlier revision of its pool, presented under
-- the current one: identical apart from the pool and selected-source
-- digests and the pool generation, with its original pool in the chain.
CREATE FUNCTION capacity_chain_compatible(w public.capacity_workload,p public.capacity_pool,body jsonb,pool_value jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE original bytea;
BEGIN
 original:=public.connector_digest(w.plan->'PoolDigest');
 RETURN (w.plan-ARRAY['SourceDigest','PoolDigest','PoolGeneration'])=(body-ARRAY['SourceDigest','PoolDigest','PoolGeneration']) AND
  (p.plan IS NOT DISTINCT FROM pool_value AND p.plan_digest=public.connector_digest(body->'PoolDigest') OR public.capacity_pool_extends(p.plan,pool_value)) AND
  (original=p.plan_digest OR EXISTS(SELECT 1 FROM public.capacity_pool_revision v WHERE v.root_id=p.root_id AND v.pool_id=p.id AND v.plan_digest=original));
EXCEPTION WHEN data_exception OR integrity_constraint_violation THEN RETURN false;
END $$;

-- The receipt names the presented plan's digests: either the original or,
-- for a chain-compatible enrollment, the current revision's.
CREATE FUNCTION capacity_enrollment_receipt_as(w public.capacity_workload,o jsonb) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.capacity_enrollment_receipt(w)||jsonb_build_object(
  'SourceDigest',to_jsonb(ARRAY(SELECT get_byte(public.connector_digest(o->'SourceDigest'),i) FROM generate_series(0,31) i)),
  'PlanDigest',to_jsonb(ARRAY(SELECT get_byte(public.connector_digest(o->'PlanDigest'),i) FROM generate_series(0,31) i)))
$$;
CREATE FUNCTION capacity_enrollment_matches_as(w public.capacity_workload,expected jsonb,o jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=public.capacity_enrollment_receipt_as(w,o);k text;fields text[]:=ARRAY['InitialObservedAt','InitialUntil','ReservedAt','CaptureBackedAt','ReadyAt'];
BEGIN
 IF expected IS NULL OR octet_length(expected::text)>8192 OR NOT public.capacity_json_fields(expected,ARRAY['Format','Key','ID','AttemptID','AllocationID','DownloadAllocationID','SourceDigest','PlanDigest','Revision','InitialObservedAt','InitialUntil','ReservedAt','CaptureBackedAt','ReadyAt','AccountVersion','AccountDigest']) OR
  (v-fields) IS DISTINCT FROM (expected-fields) OR v->'Key' IS DISTINCT FROM o->'Key' THEN RETURN false;END IF;
 FOREACH k IN ARRAY fields LOOP
  IF (v->k='null'::jsonb) IS DISTINCT FROM (expected->k='null'::jsonb) THEN RETURN false;END IF;
  IF v->k<>'null'::jsonb AND (NOT public.capacity_json_text(expected->k,20,40) OR (v->>k)::timestamptz IS DISTINCT FROM (expected->>k)::timestamptz) THEN RETURN false;END IF;
 END LOOP;RETURN true;
EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION qualify_capacity_cluster(uuid,uuid,uuid,uuid,bytea,jsonb),read_capacity_cluster_qualifications(uuid),capacity_cluster_guard(capacity_source,text),capacity_pool_extends(jsonb,jsonb),
 capacity_apply_pool_extension(capacity_source,capacity_pool,jsonb,bytea),capacity_extend_system_pool(uuid,jsonb,bytea),capacity_chain_compatible(capacity_workload,capacity_pool,jsonb,jsonb),
 capacity_enrollment_receipt_as(capacity_workload,jsonb),capacity_enrollment_matches_as(capacity_workload,jsonb,jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_lock_observation(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea) RETURNS timestamptz
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
 -- ADR-197: a regional cluster's guard is its write-once qualification.
 guard:=public.capacity_cluster_guard(s,o->'Key'->>'ClusterID');
 IF guard IS NULL THEN RAISE EXCEPTION 'capacity namespace pins unavailable' USING ERRCODE='23514';END IF;
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

CREATE OR REPLACE FUNCTION capacity_read_enrollment(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea) RETURNS jsonb
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
 -- ADR-197: exact, or made under an earlier revision of this pool.
 IF w IS DISTINCT FROM candidate OR w.mutation_xid IS NOT NULL OR w.root_id<>r OR w.account_version IS DISTINCT FROM body->>'AccountVersion' OR pool.source_uid IS DISTINCT FROM body->>'PoolUID' OR
  NOT (w.source_digest IS NOT DISTINCT FROM public.connector_digest(o->'SourceDigest') AND w.plan_digest IS NOT DISTINCT FROM public.connector_digest(o->'PlanDigest') AND w.plan IS NOT DISTINCT FROM body AND
   pool.plan IS NOT DISTINCT FROM convert_from(pool_bytes,'UTF8')::jsonb AND pool.plan_digest IS NOT DISTINCT FROM public.connector_digest(body->'PoolDigest') OR
   public.capacity_chain_compatible(w,pool,body,convert_from(pool_bytes,'UTF8')::jsonb)) THEN
  RAISE EXCEPTION 'capacity retained enrollment changed' USING ERRCODE='23514';END IF;
 IF NOT public.capacity_workload_general_exact(s,w,w.ready_at IS NOT NULL) OR w.capture_backed_at IS NOT NULL AND NOT public.capacity_workload_capture_exact(s,w) THEN RAISE EXCEPTION 'capacity child backing changed' USING ERRCODE='23514';END IF;
 IF clock_timestamp()>=until_at THEN RAISE EXCEPTION 'capacity retained read expired after locks' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt_as(w,o),'FreshUntil',until_at);
END $$;

CREATE OR REPLACE FUNCTION capacity_root_general_exact(s public.capacity_source) RETURNS boolean
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
 IF current_pool IS NULL OR backend IS NULL OR NOT (p.plan IS NOT DISTINCT FROM current_pool OR public.capacity_pool_extends(p.plan,current_pool)) OR p.id<>(backend->>'PoolID')::uuid OR p.backend_capacity_id<>(backend->>'CapacityID')::uuid OR
  p.backend_qualification_id<>(backend->>'ID')::uuid OR p.backend_qualification_digest IS DISTINCT FROM public.connector_digest(backend->'Digest') OR
  p.backed_system_bytes<>(totals->'SystemObjects'->>'Bytes')::bigint OR p.backed_system_objects<>(totals->'SystemObjects'->>'Objects')::bigint OR
  custody.store_id<>(backend->>'EvidenceStoreID')::uuid OR custody.paused OR custody.valid_until<>planned OR custody.revision<>revision OR
  custody.byte_limit<>(p.plan->'Protected'->>'Bytes')::bigint+(p.plan->'Burst'->>'Bytes')::bigint OR custody.object_limit<>(p.plan->'Protected'->>'Objects')::bigint+(p.plan->'Burst'->>'Objects')::bigint THEN RETURN false;END IF;
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

CREATE OR REPLACE FUNCTION capacity_ensure_pool(s public.capacity_source,pool_value jsonb,pool_bytes bytea) RETURNS public.capacity_pool
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
  -- ADR-197: an additive revision extends the pool, then checks exactly.
  IF p.plan IS DISTINCT FROM pool_value AND public.capacity_pool_extends(p.plan,pool_value) THEN
   p:=public.capacity_apply_pool_extension(s,p,pool_value,pool_bytes);
   SELECT * INTO STRICT c FROM public.custody_pool WHERE id=pool_id;
  END IF;
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

CREATE OR REPLACE FUNCTION capacity_finish_enrollment(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb,continuation boolean) RETURNS jsonb
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
 IF read_value->'Enrollment'='null'::jsonb OR NOT public.capacity_enrollment_matches_as(w,expected,o) OR w.mutation_xid IS NOT NULL OR s.root_mutation_xid IS NOT NULL OR
  public.capacity_managed_root_until(r,n) IS NULL OR NOT public.capacity_root_general_exact(s) OR NOT public.capacity_root_capture_exact(s) OR
  NOT public.capacity_workload_general_exact(s,w,w.ready_at IS NOT NULL) OR w.capture_backed_at IS NOT NULL AND NOT public.capacity_workload_capture_exact(s,w) OR n>=until_at THEN
  RAISE EXCEPTION 'capacity exact original backing unavailable' USING ERRCODE='23514';END IF;
 IF (purpose='capacity-capture' AND w.capture_backed_at IS NOT NULL) OR (purpose='capacity' AND w.ready_at IS NOT NULL) THEN
  RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt_as(w,o),'FreshUntil',until_at);
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
 RETURN jsonb_build_object('Enrollment',public.capacity_enrollment_receipt_as(w,o),'FreshUntil',until_at);
END $$;

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

CREATE OR REPLACE FUNCTION read_capacity_root(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE until_at timestamptz;s public.capacity_source;
BEGIN
 until_at:=public.capacity_lock_root_observation(r,'capacity',o,plan_bytes,pool_bytes);
 -- ADR-197: adopt a pending additive revision of the system pool.
 PERFORM public.capacity_extend_system_pool(r,convert_from(pool_bytes,'UTF8')::jsonb,pool_bytes);
 SELECT * INTO STRICT s FROM public.capacity_source WHERE root_id=r;
 IF s.root_mutation_xid IS NOT NULL OR s.root_configuration IS NOT NULL AND (NOT public.capacity_root_configuration_valid(s.root_configuration) OR
  NOT public.capacity_root_general_exact(s) OR s.root_configuration->'CaptureBackedAt'<>'null'::jsonb AND NOT public.capacity_root_capture_exact(s)) OR clock_timestamp()>=until_at THEN
  RAISE EXCEPTION 'capacity root disposition unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Configuration',s.root_configuration,'FreshUntil',until_at);
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

CREATE OR REPLACE FUNCTION read_capacity_audit_profiles(r uuid,i uuid,q uuid,qd bytea,av text,observed timestamptz,original_until timestamptz) RETURNS jsonb
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
 IF pool_plan IS NULL OR NOT (backing.plan IS NOT DISTINCT FROM pool_plan OR public.capacity_pool_extends(backing.plan,pool_plan)) OR public.capacity_backend_for(s,pool_plan) IS NULL OR
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

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capacity_lock_observation(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea) RETURNS timestamptz
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

CREATE OR REPLACE FUNCTION capacity_read_enrollment(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea) RETURNS jsonb
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

CREATE OR REPLACE FUNCTION capacity_root_general_exact(s public.capacity_source) RETURNS boolean
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

CREATE OR REPLACE FUNCTION capacity_ensure_pool(s public.capacity_source,pool_value jsonb,pool_bytes bytea) RETURNS public.capacity_pool
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

CREATE OR REPLACE FUNCTION capacity_finish_enrollment(r uuid,purpose text,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb,continuation boolean) RETURNS jsonb
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

CREATE OR REPLACE FUNCTION refresh_capacity_enrollment(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea,source_bytes bytea,expected jsonb) RETURNS jsonb
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

CREATE OR REPLACE FUNCTION read_capacity_root(r uuid,o jsonb,plan_bytes bytea,pool_bytes bytea) RETURNS jsonb
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

CREATE OR REPLACE FUNCTION read_capacity_audit_profiles(r uuid,i uuid,q uuid,qd bytea,av text,observed timestamptz,original_until timestamptz) RETURNS jsonb
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
DROP FUNCTION capacity_enrollment_matches_as(capacity_workload,jsonb,jsonb);
DROP FUNCTION capacity_enrollment_receipt_as(capacity_workload,jsonb);
DROP FUNCTION capacity_chain_compatible(capacity_workload,capacity_pool,jsonb,jsonb);
DROP FUNCTION capacity_extend_system_pool(uuid,jsonb,bytea);
DROP FUNCTION capacity_apply_pool_extension(capacity_source,capacity_pool,jsonb,bytea);
DROP FUNCTION capacity_pool_extends(jsonb,jsonb);
DROP FUNCTION capacity_cluster_guard(capacity_source,text);
DROP FUNCTION read_capacity_cluster_qualifications(uuid);
DROP FUNCTION qualify_capacity_cluster(uuid,uuid,uuid,uuid,bytea,jsonb);
DROP TABLE capacity_pool_revision;
DROP TABLE capacity_cluster_qualification;
DROP FUNCTION guard_capacity_append_only();
