-- +goose Up
-- ADR-245 (REQ-PER-004): decision-time PermissionSources. kubernetesExec and
-- kubernetesAccessReview sources are accepted configuration with no subject;
-- the target cluster's connector reviews each authenticated human principal
-- for each Pod when a request needs it. An allowed review mints, once per
-- source and principal, a persistent assignment ID (the capturing principal's
-- audience) and records, per Pod, the reviewed resource attributes and a
-- decision lifetime of at most the source's maxDecisionAgeSeconds (<= 60 s).
-- Additive: an older binary never reads these tables, so the ADR-227
-- compatibility floor stays at 81.

-- Accepted decision-time sources of a permission stream. A row is current
-- only in the epoch and sequence that last accepted it; accepted_audit_id is
-- the authority event that accepted this source version, whose acknowledged
-- receipt gates every decision it supports.
CREATE TABLE permission_review_source (
 stream_id uuid NOT NULL REFERENCES permission_stream(id),
 uid text NOT NULL CHECK(octet_length(uid) BETWEEN 1 AND 64),
 epoch uuid NOT NULL,
 seen_sequence bigint NOT NULL CHECK(seen_sequence>0),
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 2147483647),
 resource_version text NOT NULL CHECK(octet_length(resource_version) BETWEEN 1 AND 128),
 spec_digest bytea NOT NULL CHECK(octet_length(spec_digest)=32),
 authority_digest bytea NOT NULL CHECK(octet_length(authority_digest)=32),
 cluster_id uuid NOT NULL,
 role text NOT NULL CHECK(role IN ('workload-maintainer','evidence-reader')),
 source_json jsonb NOT NULL CHECK(jsonb_typeof(source_json)='object' AND octet_length(source_json::text)<=16384),
 accepted_audit_id uuid NOT NULL,
 PRIMARY KEY(stream_id,uid)
);
ALTER TABLE permission_review_source ADD CONSTRAINT permission_review_source_audit
 FOREIGN KEY(accepted_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX permission_review_source_cluster ON permission_review_source(stream_id,cluster_id);

-- One assignment per source and principal while the source version stays
-- equivalent. Retired IDs are never reused; a re-grant mints a new ID.
CREATE TABLE permission_review_assignment (
 id uuid PRIMARY KEY,
 stream_id uuid NOT NULL REFERENCES permission_stream(id),
 source_uid text NOT NULL CHECK(octet_length(source_uid) BETWEEN 1 AND 64),
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 subject_id text NOT NULL CHECK(octet_length(subject_id) BETWEEN 1 AND 256),
 role text NOT NULL CHECK(role IN ('workload-maintainer','evidence-reader')),
 basis_digest bytea NOT NULL CHECK(octet_length(basis_digest)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 retired_at timestamptz, retirement_audit_id uuid,
 CHECK ((retired_at IS NULL)=(retirement_audit_id IS NULL))
);
ALTER TABLE permission_review_assignment ADD CONSTRAINT permission_review_retirement_audit
 FOREIGN KEY(retirement_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
CREATE UNIQUE INDEX permission_review_current ON permission_review_assignment(stream_id,source_uid,issuer,subject_id) WHERE retired_at IS NULL;

-- The recorded resource attributes of one assignment's review of one Pod and
-- the current decision lifetime. A refusal sets fresh_until=decided_at; the
-- row stays so that a later read can review the same recorded names.
CREATE TABLE permission_review_decision (
 assignment_id uuid NOT NULL REFERENCES permission_review_assignment(id),
 pod_uid text NOT NULL CHECK(octet_length(pod_uid) BETWEEN 1 AND 64),
 cluster_id uuid NOT NULL,
 namespace_name text NOT NULL CHECK(octet_length(namespace_name) BETWEEN 1 AND 63),
 namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_kind text NOT NULL CHECK(workload_kind IN ('Deployment','StatefulSet','Pod')),
 workload_name text NOT NULL CHECK(octet_length(workload_name) BETWEEN 1 AND 253),
 workload_uid text NOT NULL CHECK(octet_length(workload_uid) BETWEEN 1 AND 64),
 pod_name text NOT NULL CHECK(octet_length(pod_name) BETWEEN 1 AND 253),
 decided_at timestamptz NOT NULL,
 fresh_until timestamptz NOT NULL,
 CHECK (fresh_until>=decided_at AND fresh_until<=decided_at+interval '60 seconds'),
 PRIMARY KEY(assignment_id,pod_uid)
);
CREATE INDEX permission_review_pod ON permission_review_decision(cluster_id,namespace_uid,workload_uid,pod_uid);

-- Capacity enrollment (ADR-197/200) needs a current accepted maintainer
-- scope for a workload. A workload that only decision-time sources cover gets
-- one from a recorded allowed maintainer review of one of its Pods by a
-- current, acknowledged source: an enrollment prerequisite, never a grant.
-- Both bodies are rewritten in place; each named text must occur exactly once.
-- +goose StatementBegin
DO $$
DECLARE r record;def text;
BEGIN
 FOR r IN SELECT * FROM (VALUES
  ('public.capacity_lock_observation(uuid,text,jsonb,bytea,bytea,bytea)','n:=clock_timestamp();until_at:=LEAST(until_at,scope_until);',
   'IF scope_until IS NULL AND EXISTS(SELECT 1 FROM public.permission_review_decision d JOIN public.permission_review_assignment a ON a.id=d.assignment_id
   JOIN public.permission_review_source rs ON rs.stream_id=a.stream_id AND rs.uid=a.source_uid JOIN public.authority_audit proof ON proof.id=rs.accepted_audit_id
   WHERE a.stream_id=r AND a.retired_at IS NULL AND a.role=''workload-maintainer'' AND rs.epoch=p.epoch AND rs.seen_sequence=p.sequence AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL AND
   d.cluster_id=(o->''Key''->>''ClusterID'')::uuid AND d.namespace_uid=o->''Key''->>''NamespaceUID'' AND d.workload_uid=o->''Key''->>''WorkloadUID'') THEN
  scope_until:=''infinity''::timestamptz;END IF;
 n:=clock_timestamp();until_at:=LEAST(until_at,scope_until);'),
  ('public.read_capacity_permission_scopes(uuid,jsonb)','IF jsonb_array_length(scopes)>1024 OR octet_length(scopes::text)>1048576 THEN',
   'IF jsonb_array_length(scopes)<1024 THEN
  scopes:=scopes||COALESCE((SELECT jsonb_agg(v.scope ORDER BY v.last DESC,v.key) FROM (
   SELECT ''PermissionReview:''||rs.uid||'':''||d.cluster_id::text||'':''||d.namespace_uid AS key,max(d.decided_at) AS last,
    jsonb_build_object(''BasisKey'',''PermissionReview:''||rs.uid||'':''||d.cluster_id::text||'':''||d.namespace_uid,''BasisUID'',rs.uid,''ClusterID'',d.cluster_id,''NamespaceUID'',d.namespace_uid,
     ''ScopeDigest'',to_jsonb(ARRAY(SELECT get_byte(rs.authority_digest,k) FROM generate_series(0,31) k)),''WorkloadUIDs'',to_jsonb((array_agg(DISTINCT d.workload_uid ORDER BY d.workload_uid))[1:1024]),''NotAfter'',NULL) AS scope
   FROM public.permission_review_decision d JOIN public.permission_review_assignment a ON a.id=d.assignment_id
   JOIN public.permission_review_source rs ON rs.stream_id=a.stream_id AND rs.uid=a.source_uid JOIN public.authority_audit proof ON proof.id=rs.accepted_audit_id
   WHERE a.stream_id=r AND a.retired_at IS NULL AND a.role=''workload-maintainer'' AND rs.epoch=stream.epoch AND rs.seen_sequence=stream.sequence AND proof.stream_id=r AND proof.acknowledged_at IS NOT NULL
   GROUP BY rs.uid,rs.authority_digest,d.cluster_id,d.namespace_uid ORDER BY max(d.decided_at) DESC,1 LIMIT 1024-jsonb_array_length(scopes)) v),''[]''::jsonb);
 END IF;
 IF jsonb_array_length(scopes)>1024 OR octet_length(scopes::text)>1048576 THEN')) AS v(f,old_text,new_text) LOOP
  def:=pg_catalog.pg_get_functiondef(r.f::regprocedure);
  IF (pg_catalog.length(def)-pg_catalog.length(pg_catalog.replace(def,r.old_text,'')))/pg_catalog.length(r.old_text)<>1 THEN
   RAISE EXCEPTION 'unexpected definition of %',r.f USING ERRCODE='55000';END IF;
  EXECUTE pg_catalog.replace(def,r.old_text,r.new_text);
 END LOOP;
END $$;
-- +goose StatementEnd
-- REQ-PER-006: one immutable encrypted authority event per decision change of
-- a (source, principal, Pod) review (first allow, allow -> refusal, refusal
-- -> allow), appended by hub-api to the existing outbox and published by the
-- hub-worker's authority publisher. A confirming review writes no event.
ALTER TABLE authority_audit DROP CONSTRAINT authority_audit_event_kind_check,
 ADD CONSTRAINT authority_audit_event_kind_check CHECK (event_kind IN ('permission-reset','permission-change','permission-suspend','permission-review'));
-- No destructive Down: retired assignment IDs and recorded review targets keep
-- historical audiences from being resurrected after a rollback.
