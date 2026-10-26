-- +goose Up
-- ADR-228: restart-triggered pod-status context captures (first S-03
-- increment). Additive: an older binary neither reads nor writes these
-- tables, so the ADR-227 compatibility floor stays at 81.

-- A policy source observation now lasts up to 30 seconds (was five): one
-- policy capture's preview, admission and regional start run on it.
-- +goose StatementBegin
DO $$
DECLARE c text;
BEGIN
 SELECT conname INTO STRICT c FROM pg_catalog.pg_constraint
 WHERE conrelid='public.policy_source'::regclass AND contype='c' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%fresh_until <= (observed_at + ''00:00:05''::interval)%';
 EXECUTE format('ALTER TABLE public.policy_source DROP CONSTRAINT %I',c);
END $$;
-- +goose StatementEnd
ALTER TABLE policy_source ADD CONSTRAINT policy_source_fresh CHECK (fresh_until>observed_at AND fresh_until<=observed_at+interval '30 seconds');

-- Executions are spent when an occurrence is admitted to the trigger budget,
-- never refunded, and never exceed the accepted ceiling.
ALTER TABLE policy_acceptance ADD COLUMN executions_spent bigint NOT NULL DEFAULT 0;
ALTER TABLE policy_acceptance ADD CONSTRAINT policy_acceptance_executions CHECK (executions_spent>=0 AND executions_spent<=COALESCE((record#>>'{Authority,Limits,MaxExecutions}')::bigint,0));

-- The last observed whole-pod restart counter of each Pod a policy watches.
-- The first observation of a Pod is its baseline; a vanished Pod's row goes.
CREATE TABLE policy_pod_watermark (
 root_id uuid NOT NULL,
 policy_uid text NOT NULL,
 pod_uid text NOT NULL CHECK (octet_length(pod_uid) BETWEEN 1 AND 64),
 restarts bigint NOT NULL CHECK (restarts BETWEEN 0 AND 2147483648),
 -- A Pod missing from one poll keeps its watermark; rows unseen for ten
 -- minutes are pruned.
 last_seen timestamptz NOT NULL,
 PRIMARY KEY(root_id,policy_uid,pod_uid),
 FOREIGN KEY(root_id,policy_uid) REFERENCES policy_source(root_id,policy_uid)
);

-- One row per (policy, Pod UID, restart count): a replayed or concurrent
-- poll of the same restart is a no-op. capture_id links the one capture.
CREATE TABLE policy_occurrence (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL,
 policy_uid text NOT NULL,
 acceptance_id uuid NOT NULL REFERENCES policy_acceptance(id),
 cluster_id uuid NOT NULL,
 workload_uid text NOT NULL CHECK (octet_length(workload_uid) BETWEEN 1 AND 64),
 pod_uid text NOT NULL CHECK (octet_length(pod_uid) BETWEEN 1 AND 64),
 restarts bigint NOT NULL CHECK (restarts BETWEEN 1 AND 2147483648),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 capture_id uuid UNIQUE REFERENCES context_capture(id),
 outcome text CHECK (outcome IN ('captured','refused')),
 UNIQUE(root_id,policy_uid,pod_uid,restarts),
 FOREIGN KEY(root_id,policy_uid) REFERENCES policy_source(root_id,policy_uid),
 CHECK (capture_id IS NULL OR outcome='captured')
);
CREATE INDEX policy_occurrence_recent ON policy_occurrence(root_id,policy_uid,created_at DESC);
CREATE INDEX policy_occurrence_open ON policy_occurrence(root_id,created_at) WHERE outcome IS NULL;

-- Trigger budgets as a generic cell rate: tat is the theoretical arrival
-- time; an occurrence is admitted while tat-(burst-1)*interval<=now, then
-- tat:=max(tat,now)+interval. policy_uid '' is the workload's shared budget
-- (one per five minutes, burst two) used by every policy on that workload;
-- a policy's own row can only tighten it.
CREATE TABLE policy_workload_window (
 root_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 workload_uid text NOT NULL CHECK (octet_length(workload_uid) BETWEEN 1 AND 64),
 policy_uid text NOT NULL CHECK (octet_length(policy_uid)<=64),
 tat timestamptz NOT NULL,
 PRIMARY KEY(root_id,cluster_id,workload_uid,policy_uid)
);

-- Content-free suppression summary: one row per policy and reason, a
-- saturating count and the first/last instants, never a row per match.
CREATE TABLE policy_suppression (
 root_id uuid NOT NULL,
 policy_uid text NOT NULL,
 reason text NOT NULL CHECK (reason IN ('cooldown','budget','coalesced','capacity','authority','unavailable')),
 first_at timestamptz NOT NULL,
 last_at timestamptz NOT NULL,
 count bigint NOT NULL CHECK (count BETWEEN 1 AND 2147483647),
 PRIMARY KEY(root_id,policy_uid,reason),
 FOREIGN KEY(root_id,policy_uid) REFERENCES policy_source(root_id,policy_uid),
 CHECK (last_at>=first_at)
);

-- A policy executor may be the actor of a context capture intent (ADR-228):
-- the exact deterministic installation-local policy principal (ADR-059).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION capture_audit_actor_valid(actor jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(actor->>'Kind'='human' OR (actor->>'Kind'='workload' AND actor->>'ClientID'='policy-executor' AND
  actor->>'Issuer' ~ '^urn:asservat:installation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND actor->>'Subject' ~ '^policy:.{1,64}$'),false)
$$;
CREATE OR REPLACE FUNCTION capture_audit_payload_matches(c public.context_capture,i jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE v jsonb:=i->'Capture';e jsonb:=convert_from(c.expectation_json,'UTF8')::jsonb;s jsonb:=convert_from(c.scope_json,'UTF8')::jsonb;a public.custody_attempt;
BEGIN
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=c.attempt_id;
 RETURN COALESCE(i->>'Name'='persist_capture_intent' AND i->>'InputFormat'='capture-intent/v2' AND NOT(i ? 'Peer') AND NOT(i ? 'Process') AND
  jsonb_typeof(v)='object' AND (v-ARRAY['RootID','CaptureID','CaseID','OccurrenceID','ArtifactID','AttemptID','Actor','Target','ScopeDigest','SubmissionDigest','ExpectationDigest','PermissionEpoch','PermissionSequence','IdentityRevision','CreatedAt','Deadline','ExpiresAt','DeleteBy','ReservedBytes'])='{}'::jsonb AND
  (i->>'ID')::uuid=c.id AND (i->>'RootID')::uuid=c.root_id AND (i->>'TraceID')::uuid=(e->>'OccurrenceID')::uuid AND
  (v->>'RootID')::uuid=c.root_id AND (v->>'CaptureID')::uuid=c.id AND (v->>'AttemptID')::uuid=c.attempt_id AND
  v->>'CaseID'=e->>'CaseID' AND v->>'OccurrenceID'=e->>'OccurrenceID' AND v->>'ArtifactID'=e->'Registration'->'Location'->>'ArtifactID' AND
  v->'Actor'=i->'Actor' AND v->'Actor'=jsonb_build_object('Issuer',s#>>'{executor,issuer}','Subject',s#>>'{executor,subject}','ClientID',s#>>'{executor,clientID}','Kind',s#>>'{executor,identityType}') AND public.capture_audit_actor_valid(v->'Actor') AND
  v->'Target'=jsonb_build_object('ClusterID',e#>>'{Registration,Location,ClusterID}','NamespaceUID',e->>'NamespaceUID','WorkloadUID',e->>'WorkloadUID','PodUID',e->>'PodUID') AND
  public.connector_digest(v->'ScopeDigest')=c.scope_digest AND public.connector_digest(v->'SubmissionDigest')=c.submission_digest AND public.connector_digest(v->'ExpectationDigest')=sha256(c.expectation_json) AND sha256(c.scope_json)=c.scope_digest AND
  (v->>'PermissionEpoch')::uuid=c.permission_epoch AND (v->>'PermissionSequence')::bigint=c.permission_sequence AND
  v->'IdentityRevision'->>'UID'=c.identity_policy_uid AND (v->'IdentityRevision'->>'Generation')::bigint=c.identity_policy_generation AND public.connector_digest(v->'IdentityRevision'->'Digest')=c.identity_policy_digest AND
  (v->>'CreatedAt')::timestamptz=c.created_at AND (i->>'CreatedAt')::timestamptz=c.created_at AND (v->>'Deadline')::timestamptz=c.deadline AND
  (v->>'ExpiresAt')::timestamptz=(e->'Registration'->>'ExpiresAt')::timestamptz AND (v->>'DeleteBy')::timestamptz=(e->'Registration'->>'DeleteBy')::timestamptz AND (v->>'ReservedBytes')::bigint=a.reserved_bytes AND
  (i->>'WriteUntil')::timestamptz<=c.deadline,false);
END $$;
-- Two public operations: policy activation and its content-free status.
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capture_audit_actor_valid(jsonb),capture_audit_payload_matches(public.context_capture,jsonb),operation_audit_lane(text),operation_audit_human_input_valid(text,text) FROM PUBLIC;
-- No destructive Down: occurrences, spend and suppression history survive.
