-- +goose Up
-- ADR-335 D5, REQ-INV-001/002: an approved grant covers matching published
-- artifacts for the requesting human on every client. Registrations
-- (access_grant_child) record each used artifact once per grant for the
-- maxArtifacts count; they carry no client. A review stays decidable until
-- its own absolute bound (not_after, policy_not_after); there is no fixed
-- review window, and result access ends at its not_after. Caps without a
-- stated reason are removed. Step-up is optional (ADR-335 D5): an approval
-- records acr/auth_time only when the reviewer's token carried them.
-- No Down: the removed client column and caps are not restored. Every
-- statement tolerates a re-Up after a downgrade probe, as in 00167.
LOCK TABLE access_grant,access_grant_child,access_grant_use IN ACCESS EXCLUSIVE MODE;
ALTER TABLE access_grant_child DISABLE TRIGGER access_grant_child_immutable;
ALTER TABLE access_grant_use DISABLE TRIGGER access_grant_use_immutable;
WITH keep AS (SELECT DISTINCT ON (parent_id,artifact_id) id,parent_id,artifact_id FROM access_grant_child ORDER BY parent_id,artifact_id,created_at,id)
UPDATE access_grant_use u SET child_id=k.id FROM access_grant_child c JOIN keep k ON k.parent_id=c.parent_id AND k.artifact_id=c.artifact_id WHERE u.child_id=c.id AND u.child_id<>k.id;
DELETE FROM access_grant_child c WHERE EXISTS(SELECT 1 FROM access_grant_child o WHERE o.parent_id=c.parent_id AND o.artifact_id=c.artifact_id AND (o.created_at,o.id)<(c.created_at,c.id));
ALTER TABLE access_grant_child ENABLE TRIGGER access_grant_child_immutable;
ALTER TABLE access_grant_use ENABLE TRIGGER access_grant_use_immutable;
ALTER TABLE access_grant_child DROP CONSTRAINT IF EXISTS access_grant_child_parent_id_artifact_id_client_id_key;
ALTER TABLE access_grant_child DROP COLUMN IF EXISTS client_id;
ALTER TABLE access_grant_child DROP CONSTRAINT IF EXISTS access_grant_child_parent_artifact;
ALTER TABLE access_grant_child ADD CONSTRAINT access_grant_child_parent_artifact UNIQUE(parent_id,artifact_id);
ALTER TABLE access_grant ALTER COLUMN review_until DROP NOT NULL;
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_check5;
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_check2;
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_not_after;
ALTER TABLE access_grant ADD CONSTRAINT access_grant_not_after CHECK (not_after IS NULL OR not_after>requested_at);
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_max_artifacts_check;
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_max_bytes_check;
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_max_operations_check;
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_pool_bounds;
ALTER TABLE access_grant ADD CONSTRAINT access_grant_pool_bounds CHECK (max_artifacts>=0 AND max_bytes>=0 AND max_operations>=0);
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_reasons_check;
ALTER TABLE access_grant ADD CONSTRAINT access_grant_reasons_check CHECK (jsonb_typeof(reasons)='array' AND jsonb_array_length(reasons)>=1);
-- Earlier rows keep their recorded expiry; new decisions follow the new rule.
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_expiry_kind;
ALTER TABLE access_grant ADD CONSTRAINT access_grant_expiry_kind CHECK (decision IS DISTINCT FROM 'approved' OR (decision_auth_time IS NULL OR decision_auth_time<=decided_at) AND (kind IN ('adHocCapture','rawQuery') AND expires_at=COALESCE(not_after,decided_at+make_interval(secs => lifetime_seconds)) OR kind='policy' AND expires_at=policy_not_after)) NOT VALID;
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS access_grant_scope_kind;
ALTER TABLE access_grant ADD CONSTRAINT access_grant_scope_kind CHECK ((
CASE
    WHEN (kind = 'rawQuery'::text) THEN ((kind = 'rawQuery'::text) AND (requester_kind = 'human'::text) AND (request_operation = 'requestRawAccess'::text) AND (requester_key IS NOT NULL) AND (octet_length(requester_key) = 32) AND (requester_key = sha256((((((((int4send(octet_length(convert_to(requester_issuer, 'UTF8'::name))) || convert_to(requester_issuer, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_subject, 'UTF8'::name)))) || convert_to(requester_subject, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_client, 'UTF8'::name)))) || convert_to(requester_client, 'UTF8'::name)) || int4send(5)) || convert_to('human'::text, 'UTF8'::name)))) AND (preview_id IS NULL) AND (capture_id IS NULL) AND (cluster_id IS NULL) AND (namespace_uid IS NULL) AND (workload_uid IS NULL) AND (pod_uid IS NULL) AND (policy_uid IS NULL) AND (policy_acceptance_id IS NULL) AND (policy_scope IS NULL) AND (policy_not_after IS NULL) AND (policy_executions_spent = 0) AND (policy_bytes_spent = 0) AND (policy_observed_bytes_spent = 0) AND (policy_observed_events_spent = 0) AND (data_class = 'raw'::text) AND (lifetime_seconds >= 1) AND (result_access IS NULL) AND (result_access_digest IS NULL) AND (not_after IS NOT NULL) AND (jsonb_typeof(raw_query) = 'object'::text) AND ((convert_from(scope, 'UTF8'::name))::jsonb = jsonb_build_object('Version', 'raw-query/v1', 'Scope', raw_query)) AND (jsonb_typeof((raw_query -> 'Artifacts'::text)) = 'array'::text) AND (jsonb_array_length((raw_query -> 'Artifacts'::text)) >= 1) AND ((raw_query -> 'Operations'::text) = ANY (ARRAY['["download_artifact"]'::jsonb, '["get_logs"]'::jsonb, '["pcap_query"]'::jsonb, '["syscall_query"]'::jsonb, '["download_artifact", "get_logs"]'::jsonb, '["download_artifact", "pcap_query"]'::jsonb, '["download_artifact", "syscall_query"]'::jsonb, '["get_logs", "pcap_query"]'::jsonb, '["get_logs", "syscall_query"]'::jsonb, '["pcap_query", "syscall_query"]'::jsonb, '["download_artifact", "get_logs", "pcap_query"]'::jsonb, '["download_artifact", "get_logs", "syscall_query"]'::jsonb, '["download_artifact", "pcap_query", "syscall_query"]'::jsonb, '["get_logs", "pcap_query", "syscall_query"]'::jsonb, '["download_artifact", "get_logs", "pcap_query", "syscall_query"]'::jsonb])) AND (max_artifacts = jsonb_array_length((raw_query -> 'Artifacts'::text))) AND (max_bytes = ((raw_query ->> 'MaxBytes'::text))::bigint) AND (max_bytes >= 1) AND (max_operations = ((raw_query ->> 'MaxOperations'::text))::bigint) AND (max_operations >= 1) AND (not_after = ((raw_query ->> 'NotAfter'::text))::timestamp with time zone))
    ELSE ((raw_query IS NULL) AND (cluster_id IS NOT NULL) AND (namespace_uid IS NOT NULL) AND (workload_uid IS NOT NULL) AND ((((kind = 'adHocCapture'::text) AND (requester_kind = 'human'::text) AND (request_operation = 'requestGrant'::text) AND (requester_key IS NULL) AND (preview_id IS NOT NULL) AND (capture_id IS NOT NULL) AND (pod_uid IS NOT NULL) AND (policy_uid IS NULL) AND (policy_acceptance_id IS NULL) AND (policy_scope IS NULL) AND (policy_not_after IS NULL) AND (lifetime_seconds >= 60) AND (policy_executions_spent = 0) AND (policy_bytes_spent = 0) AND (policy_observed_bytes_spent = 0)) OR ((kind = 'policy'::text) AND (request_operation = 'requestPolicyGrant'::text) AND (requester_key IS NOT NULL) AND (octet_length(requester_key) = 32) AND (requester_key = sha256((((((((int4send(octet_length(convert_to(requester_issuer, 'UTF8'::name))) || convert_to(requester_issuer, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_subject, 'UTF8'::name)))) || convert_to(requester_subject, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_client, 'UTF8'::name)))) || convert_to(requester_client, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_kind, 'UTF8'::name)))) || convert_to(requester_kind, 'UTF8'::name)))) AND (preview_id IS NULL) AND (capture_id IS NULL) AND (pod_uid IS NULL) AND (policy_uid IS NOT NULL) AND ((octet_length(policy_uid) >= 1) AND (octet_length(policy_uid) <= 64)) AND (policy_acceptance_id IS NOT NULL) AND (policy_scope IS NOT NULL) AND (jsonb_typeof(policy_scope) = 'object'::text) AND (octet_length((policy_scope)::text) <= 65536) AND (policy_scope ?& ARRAY['Authority'::text, 'Limits'::text, 'ApprovalPolicyRef'::text, 'ApprovalMaxAge'::text, 'RecipeDigest'::text]) AND ((policy_scope #>> '{Authority,PolicyUID}'::text[]) = policy_uid) AND ((policy_scope #>> '{Authority,ClusterID}'::text[]) = (cluster_id)::text) AND ((policy_scope #>> '{Authority,NamespaceUID}'::text[]) = namespace_uid) AND ((policy_scope #>> '{Authority,WorkloadUID}'::text[]) = workload_uid) AND ((lifetime_seconds >= 1) AND (lifetime_seconds <= 31536000)) AND ((((policy_scope ->> 'ApprovalMaxAge'::text))::bigint >= ((lifetime_seconds)::bigint * 1000000000)) AND (((policy_scope ->> 'ApprovalMaxAge'::text))::bigint <= '31536000000000000'::bigint)) AND (policy_not_after IS NOT NULL) AND (policy_not_after > requested_at) AND (policy_not_after <= (requested_at + make_interval(secs => (lifetime_seconds)::double precision))) AND (policy_not_after <= ((policy_scope #>> '{Authority,NotAfter}'::text[]))::timestamp with time zone) AND (result_access IS NULL) AND (result_access_digest IS NULL) AND (not_after IS NULL) AND (max_artifacts = 0) AND (max_bytes = 0) AND (max_operations = 0) AND (artifacts_spent = 0) AND (bytes_spent = 0) AND (operations_spent = 0) AND (policy_max_executions IS NOT NULL) AND (policy_max_executions > 0) AND (policy_max_bytes IS NOT NULL) AND (policy_max_bytes > 0) AND (policy_max_observed_bytes IS NOT NULL) AND (policy_max_observed_bytes >= 0))) IS TRUE))
END IS TRUE));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_access_grant_child_scope() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE parent public.access_grant%ROWTYPE; item jsonb; matched boolean:=false;
BEGIN
 SELECT * INTO STRICT parent FROM public.access_grant WHERE root_id=NEW.root_id AND id=NEW.parent_id;
 IF parent.kind='adHocCapture' THEN
  IF NEW.capture_id IS DISTINCT FROM parent.capture_id THEN RAISE EXCEPTION 'child capture differs from parent' USING ERRCODE='23514'; END IF;
 ELSIF parent.kind='rawQuery' THEN
  FOR item IN SELECT jsonb_array_elements(parent.raw_query->'Artifacts') LOOP
   IF item#>>'{Output,ArtifactID}'=NEW.artifact_id::text
    AND item#>>'{Output,CaptureID}'=NEW.capture_id::text
    AND item#>>'{Output,ActionID}'=NEW.action_id
    AND item#>'{Output,ArtifactDigest}'=to_jsonb(ARRAY(SELECT get_byte(NEW.artifact_digest,i)::integer FROM generate_series(0,31) i)) THEN matched:=true; END IF;
  END LOOP;
  IF NOT matched THEN RAISE EXCEPTION 'raw child is not an exact reviewed member' USING ERRCODE='23514'; END IF;
 ELSE RAISE EXCEPTION 'grant cannot parent artifact children' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_packet_query_scope_grant_current(r uuid,actor jsonb,s jsonb,binding jsonb) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g public.access_grant; c public.access_grant_child; item jsonb; matched boolean:=false; n timestamptz; grant_operation text;
BEGIN
 grant_operation:=CASE WHEN s->>'DisplayVersion'='approved-pcap-query/v1' AND s->>'NativeType'='rawPcapng' THEN 'pcap_query'
  WHEN s->>'DisplayVersion'='approved-syscall-query/v1' AND s->>'NativeType'='syscallArguments' THEN 'syscall_query'
  WHEN s->>'DisplayVersion'='approved-logs/v1' AND s->>'NativeType'='logs' THEN 'get_logs' END;
 IF grant_operation IS NULL THEN RETURN binding IS NULL AND NOT(s ? 'RawGrantID'); END IF;
 IF NOT public.context_query_scope_source_valid(s) THEN RETURN false; END IF;
 IF NOT public.capacity_json_fields(binding,ARRAY['ParentID','ChildID']) OR NOT public.context_packet_query_uuid(binding->>'ParentID') OR NOT public.context_packet_query_uuid(binding->>'ChildID') OR binding->>'ParentID' IS DISTINCT FROM s->>'RawGrantID' OR actor->>'Kind' IS DISTINCT FROM 'human' THEN RETURN false; END IF;
 SELECT * INTO g FROM public.access_grant WHERE root_id=r AND id=(binding->>'ParentID')::uuid FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM public.access_grant_child WHERE root_id=r AND id=(binding->>'ChildID')::uuid;
 n:=clock_timestamp();
 IF NOT FOUND OR c.parent_id<>g.id OR c.artifact_id::text IS DISTINCT FROM s->>'ArtifactID' OR c.capture_id::text IS DISTINCT FROM s->>'CaptureID' OR
  to_jsonb(ARRAY(SELECT get_byte(c.artifact_digest,i) FROM generate_series(0,31)i)) IS DISTINCT FROM s->'Version' OR
  g.decision IS DISTINCT FROM 'approved' OR g.revoked_at IS NOT NULL OR NOT COALESCE(n<g.expires_at,false) OR
  g.requester_kind<>'human' OR g.requester_issuer IS DISTINCT FROM actor->>'Issuer' OR g.requester_subject IS DISTINCT FROM actor->>'Subject' OR
  NOT EXISTS(SELECT 1 FROM public.context_case_locator l WHERE l.root_id=r AND l.case_id::text=s->>'CaseID' AND l.capture_id=c.capture_id AND l.artifact_id=c.artifact_id AND l.cluster_id::text=s->>'ClusterID' AND l.namespace_uid=s->>'NamespaceUID' AND l.workload_uid=s->>'WorkloadUID' AND l.pod_uid=s->>'PodUID') THEN RETURN false; END IF;
 IF g.kind='adHocCapture' THEN
  RETURN COALESCE((g.capture_id=c.capture_id OR EXISTS(
   SELECT 1 FROM public.context_capture member
   JOIN public.context_case_locator l ON l.root_id=member.root_id AND l.capture_id=member.id AND l.artifact_id=c.artifact_id
   JOIN public.context_verification verified ON verified.root_id=member.root_id AND verified.capture_id=member.id AND verified.copies_digest=c.artifact_digest AND verified.audit_acknowledged_at IS NOT NULL
   JOIN public.recording_save_group rg ON rg.root_id=member.root_id AND rg.id=member.group_id
   WHERE member.root_id=r AND member.id=c.capture_id AND rg.id=g.capture_id AND rg.scope_digest=g.execution_digest AND
   convert_from(member.expectation_json,'UTF8')::jsonb->>'ActionID'=c.action_id AND rg.group_kind='composition' AND member.group_ordinal>=0 AND cardinality(rg.child_ids) BETWEEN 2 AND 16 AND rg.child_ids[member.group_ordinal+1]=member.id AND
 member.created_at=rg.accepted_at AND member.deadline<=rg.deadline AND sha256(member.scope_json)=member.scope_digest AND sha256(rg.scope_json)=rg.scope_digest AND
 convert_from(rg.scope_json,'UTF8')::jsonb->>'schemaVersion'='recorder-group/v1' AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->member.group_ordinal->>'captureID'=member.id::text AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->member.group_ordinal->>'scopeDigest'=encode(member.scope_digest,'hex') AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->member.group_ordinal->>'actionID'=convert_from(member.expectation_json,'UTF8')::jsonb->>'ActionID' AND
 convert_from(member.expectation_json,'UTF8')::jsonb#>>'{Registration,Location,ArtifactID}'=l.artifact_id::text AND
 convert_from(member.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ParentCaptureID}'=rg.id::text AND
 (convert_from(member.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildIndex}')::integer=member.group_ordinal AND
 (convert_from(member.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildCount}')::integer=cardinality(rg.child_ids))) AND g.result_access->'operations' ? grant_operation AND g.result_access->'actionIDs' ? c.action_id AND g.cluster_id::text=s->>'ClusterID' AND g.namespace_uid=s->>'NamespaceUID' AND g.workload_uid=s->>'WorkloadUID' AND g.pod_uid=s->>'PodUID',false);
 ELSIF g.kind='rawQuery' THEN
  IF g.raw_query->>'CaseID' IS DISTINCT FROM s->>'CaseID' OR NOT(g.raw_query->'Operations' ? grant_operation) THEN RETURN false; END IF;
  FOR item IN SELECT jsonb_array_elements(g.raw_query->'Artifacts') LOOP
   IF COALESCE(item#>>'{Output,ArtifactID}'=c.artifact_id::text AND item#>>'{Output,CaptureID}'=c.capture_id::text AND item#>>'{Output,ActionID}'=c.action_id AND item#>'{Output,ArtifactDigest}'=s->'Version' AND
     item#>>'{Output,Target,ClusterID}'=s->>'ClusterID' AND item#>>'{Output,Target,NamespaceUID}'=s->>'NamespaceUID' AND item#>>'{Output,Target,WorkloadUID}'=s->>'WorkloadUID' AND item#>>'{Output,Target,PodUID}'=s->>'PodUID' AND n<(item->>'ExpiresAt')::timestamptz,false) THEN matched:=true; END IF;
  END LOOP;
  RETURN matched;
 END IF;
 RETURN false;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN RETURN false;
END $$;
-- +goose StatementEnd
