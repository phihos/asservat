-- +goose Up
-- ADR-293: exact existing-artifact disclosure on the existing parent/child/use ledger.
LOCK TABLE access_grant,access_grant_child IN ACCESS EXCLUSIVE MODE;
ALTER TABLE access_grant ADD COLUMN raw_query jsonb;
ALTER TABLE access_grant ALTER COLUMN cluster_id DROP NOT NULL;
ALTER TABLE access_grant ALTER COLUMN namespace_uid DROP NOT NULL;
ALTER TABLE access_grant ALTER COLUMN workload_uid DROP NOT NULL;
ALTER TABLE access_grant DROP CONSTRAINT access_grant_kind, DROP CONSTRAINT access_grant_scope_kind, DROP CONSTRAINT access_grant_expiry_kind, DROP CONSTRAINT access_grant_max_bytes_check, DROP CONSTRAINT access_grant_review_check;
-- Only the two old result-access/pool coupling checks are replaced; historical
-- ad hoc rows keep precisely the same scalar bounds and null semantics.
-- +goose StatementBegin
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='public.access_grant'::regclass AND contype='c'
 AND pg_get_constraintdef(oid) LIKE '%result_access IS NULL%' LOOP
  EXECUTE format('ALTER TABLE public.access_grant DROP CONSTRAINT %I',c.conname);
 END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE access_grant ADD CONSTRAINT access_grant_kind CHECK(kind IN('adHocCapture','policy','rawQuery'));
ALTER TABLE access_grant ADD CONSTRAINT access_grant_max_bytes_check CHECK(max_bytes>=0 AND max_bytes<=CASE WHEN kind='rawQuery' THEN 1099511627776 ELSE 274877906944 END);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_review_check CHECK(octet_length(review) BETWEEN 2 AND CASE WHEN kind='rawQuery' THEN 131072 ELSE 32768 END);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_result_digest CHECK ((result_access IS NULL)=(result_access_digest IS NULL));
ALTER TABLE access_grant ADD CONSTRAINT access_grant_result_pool CHECK(kind='rawQuery' OR
 ((result_access IS NULL)=(not_after IS NULL) AND (result_access IS NULL)=(max_artifacts=0) AND (max_artifacts=0)=(max_bytes=0) AND (max_bytes=0)=(max_operations=0)));
-- Exact canonical scope equality bounds raw_query without counting JSONB formatting.
ALTER TABLE access_grant ADD CONSTRAINT access_grant_scope_kind CHECK ((CASE WHEN kind='rawQuery' THEN (kind='rawQuery' AND requester_kind='human' AND request_operation='requestRawAccess'
 AND requester_key IS NOT NULL AND octet_length(requester_key)=32
 AND requester_key=sha256(int4send(octet_length(convert_to(requester_issuer,'UTF8'))) || convert_to(requester_issuer,'UTF8') || int4send(octet_length(convert_to(requester_subject,'UTF8'))) || convert_to(requester_subject,'UTF8') || int4send(octet_length(convert_to(requester_client,'UTF8'))) || convert_to(requester_client,'UTF8') || int4send(5) || convert_to('human','UTF8'))
 AND preview_id IS NULL AND capture_id IS NULL AND cluster_id IS NULL AND namespace_uid IS NULL AND workload_uid IS NULL AND pod_uid IS NULL
 AND policy_uid IS NULL AND policy_acceptance_id IS NULL AND policy_scope IS NULL AND policy_not_after IS NULL
 AND policy_executions_spent=0 AND policy_bytes_spent=0 AND policy_observed_bytes_spent=0 AND policy_observed_events_spent=0
 AND data_class='raw' AND lifetime_seconds BETWEEN 1 AND 28800
 AND result_access IS NULL AND result_access_digest IS NULL AND not_after IS NOT NULL
 AND jsonb_typeof(raw_query)='object'
 AND convert_from(scope,'UTF8')::jsonb=jsonb_build_object('Version','raw-query/v1','Scope',raw_query)
 AND jsonb_typeof(raw_query->'Artifacts')='array' AND jsonb_array_length(raw_query->'Artifacts') BETWEEN 1 AND 64
 AND raw_query->'Operations'='["download_artifact"]'::jsonb
 AND max_artifacts=jsonb_array_length(raw_query->'Artifacts')
 AND max_bytes=(raw_query->>'MaxBytes')::bigint AND max_bytes BETWEEN 1 AND 1099511627776
 AND max_operations=(raw_query->>'MaxOperations')::bigint AND max_operations BETWEEN 1 AND 10000
 AND not_after=(raw_query->>'NotAfter')::timestamptz) ELSE (raw_query IS NULL AND cluster_id IS NOT NULL AND namespace_uid IS NOT NULL AND workload_uid IS NOT NULL AND ((
 (kind='adHocCapture' AND requester_kind='human' AND request_operation='requestGrant' AND requester_key IS NULL
  AND preview_id IS NOT NULL AND capture_id IS NOT NULL AND pod_uid IS NOT NULL
  AND policy_uid IS NULL AND policy_acceptance_id IS NULL AND policy_scope IS NULL AND policy_not_after IS NULL
  AND lifetime_seconds BETWEEN 60 AND 28800
  AND policy_executions_spent=0 AND policy_bytes_spent=0 AND policy_observed_bytes_spent=0)
 OR
 (kind='policy' AND request_operation='requestPolicyGrant'
  AND requester_key IS NOT NULL AND octet_length(requester_key)=32
  AND requester_key=sha256(int4send(octet_length(convert_to(requester_issuer,'UTF8'))) || convert_to(requester_issuer,'UTF8') || int4send(octet_length(convert_to(requester_subject,'UTF8'))) || convert_to(requester_subject,'UTF8') || int4send(octet_length(convert_to(requester_client,'UTF8'))) || convert_to(requester_client,'UTF8') || int4send(octet_length(convert_to(requester_kind,'UTF8'))) || convert_to(requester_kind,'UTF8'))
  AND preview_id IS NULL AND capture_id IS NULL AND pod_uid IS NULL
  AND policy_uid IS NOT NULL AND octet_length(policy_uid) BETWEEN 1 AND 64
  AND policy_acceptance_id IS NOT NULL AND policy_scope IS NOT NULL
  AND jsonb_typeof(policy_scope)='object' AND octet_length(policy_scope::text)<=65536
  AND policy_scope ?& ARRAY['Authority','Limits','ApprovalPolicyRef','ApprovalMaxAge','RecipeDigest']
  AND policy_scope#>>'{Authority,PolicyUID}'=policy_uid
  AND policy_scope#>>'{Authority,ClusterID}'=cluster_id::text
  AND policy_scope#>>'{Authority,NamespaceUID}'=namespace_uid
  AND policy_scope#>>'{Authority,WorkloadUID}'=workload_uid
  AND lifetime_seconds BETWEEN 1 AND 31536000
  AND (policy_scope->>'ApprovalMaxAge')::bigint BETWEEN lifetime_seconds::bigint*1000000000 AND 31536000000000000
  AND policy_not_after IS NOT NULL AND policy_not_after>requested_at
  AND policy_not_after<=requested_at+make_interval(secs=>lifetime_seconds)
  AND policy_not_after<=(policy_scope#>>'{Authority,NotAfter}')::timestamptz
  AND result_access IS NULL AND result_access_digest IS NULL AND not_after IS NULL
  AND max_artifacts=0 AND max_bytes=0 AND max_operations=0
  AND artifacts_spent=0 AND bytes_spent=0 AND operations_spent=0
  AND policy_max_executions IS NOT NULL AND policy_max_executions>0
  AND policy_max_bytes IS NOT NULL AND policy_max_bytes>0
  AND policy_max_observed_bytes IS NOT NULL AND policy_max_observed_bytes>=0)
) IS TRUE)) END) IS TRUE);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_expiry_kind CHECK(
 decision IS DISTINCT FROM 'approved' OR
 (decision_acr IS NOT NULL AND decision_auth_time IS NOT NULL AND decision_auth_time<=decided_at
 AND ((kind IN ('adHocCapture','rawQuery') AND expires_at=LEAST(decided_at+make_interval(secs=>lifetime_seconds),COALESCE(not_after,'infinity'::timestamptz)))
   OR (kind='policy' AND expires_at=policy_not_after)))
);
CREATE UNIQUE INDEX access_grant_raw_request ON access_grant(root_id,requester_key,request_operation,idempotency_key) WHERE kind='rawQuery';
CREATE INDEX access_grant_raw_member ON access_grant USING gin(raw_query jsonb_path_ops) WHERE kind='rawQuery';
CREATE INDEX access_grant_raw_requester ON access_grant(root_id,requester_key,requested_at,id) WHERE kind='rawQuery';
ALTER TABLE access_grant ADD CONSTRAINT access_grant_root_parent UNIQUE(root_id,id);
ALTER TABLE access_grant_child DROP CONSTRAINT access_grant_child_exact_parent;
ALTER TABLE access_grant_child ADD CONSTRAINT access_grant_child_root_parent FOREIGN KEY(root_id,parent_id) REFERENCES access_grant(root_id,id);
-- +goose StatementBegin
CREATE FUNCTION guard_access_grant_child_scope() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE parent public.access_grant%ROWTYPE; item jsonb; matched boolean:=false;
BEGIN
 SELECT * INTO STRICT parent FROM public.access_grant WHERE root_id=NEW.root_id AND id=NEW.parent_id;
 IF parent.kind='adHocCapture' THEN
  IF NEW.capture_id IS DISTINCT FROM parent.capture_id THEN RAISE EXCEPTION 'child capture differs from parent' USING ERRCODE='23514'; END IF;
 ELSIF parent.kind='rawQuery' THEN
  IF NEW.client_id<>parent.requester_client THEN RAISE EXCEPTION 'raw child client differs from requester' USING ERRCODE='23514'; END IF;
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
CREATE TRIGGER access_grant_child_scope_guard BEFORE INSERT ON access_grant_child FOR EACH ROW EXECUTE FUNCTION guard_access_grant_child_scope();
REVOKE ALL ON FUNCTION guard_access_grant_child_scope() FROM PUBLIC;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_access_grant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 counters text[] := ARRAY['artifacts_spent','bytes_spent','operations_spent',
  'policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent','policy_observed_events_spent'];
 mutable text[] := ARRAY['decision','approver_issuer','approver_subject','approver_client','decision_reason','decision_acr','decision_auth_time','decided_at','decision_key','expires_at',
  'revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision','policy_not_after',
  'artifacts_spent','bytes_spent','operations_spent','policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent','policy_observed_events_spent'];
 spent boolean;
 before_row jsonb;
 after_row jsonb;
BEGIN
 -- Stored generated values are computed after BEFORE triggers. Compare the
 -- immutable source columns, never NEW's not-yet-computed generated fields.
 before_row := to_jsonb(OLD)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 after_row := to_jsonb(NEW)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 IF TG_OP='DELETE' OR (after_row-mutable)<>(before_row-mutable) THEN
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 spent := ROW(NEW.artifacts_spent,NEW.bytes_spent,NEW.operations_spent,NEW.policy_executions_spent,NEW.policy_bytes_spent,NEW.policy_observed_bytes_spent,NEW.policy_observed_events_spent)
   IS DISTINCT FROM ROW(OLD.artifacts_spent,OLD.bytes_spent,OLD.operations_spent,OLD.policy_executions_spent,OLD.policy_bytes_spent,OLD.policy_observed_bytes_spent,OLD.policy_observed_events_spent);
 IF NEW.artifacts_spent<OLD.artifacts_spent OR NEW.bytes_spent<OLD.bytes_spent OR NEW.operations_spent<OLD.operations_spent
  OR NEW.policy_executions_spent<OLD.policy_executions_spent OR NEW.policy_bytes_spent<OLD.policy_bytes_spent OR NEW.policy_observed_bytes_spent<OLD.policy_observed_bytes_spent OR NEW.policy_observed_events_spent<OLD.policy_observed_events_spent THEN
  RAISE EXCEPTION 'access grant spend never decreases' USING ERRCODE='23514';
 END IF;
 IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
  IF spent OR NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after
   OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1
   OR clock_timestamp()>=OLD.review_until OR (OLD.kind='policy' AND clock_timestamp()>=OLD.policy_not_after)
   OR (OLD.kind='rawQuery' AND clock_timestamp()>=OLD.not_after) THEN
   RAISE EXCEPTION 'access grant decision refused' USING ERRCODE='23514';
  END IF;
 ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
  IF spent OR NEW.revision<>OLD.revision+1 OR (after_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision'])<>(before_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision']) THEN
   RAISE EXCEPTION 'access grant revocation refused' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after THEN
  IF OLD.kind<>'policy' OR NEW.policy_not_after IS NULL OR NEW.policy_not_after>=OLD.policy_not_after
   OR (after_row-ARRAY['policy_not_after','expires_at'])<>(before_row-ARRAY['policy_not_after','expires_at'])
   OR NEW.expires_at IS DISTINCT FROM (CASE WHEN OLD.decision='approved' THEN NEW.policy_not_after ELSE NULL END) THEN
   RAISE EXCEPTION 'access grant deadline only shortens' USING ERRCODE='23514';
  END IF;
 ELSIF spent THEN
  IF OLD.decision IS DISTINCT FROM 'approved' OR OLD.revoked_at IS NOT NULL OR clock_timestamp()>=OLD.expires_at
   OR (after_row-counters)<>(before_row-counters) THEN
   RAISE EXCEPTION 'access grant pool is not usable' USING ERRCODE='23514';
  END IF;
 ELSE
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format IN ('capture-intent/v2','capture-intent-reason/v1')
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd

-- +goose Down
-- Never discard an existing reviewed scope, child or spent disclosure pool.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM access_grant WHERE kind='rawQuery') OR EXISTS(SELECT 1 FROM operation_audit WHERE intent->>'Name'='request_raw_access') THEN RAISE EXCEPTION 'retained raw-query grants prevent rollback' USING ERRCODE='23514'; END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER access_grant_child_scope_guard ON access_grant_child;
DROP FUNCTION guard_access_grant_child_scope();
ALTER TABLE access_grant_child DROP CONSTRAINT access_grant_child_root_parent;
ALTER TABLE access_grant_child ADD CONSTRAINT access_grant_child_exact_parent FOREIGN KEY(root_id,parent_id,capture_id) REFERENCES access_grant(root_id,id,capture_id);
ALTER TABLE access_grant DROP CONSTRAINT access_grant_root_parent;
DROP INDEX access_grant_raw_request;
DROP INDEX access_grant_raw_member;
DROP INDEX access_grant_raw_requester;
ALTER TABLE access_grant DROP CONSTRAINT access_grant_kind, DROP CONSTRAINT access_grant_scope_kind, DROP CONSTRAINT access_grant_expiry_kind, DROP CONSTRAINT access_grant_max_bytes_check, DROP CONSTRAINT access_grant_result_digest, DROP CONSTRAINT access_grant_result_pool, DROP CONSTRAINT access_grant_review_check;
ALTER TABLE access_grant DROP COLUMN raw_query;
ALTER TABLE access_grant ALTER COLUMN cluster_id SET NOT NULL;
ALTER TABLE access_grant ALTER COLUMN namespace_uid SET NOT NULL;
ALTER TABLE access_grant ALTER COLUMN workload_uid SET NOT NULL;
ALTER TABLE access_grant ADD CONSTRAINT access_grant_kind CHECK(kind IN('adHocCapture','policy'));
ALTER TABLE access_grant ADD CONSTRAINT access_grant_max_bytes_check CHECK(max_bytes BETWEEN 0 AND 274877906944);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_review_check CHECK(octet_length(review) BETWEEN 2 AND 32768);
ALTER TABLE access_grant ADD CHECK ((result_access IS NULL)=(result_access_digest IS NULL) AND (result_access IS NULL)=(not_after IS NULL));
ALTER TABLE access_grant ADD CHECK ((result_access IS NULL)=(max_artifacts=0) AND (max_artifacts=0)=(max_bytes=0) AND (max_bytes=0)=(max_operations=0));
ALTER TABLE access_grant ADD CONSTRAINT access_grant_scope_kind CHECK((
 (kind='adHocCapture' AND requester_kind='human' AND request_operation='requestGrant' AND requester_key IS NULL
  AND preview_id IS NOT NULL AND capture_id IS NOT NULL AND pod_uid IS NOT NULL
  AND policy_uid IS NULL AND policy_acceptance_id IS NULL AND policy_scope IS NULL AND policy_not_after IS NULL
  AND lifetime_seconds BETWEEN 60 AND 28800
  AND policy_executions_spent=0 AND policy_bytes_spent=0 AND policy_observed_bytes_spent=0)
 OR
 (kind='policy' AND request_operation='requestPolicyGrant'
  AND requester_key IS NOT NULL AND octet_length(requester_key)=32
  AND requester_key=sha256(int4send(octet_length(convert_to(requester_issuer,'UTF8'))) || convert_to(requester_issuer,'UTF8') || int4send(octet_length(convert_to(requester_subject,'UTF8'))) || convert_to(requester_subject,'UTF8') || int4send(octet_length(convert_to(requester_client,'UTF8'))) || convert_to(requester_client,'UTF8') || int4send(octet_length(convert_to(requester_kind,'UTF8'))) || convert_to(requester_kind,'UTF8'))
  AND preview_id IS NULL AND capture_id IS NULL AND pod_uid IS NULL
  AND policy_uid IS NOT NULL AND octet_length(policy_uid) BETWEEN 1 AND 64
  AND policy_acceptance_id IS NOT NULL AND policy_scope IS NOT NULL
  AND jsonb_typeof(policy_scope)='object' AND octet_length(policy_scope::text)<=65536
  AND policy_scope ?& ARRAY['Authority','Limits','ApprovalPolicyRef','ApprovalMaxAge','RecipeDigest']
  AND policy_scope#>>'{Authority,PolicyUID}'=policy_uid
  AND policy_scope#>>'{Authority,ClusterID}'=cluster_id::text
  AND policy_scope#>>'{Authority,NamespaceUID}'=namespace_uid
  AND policy_scope#>>'{Authority,WorkloadUID}'=workload_uid
  AND lifetime_seconds BETWEEN 1 AND 31536000
  AND (policy_scope->>'ApprovalMaxAge')::bigint BETWEEN lifetime_seconds::bigint*1000000000 AND 31536000000000000
  AND policy_not_after IS NOT NULL AND policy_not_after>requested_at
  AND policy_not_after<=requested_at+make_interval(secs=>lifetime_seconds)
  AND policy_not_after<=(policy_scope#>>'{Authority,NotAfter}')::timestamptz
  AND result_access IS NULL AND result_access_digest IS NULL AND not_after IS NULL
  AND max_artifacts=0 AND max_bytes=0 AND max_operations=0
  AND artifacts_spent=0 AND bytes_spent=0 AND operations_spent=0
  AND policy_max_executions IS NOT NULL AND policy_max_executions>0
  AND policy_max_bytes IS NOT NULL AND policy_max_bytes>0
  AND policy_max_observed_bytes IS NOT NULL AND policy_max_observed_bytes>=0)
) IS TRUE);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_expiry_kind CHECK(
 decision IS DISTINCT FROM 'approved' OR
 (decision_acr IS NOT NULL AND decision_auth_time IS NOT NULL AND decision_auth_time<=decided_at
 AND ((kind='adHocCapture' AND expires_at=LEAST(decided_at+make_interval(secs=>lifetime_seconds),COALESCE(not_after,'infinity'::timestamptz)))
   OR (kind='policy' AND expires_at=policy_not_after)))
);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_access_grant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 counters text[] := ARRAY['artifacts_spent','bytes_spent','operations_spent',
  'policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent','policy_observed_events_spent'];
 mutable text[] := ARRAY['decision','approver_issuer','approver_subject','approver_client','decision_reason','decision_acr','decision_auth_time','decided_at','decision_key','expires_at',
  'revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision','policy_not_after',
  'artifacts_spent','bytes_spent','operations_spent','policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent','policy_observed_events_spent'];
 spent boolean;
 before_row jsonb;
 after_row jsonb;
BEGIN
 -- Stored generated values are computed after BEFORE triggers. Compare the
 -- immutable source columns, never NEW's not-yet-computed generated fields.
 before_row := to_jsonb(OLD)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 after_row := to_jsonb(NEW)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 IF TG_OP='DELETE' OR (after_row-mutable)<>(before_row-mutable) THEN
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 spent := ROW(NEW.artifacts_spent,NEW.bytes_spent,NEW.operations_spent,NEW.policy_executions_spent,NEW.policy_bytes_spent,NEW.policy_observed_bytes_spent,NEW.policy_observed_events_spent)
   IS DISTINCT FROM ROW(OLD.artifacts_spent,OLD.bytes_spent,OLD.operations_spent,OLD.policy_executions_spent,OLD.policy_bytes_spent,OLD.policy_observed_bytes_spent,OLD.policy_observed_events_spent);
 IF NEW.artifacts_spent<OLD.artifacts_spent OR NEW.bytes_spent<OLD.bytes_spent OR NEW.operations_spent<OLD.operations_spent
  OR NEW.policy_executions_spent<OLD.policy_executions_spent OR NEW.policy_bytes_spent<OLD.policy_bytes_spent OR NEW.policy_observed_bytes_spent<OLD.policy_observed_bytes_spent OR NEW.policy_observed_events_spent<OLD.policy_observed_events_spent THEN
  RAISE EXCEPTION 'access grant spend never decreases' USING ERRCODE='23514';
 END IF;
 IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
  IF spent OR NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after
   OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1
   OR clock_timestamp()>=OLD.review_until OR (OLD.kind='policy' AND clock_timestamp()>=OLD.policy_not_after) THEN
   RAISE EXCEPTION 'access grant decision refused' USING ERRCODE='23514';
  END IF;
 ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
  IF spent OR NEW.revision<>OLD.revision+1 OR (after_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision'])<>(before_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision']) THEN
   RAISE EXCEPTION 'access grant revocation refused' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after THEN
  IF OLD.kind<>'policy' OR NEW.policy_not_after IS NULL OR NEW.policy_not_after>=OLD.policy_not_after
   OR (after_row-ARRAY['policy_not_after','expires_at'])<>(before_row-ARRAY['policy_not_after','expires_at'])
   OR NEW.expires_at IS DISTINCT FROM (CASE WHEN OLD.decision='approved' THEN NEW.policy_not_after ELSE NULL END) THEN
   RAISE EXCEPTION 'access grant deadline only shortens' USING ERRCODE='23514';
  END IF;
 ELSIF spent THEN
  IF OLD.decision IS DISTINCT FROM 'approved' OR OLD.revoked_at IS NOT NULL OR clock_timestamp()>=OLD.expires_at
   OR (after_row-counters)<>(before_row-counters) THEN
   RAISE EXCEPTION 'access grant pool is not usable' USING ERRCODE='23514';
  END IF;
 ELSE
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format IN ('capture-intent/v2','capture-intent-reason/v1')
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','list_capture_profiles','get_capture_profile') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
