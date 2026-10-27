-- +goose Up
-- ADR-249 (S-04 increment 12): individual approval of one sensitive
-- acquisition plan (adHocCapture AccessGrant, REQ-AUT-003, REQ-INV-001..003).
-- Additive: an older binary neither reads nor writes these tables and never
-- serves the four grant operations, so the ADR-227 compatibility floor stays
-- at 81.

-- One row per reviewed plan (capture identity). The phase is derived at read
-- time: Pending, Approved, Denied, Revoked or Expired. After the insert only
-- one decision, one revocation and the monotonic pool counters change.
CREATE TABLE access_grant (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL,
 kind text NOT NULL CHECK (kind='adHocCapture'),
 -- The reviewed preview and its capture identity; the grant never covers
 -- another capture, even one with an identical plan.
 preview_id uuid NOT NULL,
 capture_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK (octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_uid text NOT NULL CHECK (octet_length(workload_uid) BETWEEN 1 AND 64),
 pod_uid text NOT NULL CHECK (octet_length(pod_uid) BETWEEN 1 AND 64),
 -- SHA-256 of scope (the canonical recorder-preview/v1 plan), of the
 -- resultAccess instruction and of the complete review (what is approved).
 execution_digest bytea NOT NULL CHECK (octet_length(execution_digest)=32 AND execution_digest=sha256(scope)),
 result_access_digest bytea CHECK (octet_length(result_access_digest)=32),
 review_digest bytea NOT NULL CHECK (octet_length(review_digest)=32),
 data_class text NOT NULL CHECK (data_class IN ('metadata','extract','raw')),
 reasons jsonb NOT NULL CHECK (jsonb_typeof(reasons)='array' AND jsonb_array_length(reasons) BETWEEN 1 AND 16 AND octet_length(reasons::text)<=8192),
 -- The review summary's exact bytes (bytea, not jsonb: the review digest
 -- covers them byte for byte).
 review bytea NOT NULL CHECK (octet_length(review) BETWEEN 2 AND 32768),
 scope bytea NOT NULL CHECK (octet_length(scope) BETWEEN 2 AND 65536),
 -- The requesting human (issuer, subject and the requesting client).
 requester_issuer text NOT NULL CHECK (octet_length(requester_issuer) BETWEEN 1 AND 2048),
 requester_subject text NOT NULL CHECK (octet_length(requester_subject) BETWEEN 1 AND 256),
 requester_client text NOT NULL CHECK (octet_length(requester_client) BETWEEN 1 AND 256),
 lifetime_seconds integer NOT NULL CHECK (lifetime_seconds BETWEEN 60 AND 28800),
 -- Same-human result access and its one shared, finite disclosure pool.
 result_access jsonb CHECK (jsonb_typeof(result_access)='object' AND octet_length(result_access::text)<=8192),
 -- The instruction's absolute end; it can only shorten the grant's expiry.
 not_after timestamptz,
 max_artifacts integer NOT NULL DEFAULT 0 CHECK (max_artifacts BETWEEN 0 AND 64),
 max_bytes bigint NOT NULL DEFAULT 0 CHECK (max_bytes BETWEEN 0 AND 274877906944),
 max_operations bigint NOT NULL DEFAULT 0 CHECK (max_operations BETWEEN 0 AND 10000),
 artifacts_spent integer NOT NULL DEFAULT 0,
 bytes_spent bigint NOT NULL DEFAULT 0,
 operations_spent bigint NOT NULL DEFAULT 0,
 idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
 request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 review_until timestamptz NOT NULL,
 -- One decision by a distinct human reviewer.
 decision text CHECK (decision IN ('approved','denied')),
 approver_issuer text CHECK (octet_length(approver_issuer) BETWEEN 1 AND 2048),
 approver_subject text CHECK (octet_length(approver_subject) BETWEEN 1 AND 256),
 approver_client text CHECK (octet_length(approver_client) BETWEEN 1 AND 256),
 decision_reason text CHECK (octet_length(decision_reason) BETWEEN 1 AND 512),
 decision_acr text CHECK (octet_length(decision_acr) BETWEEN 1 AND 128),
 decision_auth_time timestamptz,
 decided_at timestamptz,
 decision_key text CHECK (octet_length(decision_key) BETWEEN 1 AND 128),
 expires_at timestamptz,
 -- One revocation by the requester or a current approver.
 revoked_at timestamptz,
 revoker_issuer text CHECK (octet_length(revoker_issuer) BETWEEN 1 AND 2048),
 revoker_subject text CHECK (octet_length(revoker_subject) BETWEEN 1 AND 256),
 revoker_client text CHECK (octet_length(revoker_client) BETWEEN 1 AND 256),
 revoke_key text CHECK (octet_length(revoke_key) BETWEEN 1 AND 128),
 revision smallint NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 3),
 UNIQUE(root_id,capture_id),
 UNIQUE(root_id,requester_issuer,requester_subject,idempotency_key),
 CHECK ((result_access IS NULL)=(result_access_digest IS NULL) AND (result_access IS NULL)=(not_after IS NULL)),
 CHECK (not_after IS NULL OR (not_after>requested_at AND not_after<=requested_at+interval '8 hours')),
 CHECK ((result_access IS NULL)=(max_artifacts=0) AND (max_artifacts=0)=(max_bytes=0) AND (max_bytes=0)=(max_operations=0)),
 CHECK (artifacts_spent BETWEEN 0 AND max_artifacts AND bytes_spent BETWEEN 0 AND max_bytes AND operations_spent BETWEEN 0 AND max_operations),
 CHECK (review_until>requested_at AND review_until<=requested_at+interval '1 hour'),
 CHECK ((decision IS NULL)=(approver_issuer IS NULL) AND (decision IS NULL)=(approver_subject IS NULL) AND (decision IS NULL)=(approver_client IS NULL)
  AND (decision IS NULL)=(decision_reason IS NULL) AND (decision IS NULL)=(decided_at IS NULL) AND (decision IS NULL)=(decision_key IS NULL)),
 -- Self-approval is refused by issuer and subject, whatever the client.
 CHECK (decision IS NULL OR NOT (approver_issuer=requester_issuer AND approver_subject=requester_subject)),
 CHECK (decided_at IS NULL OR (decided_at>=requested_at AND decided_at<=review_until)),
 CHECK ((decision IS NOT DISTINCT FROM 'approved')=(expires_at IS NOT NULL)),
 CHECK (decision IS DISTINCT FROM 'approved' OR (expires_at=LEAST(decided_at+make_interval(secs => lifetime_seconds),COALESCE(not_after,'infinity'::timestamptz)) AND decision_acr IS NOT NULL AND decision_auth_time IS NOT NULL AND decision_auth_time<=decided_at)),
 CHECK ((revoked_at IS NULL)=(revoke_key IS NULL) AND (revoked_at IS NULL)=(revoker_issuer IS NULL) AND (revoked_at IS NULL)=(revoker_subject IS NULL) AND (revoked_at IS NULL)=(revoker_client IS NULL))
);
-- The approver inbox reads pending rows newest first; the requester lists own rows.
CREATE INDEX access_grant_pending ON access_grant(root_id,requested_at DESC,id) WHERE decision IS NULL AND revoked_at IS NULL;
CREATE INDEX access_grant_requester ON access_grant(root_id,requester_issuer,requester_subject,requested_at DESC);

-- Exact child grants (REQ-INV-002): one existing published artifact of the
-- approved capture for one approved client of the original human. Unique per
-- parent, artifact and client, so a repeated commit delivery is idempotent.
-- Children inherit the parent's decision, expiry, revocation and pool.
CREATE TABLE access_grant_child (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL,
 parent_id uuid NOT NULL REFERENCES access_grant(id) ON DELETE NO ACTION,
 capture_id uuid NOT NULL,
 action_id text NOT NULL CHECK (octet_length(action_id) BETWEEN 1 AND 64),
 artifact_id uuid NOT NULL,
 artifact_digest bytea NOT NULL CHECK (octet_length(artifact_digest)=32),
 client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 256),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(parent_id,artifact_id,client_id)
);

-- One reservation per operation ID charged to the parent pool before
-- delivery. A retry with the same ID returns it without charging again; an
-- uncertain delivery stays charged (REQ-AUT-004).
CREATE TABLE access_grant_use (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL,
 parent_id uuid NOT NULL REFERENCES access_grant(id) ON DELETE NO ACTION,
 child_id uuid NOT NULL REFERENCES access_grant_child(id) ON DELETE NO ACTION,
 operation text NOT NULL CHECK (operation='download_artifact'),
 bytes bigint NOT NULL CHECK (bytes>=0),
 operations bigint NOT NULL CHECK (operations>=0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK (bytes+operations>0)
);

-- After the insert: exactly one decision (revision 1 -> 2) while the request
-- is reviewable, one revocation (revision +1), and pool counters that only
-- grow, only on an approved, unrevoked, unexpired grant. Nothing else changes.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_access_grant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 mutable text[] := ARRAY['decision','approver_issuer','approver_subject','approver_client','decision_reason','decision_acr','decision_auth_time','decided_at','decision_key','expires_at',
  'revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision','artifacts_spent','bytes_spent','operations_spent'];
 spent boolean;
BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-mutable)<>(to_jsonb(OLD)-mutable) THEN
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 spent := NEW.artifacts_spent<>OLD.artifacts_spent OR NEW.bytes_spent<>OLD.bytes_spent OR NEW.operations_spent<>OLD.operations_spent;
 IF NEW.artifacts_spent<OLD.artifacts_spent OR NEW.bytes_spent<OLD.bytes_spent OR NEW.operations_spent<OLD.operations_spent THEN
  RAISE EXCEPTION 'access grant spend never decreases' USING ERRCODE='23514';
 END IF;
 IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
  IF spent OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1 OR clock_timestamp()>=OLD.review_until THEN
   RAISE EXCEPTION 'access grant decision refused' USING ERRCODE='23514';
  END IF;
 ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
  IF spent OR NEW.revision<>OLD.revision+1 OR (to_jsonb(NEW)-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision'])<>(to_jsonb(OLD)-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision']) THEN
   RAISE EXCEPTION 'access grant revocation refused' USING ERRCODE='23514';
  END IF;
 ELSIF spent THEN
  IF OLD.decision IS DISTINCT FROM 'approved' OR OLD.revoked_at IS NOT NULL OR clock_timestamp()>=OLD.expires_at
   OR (to_jsonb(NEW)-ARRAY['artifacts_spent','bytes_spent','operations_spent'])<>(to_jsonb(OLD)-ARRAY['artifacts_spent','bytes_spent','operations_spent']) THEN
   RAISE EXCEPTION 'access grant pool is not usable' USING ERRCODE='23514';
  END IF;
 ELSE
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION protect_access_grant_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'access grant history is append-only' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER access_grant_immutable BEFORE UPDATE OR DELETE ON access_grant FOR EACH ROW EXECUTE FUNCTION protect_access_grant();
CREATE TRIGGER access_grant_child_immutable BEFORE UPDATE OR DELETE ON access_grant_child FOR EACH ROW EXECUTE FUNCTION protect_access_grant_history();
CREATE TRIGGER access_grant_use_immutable BEFORE UPDATE OR DELETE ON access_grant_use FOR EACH ROW EXECUTE FUNCTION protect_access_grant_history();
REVOKE ALL ON FUNCTION protect_access_grant(),protect_access_grant_history() FROM PUBLIC;

-- Four public grant operations on the normal audit lane. The definition is
-- copied from 00093 (ADR-240), so it keeps every earlier name.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_lane(text),operation_audit_human_input_valid(text,text) FROM PUBLIC;
-- No destructive Down: grants, decisions, revocations and spend are audit-relevant history.
