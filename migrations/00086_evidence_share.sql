-- +goose Up
-- ADR-232 (S-06 increment 1): concrete shares of one stored pod-status
-- artifact. Additive: an older binary neither reads nor writes this table and
-- never serves the three share operations, so the ADR-227 compatibility floor
-- stays at 81.

-- One row per share of one artifact. The state is derived at read time:
-- Active, Expired (expires_at), Revoked (revoked_at) or Suspended (no pinned
-- management assignment is current; computed from the permission projection).
-- Only revocation is ever written after the insert.
CREATE TABLE evidence_share (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL,
 -- The located, published artifact and the exact target its case route names.
 artifact_id uuid NOT NULL REFERENCES context_case_locator(artifact_id) ON DELETE NO ACTION,
 case_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK (octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_uid text NOT NULL CHECK (octet_length(workload_uid) BETWEEN 1 AND 64),
 pod_uid text NOT NULL CHECK (octet_length(pod_uid) BETWEEN 1 AND 64),
 -- The verified artifact version the creator saw: a concrete snapshot.
 version bytea NOT NULL CHECK (octet_length(version)=32),
 -- Immutable creator (a human principal of the configured issuer).
 creator_issuer text NOT NULL CHECK (octet_length(creator_issuer) BETWEEN 1 AND 2048),
 creator_subject text NOT NULL CHECK (octet_length(creator_subject) BETWEEN 1 AND 256),
 creator_client text NOT NULL CHECK (octet_length(creator_client) BETWEEN 1 AND 256),
 -- The creator's contributing evidence-owner assignments (exact IDs and
 -- basis digests) at creation; at most eight.
 management jsonb NOT NULL CHECK (jsonb_typeof(management)='array' AND jsonb_array_length(management) BETWEEN 1 AND 8 AND octet_length(management::text)<=32768),
 -- Issuer-scoped User/Group recipients, at most eight, and their lookup keys.
 recipients jsonb NOT NULL CHECK (jsonb_typeof(recipients)='array' AND jsonb_array_length(recipients) BETWEEN 1 AND 8 AND octet_length(recipients::text)<=32768),
 recipient_keys text[] NOT NULL CHECK (cardinality(recipient_keys) BETWEEN 1 AND 8),
 idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
 request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 -- At most seven days (a constant, ADR-232) and never past the artifact's
 -- effective access deadline at creation.
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 revoke_key text CHECK (octet_length(revoke_key) BETWEEN 1 AND 128),
 revision bigint NOT NULL DEFAULT 1,
 UNIQUE(root_id,creator_issuer,creator_subject,idempotency_key),
 CHECK (expires_at>created_at AND expires_at<=created_at+interval '7 days'),
 CHECK ((revoked_at IS NULL)=(revoke_key IS NULL)),
 CHECK ((revoked_at IS NULL AND revision=1) OR (revoked_at IS NOT NULL AND revision=2))
);
-- A recipient's read looks up by (artifact, its keys); the per-artifact cap
-- counts unrevoked rows. Owned and received lists are bounded pages.
CREATE INDEX evidence_share_artifact ON evidence_share(root_id,artifact_id) WHERE revoked_at IS NULL;
CREATE INDEX evidence_share_creator ON evidence_share(root_id,creator_issuer,creator_subject,created_at DESC);
CREATE INDEX evidence_share_recipient ON evidence_share USING gin(recipient_keys);

-- Revocation is the only change and happens once; every other column is
-- immutable after the insert.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_evidence_share() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revision<>2 OR
  (to_jsonb(NEW)-ARRAY['revoked_at','revoke_key','revision'])<>(to_jsonb(OLD)-ARRAY['revoked_at','revoke_key','revision']) THEN
  RAISE EXCEPTION 'evidence share is immutable except for one revocation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER evidence_share_immutable BEFORE UPDATE OR DELETE ON evidence_share FOR EACH ROW EXECUTE FUNCTION protect_evidence_share();
REVOKE ALL ON FUNCTION protect_evidence_share() FROM PUBLIC;

-- Three public share operations on the normal audit lane.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_lane(text),operation_audit_human_input_valid(text,text) FROM PUBLIC;
-- No destructive Down: shares and their revocations are audit-relevant history.
