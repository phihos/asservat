-- +goose Up
-- ADR-238 (S-06 increment 9): explicit share management, audited transfer
-- and administrator revocation. A transfer replaces only the pinned
-- management of an unrevoked, unexpired share and adds one revision; the
-- revocation adds one revision too. Additive for older binaries: they never
-- serve transfer_share, and they read only rows whose revision is 1 or 2
-- unless a newer binary transferred them; an older binary refuses such a row
-- as invalid (fail closed), so the ADR-227 compatibility floor stays at 81.
ALTER TABLE evidence_share
 ADD COLUMN transfer_key text CHECK (octet_length(transfer_key) BETWEEN 1 AND 128),
 ADD COLUMN transfer_digest bytea CHECK (octet_length(transfer_digest)=32),
 ADD CONSTRAINT evidence_share_transfer_pair CHECK ((transfer_key IS NULL)=(transfer_digest IS NULL));

-- Replace the increment 1 revision rule (unrevoked=1, revoked=2) with: every
-- change adds one revision, a revoked share has at least revision 2.
-- +goose StatementBegin
DO $$
DECLARE c text;
BEGIN
 SELECT conname INTO STRICT c FROM pg_constraint WHERE conrelid='evidence_share'::regclass AND contype='c'
  AND pg_get_constraintdef(oid) LIKE '%revision = 1%' AND pg_get_constraintdef(oid) LIKE '%revision = 2%';
 EXECUTE format('ALTER TABLE evidence_share DROP CONSTRAINT %I', c);
END $$;
-- +goose StatementEnd
-- The administrator's management-only listing pages all shares newest first.
CREATE INDEX evidence_share_administered ON evidence_share(root_id,created_at DESC,id DESC);
ALTER TABLE evidence_share ADD CONSTRAINT evidence_share_revision CHECK (revision BETWEEN 1 AND 1000000000 AND (revoked_at IS NULL OR revision>=2));

-- Two changes remain possible on a live share, each adding exactly one
-- revision: one revocation, or a transfer of its management (with the
-- transfer's idempotency key and digest). Creator, artifact, recipients and
-- expiry are immutable; a revoked share never changes again.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_evidence_share() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'evidence share is immutable except for revocation and management transfer' USING ERRCODE='23514';
 END IF;
 IF NEW.revoked_at IS NOT NULL THEN
  IF (to_jsonb(NEW)-ARRAY['revoked_at','revoke_key','revision'])<>(to_jsonb(OLD)-ARRAY['revoked_at','revoke_key','revision']) THEN
   RAISE EXCEPTION 'evidence share revocation changes only the revocation' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.transfer_key IS NULL OR OLD.expires_at<=clock_timestamp() OR
  (to_jsonb(NEW)-ARRAY['management','transfer_key','transfer_digest','revision'])<>(to_jsonb(OLD)-ARRAY['management','transfer_key','transfer_digest','revision']) THEN
  RAISE EXCEPTION 'evidence share transfer changes only the management of a live share' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- One more public share operation on the normal audit lane. The definition
-- also keeps the names of the parallel S-06 migrations 00089
-- (list_capture_history, get_capture_settings, ADR-236) and 00090
-- (preview_access_change, ADR-237), so the merge order drops no name.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_lane(text),operation_audit_human_input_valid(text,text) FROM PUBLIC;
-- No destructive Down: transfers and revocations are audit-relevant history.
