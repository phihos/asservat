-- +goose Up
-- ADR-229: deactivate_policy is a third public policy operation. A
-- deactivation clears policy_source.active_id, which every binary since
-- migration 00019 already treats as "not accepted", so an older binary also
-- stops polling and refuses the policy's captures. Only these two operation
-- name functions change; the ADR-227 compatibility floor stays at 81.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_lane(text),operation_audit_human_input_valid(text,text) FROM PUBLIC;
-- No destructive Down: deactivation history is the cleared active_id plus the
-- encrypted operation audit; nothing to undo.
