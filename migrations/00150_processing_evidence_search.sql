-- +goose Up
-- The browser processing-evidence search uses the existing normal audit lane.
-- Earlier operation names, input formats and function privileges remain compatible.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','get_live_capacity','list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','search_processing_evidence','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_target_discovery','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_target_discovery','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='search_processing_evidence' THEN input_format IS NOT DISTINCT FROM 'context-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format IN ('capture-intent/v2','capture-intent-reason/v1')
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','get_live_capacity','list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd

-- +goose Down
-- Fence new writes until the old validators and version are restored.
LOCK TABLE public.operation_audit IN SHARE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.operation_audit WHERE intent->>'Name'='search_processing_evidence') THEN
  RAISE EXCEPTION 'retained processing evidence search audit prevents downgrade' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','get_live_capacity','list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_target_discovery','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_target_discovery','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format IN ('capture-intent/v2','capture-intent-reason/v1')
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','get_live_capacity','list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
