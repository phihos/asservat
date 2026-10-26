-- +goose Up
-- ADR-236 (S-06 increment 6): recent capture history and "Collect again".
-- Additive: an older binary neither reads these columns nor serves the two
-- history operations, and its inserts still fill them through the trigger
-- below, so the ADR-227 compatibility floor stays at 81.

-- The typed target identity and origin of each accepted capture. They are
-- derived from the immutable accepted record at insert (acceptance) and never
-- change. Rows accepted before this migration keep NULL: history starts here
-- (no backfill). A recreated namespace or workload has another UID and so
-- never joins an earlier workload's history.
ALTER TABLE context_capture ADD COLUMN history_cluster_id uuid;
ALTER TABLE context_capture ADD COLUMN history_namespace_uid text;
ALTER TABLE context_capture ADD COLUMN history_workload_uid text;
ALTER TABLE context_capture ADD COLUMN history_origin text;
ALTER TABLE context_capture ADD CONSTRAINT context_capture_history_identity CHECK (
 (history_cluster_id IS NULL AND history_namespace_uid IS NULL AND history_workload_uid IS NULL AND history_origin IS NULL) OR
 (history_cluster_id IS NOT NULL AND octet_length(history_namespace_uid) BETWEEN 1 AND 64 AND octet_length(history_workload_uid) BETWEEN 1 AND 64 AND history_origin IN ('manual','policy')));

-- +goose StatementBegin
CREATE FUNCTION fill_context_capture_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE e jsonb;s jsonb;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.history_cluster_id,NEW.history_namespace_uid,NEW.history_workload_uid,NEW.history_origin) IS DISTINCT FROM ROW(OLD.history_cluster_id,OLD.history_namespace_uid,OLD.history_workload_uid,OLD.history_origin) THEN
   RAISE EXCEPTION 'capture history identity is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 -- Caller-supplied values are ignored: the accepted record is the only source.
 e:=convert_from(NEW.expectation_json,'UTF8')::jsonb;
 s:=convert_from(NEW.scope_json,'UTF8')::jsonb;
 NEW.history_cluster_id:=(e#>>'{Registration,Location,ClusterID}')::uuid;
 NEW.history_namespace_uid:=e->>'NamespaceUID';
 NEW.history_workload_uid:=e->>'WorkloadUID';
 -- capture_audit_actor_valid admits only a human or the policy executor.
 NEW.history_origin:=CASE WHEN s#>>'{executor,identityType}'='human' THEN 'manual' ELSE 'policy' END;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION fill_context_capture_history() FROM PUBLIC;
CREATE TRIGGER context_capture_history_fill BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION fill_context_capture_history();

-- The retained capture-intent view keeps exposing every capture column; a
-- replaced view may only append columns, so its earlier columns are unchanged.
CREATE OR REPLACE VIEW capture_operation_intents WITH(security_barrier=true) AS
SELECT c.* FROM public.context_capture c WHERE c.intent_operation_id=c.id AND
 public.capture_audit_role_ok(c.root_id,'reader');

-- One keyset page per (workload, origin), newest first.
CREATE INDEX context_capture_history ON context_capture(root_id,history_cluster_id,history_namespace_uid,history_workload_uid,history_origin,created_at DESC,id DESC) WHERE history_workload_uid IS NOT NULL;

-- Two read-only public operations on the normal audit lane. These definitions
-- include every operation name of migrations 00086 and 00087 (explain_access,
-- ADR-234), so the order in which those migrations merge drops no name.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','list_capture_history','get_capture_settings') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format='capture-intent/v2'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','list_capture_history','get_capture_settings') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_lane(text),operation_audit_human_input_valid(text,text) FROM PUBLIC;
-- No destructive Down: history columns are derived audit-relevant facts.
