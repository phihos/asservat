-- +goose Up
-- Erasure uses the already compiled processing decision duty. Only this fixed
-- trigger branch can stage and apply the exact audited retention shortening.
-- The processing decision uses a restricted search path for its nested
-- custody update. Resolve the retention ledger by its exact schema.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.protect_custody_retention() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.retention_sequence<>0 OR (NEW.effective_expires_at IS NOT NULL AND NEW.effective_expires_at<>NEW.expires_at) OR (NEW.effective_delete_by IS NOT NULL AND NEW.effective_delete_by<>NEW.delete_by) THEN RAISE EXCEPTION 'initial retention must match registration'; END IF;
  NEW.effective_expires_at:=NEW.expires_at;NEW.effective_delete_by:=NEW.delete_by;RETURN NEW;
 END IF;
 IF (NEW.id,NEW.cluster_id,NEW.artifact_id,NEW.allocation_id,NEW.request_digest,NEW.pool_revision,NEW.allocation_revision,NEW.native_limit,NEW.reserved_bytes,NEW.anchor_at,NEW.write_until,NEW.expires_at,NEW.delete_by) IS DISTINCT FROM
 (OLD.id,OLD.cluster_id,OLD.artifact_id,OLD.allocation_id,OLD.request_digest,OLD.pool_revision,OLD.allocation_revision,OLD.native_limit,OLD.reserved_bytes,OLD.anchor_at,OLD.write_until,OLD.expires_at,OLD.delete_by) THEN RAISE EXCEPTION 'immutable custody registration'; END IF;
 IF (NEW.retention_sequence,NEW.effective_expires_at,NEW.effective_delete_by) IS DISTINCT FROM (OLD.retention_sequence,OLD.effective_expires_at,OLD.effective_delete_by) THEN
  IF NEW.retention_sequence<>OLD.retention_sequence+1 OR NEW.effective_expires_at>OLD.effective_expires_at OR NEW.effective_delete_by>OLD.effective_delete_by OR NOT EXISTS(SELECT 1 FROM public.retention_decision d WHERE d.attempt_id=OLD.id AND d.sequence=NEW.retention_sequence AND d.previous_expires_at=OLD.effective_expires_at AND d.previous_delete_by=OLD.effective_delete_by AND d.expires_at=NEW.effective_expires_at AND d.delete_by=NEW.effective_delete_by) THEN RAISE EXCEPTION 'retention decision mismatch'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

ALTER TABLE public.processing_decision ADD COLUMN erasure_decision bytea;
ALTER TABLE public.processing_decision DROP CONSTRAINT processing_decision_action_check;
ALTER TABLE public.processing_decision ADD CONSTRAINT processing_decision_action_check
 CHECK(action IN ('initialize_processing','restrict_processing','release_processing','request_early_erasure'));
ALTER TABLE public.processing_decision ADD CONSTRAINT processing_decision_erasure_payload_check
 CHECK((action='request_early_erasure')=(erasure_decision IS NOT NULL) AND
       (erasure_decision IS NULL OR octet_length(erasure_decision) BETWEEN 1 AND 32768));
-- +goose StatementBegin
DO $$ DECLARE binding name;
BEGIN
 SELECT conname INTO STRICT binding FROM pg_catalog.pg_constraint
 WHERE conrelid='public.processing_decision'::regclass AND contype='c'
  AND pg_get_constraintdef(oid) LIKE '%rule_id IS NULL%initialize_processing%release_account IS NULL%';
 EXECUTE format('ALTER TABLE public.processing_decision DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK((rule_id IS NULL)=(action IN (''initialize_processing'',''request_early_erasure'')) AND (rule_id IS NULL)=(release_account IS NULL))',binding,binding);
END $$;
-- +goose StatementEnd
CREATE INDEX processing_erasure_attempt ON public.processing_decision(root_id,(scope#>>'{Location,AttemptID}'),request_until)
 WHERE action='request_early_erasure';
CREATE UNIQUE INDEX processing_erasure_applied ON public.processing_decision(root_id,(scope#>>'{Location,AttemptID}'))
 WHERE action='request_early_erasure' AND applied_at IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION processing_erasure_attempt(d public.processing_decision,p public.processing_root) RETURNS public.custody_attempt
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.custody_attempt; l public.context_processing; doc jsonb; origins jsonb; storage_pool_id uuid; n timestamptz;
BEGIN
 IF d.action IS DISTINCT FROM 'request_early_erasure' OR d.root_id IS DISTINCT FROM p.root_id OR p.initialized_at IS NULL OR
    d.rule_id IS NOT NULL OR d.release_account IS NOT NULL OR d.expected_revision<>0 OR
    d.scope->>'Kind' IS DISTINCT FROM 'artifact' OR NOT public.processing_scope_valid(d.scope) THEN
  RAISE EXCEPTION 'invalid processing erasure scope' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT l FROM public.context_processing WHERE root_id=d.root_id AND
  cluster_id=(d.scope#>>'{Location,ClusterID}')::uuid AND artifact_id=(d.scope#>>'{Location,ArtifactID}')::uuid AND attempt_id=(d.scope#>>'{Location,AttemptID}')::uuid;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=l.attempt_id;
 SELECT ca.pool_id INTO STRICT storage_pool_id FROM public.custody_allocation ca WHERE ca.id=a.allocation_id;
 PERFORM 1 FROM public.custody_pool cp WHERE cp.id=storage_pool_id FOR UPDATE;
 PERFORM 1 FROM public.custody_allocation ca WHERE ca.id=a.allocation_id AND ca.pool_id=storage_pool_id FOR UPDATE;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=l.attempt_id FOR UPDATE;
 n:=clock_timestamp();
 IF n>=d.request_until OR n>=p.valid_until OR d.request_until>=l.retire_by OR
    a.artifact_id<>l.artifact_id OR a.cluster_id<>l.cluster_id OR a.anchor_at<>l.anchor_at OR a.delete_by<>l.delete_by OR
    a.state<>'stored_unpublished' OR n>=a.effective_expires_at OR a.effective_expires_at<=a.anchor_at OR
    NOT EXISTS(SELECT 1 FROM public.context_catalog cat
     JOIN public.context_verification v ON v.root_id=cat.root_id AND v.capture_id=cat.capture_id
     JOIN public.context_capture c ON c.root_id=cat.root_id AND c.id=cat.capture_id
     JOIN public.context_writer_completion w ON w.root_id=c.root_id AND w.capture_id=c.id AND w.attempt_id=c.attempt_id
     JOIN public.context_execution x ON x.root_id=w.root_id AND x.capture_id=w.capture_id AND x.attempt_id=w.attempt_id
     JOIN public.fleet_trust f ON f.installation_id=w.installation_id AND f.activated_postmaster_at=w.postmaster_at AND f.activated_database_oid=w.database_oid
     JOIN public.fleet_current_trust t ON t.installation_id=f.installation_id AND t.issuer_epoch=w.issuer_epoch
     WHERE cat.root_id=l.root_id AND cat.artifact_id=l.artifact_id AND cat.capture_id=l.capture_id AND c.attempt_id=a.id
      AND v.audit_acknowledged_at IS NOT NULL AND v.copies_digest=a.copies_digest AND v.expectation_digest=w.expectation_digest
      AND x.writer_protocol='closed-small-context/v1' AND x.phase='stored' AND x.copies_digest=w.copies_digest
      AND w.copies_digest=a.copies_digest AND w.registration_digest=a.request_digest AND w.installation_id=p.installation_id AND w.issuer_epoch=p.issuer_epoch
      AND w.closed_at<=n AND public.incarnation_current(w.postmaster_at) AND w.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
      AND NOT t.recovery_blocked AND NOT t.suspended AND t.observed_at<=n AND n<t.fresh_until) THEN
  RAISE EXCEPTION 'processing erasure needs current verified closed writer' USING ERRCODE='23514'; END IF;
 IF a.retention_sequence=0 THEN
  SELECT convert_from(c.expectation_json,'UTF8')::jsonb->'RetentionRules' INTO STRICT origins FROM public.context_capture c WHERE c.root_id=l.root_id AND c.id=l.capture_id;
 ELSE
  SELECT convert_from(r.decision_json,'UTF8')::jsonb->'Origins' INTO STRICT origins FROM public.retention_decision r
   WHERE r.root_id=l.root_id AND r.attempt_id=a.id AND r.sequence=a.retention_sequence;
 END IF;
 doc:=convert_from(d.erasure_decision,'UTF8')::jsonb;
 IF NOT public.capacity_json_fields(doc,ARRAY['ID','RootID','Location','Target','Sequence','RegistrationDigest','PolicyRevision','Policies','Origins','Previous','Effective','ObservedAt','ValidUntil']) OR
    doc->>'ID' IS DISTINCT FROM d.id::text OR doc->>'RootID' IS DISTINCT FROM d.root_id::text OR doc->'Location' IS DISTINCT FROM d.scope->'Location' OR
    doc->'Target' IS DISTINCT FROM jsonb_build_object('ClusterID',l.cluster_id,'NamespaceUID',l.namespace_uid,'WorkloadUID',l.workload_uid,'PodUID',l.pod_uid) OR
    (doc->>'Sequence')::bigint IS DISTINCT FROM a.retention_sequence+1 OR public.connector_digest(doc->'RegistrationDigest') IS DISTINCT FROM a.request_digest OR
    NOT public.capacity_json_fields(doc->'PolicyRevision',ARRAY['UID','Generation','Digest']) OR
    doc#>>'{PolicyRevision,UID}' IS DISTINCT FROM 'erasure:'||d.id::text OR doc#>'{PolicyRevision,Generation}' IS DISTINCT FROM '1'::jsonb OR
    public.connector_digest(doc#>'{PolicyRevision,Digest}') IS DISTINCT FROM d.decision_digest OR
    jsonb_typeof(origins) IS DISTINCT FROM 'array' OR jsonb_array_length(origins) NOT BETWEEN 1 AND 64 OR
    doc->'Policies' IS DISTINCT FROM origins OR doc->'Origins' IS DISTINCT FROM origins OR
    NOT public.capacity_json_fields(doc->'Previous',ARRAY['AnchorAt','ExpiresAt','DeleteBy']) OR
    NOT public.capacity_json_fields(doc->'Effective',ARRAY['AnchorAt','ExpiresAt','DeleteBy']) OR
    (doc#>>'{Previous,AnchorAt}')::timestamptz IS DISTINCT FROM a.anchor_at OR (doc#>>'{Previous,ExpiresAt}')::timestamptz IS DISTINCT FROM a.effective_expires_at OR
    (doc#>>'{Previous,DeleteBy}')::timestamptz IS DISTINCT FROM a.effective_delete_by OR
    (doc#>>'{Effective,AnchorAt}')::timestamptz IS DISTINCT FROM a.anchor_at OR (doc#>>'{Effective,ExpiresAt}')::timestamptz IS DISTINCT FROM a.anchor_at OR
    (doc#>>'{Effective,DeleteBy}')::timestamptz IS DISTINCT FROM a.effective_delete_by OR
    (doc->>'ObservedAt')::timestamptz IS DISTINCT FROM d.created_at OR (doc->>'ValidUntil')::timestamptz IS DISTINCT FROM d.request_until THEN
  RAISE EXCEPTION 'processing erasure payload does not match retained custody' USING ERRCODE='23514'; END IF;
 RETURN a;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.processing_erasure_attempt(public.processing_decision,public.processing_root) FROM PUBLIC;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_processing_decision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; r public.processing_rule; a public.operation_audit; n timestamptz; a_erasure public.custody_attempt;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing decision retirement requires independent completion' USING ERRCODE='23514'; END IF;
 -- Lock recovery before the permission/processing and storage locks for the erasure action.
 IF NEW.action='request_early_erasure' THEN
  PERFORM 1 FROM public.fleet_current_trust f WHERE f.installation_id=(SELECT installation_id FROM public.processing_root WHERE root_id=NEW.root_id) FOR SHARE;
 END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 IF NEW.rule_id IS NOT NULL THEN SELECT * INTO STRICT r FROM public.processing_rule WHERE root_id=NEW.root_id AND id=NEW.rule_id FOR UPDATE; END IF;
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  IF NEW.valid_until IS NOT NULL OR NEW.retire_by IS NOT NULL THEN RAISE EXCEPTION 'processing decision dates are source owned' USING ERRCODE='23514'; END IF;
  NEW.valid_until:=p.valid_until; NEW.retire_by:=p.retire_by;
  IF NEW.rule_id IS NOT NULL THEN NEW.valid_until:=r.valid_until; NEW.retire_by:=r.retire_by; END IF;
  IF n>=NEW.valid_until OR NEW.request_until>NEW.valid_until OR n<NEW.created_at OR n>=NEW.request_until OR n>=p.valid_until OR NEW.applied_at IS NOT NULL OR NEW.audit_digest IS NOT NULL OR NEW.result_revision IS NOT NULL OR NEW.result_sequence IS NOT NULL OR
     NEW.intent_seed->>'ID' IS DISTINCT FROM NEW.id::text OR NEW.intent_seed->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.intent_seed->>'Name' IS DISTINCT FROM NEW.action OR NEW.intent_seed->>'InputFormat' IS DISTINCT FROM 'processing-input/v1' OR
     (NEW.intent_seed->>'CreatedAt')::timestamptz IS DISTINCT FROM NEW.created_at OR (NEW.intent_seed->>'RequestUntil')::timestamptz IS DISTINCT FROM NEW.request_until OR
     NEW.outcome_json->>'Status' IS DISTINCT FROM 'success' OR NEW.outcome_json->>'Reason' IS DISTINCT FROM 'prepared' OR NEW.outcome_json->>'Effect' IS DISTINCT FROM 'unknown' OR NEW.outcome_json->>'ClientReceipt' IS DISTINCT FROM 'unknown' OR NEW.outcome_json?'Intent' THEN
   RAISE EXCEPTION 'invalid prepared processing decision' USING ERRCODE='23514'; END IF;
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR NEW.expected_revision<>0 OR p.root_transitions>=p.max_root_transitions OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN
    RAISE EXCEPTION 'processing completeness needs empty reviewed history' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET root_transitions=root_transitions+1 WHERE root_id=NEW.root_id;
  ELSIF NEW.action='request_early_erasure' THEN
   IF p.root_transitions+2>=p.max_root_transitions THEN RAISE EXCEPTION 'processing erasure capacity unavailable' USING ERRCODE='23514'; END IF;
   IF EXISTS(SELECT 1 FROM public.processing_decision d WHERE d.root_id=NEW.root_id AND d.action=NEW.action
       AND d.scope#>>'{Location,AttemptID}'=NEW.scope#>>'{Location,AttemptID}' AND (d.applied_at IS NOT NULL OR d.request_until>n)) THEN
    RAISE EXCEPTION 'processing erasure already requested' USING ERRCODE='23505'; END IF;
   IF NEW.outcome_json->'ArtifactIDs' IS DISTINCT FROM jsonb_build_array(NEW.scope#>>'{Location,ArtifactID}') THEN
    RAISE EXCEPTION 'processing erasure audit must name the exact artifact' USING ERRCODE='23514'; END IF;
   PERFORM public.processing_erasure_attempt(NEW,p);
   SELECT LEAST(p.retire_by,l.retire_by) INTO STRICT NEW.retire_by FROM public.context_processing l
    WHERE l.root_id=NEW.root_id AND l.artifact_id=(NEW.scope#>>'{Location,ArtifactID}')::uuid;
   NEW.valid_until:=LEAST(p.valid_until,NEW.retire_by-interval '1 microsecond');
   IF NEW.request_until>NEW.valid_until THEN RAISE EXCEPTION 'processing erasure original retention ended' USING ERRCODE='23514'; END IF;
   -- Two backed root-transition units cover the decision, cutoff and lifecycle
   -- acknowledgement. Keep one existing unit for backed root renewal.
   UPDATE public.processing_root SET root_transitions=root_transitions+2 WHERE root_id=NEW.root_id;
   IF clock_timestamp()>=NEW.request_until THEN RAISE EXCEPTION 'processing erasure expired after reserve' USING ERRCODE='23514'; END IF;
  ELSE
   IF p.initialized_at IS NULL OR NEW.release_account IS DISTINCT FROM r.release_account OR NOT public.processing_scope_valid(NEW.scope) OR NEW.scope IS DISTINCT FROM r.scope OR NEW.expected_revision<>r.revision OR r.decisions>=16 OR
      (NEW.action='restrict_processing' AND (r.revision%2<>0 OR r.decisions>=15)) OR
      (NEW.action='release_processing' AND (r.revision%2<>1 OR r.state<>'restricted')) OR
      (NEW.action='restrict_processing' AND EXISTS(SELECT 1 FROM public.context_processing c WHERE c.root_id=NEW.root_id AND c.delete_by>r.valid_until AND
       ((r.scope->>'Kind'='artifact' AND c.artifact_id=(r.scope#>>'{Location,ArtifactID}')::uuid AND c.attempt_id=(r.scope#>>'{Location,AttemptID}')::uuid AND c.cluster_id=(r.scope#>>'{Location,ClusterID}')::uuid) OR
        (r.scope->>'Kind'='workloadInterval' AND c.cluster_id=(r.scope->>'ClusterID')::uuid AND c.namespace_uid=r.scope->>'NamespaceUID' AND c.workload_uid=r.scope->>'WorkloadUID' AND c.anchor_at>=(r.scope->>'AcquiredFrom')::timestamptz AND c.anchor_at<(r.scope->>'AcquiredUntil')::timestamptz)))) OR
      EXISTS(SELECT 1 FROM public.processing_decision d WHERE d.root_id=NEW.root_id AND d.rule_id=NEW.rule_id AND d.applied_at IS NULL AND d.request_until>n) THEN
    RAISE EXCEPTION 'processing decision scope or capacity unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET decisions=decisions+1 WHERE root_id=NEW.root_id AND id=NEW.rule_id;
  END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['applied_at','audit_digest','result_revision','result_sequence']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['applied_at','audit_digest','result_revision','result_sequence']) OR OLD.applied_at IS NOT NULL OR NEW.applied_at IS NULL OR n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN
   RAISE EXCEPTION 'immutable or expired processing decision' USING ERRCODE='23514'; END IF;
  -- Every nested root write checks the prepaid release pool. Take it before
  -- the audit row, matching journal replay's pool -> audit ordering. Otherwise
  -- apply could hold the audit row while replay holds the pool.
  IF NEW.action='request_early_erasure' THEN
   a_erasure:=public.processing_erasure_attempt(NEW,p);
  ELSE
   PERFORM 1 FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='processing' FOR SHARE;
  END IF;
  SELECT * INTO STRICT a FROM public.operation_audit WHERE root_id=NEW.root_id AND id=NEW.id FOR SHARE;
  n:=clock_timestamp();
  IF n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until OR a.lane<>(CASE WHEN NEW.action='release_processing' THEN 'processing' ELSE 'normal' END) OR a.intent_receipt IS NULL OR a.outcome_receipt IS NULL OR
     (a.intent-ARRAY['Actor','Peer','Process']) IS DISTINCT FROM NEW.intent_seed OR sha256(convert_to((a.intent->'Actor')::text,'UTF8')) IS DISTINCT FROM NEW.actor_digest OR
     a.outcome->'Intent' IS DISTINCT FROM a.intent OR (a.outcome-'Intent') IS DISTINCT FROM NEW.outcome_json OR
     NEW.audit_digest IS DISTINCT FROM sha256(convert_to(a.outcome_receipt::text,'UTF8')) THEN
   RAISE EXCEPTION 'processing decision needs exact independent audit' USING ERRCODE='23514'; END IF;
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN RAISE EXCEPTION 'processing history changed during review' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET initialized_at=n,initialization_id=NEW.id,sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=0;
  ELSIF NEW.action='request_early_erasure' THEN
   IF a.issuer_epoch IS DISTINCT FROM p.issuer_epoch OR NOT EXISTS(
     SELECT 1 FROM public.operation_audit_lifecycle h WHERE h.root_id=a.root_id AND h.operation_id=a.id AND h.lane='normal'
      AND h.installation_id=p.installation_id AND h.issuer_epoch=p.issuer_epoch AND public.incarnation_current(h.postmaster_at)
      AND h.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
      AND h.binding=a.intent->'Lifecycle' AND h.intent_completion->'Receipt'=a.intent_receipt AND h.outcome_completion->'Receipt'=a.outcome_receipt) THEN
    RAISE EXCEPTION 'processing erasure needs exact closed audit' USING ERRCODE='23514'; END IF;
   INSERT INTO public.retention_decision(id,root_id,attempt_id,sequence,previous_expires_at,previous_delete_by,expires_at,delete_by,decision_digest,decision_json)
    VALUES(NEW.id,NEW.root_id,a_erasure.id,a_erasure.retention_sequence+1,a_erasure.effective_expires_at,a_erasure.effective_delete_by,
           a_erasure.anchor_at,a_erasure.effective_delete_by,sha256(NEW.erasure_decision),NEW.erasure_decision);
   UPDATE public.custody_attempt SET effective_expires_at=a_erasure.anchor_at,retention_sequence=a_erasure.retention_sequence+1 WHERE id=a_erasure.id;
   NEW.result_revision:=0;
  ELSE
   IF p.initialized_at IS NULL OR r.revision<>NEW.expected_revision OR r.scope IS DISTINCT FROM NEW.scope OR
      (NEW.action='release_processing' AND r.state<>'restricted') OR (NEW.action='restrict_processing' AND r.state NOT IN ('reserved','released')) THEN
    RAISE EXCEPTION 'processing decision CAS changed' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET revision=revision+1,state=CASE WHEN NEW.action='release_processing' THEN 'released' ELSE 'restricted' END,current_decision=NEW.id WHERE root_id=NEW.root_id AND id=NEW.rule_id;
   UPDATE public.processing_root SET sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=r.revision+1;
  END IF;
  -- Nested counter/rule triggers can wait for the separately protected audit
  -- pool. Recheck the original decision interval after those writes as well;
  -- an expiry rolls back every nested effect in this transaction.
  n:=clock_timestamp();
  IF n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN RAISE EXCEPTION 'processing decision expired after nested locks' USING ERRCODE='23514'; END IF;
  IF NEW.action='request_early_erasure' AND NOT EXISTS(SELECT 1 FROM public.fleet_current_trust t
      WHERE t.installation_id=p.installation_id AND t.issuer_epoch=p.issuer_epoch AND NOT t.recovery_blocked AND NOT t.suspended
       AND t.observed_at<=n AND n<t.fresh_until) THEN
   RAISE EXCEPTION 'processing erasure recovery expired after apply' USING ERRCODE='23514'; END IF;
  NEW.applied_at:=n; NEW.result_sequence:=CASE WHEN NEW.action='request_early_erasure' THEN p.sequence ELSE p.sequence+1 END;
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
 WHEN operation_name IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','get_live_capacity','list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','search_processing_evidence','request_early_erasure','get_processing_erasure','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_target_discovery','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_target_discovery','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name IN ('search_processing_evidence','get_processing_erasure') THEN input_format IS NOT DISTINCT FROM 'context-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format IN ('capture-intent/v2','capture-intent-reason/v1')
 WHEN operation_name='request_early_erasure' THEN input_format IS NOT DISTINCT FROM 'processing-input/v1'
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','get_live_capacity','list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd

-- +goose Down
LOCK TABLE public.processing_decision, public.operation_audit IN SHARE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.processing_decision WHERE action='request_early_erasure') OR
    EXISTS(SELECT 1 FROM public.operation_audit WHERE intent->>'Name' IN ('request_early_erasure','get_processing_erasure')) THEN
  RAISE EXCEPTION 'retained processing erasure prevents downgrade' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_processing_decision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; r public.processing_rule; a public.operation_audit; n timestamptz; output jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing decision retirement requires independent completion' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 IF NEW.rule_id IS NOT NULL THEN SELECT * INTO STRICT r FROM public.processing_rule WHERE root_id=NEW.root_id AND id=NEW.rule_id FOR UPDATE; END IF;
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  IF NEW.valid_until IS NOT NULL OR NEW.retire_by IS NOT NULL THEN RAISE EXCEPTION 'processing decision dates are source owned' USING ERRCODE='23514'; END IF;
  NEW.valid_until:=p.valid_until; NEW.retire_by:=p.retire_by;
  IF NEW.rule_id IS NOT NULL THEN NEW.valid_until:=r.valid_until; NEW.retire_by:=r.retire_by; END IF;
  IF n>=NEW.valid_until OR NEW.request_until>NEW.valid_until OR n<NEW.created_at OR n>=NEW.request_until OR n>=p.valid_until OR NEW.applied_at IS NOT NULL OR NEW.audit_digest IS NOT NULL OR NEW.result_revision IS NOT NULL OR NEW.result_sequence IS NOT NULL OR
     NEW.intent_seed->>'ID' IS DISTINCT FROM NEW.id::text OR NEW.intent_seed->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.intent_seed->>'Name' IS DISTINCT FROM NEW.action OR NEW.intent_seed->>'InputFormat' IS DISTINCT FROM 'processing-input/v1' OR
     (NEW.intent_seed->>'CreatedAt')::timestamptz IS DISTINCT FROM NEW.created_at OR (NEW.intent_seed->>'RequestUntil')::timestamptz IS DISTINCT FROM NEW.request_until OR
     NEW.outcome_json->>'Status' IS DISTINCT FROM 'success' OR NEW.outcome_json->>'Reason' IS DISTINCT FROM 'prepared' OR NEW.outcome_json->>'Effect' IS DISTINCT FROM 'unknown' OR NEW.outcome_json->>'ClientReceipt' IS DISTINCT FROM 'unknown' OR NEW.outcome_json?'Intent' THEN
   RAISE EXCEPTION 'invalid prepared processing decision' USING ERRCODE='23514'; END IF;
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR NEW.expected_revision<>0 OR p.root_transitions>=p.max_root_transitions OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN
    RAISE EXCEPTION 'processing completeness needs empty reviewed history' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET root_transitions=root_transitions+1 WHERE root_id=NEW.root_id;
  ELSE
   IF p.initialized_at IS NULL OR NEW.release_account IS DISTINCT FROM r.release_account OR NOT public.processing_scope_valid(NEW.scope) OR NEW.scope IS DISTINCT FROM r.scope OR NEW.expected_revision<>r.revision OR r.decisions>=16 OR
      (NEW.action='restrict_processing' AND (r.revision%2<>0 OR r.decisions>=15)) OR
      (NEW.action='release_processing' AND (r.revision%2<>1 OR r.state<>'restricted')) OR
      (NEW.action='restrict_processing' AND EXISTS(SELECT 1 FROM public.context_processing c WHERE c.root_id=NEW.root_id AND c.delete_by>r.valid_until AND
       ((r.scope->>'Kind'='artifact' AND c.artifact_id=(r.scope#>>'{Location,ArtifactID}')::uuid AND c.attempt_id=(r.scope#>>'{Location,AttemptID}')::uuid AND c.cluster_id=(r.scope#>>'{Location,ClusterID}')::uuid) OR
        (r.scope->>'Kind'='workloadInterval' AND c.cluster_id=(r.scope->>'ClusterID')::uuid AND c.namespace_uid=r.scope->>'NamespaceUID' AND c.workload_uid=r.scope->>'WorkloadUID' AND c.anchor_at>=(r.scope->>'AcquiredFrom')::timestamptz AND c.anchor_at<(r.scope->>'AcquiredUntil')::timestamptz)))) OR
      EXISTS(SELECT 1 FROM public.processing_decision d WHERE d.root_id=NEW.root_id AND d.rule_id=NEW.rule_id AND d.applied_at IS NULL AND d.request_until>n) THEN
    RAISE EXCEPTION 'processing decision scope or capacity unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET decisions=decisions+1 WHERE root_id=NEW.root_id AND id=NEW.rule_id;
  END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['applied_at','audit_digest','result_revision','result_sequence']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['applied_at','audit_digest','result_revision','result_sequence']) OR OLD.applied_at IS NOT NULL OR NEW.applied_at IS NULL OR n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN
   RAISE EXCEPTION 'immutable or expired processing decision' USING ERRCODE='23514'; END IF;
  -- Every nested root write checks the prepaid release pool. Take it before
  -- the audit row, matching journal replay's pool -> audit ordering. Otherwise
  -- apply could hold the audit row while replay holds the pool.
  PERFORM 1 FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='processing' FOR SHARE;
  SELECT * INTO STRICT a FROM public.operation_audit WHERE root_id=NEW.root_id AND id=NEW.id FOR SHARE;
  n:=clock_timestamp();
  IF n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until OR a.lane<>(CASE WHEN NEW.action='release_processing' THEN 'processing' ELSE 'normal' END) OR a.intent_receipt IS NULL OR a.outcome_receipt IS NULL OR
     (a.intent-ARRAY['Actor','Peer','Process']) IS DISTINCT FROM NEW.intent_seed OR sha256(convert_to((a.intent->'Actor')::text,'UTF8')) IS DISTINCT FROM NEW.actor_digest OR
     a.outcome->'Intent' IS DISTINCT FROM a.intent OR (a.outcome-'Intent') IS DISTINCT FROM NEW.outcome_json OR
     NEW.audit_digest IS DISTINCT FROM sha256(convert_to(a.outcome_receipt::text,'UTF8')) THEN
   RAISE EXCEPTION 'processing decision needs exact independent audit' USING ERRCODE='23514'; END IF;
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN RAISE EXCEPTION 'processing history changed during review' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET initialized_at=n,initialization_id=NEW.id,sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=0;
  ELSE
   IF p.initialized_at IS NULL OR r.revision<>NEW.expected_revision OR r.scope IS DISTINCT FROM NEW.scope OR
      (NEW.action='release_processing' AND r.state<>'restricted') OR (NEW.action='restrict_processing' AND r.state NOT IN ('reserved','released')) THEN
    RAISE EXCEPTION 'processing decision CAS changed' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET revision=revision+1,state=CASE WHEN NEW.action='release_processing' THEN 'released' ELSE 'restricted' END,current_decision=NEW.id WHERE root_id=NEW.root_id AND id=NEW.rule_id;
   UPDATE public.processing_root SET sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=r.revision+1;
  END IF;
  -- Nested counter/rule triggers can wait for the separately protected audit
  -- pool. Recheck the original decision interval after those writes as well;
  -- an expiry rolls back every nested effect in this transaction.
  n:=clock_timestamp();
  IF n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN RAISE EXCEPTION 'processing decision expired after nested locks' USING ERRCODE='23514'; END IF;
  NEW.applied_at:=n; NEW.result_sequence:=p.sequence+1;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP FUNCTION public.processing_erasure_attempt(public.processing_decision,public.processing_root);
DROP INDEX public.processing_erasure_applied;
DROP INDEX public.processing_erasure_attempt;
ALTER TABLE public.processing_decision DROP CONSTRAINT processing_decision_erasure_payload_check;
ALTER TABLE public.processing_decision DROP COLUMN erasure_decision;
ALTER TABLE public.processing_decision DROP CONSTRAINT processing_decision_action_check;
ALTER TABLE public.processing_decision ADD CONSTRAINT processing_decision_action_check
 CHECK(action IN ('initialize_processing','restrict_processing','release_processing'));
-- +goose StatementBegin
DO $$ DECLARE binding name;
BEGIN
 SELECT conname INTO STRICT binding FROM pg_catalog.pg_constraint
 WHERE conrelid='public.processing_decision'::regclass AND contype='c'
  AND pg_get_constraintdef(oid) LIKE '%rule_id IS NULL%initialize_processing%release_account IS NULL%';
 EXECUTE format('ALTER TABLE public.processing_decision DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK((rule_id IS NULL)=(action=''initialize_processing'') AND (rule_id IS NULL)=(release_account IS NULL))',binding,binding);
END $$;
-- +goose StatementEnd

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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.protect_custody_retention() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.retention_sequence<>0 OR (NEW.effective_expires_at IS NOT NULL AND NEW.effective_expires_at<>NEW.expires_at) OR (NEW.effective_delete_by IS NOT NULL AND NEW.effective_delete_by<>NEW.delete_by) THEN RAISE EXCEPTION 'initial retention must match registration'; END IF;
  NEW.effective_expires_at:=NEW.expires_at;NEW.effective_delete_by:=NEW.delete_by;RETURN NEW;
 END IF;
 IF (NEW.id,NEW.cluster_id,NEW.artifact_id,NEW.allocation_id,NEW.request_digest,NEW.pool_revision,NEW.allocation_revision,NEW.native_limit,NEW.reserved_bytes,NEW.anchor_at,NEW.write_until,NEW.expires_at,NEW.delete_by) IS DISTINCT FROM
 (OLD.id,OLD.cluster_id,OLD.artifact_id,OLD.allocation_id,OLD.request_digest,OLD.pool_revision,OLD.allocation_revision,OLD.native_limit,OLD.reserved_bytes,OLD.anchor_at,OLD.write_until,OLD.expires_at,OLD.delete_by) THEN RAISE EXCEPTION 'immutable custody registration'; END IF;
 IF (NEW.retention_sequence,NEW.effective_expires_at,NEW.effective_delete_by) IS DISTINCT FROM (OLD.retention_sequence,OLD.effective_expires_at,OLD.effective_delete_by) THEN
  IF NEW.retention_sequence<>OLD.retention_sequence+1 OR NEW.effective_expires_at>OLD.effective_expires_at OR NEW.effective_delete_by>OLD.effective_delete_by OR NOT EXISTS(SELECT 1 FROM retention_decision d WHERE d.attempt_id=OLD.id AND d.sequence=NEW.retention_sequence AND d.previous_expires_at=OLD.effective_expires_at AND d.previous_delete_by=OLD.effective_delete_by AND d.expires_at=NEW.effective_expires_at AND d.delete_by=NEW.effective_delete_by) THEN RAISE EXCEPTION 'retention decision mismatch'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
