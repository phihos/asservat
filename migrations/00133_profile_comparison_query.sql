-- +goose Up
-- ADR-295: one fixed two-source comparison, atomically prepaid once per
-- principal/root and ten units per source workload, with two key children.
-- Existing single-source encodings, bounds, role masks and charges are retained.
ALTER TABLE context_query ADD COLUMN baseline_allocation_id uuid;
ALTER TABLE context_query ADD FOREIGN KEY(baseline_allocation_id,root_id) REFERENCES context_query_allocation(id,root_id);
ALTER TABLE download_worker ADD COLUMN baseline_query_allocation_id uuid REFERENCES context_query_allocation(id);
ALTER TABLE context_query DROP CONSTRAINT context_query_query_check;
ALTER TABLE context_query ADD CONSTRAINT context_query_query_check CHECK(jsonb_typeof(query)='object' AND octet_length(query::text) BETWEEN 2 AND CASE WHEN query#>'{Scope,Comparison}' IS NOT NULL THEN 98304 ELSE 65536 END);
ALTER TABLE download_worker DROP CONSTRAINT download_worker_intent_json_check;
ALTER TABLE download_worker ADD CONSTRAINT download_worker_intent_json_check CHECK(octet_length(intent_json) BETWEEN 1 AND CASE WHEN baseline_query_allocation_id IS NOT NULL THEN 98304 ELSE 65536 END);
ALTER TABLE context_query_batch DROP CONSTRAINT context_query_batch_batch_check;
ALTER TABLE context_query_batch ADD CONSTRAINT context_query_batch_batch_check CHECK(jsonb_typeof(batch)='object' AND octet_length(batch::text) BETWEEN 2 AND CASE WHEN batch#>>'{Request,Call,Tool}'='compare_profiles' THEN 32768 ELSE 16384 END);
ALTER TABLE context_query_batch DROP CONSTRAINT query_native_pair;
ALTER TABLE context_query_batch ADD CONSTRAINT query_native_pair CHECK((native_operation IS NULL AND native_authority IS NULL AND NOT native_closed) OR COALESCE(jsonb_typeof(native_operation)='object' AND octet_length(native_operation::text) BETWEEN 2 AND 16384 AND jsonb_typeof(native_authority)='object' AND octet_length(native_authority::text) BETWEEN 2 AND CASE WHEN native_authority#>'{Scope,Comparison}' IS NOT NULL THEN 131072 ELSE 65536 END,false));
-- Parent identity is immutable even before a worker is claimed.
ALTER TABLE context_query_key_binding ADD COLUMN child_id uuid;
ALTER TABLE context_query_key_binding ADD COLUMN source_ordinal smallint CHECK(source_ordinal IN (0,1));
ALTER TABLE context_query_key_binding DISABLE TRIGGER context_query_key_guard;
UPDATE context_query_key_binding SET child_id=batch_id;
ALTER TABLE context_query_key_binding ENABLE TRIGGER context_query_key_guard;
ALTER TABLE context_query_key_binding ALTER COLUMN child_id SET NOT NULL;
ALTER TABLE context_query_key_binding DROP CONSTRAINT context_query_key_binding_pkey;
ALTER TABLE context_query_key_binding ADD PRIMARY KEY(child_id);
CREATE UNIQUE INDEX context_query_legacy_key_child ON context_query_key_binding(batch_id) WHERE source_ordinal IS NULL;
CREATE UNIQUE INDEX context_query_comparison_key_child ON context_query_key_binding(batch_id,source_ordinal) WHERE source_ordinal IS NOT NULL;
ALTER TABLE context_query_key_binding DROP CONSTRAINT context_query_key_binding_binding_check;
ALTER TABLE context_query_key_binding ADD CONSTRAINT context_query_key_binding_binding_check CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text) BETWEEN 2 AND CASE WHEN source_ordinal IS NOT NULL THEN 4096 WHEN binding#>>'{Authority,Scope,NativeType}' IN ('syscallRecords','syscallArguments') THEN 49152 ELSE 16384 END);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_scope_source_valid_legacy133(s jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb:=s->'Syscalls'; n integer; i integer; name text; previous text;
BEGIN
 IF s ? 'Comparison' THEN RETURN false; END IF;
 IF s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN
  IF NOT COALESCE(NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   s->>'SourceFormat'=CASE s->>'NativeType' WHEN 'syscallRecords' THEN 'asservat-syscall-events/v1' ELSE 'asservat-syscall-arguments/v1' END AND
   public.capacity_json_fields(w,ARRAY['View','Start','Limit','Binding','Names','NameCount','ErrorsOnly']) AND
   w->>'View' IN ('summary','events') AND s->>'DisplayVersion'=CASE w->>'View' WHEN 'summary' THEN 'approved-syscall-summary/v1' WHEN 'events' THEN 'approved-syscall-events/v1' END AND
   public.capacity_json_integer(w->'Start',0,999999) AND public.capacity_json_integer(w->'Limit',1,100) AND
   public.capacity_json_integer(w->'NameCount',0,64) AND jsonb_typeof(w->'Binding')='string' AND jsonb_typeof(w->'ErrorsOnly')='boolean' AND jsonb_typeof(w->'Names')='array',false)
   THEN RETURN false; END IF;
  IF jsonb_array_length(w->'Names')<>64 THEN RETURN false; END IF;
  IF NOT ((w->>'Start'='0' AND w->>'Binding'='') OR (w->>'Start'<>'0' AND w->>'Binding'~'^[0-9a-f]{32}$')) THEN RETURN false; END IF;
  n:=(w->>'NameCount')::integer;
  IF w->>'View'='summary' AND (n<>0 OR (w->>'ErrorsOnly')::boolean) THEN RETURN false; END IF;
  FOR i IN 0..63 LOOP
   IF jsonb_typeof(w->'Names'->i) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
   name:=w->'Names'->>i;
   IF i<n THEN
    IF char_length(name) NOT BETWEEN 1 AND 64 OR previous COLLATE "C">=name COLLATE "C" THEN RETURN false; END IF;
    previous:=name;
   ELSIF name<>'' THEN RETURN false;
   END IF;
  END LOOP;
  RETURN true;
 END IF;
 IF s ? 'Syscalls' THEN RETURN false; END IF;
 RETURN COALESCE(CASE WHEN NOT (s ? 'NativeType') THEN NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND s->>'SourceFormat'='asservat-pod-status/v1' AND s->>'DisplayVersion'='approved-pod-status-display/v1'
  WHEN s->>'NativeType'='httpHeaders' THEN NOT (s ? 'Profile') AND jsonb_typeof(s->'Headers')='object' AND (s->'Headers'->>'Limit')::integer BETWEEN 1 AND 100 AND (s->'Headers'->>'Start')::integer BETWEEN 0 AND 32759 AND
   s->>'SourceFormat'='http-response-headers/v1' AND s->>'DisplayVersion'='approved-http-headers-page/v1' AND s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb
  WHEN s->>'NativeType'='pprof' THEN NOT (s ? 'Headers') AND public.capacity_json_fields(s->'Profile',ARRAY['SampleType','TopN']) AND
   jsonb_typeof(s->'Profile'->'SampleType')='string' AND octet_length(s->'Profile'->>'SampleType') BETWEEN 1 AND 64 AND (s->'Profile'->>'SampleType') !~ '[[:cntrl:]]' AND
   public.capacity_json_integer(s->'Profile'->'TopN',1,100) AND s->>'SourceFormat'='pprof' AND s->>'DisplayVersion'='approved-pprof-summary/v1' AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32]))
  ELSE false END,false);
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION context_query_comparison_source(s jsonb,baseline boolean) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_set((s-'Comparison') || CASE WHEN baseline THEN s#>'{Comparison,Baseline}' ELSE '{}'::jsonb END,'{DisplayVersion}','"approved-pprof-summary/v1"'::jsonb)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_scope_source_valid(s jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb:=s->'Comparison'; b jsonb:=w->'Baseline'; k text; i integer;
BEGIN
 IF NOT (s ? 'Comparison') THEN RETURN public.context_query_scope_source_valid_legacy133(s); END IF;
 IF NOT COALESCE(s->>'NativeType'='pprof' AND s->>'DisplayVersion'='approved-pprof-comparison/v1' AND
  public.capacity_json_fields(w,ARRAY['Normalization','Baseline']) AND w->>'Normalization' IN ('none','perSecond') AND
  public.capacity_json_fields(b,ARRAY['CaseID','ArtifactID','CaptureID','ClusterID','NamespaceUID','WorkloadUID','PodUID','Version']) AND
  public.context_query_scope_source_valid_legacy133(public.context_query_comparison_source(s,false)) AND
  public.context_query_scope_source_valid_legacy133(public.context_query_comparison_source(s,true)),false) THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['CaseID','ArtifactID','CaptureID','ClusterID'] LOOP
  IF jsonb_typeof(b->k) IS DISTINCT FROM 'string' OR (b->>k)='00000000-0000-0000-0000-000000000000' OR (b->>k)!~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN RETURN false; END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['NamespaceUID','WorkloadUID','PodUID'] LOOP
  IF jsonb_typeof(b->k) IS DISTINCT FROM 'string' OR octet_length(b->>k) NOT BETWEEN 1 AND 64 OR (b->>k)~'[[:cntrl:]]' THEN RETURN false; END IF;
 END LOOP;
 IF jsonb_typeof(b->'Version') IS DISTINCT FROM 'array' OR jsonb_array_length(b->'Version')<>32 OR b->'Version'=to_jsonb(array_fill(0,ARRAY[32])) THEN RETURN false; END IF;
 FOR i IN 0..31 LOOP IF NOT public.capacity_json_integer(b->'Version'->i,0,255) THEN RETURN false; END IF; END LOOP;
 IF b->>'ArtifactID'=s->>'ArtifactID' AND public.context_query_comparison_source(s,true) IS DISTINCT FROM public.context_query_comparison_source(s,false) THEN RETURN false; END IF;
 RETURN true;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_begin_tool(s jsonb) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s ? 'Comparison' THEN 'compare_profiles' WHEN s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN CASE s->'Syscalls'->>'View' WHEN 'summary' THEN 'get_syscall_summary' WHEN 'events' THEN 'get_syscall_events' ELSE NULL END WHEN s->>'NativeType'='httpHeaders' THEN 'get_http_headers' WHEN s->>'NativeType'='pprof' THEN 'get_profile_summary' ELSE 'get_file_excerpt' END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_units(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s ? 'Comparison' THEN 20 WHEN s->>'NativeType' IN ('httpHeaders','syscallRecords','syscallArguments') THEN 2 WHEN s->>'NativeType'='pprof' THEN 10 ELSE 1 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_http_headers','get_profile_summary','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format IN ('capture-intent/v2','capture-intent-reason/v1')
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.operation_audit_pool; a public.operation_audit_account; n timestamptz; prepaid boolean:=false;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'invalid operation audit source' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d JOIN public.fleet_current_trust t ON t.installation_id=d.installation_id
   WHERE d.operation_id=OLD.id AND d.root_id=OLD.root_id AND d.finalization_xid=pg_current_xact_id() AND d.terminal_acknowledged_at IS NOT NULL AND
    NOT t.recovery_blocked AND NOT t.suspended AND clock_timestamp()<t.fresh_until AND t.issuer_epoch=d.issuer_epoch AND public.incarnation_current(d.postmaster_at) AND (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())=d.database_oid AND clock_timestamp()<(d.lease->>'Until')::timestamptz)
   THEN RAISE EXCEPTION 'audit retirement unavailable' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT p FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
  n:=clock_timestamp();
  prepaid:=public.connector_retirement_prepaid(NEW);
  IF NEW.intent->>'Name'='connector_retirement' AND NOT prepaid THEN RAISE EXCEPTION 'connector retirement has no paid original ticket' USING ERRCODE='23514';END IF;
  IF (NOT prepaid AND (p.paused OR n>=p.valid_until)) OR n>=NEW.request_until OR n<(NEW.intent->>'CreatedAt')::timestamptz OR NEW.intent_started OR NEW.intent_receipt IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.outcome_started OR NEW.outcome_receipt IS NOT NULL OR
   NOT (NEW.intent ?& ARRAY['ID','RootID','MACVersion','AccountVersion','Name','CreatedAt','RequestUntil','WriteUntil','RetainUntil']) OR public.operation_audit_lane(NEW.intent->>'Name') IS NULL OR NOT public.connector_operation_actor_valid(NEW.intent) OR
   ((NEW.intent ? 'Capture') IS DISTINCT FROM (NEW.lane='capture')) OR
   (NEW.intent->>'ID')::uuid<>NEW.id OR (NEW.intent->>'RootID')::uuid<>NEW.root_id OR NEW.intent->>'AccountVersion'<>p.account_version OR
   NEW.request_until<>(NEW.intent->>'RequestUntil')::timestamptz OR NEW.write_until<>(NEW.intent->>'WriteUntil')::timestamptz OR NEW.retain_until<>(NEW.intent->>'RetainUntil')::timestamptz OR
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+(CASE WHEN NEW.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result','prepare_artifact_download','get_artifact_download') THEN interval '20 seconds' WHEN NEW.intent->>'Name' IN ('request_capture','preview_capture') THEN interval '15 seconds' WHEN NEW.lane='capture' AND NEW.intent->>'Name'='persist_capture_intent' AND EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.id AND public.capture_audit_payload_matches(c,NEW.intent) AND c.group_id IS NOT NULL AND c.group_ordinal IS NOT NULL AND NEW.request_until<=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN interval '15 seconds' ELSE interval '5 seconds' END) OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
   NEW.retain_until>(NEW.intent->>'CreatedAt')::timestamptz+make_interval(secs=>p.retained_seconds::double precision) OR
   NEW.lane IS DISTINCT FROM public.operation_audit_lane(NEW.intent->>'Name') THEN
   RAISE EXCEPTION 'operation audit unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO a FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest FOR UPDATE;
  IF NOT FOUND THEN
   IF p.accounts>=p.account_limit THEN RAISE EXCEPTION 'audit accounts exhausted' USING ERRCODE='23514'; END IF;
   UPDATE public.operation_audit_pool SET accounts=accounts+1 WHERE root_id=NEW.root_id AND lane=NEW.lane;
   INSERT INTO public.operation_audit_account(root_id,lane,principal_digest) VALUES(NEW.root_id,NEW.lane,NEW.principal_digest) RETURNING * INTO a;
  END IF;
  IF a.charged>=p.records_per_account THEN RAISE EXCEPTION 'audit records exhausted' USING ERRCODE='23514'; END IF;
  UPDATE public.operation_audit_account SET charged=charged+1 WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.lane,NEW.issuer_epoch,NEW.principal_digest,NEW.intent,NEW.request_until,NEW.write_until,NEW.retain_until) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.lane,OLD.issuer_epoch,OLD.principal_digest,OLD.intent,OLD.request_until,OLD.write_until,OLD.retain_until) OR
   (OLD.intent_started AND NOT NEW.intent_started) OR (OLD.outcome_started AND NOT NEW.outcome_started) OR
   (OLD.intent_receipt IS NOT NULL AND NEW.intent_receipt IS DISTINCT FROM OLD.intent_receipt) OR
   (OLD.outcome IS NOT NULL AND NEW.outcome IS DISTINCT FROM OLD.outcome) OR
   (OLD.outcome_receipt IS NOT NULL AND NEW.outcome_receipt IS DISTINCT FROM OLD.outcome_receipt) THEN
   RAISE EXCEPTION 'immutable operation audit' USING ERRCODE='23514'; END IF;
  IF NEW.intent ? 'Lifecycle' AND NOT public.capture_audit_receipts_current(NEW) AND NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.operation_id=NEW.id AND
    (NEW.intent_receipt IS NULL OR d.intent_completion->'Receipt'=NEW.intent_receipt) AND (NEW.outcome_receipt IS NULL OR d.outcome_completion->'Receipt'=NEW.outcome_receipt)) THEN
   RAISE EXCEPTION 'receipt lacks positive writer completion' USING ERRCODE='23514'; END IF;
  n:=clock_timestamp();
  IF n>=NEW.write_until OR (NOT OLD.intent_started AND NEW.intent_started AND n>=NEW.request_until) THEN
   RAISE EXCEPTION 'operation audit interval expired' USING ERRCODE='23514'; END IF;
  IF NEW.outcome IS NOT NULL AND NEW.outcome->'Intent' IS DISTINCT FROM NEW.intent THEN
   RAISE EXCEPTION 'outcome intent mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_intent_current(r uuid,op uuid,actor jsonb,epoch uuid,call jsonb) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.operation_audit a
 JOIN public.operation_audit_lifecycle l ON l.operation_id=a.id AND l.root_id=a.root_id
 JOIN public.fleet_current_trust t ON t.installation_id=l.installation_id
 WHERE a.id=op AND a.root_id=r AND a.lane='normal' AND l.lane='normal' AND a.issuer_epoch=epoch AND l.issuer_epoch=epoch AND t.issuer_epoch=epoch
 AND NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until
 AND public.incarnation_current(l.postmaster_at) AND l.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND a.intent_started AND a.intent_receipt IS NOT NULL AND l.intent_completion IS NOT NULL AND l.intent_completion->'Receipt'=a.intent_receipt
 AND l.binding=a.intent->'Lifecycle' AND l.retirement IS NULL AND NOT l.certificate_started AND l.finalization_xid IS NULL
 AND a.intent->'Actor'=actor AND call->'Principal'=actor AND call->>'ID'=op::text AND call->>'RootID'=r::text
 AND a.intent->>'Name'=call->>'Tool' AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result')
 AND a.intent->>'InputFormat'='context-query-input/v1' AND call->>'InputFormat'='context-query-input/v1'
 AND a.intent->>'MACVersion'=call->>'MACVersion' AND a.intent->'InputDigest'=call->'InputDigest' AND a.intent->'PrincipalDigest'=call->'PrincipalDigest'
 AND (a.intent->>'CreatedAt')::timestamptz=(call->>'StartedAt')::timestamptz AND a.request_until=(call->>'Until')::timestamptz AND a.write_until=(call->>'WriteUntil')::timestamptz
 AND (a.intent->>'CreatedAt')::timestamptz<=clock_timestamp() AND clock_timestamp()<a.request_until
 AND l.intent_completion->>'Protocol'='closed-operation-audit/v1' AND l.intent_completion->>'RootID'=r::text AND l.intent_completion->>'OperationID'=op::text
 AND l.intent_completion->>'StoreID'=l.binding->'Policy'->>'StoreID' AND l.intent_completion->>'Phase'='intent'
 AND (l.intent_completion->>'StoredAt')::timestamptz>=(a.intent->>'CreatedAt')::timestamptz
 AND (l.intent_completion->>'ClosedAt')::timestamptz>=(l.intent_completion->>'StoredAt')::timestamptz
 AND (l.intent_completion->>'ClosedAt')::timestamptz<a.write_until AND (l.intent_completion->>'ClosedAt')::timestamptz<=clock_timestamp()),false)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_outcome_closed(r uuid,op uuid,actor jsonb,epoch uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.operation_audit a
 JOIN public.operation_audit_lifecycle l ON l.operation_id=a.id AND l.root_id=a.root_id
 JOIN public.fleet_current_trust t ON t.installation_id=l.installation_id
 WHERE a.id=op AND a.root_id=r AND a.lane='normal' AND l.lane='normal' AND a.issuer_epoch=epoch AND l.issuer_epoch=epoch AND t.issuer_epoch=epoch AND NOT t.recovery_blocked
 AND public.incarnation_current(l.postmaster_at) AND l.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND a.intent->'Actor'=actor AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') AND a.intent->>'InputFormat'='context-query-input/v1'
 AND a.intent_started AND a.intent_receipt IS NOT NULL AND l.intent_completion->'Receipt'=a.intent_receipt
 AND a.outcome_started AND a.outcome_receipt IS NOT NULL AND l.outcome_completion->'Receipt'=a.outcome_receipt
 AND a.outcome->>'Effect' IN ('none','accepted','unknown') AND a.outcome->'Intent'=a.intent
 AND l.binding=a.intent->'Lifecycle' AND l.retirement IS NULL AND NOT l.certificate_started AND l.finalization_xid IS NULL
 AND l.outcome_completion->>'Protocol'='closed-operation-audit/v1' AND l.outcome_completion->>'RootID'=r::text AND l.outcome_completion->>'OperationID'=op::text
 AND l.outcome_completion->>'StoreID'=l.binding->'Policy'->>'StoreID' AND l.outcome_completion->>'Phase'='outcome'
 AND (l.outcome_completion->>'StoredAt')::timestamptz>=(a.intent->>'CreatedAt')::timestamptz
 AND (l.outcome_completion->>'ClosedAt')::timestamptz>=(l.outcome_completion->>'StoredAt')::timestamptz
 AND (l.outcome_completion->>'ClosedAt')::timestamptz<a.write_until AND (l.outcome_completion->>'ClosedAt')::timestamptz<=clock_timestamp()),false)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_query_account() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query account remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=NEW.root_id FOR UPDATE;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-'allocated') IS DISTINCT FROM (to_jsonb(OLD)-'allocated') OR NEW.allocated-OLD.allocated NOT IN (1,2,10,20) THEN RAISE EXCEPTION 'query account mutation denied' USING ERRCODE='23514'; END IF;
 ELSIF NEW.allocated<>0 THEN RAISE EXCEPTION 'query initial account spend invalid' USING ERRCODE='23514';
 ELSIF TG_TABLE_NAME='context_query_principal' THEN
  UPDATE public.context_query_backing SET principals=principals+1 WHERE root_id=NEW.root_id;
 ELSE
  IF NEW.query_limit>b.query_limit THEN RAISE EXCEPTION 'query allocation exceeds root' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query_backing SET allocations=allocations+1 WHERE root_id=NEW.root_id;
 END IF;
 IF TG_TABLE_NAME='context_query_principal' AND NEW.allocated>b.principal_query_limit THEN RAISE EXCEPTION 'query principal capacity exhausted' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_query() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing; a public.context_query_allocation; ba public.context_query_allocation; bp jsonb; bs jsonb; pair boolean; aid uuid; p public.context_query_principal; n timestamptz; u integer;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query history retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['generation','active_batch','polls','controls','uncertain']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['generation','active_batch','polls','controls','uncertain']) OR
   NEW.generation<OLD.generation OR NEW.generation>OLD.generation+1 OR NEW.polls<OLD.polls OR NEW.controls<>OLD.controls+1 OR OLD.uncertain AND NOT NEW.uncertain OR
   NEW.polls>(NEW.query->'Plan'->'Profile'->>'PollLimit')::bigint OR NEW.controls>(NEW.query->'Plan'->'Profile'->>'ControlTransitionLimit')::bigint THEN RAISE EXCEPTION 'query counters immutable' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=NEW.root_id FOR UPDATE;
 pair:=NEW.query#>'{Scope,Comparison}' IS NOT NULL;
 IF pair IS DISTINCT FROM (NEW.baseline_allocation_id IS NOT NULL) OR pair IS DISTINCT FROM (NEW.query ? 'BaselinePlan') THEN RAISE EXCEPTION 'comparison plan branch mismatch' USING ERRCODE='23514'; END IF;
 FOR aid IN SELECT id FROM public.context_query_allocation WHERE root_id=NEW.root_id AND id IN (NEW.allocation_id,NEW.baseline_allocation_id) ORDER BY id FOR UPDATE LOOP NULL; END LOOP;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id;
 IF pair THEN SELECT * INTO STRICT ba FROM public.context_query_allocation WHERE id=NEW.baseline_allocation_id AND root_id=NEW.root_id; END IF;
 SELECT * INTO STRICT p FROM public.context_query_principal WHERE id=NEW.account_id AND root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 u:=public.context_query_units(NEW.query->'Scope');
 IF NOT public.context_query_intent_current(NEW.root_id,NEW.operation_id,NEW.actor,NEW.issuer_epoch,NEW.initial_request->'Call') OR
  NOT public.context_query_complete_object(NEW.query,ARRAY['ID','OperationID','WorkerID','Scope','Plan','RecoveryIssuerEpoch','RecoveryRevision','CreatedAt','Deadline','WorkerUntil','CredentialUntil','ProviderUntil','CleanupUntil']) OR
  NOT public.context_query_complete_object(NEW.query->'Plan',ARRAY['AcceptanceID','AccountID','AllocationID','RootID','InstallationID','ClusterID','NamespaceUID','WorkloadUID','AllocationRevision','PoolSource','PolicySource','Principal','Profile','ObservedAt','ValidUntil','HardUntil','EffectsUntil','CleanupUntil','RetireBy']) OR
  NOT public.context_query_complete_object(NEW.query->'Scope',ARRAY['RootID','CaseID','ArtifactID','CaptureID','ClusterID','NamespaceUID','WorkloadUID','PodUID','Version','SourceProjectionDigest','SourceFormat','DisplayVersion','Selection','Principal']) OR
  NOT public.context_query_scope_source_valid(NEW.query->'Scope') OR
  (NEW.query->'Scope'->>'NativeType' IN ('pprof','syscallRecords','syscallArguments') AND ((NEW.query->'Plan'->'Profile'->'Worker'->>'MemoryBytes')::bigint<268435456 OR (NEW.query->'Plan'->'Profile'->'Worker'->>'WorkerTransientBytes')::bigint<268435456)) OR
  b.suspended OR p.principal_key<>NEW.principal_key OR NEW.generation<>0 OR NEW.active_batch IS NOT NULL OR NEW.polls<>0 OR NEW.controls<>0 OR NEW.uncertain OR
  ((NEW.query->'Plan'->'Profile')-'Path') IS DISTINCT FROM (b.profile-'Path') OR NEW.query->'Plan'->'Profile'->'Path'->>'TargetClusterID' IS DISTINCT FROM a.cluster_id::text OR NOT public.context_query_shared_profile_current(NEW.root_id,NEW.query->'Plan'->'Profile') OR NOT public.context_query_capacity_allocation_current(NEW.root_id,a.id) OR NEW.query->'Plan'->>'AcceptanceID'<>b.acceptance_id::text OR NEW.query->'Plan'->>'AllocationID'<>a.id::text OR
  NEW.query->'Plan'->>'AccountID'<>p.id::text OR NEW.query->'Plan'->>'ClusterID'<>a.cluster_id::text OR NEW.query->'Plan'->>'NamespaceUID'<>a.namespace_uid OR NEW.query->'Plan'->>'WorkloadUID'<>a.workload_uid OR
  NEW.query->'Plan'->'Principal' IS DISTINCT FROM NEW.actor OR NEW.query->'Scope'->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.query->'Scope'->>'ClusterID' IS DISTINCT FROM a.cluster_id::text OR NEW.query->'Scope'->>'NamespaceUID' IS DISTINCT FROM a.namespace_uid OR NEW.query->'Scope'->>'WorkloadUID' IS DISTINCT FROM a.workload_uid OR
  NEW.query->'Plan'->'PoolSource' IS DISTINCT FROM a.pool_source OR NEW.query->'Plan'->'PolicySource' IS DISTINCT FROM a.policy_source OR
  (NEW.query->'Plan'->>'AllocationRevision')::bigint<>a.revision OR NEW.query->'Scope'->'Principal' IS DISTINCT FROM NEW.actor OR
  NEW.query->>'ID'<>NEW.id::text OR NEW.query->>'WorkerID'<>NEW.worker_id::text OR NEW.query->>'OperationID'<>NEW.operation_id::text OR
  (NEW.query->>'CreatedAt')::timestamptz<>NEW.created_at OR (NEW.query->>'Deadline')::timestamptz<>NEW.deadline OR (NEW.query->>'CleanupUntil')::timestamptz<>NEW.cleanup_until OR
  NEW.deadline>NEW.created_at+make_interval(secs=>(b.profile->>'Lifetime')::double precision/1000000000) OR
  (NEW.query->'Plan'->>'RootID')::uuid<>NEW.root_id OR (NEW.query->'Plan'->>'InstallationID')::uuid<>b.installation_id OR
  (NEW.query->'Plan'->>'RetireBy')::timestamptz<>NEW.retire_by OR NEW.retire_by<>b.retire_by OR
  (NEW.query->'Plan'->>'HardUntil')::timestamptz<>b.hard_until OR (NEW.query->'Plan'->>'EffectsUntil')::timestamptz<>b.effects_until OR (NEW.query->'Plan'->>'CleanupUntil')::timestamptz<>b.cleanup_until OR
  NEW.deadline>b.hard_until OR NEW.cleanup_until>b.cleanup_until OR n>=(NEW.query->'Plan'->>'ValidUntil')::timestamptz OR n<(NEW.query->'Plan'->>'ObservedAt')::timestamptz OR
  (NEW.query->>'WorkerUntil')::timestamptz>b.effects_until OR (NEW.query->>'CredentialUntil')::timestamptz>b.effects_until OR (NEW.query->>'ProviderUntil')::timestamptz>b.effects_until OR
  NEW.query->>'RecoveryIssuerEpoch' IS DISTINCT FROM NEW.issuer_epoch::text OR NEW.created_at>n OR NEW.created_at<(NEW.initial_request->'Call'->>'StartedAt')::timestamptz OR
  NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR n>=NEW.deadline THEN
  RAISE EXCEPTION 'query accepted backing unavailable' USING ERRCODE='23514'; END IF;
 IF pair THEN
  bp:=NEW.query->'BaselinePlan'; bs:=public.context_query_comparison_source(NEW.query->'Scope',true);
  IF (bp#>>'{Profile,Worker,MemoryBytes}')::bigint<402653184 OR (bp#>>'{Profile,Worker,WorkerTransientBytes}')::bigint<402653184 OR (NEW.query#>>'{Plan,Profile,Worker,MemoryBytes}')::bigint<402653184 OR (NEW.query#>>'{Plan,Profile,Worker,WorkerTransientBytes}')::bigint<402653184 OR NOT public.context_query_complete_object(bp,ARRAY['AcceptanceID','AccountID','AllocationID','RootID','InstallationID','ClusterID','NamespaceUID','WorkloadUID','AllocationRevision','PoolSource','PolicySource','Principal','Profile','ObservedAt','ValidUntil','HardUntil','EffectsUntil','CleanupUntil','RetireBy']) OR
   bp->>'AllocationID' IS DISTINCT FROM ba.id::text OR bp->>'RootID' IS DISTINCT FROM NEW.root_id::text OR bp->>'InstallationID' IS DISTINCT FROM b.installation_id::text OR bp->>'AcceptanceID' IS DISTINCT FROM b.acceptance_id::text OR bp->>'AccountID' IS DISTINCT FROM p.id::text OR bp->'Principal' IS DISTINCT FROM NEW.actor OR
   bp->>'ClusterID' IS DISTINCT FROM ba.cluster_id::text OR bp->>'NamespaceUID' IS DISTINCT FROM ba.namespace_uid OR bp->>'WorkloadUID' IS DISTINCT FROM ba.workload_uid OR
   bs->>'ClusterID' IS DISTINCT FROM ba.cluster_id::text OR bs->>'NamespaceUID' IS DISTINCT FROM ba.namespace_uid OR bs->>'WorkloadUID' IS DISTINCT FROM ba.workload_uid OR
   (bp->>'AllocationRevision')::bigint IS DISTINCT FROM ba.revision OR bp->'PoolSource' IS DISTINCT FROM ba.pool_source OR bp->'PolicySource' IS DISTINCT FROM ba.policy_source OR
   ((bp->'Profile')-'Path') IS DISTINCT FROM (b.profile-'Path') OR ((bp#>'{Profile,Path}')-ARRAY['ID','TargetClusterID']) IS DISTINCT FROM ((NEW.query#>'{Plan,Profile,Path}')-ARRAY['ID','TargetClusterID']) OR bp#>>'{Profile,Path,TargetClusterID}' IS DISTINCT FROM ba.cluster_id::text OR
   NOT public.context_query_shared_profile_current(NEW.root_id,bp->'Profile') OR NOT public.context_query_capacity_allocation_current(NEW.root_id,ba.id) OR
   ((ba.cluster_id,ba.namespace_uid,ba.workload_uid)=(a.cluster_id,a.namespace_uid,a.workload_uid)) IS DISTINCT FROM (ba.id=a.id) OR
   (bp->>'HardUntil')::timestamptz IS DISTINCT FROM b.hard_until OR (bp->>'EffectsUntil')::timestamptz IS DISTINCT FROM b.effects_until OR (bp->>'CleanupUntil')::timestamptz IS DISTINCT FROM b.cleanup_until OR (bp->>'RetireBy')::timestamptz IS DISTINCT FROM b.retire_by OR n>=(bp->>'ValidUntil')::timestamptz OR n<(bp->>'ObservedAt')::timestamptz THEN
   RAISE EXCEPTION 'comparison baseline backing unavailable' USING ERRCODE='23514';
  END IF;
 END IF;
 UPDATE public.context_query_backing SET allocated=allocated+u WHERE root_id=NEW.root_id;
 IF pair AND ba.id<>a.id THEN
  UPDATE public.context_query_allocation SET allocated=allocated+10 WHERE id IN (a.id,ba.id);
 ELSE UPDATE public.context_query_allocation SET allocated=allocated+u WHERE id=NEW.allocation_id; END IF;
 UPDATE public.context_query_principal SET allocated=allocated+u WHERE id=NEW.account_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_query_child() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE q public.context_query; n timestamptz; begin_tool text; call_tool text; key_batch public.context_query_batch;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query child history remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT q FROM public.context_query WHERE id=NEW.query_id FOR UPDATE;
 n:=clock_timestamp();
 begin_tool:=public.context_query_begin_tool(q.query->'Scope');
 IF TG_TABLE_NAME='context_query_batch' AND TG_OP='UPDATE' THEN
  IF ROW(NEW.native_operation,NEW.native_authority,NEW.native_closed) IS DISTINCT FROM ROW(OLD.native_operation,OLD.native_authority,OLD.native_closed) THEN
   IF (to_jsonb(NEW)-ARRAY['native_operation','native_authority','native_closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['native_operation','native_authority','native_closed']) OR
    OLD.closed OR OLD.native_closed OR q.active_batch IS DISTINCT FROM NEW.id OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') THEN
    RAISE EXCEPTION 'query native operation unavailable' USING ERRCODE='23514';
   END IF;
   IF OLD.native_operation IS NULL THEN
    IF NEW.native_closed OR NOT public.context_query_complete_object(NEW.native_operation,ARRAY['Path','Processing','Reference','Kind','HubPodUID','HubProcessEpoch','WorkerPodUID','WorkerPublicKey','SourceVersion','ParentID','Generation','StartedAt','Until']) OR
     NEW.native_operation->>'Kind' IS DISTINCT FROM 'read-approved-context' OR
     NEW.native_operation->'Reference'->>'QueryID' IS DISTINCT FROM q.id::text OR
     COALESCE(NEW.native_operation->'Reference'->>'SessionID','')<>'' OR
     NEW.native_operation->'Reference'->>'WorkerID' IS DISTINCT FROM q.worker_id::text OR
     NEW.native_operation->'Reference'->>'OperationID' IS DISTINCT FROM NEW.id::text OR
     (NEW.native_operation->'Reference'->>'Fence')::bigint IS DISTINCT FROM NEW.generation OR
     NEW.native_operation->>'ParentID' IS DISTINCT FROM NEW.id::text OR
     (NEW.native_operation->>'Generation')::smallint IS DISTINCT FROM NEW.generation OR
     (NEW.native_operation->>'StartedAt')::timestamptz>n OR
     n>=(NEW.native_operation->>'Until')::timestamptz OR
     (NEW.native_operation->>'Until')::timestamptz>(NEW.batch->>'Until')::timestamptz OR
     NEW.native_authority->'Scope' IS DISTINCT FROM q.query->'Scope' OR
     NEW.native_operation->'SourceVersion' IS DISTINCT FROM q.query#>'{Scope,Version}' OR
     NEW.native_operation->'Path' IS DISTINCT FROM ((NEW.native_authority#>'{Environment,Path}')-'Purpose') OR NEW.native_operation->'Processing' IS DISTINCT FROM NEW.native_authority#>'{Environment,Processing}' OR
     (CASE WHEN q.query#>'{Scope,Comparison}' IS NOT NULL THEN
      NOT public.capacity_json_fields(NEW.native_operation->'Baseline',ARRAY['Path','Processing','SourceVersion']) OR
      NEW.native_authority#>'{Baseline,Baseline}' IS NOT NULL OR NEW.native_authority#>'{Baseline,Scope}' IS DISTINCT FROM public.context_query_comparison_source(q.query->'Scope',true) OR
      NEW.native_operation#>'{Baseline,SourceVersion}' IS DISTINCT FROM q.query#>'{Scope,Comparison,Baseline,Version}' OR NEW.native_operation#>'{Baseline,Path}' IS DISTINCT FROM ((NEW.native_authority#>'{Baseline,Environment,Path}')-'Purpose') OR NEW.native_operation#>'{Baseline,Processing}' IS DISTINCT FROM NEW.native_authority#>'{Baseline,Environment,Processing}'
     ELSE NEW.native_operation ? 'Baseline' OR NEW.native_authority ? 'Baseline' END) THEN
     RAISE EXCEPTION 'query native identity mismatch' USING ERRCODE='23514';
    END IF;
   ELSIF NOT NEW.native_closed OR NEW.native_operation IS DISTINCT FROM OLD.native_operation OR NEW.native_authority IS DISTINCT FROM OLD.native_authority THEN
    RAISE EXCEPTION 'query native identity immutable' USING ERRCODE='23514';
   END IF;
   UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
   RETURN NEW;
  END IF;
 END IF;
 IF TG_TABLE_NAME='context_query_call' THEN
  call_tool:=begin_tool;
  IF NEW.is_poll THEN call_tool:='get_query_result'; END IF;
  IF TG_OP<>'INSERT' OR n>=q.deadline OR NOT public.context_query_complete_object(NEW.request,ARRAY['Call','OwnerID','HubProcessEpoch']) OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.request->'Call') OR NEW.request->'Call'->>'ID'<>NEW.operation_id::text OR NEW.request->'Call'->'Principal' IS DISTINCT FROM q.actor OR
   NEW.request->'Call'->>'RootID'<>q.root_id::text OR NEW.is_poll<>(NEW.operation_id<>q.operation_id) OR NEW.request->'Call'->>'Tool' IS DISTINCT FROM call_tool THEN RAISE EXCEPTION 'query invocation mismatch' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET polls=polls+CASE WHEN NEW.is_poll THEN 1 ELSE 0 END,controls=controls+1 WHERE id=q.id;
 ELSIF TG_TABLE_NAME='context_query_batch' THEN
  IF TG_OP='INSERT' THEN
   IF NOT public.context_query_complete_object(NEW.batch,ARRAY['ID','QueryID','OperationID','Generation','Worker','Request','StartedAt','Until','CleanupUntil']) OR
    n>=q.deadline OR (NEW.batch->>'StartedAt')::timestamptz>n OR n>=(NEW.batch->>'Until')::timestamptz OR
    (NEW.batch->>'Until')::timestamptz>q.deadline OR (NEW.batch->>'Until')::timestamptz>(NEW.batch->'Request'->'Call'->>'Until')::timestamptz OR (NEW.batch->>'CleanupUntil')::timestamptz<>q.cleanup_until OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') OR
    q.active_batch IS NOT NULL OR q.uncertain OR NEW.generation<>q.generation+1 OR NEW.generation>public.context_query_read_batches(q.query->'Scope') OR NEW.claim_id IS NOT NULL OR NEW.closed OR
    NEW.batch->>'OperationID' IS DISTINCT FROM NEW.operation_id::text OR NEW.batch->>'ID'<>NEW.id::text OR NEW.batch->>'QueryID'<>q.id::text OR (NEW.batch->>'Generation')::smallint<>NEW.generation OR
    NOT EXISTS(SELECT 1 FROM public.context_query_call c WHERE c.operation_id=NEW.operation_id AND c.query_id=q.id AND c.request=NEW.batch->'Request') OR
    NOT EXISTS(SELECT 1 FROM public.context_query_worker w WHERE w.query_id=q.id AND w.binding=NEW.batch->'Worker') THEN RAISE EXCEPTION 'query batch unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET generation=NEW.generation,active_batch=NEW.id,controls=controls+1 WHERE id=q.id;
  ELSE
   IF (to_jsonb(NEW)-ARRAY['claim_id','closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['claim_id','closed']) OR OLD.closed OR q.active_batch IS DISTINCT FROM NEW.id OR
    OLD.claim_id IS NOT NULL AND NEW.claim_id IS DISTINCT FROM OLD.claim_id OR OLD.claim_id IS NULL AND NEW.claim_id IS NULL OR
    OLD.claim_id IS NULL AND NEW.closed OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    NOT NEW.closed AND (OLD.claim_id IS NOT NULL OR n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call')) OR
    NEW.closed AND (NEW.native_operation IS NOT NULL AND NOT NEW.native_closed OR n>=q.cleanup_until OR n>=(NEW.batch->'Request'->'Call'->>'WriteUntil')::timestamptz OR NOT public.context_query_outcome_closed(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch)) THEN RAISE EXCEPTION 'query batch claim or close unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET active_batch=CASE WHEN NEW.closed THEN NULL ELSE active_batch END,controls=controls+1 WHERE id=q.id;
  END IF;
 ELSIF TG_TABLE_NAME='context_query_worker' THEN
  IF TG_OP<>'INSERT' OR NEW.worker_id<>q.worker_id OR NEW.binding->>'QueryID' IS DISTINCT FROM q.id::text OR NEW.binding->>'WorkerID' IS DISTINCT FROM q.worker_id::text THEN RAISE EXCEPTION 'query worker immutable' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 ELSE
  IF TG_OP='INSERT' AND NEW.source_ordinal IS NULL AND NEW.child_id IS NULL THEN NEW.child_id:=NEW.batch_id; END IF;
  IF q.query#>'{Scope,Comparison}' IS NOT NULL THEN
   SELECT * INTO STRICT key_batch FROM public.context_query_batch WHERE id=NEW.batch_id AND query_id=q.id;
   IF NOT public.capacity_json_fields(NEW.binding,ARRAY['ID','QueryID','BatchID','WorkerID','ProcessEpoch','SourceOrdinal','SourceVersion','AuthorityDigest','PublicKey','Certificate','Scope','CreatedAt','Until']) OR
    key_batch.native_operation IS NULL OR key_batch.native_closed OR key_batch.closed OR key_batch.claim_id IS DISTINCT FROM key_batch.id OR
    NEW.binding->'AuthorityDigest' IS DISTINCT FROM key_batch.native_authority->'DecisionDigest' OR NEW.binding->>'WorkerID' IS DISTINCT FROM q.worker_id::text OR
    NEW.binding->>'ProcessEpoch' IS DISTINCT FROM key_batch.batch#>>'{Worker,ProcessEpoch}' OR NEW.binding->'Certificate' IS DISTINCT FROM key_batch.batch#>'{Worker,Certificate}' OR NEW.binding->'PublicKey' IS DISTINCT FROM key_batch.native_operation->'WorkerPublicKey' OR
    NEW.binding#>>'{Scope,InstallationID}' IS DISTINCT FROM q.query#>>'{Plan,InstallationID}' OR NEW.binding#>>'{Scope,Purpose}' IS DISTINCT FROM 'artifact' OR
    (NEW.binding->>'CreatedAt')::timestamptz<(key_batch.batch->>'StartedAt')::timestamptz OR (NEW.binding->>'CreatedAt')::timestamptz>n OR n>=(NEW.binding->>'Until')::timestamptz OR
    (NEW.binding->>'Until')::timestamptz>(key_batch.batch->>'Until')::timestamptz OR (NEW.binding->>'Until')::timestamptz>(key_batch.native_authority->>'ValidUntil')::timestamptz OR (NEW.binding->>'Until')::timestamptz>(q.query->>'ProviderUntil')::timestamptz THEN RAISE EXCEPTION 'comparison key parent mismatch' USING ERRCODE='23514'; END IF;
   IF NEW.source_ordinal IS NULL OR NEW.child_id=NEW.batch_id OR NEW.binding->>'ID' IS DISTINCT FROM NEW.child_id::text OR NEW.binding->>'QueryID' IS DISTINCT FROM q.id::text OR NEW.binding->>'BatchID' IS DISTINCT FROM NEW.batch_id::text OR (NEW.binding->>'SourceOrdinal')::integer IS DISTINCT FROM NEW.source_ordinal OR
    NEW.binding->'SourceVersion' IS DISTINCT FROM (CASE NEW.source_ordinal WHEN 0 THEN q.query#>'{Scope,Comparison,Baseline,Version}' WHEN 1 THEN q.query#>'{Scope,Version}' END) THEN RAISE EXCEPTION 'comparison key child mismatch' USING ERRCODE='23514'; END IF;
  ELSIF NEW.source_ordinal IS NOT NULL OR NEW.child_id IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'legacy key child mismatch' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' THEN
   IF NEW.used_roles<>0 OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key binding unavailable' USING ERRCODE='23514'; END IF;
  ELSIF (to_jsonb(NEW)-'used_roles') IS DISTINCT FROM (to_jsonb(OLD)-'used_roles') OR (NEW.used_roles|OLD.used_roles)<>NEW.used_roles OR
   (NEW.used_roles#OLD.used_roles) NOT IN (1,2,4) OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key role already spent' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION require_comparison_key_pair() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.source_ordinal IS NOT NULL AND (SELECT count(*) FROM public.context_query_key_binding WHERE batch_id=NEW.batch_id AND query_id=NEW.query_id AND source_ordinal IS NOT NULL)<>2 THEN
  RAISE EXCEPTION 'comparison requires both key children atomically' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER comparison_key_pair AFTER INSERT ON context_query_key_binding DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_comparison_key_pair();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_worker() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.session_id,NEW.query_id,NEW.root_id,NEW.installation_id,NEW.allocation_id,NEW.query_allocation_id,NEW.baseline_query_allocation_id,NEW.principal_key,NEW.generation,NEW.intent_json,NEW.run_until)
 IS DISTINCT FROM ROW(OLD.id,OLD.session_id,OLD.query_id,OLD.root_id,OLD.installation_id,OLD.allocation_id,OLD.query_allocation_id,OLD.baseline_query_allocation_id,OLD.principal_key,OLD.generation,OLD.intent_json,OLD.run_until)
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json)
 OR (OLD.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at)
 OR (OLD.job_json IS NOT NULL AND NEW.job_json IS DISTINCT FROM OLD.job_json)
 OR (OLD.binding_json IS NOT NULL AND NEW.binding_json IS DISTINCT FROM OLD.binding_json)
 OR (OLD.termination_json IS NOT NULL AND NEW.termination_json IS DISTINCT FROM OLD.termination_json)
 OR (OLD.retired_proof_json IS NOT NULL AND NEW.retired_proof_json IS DISTINCT FROM OLD.retired_proof_json)
 OR (OLD.abandoned_at IS NOT NULL AND NEW.abandoned_at IS DISTINCT FROM OLD.abandoned_at)
 OR (NEW.abandoned_at IS NOT NULL AND clock_timestamp()<NEW.run_until) THEN
  RAISE EXCEPTION 'acquisition worker identity and consumed transitions are immutable';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION guard_comparison_worker_parent() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE q public.context_query;
BEGIN
 IF NEW.query_id IS NULL THEN
  IF NEW.baseline_query_allocation_id IS NOT NULL THEN RAISE EXCEPTION 'download cannot name comparison allocation' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT * INTO STRICT q FROM public.context_query WHERE id=NEW.query_id AND root_id=NEW.root_id;
  IF NEW.query_allocation_id IS DISTINCT FROM q.allocation_id OR NEW.baseline_query_allocation_id IS DISTINCT FROM q.baseline_allocation_id OR convert_from(NEW.intent_json,'UTF8')::jsonb->'Query' IS DISTINCT FROM q.query THEN RAISE EXCEPTION 'comparison worker parent mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER comparison_worker_parent BEFORE INSERT ON download_worker FOR EACH ROW EXECUTE FUNCTION guard_comparison_worker_parent();
REVOKE ALL ON FUNCTION context_query_scope_source_valid_legacy133(jsonb),context_query_comparison_source(jsonb,boolean),guard_comparison_worker_parent(),require_comparison_key_pair() FROM PUBLIC;

-- +goose Down
-- Historical paired state cannot be interpreted or refunded by the old binary.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.context_query WHERE baseline_allocation_id IS NOT NULL OR query#>'{Scope,Comparison}' IS NOT NULL) OR EXISTS(SELECT 1 FROM public.context_query_key_binding WHERE source_ordinal IS NOT NULL) OR EXISTS(SELECT 1 FROM public.download_worker WHERE baseline_query_allocation_id IS NOT NULL) THEN
 RAISE EXCEPTION 'comparison history retained; downgrade refused' USING ERRCODE='55000'; END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER comparison_key_pair ON context_query_key_binding;
DROP FUNCTION require_comparison_key_pair();
DROP TRIGGER comparison_worker_parent ON download_worker;
DROP FUNCTION guard_comparison_worker_parent();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_download_worker() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.session_id,NEW.query_id,NEW.root_id,NEW.installation_id,NEW.allocation_id,NEW.query_allocation_id,NEW.principal_key,NEW.generation,NEW.intent_json,NEW.run_until)
 IS DISTINCT FROM ROW(OLD.id,OLD.session_id,OLD.query_id,OLD.root_id,OLD.installation_id,OLD.allocation_id,OLD.query_allocation_id,OLD.principal_key,OLD.generation,OLD.intent_json,OLD.run_until)
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json)
 OR (OLD.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at)
 OR (OLD.job_json IS NOT NULL AND NEW.job_json IS DISTINCT FROM OLD.job_json)
 OR (OLD.binding_json IS NOT NULL AND NEW.binding_json IS DISTINCT FROM OLD.binding_json)
 OR (OLD.termination_json IS NOT NULL AND NEW.termination_json IS DISTINCT FROM OLD.termination_json)
 OR (OLD.retired_proof_json IS NOT NULL AND NEW.retired_proof_json IS DISTINCT FROM OLD.retired_proof_json)
 OR (OLD.abandoned_at IS NOT NULL AND NEW.abandoned_at IS DISTINCT FROM OLD.abandoned_at)
 OR (NEW.abandoned_at IS NOT NULL AND clock_timestamp()<NEW.run_until) THEN
  RAISE EXCEPTION 'acquisition worker identity and consumed transitions are immutable';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_query_account() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query account remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=NEW.root_id FOR UPDATE;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-'allocated') IS DISTINCT FROM (to_jsonb(OLD)-'allocated') OR NEW.allocated-OLD.allocated NOT IN (1,2,10) THEN RAISE EXCEPTION 'query account mutation denied' USING ERRCODE='23514'; END IF;
 ELSIF NEW.allocated<>0 THEN RAISE EXCEPTION 'query initial account spend invalid' USING ERRCODE='23514';
 ELSIF TG_TABLE_NAME='context_query_principal' THEN
  UPDATE public.context_query_backing SET principals=principals+1 WHERE root_id=NEW.root_id;
 ELSE
  IF NEW.query_limit>b.query_limit THEN RAISE EXCEPTION 'query allocation exceeds root' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query_backing SET allocations=allocations+1 WHERE root_id=NEW.root_id;
 END IF;
 IF TG_TABLE_NAME='context_query_principal' AND NEW.allocated>b.principal_query_limit THEN RAISE EXCEPTION 'query principal capacity exhausted' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_query_child() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE q public.context_query; n timestamptz; begin_tool text; call_tool text;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query child history remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT q FROM public.context_query WHERE id=NEW.query_id FOR UPDATE;
 n:=clock_timestamp();
 begin_tool:=public.context_query_begin_tool(q.query->'Scope');
 IF TG_TABLE_NAME='context_query_batch' AND TG_OP='UPDATE' THEN
  IF ROW(NEW.native_operation,NEW.native_authority,NEW.native_closed) IS DISTINCT FROM ROW(OLD.native_operation,OLD.native_authority,OLD.native_closed) THEN
   IF (to_jsonb(NEW)-ARRAY['native_operation','native_authority','native_closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['native_operation','native_authority','native_closed']) OR
    OLD.closed OR OLD.native_closed OR q.active_batch IS DISTINCT FROM NEW.id OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') THEN
    RAISE EXCEPTION 'query native operation unavailable' USING ERRCODE='23514';
   END IF;
   IF OLD.native_operation IS NULL THEN
    IF NEW.native_closed OR NOT public.context_query_complete_object(NEW.native_operation,ARRAY['Path','Processing','Reference','Kind','HubPodUID','HubProcessEpoch','WorkerPodUID','WorkerPublicKey','SourceVersion','ParentID','Generation','StartedAt','Until']) OR
     NEW.native_operation->>'Kind' IS DISTINCT FROM 'read-approved-context' OR
     NEW.native_operation->'Reference'->>'QueryID' IS DISTINCT FROM q.id::text OR
     COALESCE(NEW.native_operation->'Reference'->>'SessionID','')<>'' OR
     NEW.native_operation->'Reference'->>'WorkerID' IS DISTINCT FROM q.worker_id::text OR
     NEW.native_operation->'Reference'->>'OperationID' IS DISTINCT FROM NEW.id::text OR
     (NEW.native_operation->'Reference'->>'Fence')::bigint IS DISTINCT FROM NEW.generation OR
     NEW.native_operation->>'ParentID' IS DISTINCT FROM NEW.id::text OR
     (NEW.native_operation->>'Generation')::smallint IS DISTINCT FROM NEW.generation OR
     (NEW.native_operation->>'StartedAt')::timestamptz>n OR
     n>=(NEW.native_operation->>'Until')::timestamptz OR
     (NEW.native_operation->>'Until')::timestamptz>(NEW.batch->>'Until')::timestamptz OR
     NEW.native_authority->'Scope' IS DISTINCT FROM q.query->'Scope' THEN
     RAISE EXCEPTION 'query native identity mismatch' USING ERRCODE='23514';
    END IF;
   ELSIF NOT NEW.native_closed OR NEW.native_operation IS DISTINCT FROM OLD.native_operation OR NEW.native_authority IS DISTINCT FROM OLD.native_authority THEN
    RAISE EXCEPTION 'query native identity immutable' USING ERRCODE='23514';
   END IF;
   UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
   RETURN NEW;
  END IF;
 END IF;
 IF TG_TABLE_NAME='context_query_call' THEN
  call_tool:=begin_tool;
  IF NEW.is_poll THEN call_tool:='get_query_result'; END IF;
  IF TG_OP<>'INSERT' OR n>=q.deadline OR NOT public.context_query_complete_object(NEW.request,ARRAY['Call','OwnerID','HubProcessEpoch']) OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.request->'Call') OR NEW.request->'Call'->>'ID'<>NEW.operation_id::text OR NEW.request->'Call'->'Principal' IS DISTINCT FROM q.actor OR
   NEW.request->'Call'->>'RootID'<>q.root_id::text OR NEW.is_poll<>(NEW.operation_id<>q.operation_id) OR NEW.request->'Call'->>'Tool' IS DISTINCT FROM call_tool THEN RAISE EXCEPTION 'query invocation mismatch' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET polls=polls+CASE WHEN NEW.is_poll THEN 1 ELSE 0 END,controls=controls+1 WHERE id=q.id;
 ELSIF TG_TABLE_NAME='context_query_batch' THEN
  IF TG_OP='INSERT' THEN
   IF NOT public.context_query_complete_object(NEW.batch,ARRAY['ID','QueryID','OperationID','Generation','Worker','Request','StartedAt','Until','CleanupUntil']) OR
    n>=q.deadline OR (NEW.batch->>'StartedAt')::timestamptz>n OR n>=(NEW.batch->>'Until')::timestamptz OR
    (NEW.batch->>'Until')::timestamptz>q.deadline OR (NEW.batch->>'Until')::timestamptz>(NEW.batch->'Request'->'Call'->>'Until')::timestamptz OR (NEW.batch->>'CleanupUntil')::timestamptz<>q.cleanup_until OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') OR
    q.active_batch IS NOT NULL OR q.uncertain OR NEW.generation<>q.generation+1 OR NEW.generation>public.context_query_read_batches(q.query->'Scope') OR NEW.claim_id IS NOT NULL OR NEW.closed OR
    NEW.batch->>'OperationID' IS DISTINCT FROM NEW.operation_id::text OR NEW.batch->>'ID'<>NEW.id::text OR NEW.batch->>'QueryID'<>q.id::text OR (NEW.batch->>'Generation')::smallint<>NEW.generation OR
    NOT EXISTS(SELECT 1 FROM public.context_query_call c WHERE c.operation_id=NEW.operation_id AND c.query_id=q.id AND c.request=NEW.batch->'Request') OR
    NOT EXISTS(SELECT 1 FROM public.context_query_worker w WHERE w.query_id=q.id AND w.binding=NEW.batch->'Worker') THEN RAISE EXCEPTION 'query batch unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET generation=NEW.generation,active_batch=NEW.id,controls=controls+1 WHERE id=q.id;
  ELSE
   IF (to_jsonb(NEW)-ARRAY['claim_id','closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['claim_id','closed']) OR OLD.closed OR q.active_batch IS DISTINCT FROM NEW.id OR
    OLD.claim_id IS NOT NULL AND NEW.claim_id IS DISTINCT FROM OLD.claim_id OR OLD.claim_id IS NULL AND NEW.claim_id IS NULL OR
    OLD.claim_id IS NULL AND NEW.closed OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    NOT NEW.closed AND (OLD.claim_id IS NOT NULL OR n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call')) OR
    NEW.closed AND (NEW.native_operation IS NOT NULL AND NOT NEW.native_closed OR n>=q.cleanup_until OR n>=(NEW.batch->'Request'->'Call'->>'WriteUntil')::timestamptz OR NOT public.context_query_outcome_closed(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch)) THEN RAISE EXCEPTION 'query batch claim or close unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET active_batch=CASE WHEN NEW.closed THEN NULL ELSE active_batch END,controls=controls+1 WHERE id=q.id;
  END IF;
 ELSIF TG_TABLE_NAME='context_query_worker' THEN
  IF TG_OP<>'INSERT' OR NEW.worker_id<>q.worker_id OR NEW.binding->>'QueryID' IS DISTINCT FROM q.id::text OR NEW.binding->>'WorkerID' IS DISTINCT FROM q.worker_id::text THEN RAISE EXCEPTION 'query worker immutable' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 ELSE
  IF TG_OP='INSERT' THEN
   IF NEW.used_roles<>0 OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key binding unavailable' USING ERRCODE='23514'; END IF;
  ELSIF (to_jsonb(NEW)-'used_roles') IS DISTINCT FROM (to_jsonb(OLD)-'used_roles') OR (NEW.used_roles|OLD.used_roles)<>NEW.used_roles OR
   (NEW.used_roles#OLD.used_roles) NOT IN (1,2,4) OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key role already spent' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_query() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b public.context_query_backing; a public.context_query_allocation; p public.context_query_principal; n timestamptz; u integer;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query history retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['generation','active_batch','polls','controls','uncertain']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['generation','active_batch','polls','controls','uncertain']) OR
   NEW.generation<OLD.generation OR NEW.generation>OLD.generation+1 OR NEW.polls<OLD.polls OR NEW.controls<>OLD.controls+1 OR OLD.uncertain AND NOT NEW.uncertain OR
   NEW.polls>(NEW.query->'Plan'->'Profile'->>'PollLimit')::bigint OR NEW.controls>(NEW.query->'Plan'->'Profile'->>'ControlTransitionLimit')::bigint THEN RAISE EXCEPTION 'query counters immutable' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.context_query_principal WHERE id=NEW.account_id AND root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 u:=public.context_query_units(NEW.query->'Scope');
 IF NOT public.context_query_intent_current(NEW.root_id,NEW.operation_id,NEW.actor,NEW.issuer_epoch,NEW.initial_request->'Call') OR
  NOT public.context_query_complete_object(NEW.query,ARRAY['ID','OperationID','WorkerID','Scope','Plan','RecoveryIssuerEpoch','RecoveryRevision','CreatedAt','Deadline','WorkerUntil','CredentialUntil','ProviderUntil','CleanupUntil']) OR
  NOT public.context_query_complete_object(NEW.query->'Plan',ARRAY['AcceptanceID','AccountID','AllocationID','RootID','InstallationID','ClusterID','NamespaceUID','WorkloadUID','AllocationRevision','PoolSource','PolicySource','Principal','Profile','ObservedAt','ValidUntil','HardUntil','EffectsUntil','CleanupUntil','RetireBy']) OR
  NOT public.context_query_complete_object(NEW.query->'Scope',ARRAY['RootID','CaseID','ArtifactID','CaptureID','ClusterID','NamespaceUID','WorkloadUID','PodUID','Version','SourceProjectionDigest','SourceFormat','DisplayVersion','Selection','Principal']) OR
  NOT public.context_query_scope_source_valid(NEW.query->'Scope') OR
  (NEW.query->'Scope'->>'NativeType' IN ('pprof','syscallRecords','syscallArguments') AND ((NEW.query->'Plan'->'Profile'->'Worker'->>'MemoryBytes')::bigint<268435456 OR (NEW.query->'Plan'->'Profile'->'Worker'->>'WorkerTransientBytes')::bigint<268435456)) OR
  b.suspended OR p.principal_key<>NEW.principal_key OR NEW.generation<>0 OR NEW.active_batch IS NOT NULL OR NEW.polls<>0 OR NEW.controls<>0 OR NEW.uncertain OR
  ((NEW.query->'Plan'->'Profile')-'Path') IS DISTINCT FROM (b.profile-'Path') OR NEW.query->'Plan'->'Profile'->'Path'->>'TargetClusterID' IS DISTINCT FROM a.cluster_id::text OR NOT public.context_query_shared_profile_current(NEW.root_id,NEW.query->'Plan'->'Profile') OR NOT public.context_query_capacity_allocation_current(NEW.root_id,a.id) OR NEW.query->'Plan'->>'AcceptanceID'<>b.acceptance_id::text OR NEW.query->'Plan'->>'AllocationID'<>a.id::text OR
  NEW.query->'Plan'->>'AccountID'<>p.id::text OR NEW.query->'Plan'->>'ClusterID'<>a.cluster_id::text OR NEW.query->'Plan'->>'NamespaceUID'<>a.namespace_uid OR NEW.query->'Plan'->>'WorkloadUID'<>a.workload_uid OR
  NEW.query->'Plan'->'Principal' IS DISTINCT FROM NEW.actor OR NEW.query->'Scope'->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.query->'Scope'->>'ClusterID' IS DISTINCT FROM a.cluster_id::text OR NEW.query->'Scope'->>'NamespaceUID' IS DISTINCT FROM a.namespace_uid OR NEW.query->'Scope'->>'WorkloadUID' IS DISTINCT FROM a.workload_uid OR
  NEW.query->'Plan'->'PoolSource' IS DISTINCT FROM a.pool_source OR NEW.query->'Plan'->'PolicySource' IS DISTINCT FROM a.policy_source OR
  (NEW.query->'Plan'->>'AllocationRevision')::bigint<>a.revision OR NEW.query->'Scope'->'Principal' IS DISTINCT FROM NEW.actor OR
  NEW.query->>'ID'<>NEW.id::text OR NEW.query->>'WorkerID'<>NEW.worker_id::text OR NEW.query->>'OperationID'<>NEW.operation_id::text OR
  (NEW.query->>'CreatedAt')::timestamptz<>NEW.created_at OR (NEW.query->>'Deadline')::timestamptz<>NEW.deadline OR (NEW.query->>'CleanupUntil')::timestamptz<>NEW.cleanup_until OR
  NEW.deadline>NEW.created_at+make_interval(secs=>(b.profile->>'Lifetime')::double precision/1000000000) OR
  (NEW.query->'Plan'->>'RootID')::uuid<>NEW.root_id OR (NEW.query->'Plan'->>'InstallationID')::uuid<>b.installation_id OR
  (NEW.query->'Plan'->>'RetireBy')::timestamptz<>NEW.retire_by OR NEW.retire_by<>b.retire_by OR
  (NEW.query->'Plan'->>'HardUntil')::timestamptz<>b.hard_until OR (NEW.query->'Plan'->>'EffectsUntil')::timestamptz<>b.effects_until OR (NEW.query->'Plan'->>'CleanupUntil')::timestamptz<>b.cleanup_until OR
  NEW.deadline>b.hard_until OR NEW.cleanup_until>b.cleanup_until OR n>=(NEW.query->'Plan'->>'ValidUntil')::timestamptz OR n<(NEW.query->'Plan'->>'ObservedAt')::timestamptz OR
  (NEW.query->>'WorkerUntil')::timestamptz>b.effects_until OR (NEW.query->>'CredentialUntil')::timestamptz>b.effects_until OR (NEW.query->>'ProviderUntil')::timestamptz>b.effects_until OR
  NEW.query->>'RecoveryIssuerEpoch' IS DISTINCT FROM NEW.issuer_epoch::text OR NEW.created_at>n OR NEW.created_at<(NEW.initial_request->'Call'->>'StartedAt')::timestamptz OR
  NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR n>=NEW.deadline THEN
  RAISE EXCEPTION 'query accepted backing unavailable' USING ERRCODE='23514'; END IF;
 UPDATE public.context_query_backing SET allocated=allocated+u WHERE root_id=NEW.root_id;
 UPDATE public.context_query_allocation SET allocated=allocated+u WHERE id=NEW.allocation_id;
 UPDATE public.context_query_principal SET allocated=allocated+u WHERE id=NEW.account_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_outcome_closed(r uuid,op uuid,actor jsonb,epoch uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.operation_audit a
 JOIN public.operation_audit_lifecycle l ON l.operation_id=a.id AND l.root_id=a.root_id
 JOIN public.fleet_current_trust t ON t.installation_id=l.installation_id
 WHERE a.id=op AND a.root_id=r AND a.lane='normal' AND l.lane='normal' AND a.issuer_epoch=epoch AND l.issuer_epoch=epoch AND t.issuer_epoch=epoch AND NOT t.recovery_blocked
 AND public.incarnation_current(l.postmaster_at) AND l.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND a.intent->'Actor'=actor AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_syscall_summary','get_syscall_events','get_query_result') AND a.intent->>'InputFormat'='context-query-input/v1'
 AND a.intent_started AND a.intent_receipt IS NOT NULL AND l.intent_completion->'Receipt'=a.intent_receipt
 AND a.outcome_started AND a.outcome_receipt IS NOT NULL AND l.outcome_completion->'Receipt'=a.outcome_receipt
 AND a.outcome->>'Effect' IN ('none','accepted','unknown') AND a.outcome->'Intent'=a.intent
 AND l.binding=a.intent->'Lifecycle' AND l.retirement IS NULL AND NOT l.certificate_started AND l.finalization_xid IS NULL
 AND l.outcome_completion->>'Protocol'='closed-operation-audit/v1' AND l.outcome_completion->>'RootID'=r::text AND l.outcome_completion->>'OperationID'=op::text
 AND l.outcome_completion->>'StoreID'=l.binding->'Policy'->>'StoreID' AND l.outcome_completion->>'Phase'='outcome'
 AND (l.outcome_completion->>'StoredAt')::timestamptz>=(a.intent->>'CreatedAt')::timestamptz
 AND (l.outcome_completion->>'ClosedAt')::timestamptz>=(l.outcome_completion->>'StoredAt')::timestamptz
 AND (l.outcome_completion->>'ClosedAt')::timestamptz<a.write_until AND (l.outcome_completion->>'ClosedAt')::timestamptz<=clock_timestamp()),false)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_intent_current(r uuid,op uuid,actor jsonb,epoch uuid,call jsonb) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.operation_audit a
 JOIN public.operation_audit_lifecycle l ON l.operation_id=a.id AND l.root_id=a.root_id
 JOIN public.fleet_current_trust t ON t.installation_id=l.installation_id
 WHERE a.id=op AND a.root_id=r AND a.lane='normal' AND l.lane='normal' AND a.issuer_epoch=epoch AND l.issuer_epoch=epoch AND t.issuer_epoch=epoch
 AND NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until
 AND public.incarnation_current(l.postmaster_at) AND l.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND a.intent_started AND a.intent_receipt IS NOT NULL AND l.intent_completion IS NOT NULL AND l.intent_completion->'Receipt'=a.intent_receipt
 AND l.binding=a.intent->'Lifecycle' AND l.retirement IS NULL AND NOT l.certificate_started AND l.finalization_xid IS NULL
 AND a.intent->'Actor'=actor AND call->'Principal'=actor AND call->>'ID'=op::text AND call->>'RootID'=r::text
 AND a.intent->>'Name'=call->>'Tool' AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_syscall_summary','get_syscall_events','get_query_result')
 AND a.intent->>'InputFormat'='context-query-input/v1' AND call->>'InputFormat'='context-query-input/v1'
 AND a.intent->>'MACVersion'=call->>'MACVersion' AND a.intent->'InputDigest'=call->'InputDigest' AND a.intent->'PrincipalDigest'=call->'PrincipalDigest'
 AND (a.intent->>'CreatedAt')::timestamptz=(call->>'StartedAt')::timestamptz AND a.request_until=(call->>'Until')::timestamptz AND a.write_until=(call->>'WriteUntil')::timestamptz
 AND (a.intent->>'CreatedAt')::timestamptz<=clock_timestamp() AND clock_timestamp()<a.request_until
 AND l.intent_completion->>'Protocol'='closed-operation-audit/v1' AND l.intent_completion->>'RootID'=r::text AND l.intent_completion->>'OperationID'=op::text
 AND l.intent_completion->>'StoreID'=l.binding->'Policy'->>'StoreID' AND l.intent_completion->>'Phase'='intent'
 AND (l.intent_completion->>'StoredAt')::timestamptz>=(a.intent->>'CreatedAt')::timestamptz
 AND (l.intent_completion->>'ClosedAt')::timestamptz>=(l.intent_completion->>'StoredAt')::timestamptz
 AND (l.intent_completion->>'ClosedAt')::timestamptz<a.write_until AND (l.intent_completion->>'ClosedAt')::timestamptz<=clock_timestamp()),false)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.operation_audit_pool; a public.operation_audit_account; n timestamptz; prepaid boolean:=false;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'invalid operation audit source' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d JOIN public.fleet_current_trust t ON t.installation_id=d.installation_id
   WHERE d.operation_id=OLD.id AND d.root_id=OLD.root_id AND d.finalization_xid=pg_current_xact_id() AND d.terminal_acknowledged_at IS NOT NULL AND
    NOT t.recovery_blocked AND NOT t.suspended AND clock_timestamp()<t.fresh_until AND t.issuer_epoch=d.issuer_epoch AND public.incarnation_current(d.postmaster_at) AND (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())=d.database_oid AND clock_timestamp()<(d.lease->>'Until')::timestamptz)
   THEN RAISE EXCEPTION 'audit retirement unavailable' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT p FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
  n:=clock_timestamp();
  prepaid:=public.connector_retirement_prepaid(NEW);
  IF NEW.intent->>'Name'='connector_retirement' AND NOT prepaid THEN RAISE EXCEPTION 'connector retirement has no paid original ticket' USING ERRCODE='23514';END IF;
  IF (NOT prepaid AND (p.paused OR n>=p.valid_until)) OR n>=NEW.request_until OR n<(NEW.intent->>'CreatedAt')::timestamptz OR NEW.intent_started OR NEW.intent_receipt IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.outcome_started OR NEW.outcome_receipt IS NOT NULL OR
   NOT (NEW.intent ?& ARRAY['ID','RootID','MACVersion','AccountVersion','Name','CreatedAt','RequestUntil','WriteUntil','RetainUntil']) OR public.operation_audit_lane(NEW.intent->>'Name') IS NULL OR NOT public.connector_operation_actor_valid(NEW.intent) OR
   ((NEW.intent ? 'Capture') IS DISTINCT FROM (NEW.lane='capture')) OR
   (NEW.intent->>'ID')::uuid<>NEW.id OR (NEW.intent->>'RootID')::uuid<>NEW.root_id OR NEW.intent->>'AccountVersion'<>p.account_version OR
   NEW.request_until<>(NEW.intent->>'RequestUntil')::timestamptz OR NEW.write_until<>(NEW.intent->>'WriteUntil')::timestamptz OR NEW.retain_until<>(NEW.intent->>'RetainUntil')::timestamptz OR
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+(CASE WHEN NEW.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_syscall_summary','get_syscall_events','get_query_result','prepare_artifact_download','get_artifact_download') THEN interval '20 seconds' WHEN NEW.intent->>'Name' IN ('request_capture','preview_capture') THEN interval '15 seconds' WHEN NEW.lane='capture' AND NEW.intent->>'Name'='persist_capture_intent' AND EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.id AND public.capture_audit_payload_matches(c,NEW.intent) AND c.group_id IS NOT NULL AND c.group_ordinal IS NOT NULL AND NEW.request_until<=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN interval '15 seconds' ELSE interval '5 seconds' END) OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
   NEW.retain_until>(NEW.intent->>'CreatedAt')::timestamptz+make_interval(secs=>p.retained_seconds::double precision) OR
   NEW.lane IS DISTINCT FROM public.operation_audit_lane(NEW.intent->>'Name') THEN
   RAISE EXCEPTION 'operation audit unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO a FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest FOR UPDATE;
  IF NOT FOUND THEN
   IF p.accounts>=p.account_limit THEN RAISE EXCEPTION 'audit accounts exhausted' USING ERRCODE='23514'; END IF;
   UPDATE public.operation_audit_pool SET accounts=accounts+1 WHERE root_id=NEW.root_id AND lane=NEW.lane;
   INSERT INTO public.operation_audit_account(root_id,lane,principal_digest) VALUES(NEW.root_id,NEW.lane,NEW.principal_digest) RETURNING * INTO a;
  END IF;
  IF a.charged>=p.records_per_account THEN RAISE EXCEPTION 'audit records exhausted' USING ERRCODE='23514'; END IF;
  UPDATE public.operation_audit_account SET charged=charged+1 WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.lane,NEW.issuer_epoch,NEW.principal_digest,NEW.intent,NEW.request_until,NEW.write_until,NEW.retain_until) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.lane,OLD.issuer_epoch,OLD.principal_digest,OLD.intent,OLD.request_until,OLD.write_until,OLD.retain_until) OR
   (OLD.intent_started AND NOT NEW.intent_started) OR (OLD.outcome_started AND NOT NEW.outcome_started) OR
   (OLD.intent_receipt IS NOT NULL AND NEW.intent_receipt IS DISTINCT FROM OLD.intent_receipt) OR
   (OLD.outcome IS NOT NULL AND NEW.outcome IS DISTINCT FROM OLD.outcome) OR
   (OLD.outcome_receipt IS NOT NULL AND NEW.outcome_receipt IS DISTINCT FROM OLD.outcome_receipt) THEN
   RAISE EXCEPTION 'immutable operation audit' USING ERRCODE='23514'; END IF;
  IF NEW.intent ? 'Lifecycle' AND NOT public.capture_audit_receipts_current(NEW) AND NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.operation_id=NEW.id AND
    (NEW.intent_receipt IS NULL OR d.intent_completion->'Receipt'=NEW.intent_receipt) AND (NEW.outcome_receipt IS NULL OR d.outcome_completion->'Receipt'=NEW.outcome_receipt)) THEN
   RAISE EXCEPTION 'receipt lacks positive writer completion' USING ERRCODE='23514'; END IF;
  n:=clock_timestamp();
  IF n>=NEW.write_until OR (NOT OLD.intent_started AND NEW.intent_started AND n>=NEW.request_until) THEN
   RAISE EXCEPTION 'operation audit interval expired' USING ERRCODE='23514'; END IF;
  IF NEW.outcome IS NOT NULL AND NEW.outcome->'Intent' IS DISTINCT FROM NEW.intent THEN
   RAISE EXCEPTION 'outcome intent mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format IN ('capture-intent/v2','capture-intent-reason/v1')
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_units(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'NativeType' IN ('httpHeaders','syscallRecords','syscallArguments') THEN 2 WHEN s->>'NativeType'='pprof' THEN 10 ELSE 1 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_begin_tool(s jsonb) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN CASE s->'Syscalls'->>'View' WHEN 'summary' THEN 'get_syscall_summary' WHEN 'events' THEN 'get_syscall_events' ELSE NULL END WHEN s->>'NativeType'='httpHeaders' THEN 'get_http_headers' WHEN s->>'NativeType'='pprof' THEN 'get_profile_summary' ELSE 'get_file_excerpt' END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_scope_source_valid(s jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb:=s->'Syscalls'; n integer; i integer; name text; previous text;
BEGIN
 IF s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN
  IF NOT COALESCE(NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   s->>'SourceFormat'=CASE s->>'NativeType' WHEN 'syscallRecords' THEN 'asservat-syscall-events/v1' ELSE 'asservat-syscall-arguments/v1' END AND
   public.capacity_json_fields(w,ARRAY['View','Start','Limit','Binding','Names','NameCount','ErrorsOnly']) AND
   w->>'View' IN ('summary','events') AND s->>'DisplayVersion'=CASE w->>'View' WHEN 'summary' THEN 'approved-syscall-summary/v1' WHEN 'events' THEN 'approved-syscall-events/v1' END AND
   public.capacity_json_integer(w->'Start',0,999999) AND public.capacity_json_integer(w->'Limit',1,100) AND
   public.capacity_json_integer(w->'NameCount',0,64) AND jsonb_typeof(w->'Binding')='string' AND jsonb_typeof(w->'ErrorsOnly')='boolean' AND jsonb_typeof(w->'Names')='array',false)
   THEN RETURN false; END IF;
  IF jsonb_array_length(w->'Names')<>64 THEN RETURN false; END IF;
  IF NOT ((w->>'Start'='0' AND w->>'Binding'='') OR (w->>'Start'<>'0' AND w->>'Binding'~'^[0-9a-f]{32}$')) THEN RETURN false; END IF;
  n:=(w->>'NameCount')::integer;
  IF w->>'View'='summary' AND (n<>0 OR (w->>'ErrorsOnly')::boolean) THEN RETURN false; END IF;
  FOR i IN 0..63 LOOP
   IF jsonb_typeof(w->'Names'->i) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
   name:=w->'Names'->>i;
   IF i<n THEN
    IF char_length(name) NOT BETWEEN 1 AND 64 OR previous COLLATE "C">=name COLLATE "C" THEN RETURN false; END IF;
    previous:=name;
   ELSIF name<>'' THEN RETURN false;
   END IF;
  END LOOP;
  RETURN true;
 END IF;
 IF s ? 'Syscalls' THEN RETURN false; END IF;
 RETURN COALESCE(CASE WHEN NOT (s ? 'NativeType') THEN NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND s->>'SourceFormat'='asservat-pod-status/v1' AND s->>'DisplayVersion'='approved-pod-status-display/v1'
  WHEN s->>'NativeType'='httpHeaders' THEN NOT (s ? 'Profile') AND jsonb_typeof(s->'Headers')='object' AND (s->'Headers'->>'Limit')::integer BETWEEN 1 AND 100 AND (s->'Headers'->>'Start')::integer BETWEEN 0 AND 32759 AND
   s->>'SourceFormat'='http-response-headers/v1' AND s->>'DisplayVersion'='approved-http-headers-page/v1' AND s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb
  WHEN s->>'NativeType'='pprof' THEN NOT (s ? 'Headers') AND public.capacity_json_fields(s->'Profile',ARRAY['SampleType','TopN']) AND
   jsonb_typeof(s->'Profile'->'SampleType')='string' AND octet_length(s->'Profile'->>'SampleType') BETWEEN 1 AND 64 AND (s->'Profile'->>'SampleType') !~ '[[:cntrl:]]' AND
   public.capacity_json_integer(s->'Profile'->'TopN',1,100) AND s->>'SourceFormat'='pprof' AND s->>'DisplayVersion'='approved-pprof-summary/v1' AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32]))
  ELSE false END,false);
END $$;
-- +goose StatementEnd
DROP FUNCTION context_query_comparison_source(jsonb,boolean);
DROP FUNCTION context_query_scope_source_valid_legacy133(jsonb);
DROP INDEX context_query_comparison_key_child;
DROP INDEX context_query_legacy_key_child;
ALTER TABLE context_query_key_binding DROP CONSTRAINT context_query_key_binding_pkey;
ALTER TABLE context_query_key_binding ADD PRIMARY KEY(batch_id);
ALTER TABLE context_query_key_binding DROP CONSTRAINT context_query_key_binding_binding_check;
ALTER TABLE context_query_key_binding DROP COLUMN child_id;
ALTER TABLE context_query_key_binding DROP COLUMN source_ordinal;
ALTER TABLE context_query_key_binding ADD CONSTRAINT context_query_key_binding_binding_check CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text) BETWEEN 2 AND CASE WHEN binding#>>'{Authority,Scope,NativeType}' IN ('syscallRecords','syscallArguments') THEN 49152 ELSE 16384 END);
ALTER TABLE context_query DROP COLUMN baseline_allocation_id;
ALTER TABLE download_worker DROP CONSTRAINT download_worker_intent_json_check;
ALTER TABLE download_worker DROP COLUMN baseline_query_allocation_id;
ALTER TABLE context_query DROP CONSTRAINT context_query_query_check;
ALTER TABLE context_query ADD CONSTRAINT context_query_query_check CHECK(jsonb_typeof(query)='object' AND octet_length(query::text) BETWEEN 2 AND 65536);
ALTER TABLE download_worker ADD CONSTRAINT download_worker_intent_json_check CHECK(octet_length(intent_json) BETWEEN 1 AND 65536);
ALTER TABLE context_query_batch DROP CONSTRAINT context_query_batch_batch_check;
ALTER TABLE context_query_batch ADD CONSTRAINT context_query_batch_batch_check CHECK(jsonb_typeof(batch)='object' AND octet_length(batch::text) BETWEEN 2 AND 16384);
ALTER TABLE context_query_batch DROP CONSTRAINT query_native_pair;
ALTER TABLE context_query_batch ADD CONSTRAINT query_native_pair CHECK((native_operation IS NULL AND native_authority IS NULL AND NOT native_closed) OR COALESCE(jsonb_typeof(native_operation)='object' AND octet_length(native_operation::text) BETWEEN 2 AND 16384 AND jsonb_typeof(native_authority)='object' AND octet_length(native_authority::text) BETWEEN 2 AND 65536,false));
