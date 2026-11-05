-- +goose Up
-- Bounded metadata process snapshots reuse the existing capture/query journals.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_scope_source_valid(s jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb:=s->'Comparison'; b jsonb:=w->'Baseline'; k text; i integer;
BEGIN
 IF s->>'DisplayVersion'='approved-processes/v1' THEN
  RETURN COALESCE(s->>'NativeType'='processes' AND s->>'SourceFormat'='asservat-processes/v1' AND
   NOT(s ? 'Headers') AND NOT(s ? 'Profile') AND NOT(s ? 'Syscalls') AND NOT(s ? 'Logs') AND NOT(s ? 'Comparison') AND NOT(s ? 'PacketQuery') AND NOT(s ? 'RawGrantID') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   public.capacity_json_fields(s->'Discovery',ARRAY['Section','Start','Limit','Binding']) AND
   s#>>'{Discovery,Section}' IN ('summary','processes') AND
   public.capacity_json_integer(s#>'{Discovery,Start}',0,256) AND public.capacity_json_integer(s#>'{Discovery,Limit}',1,100) AND
   jsonb_typeof(s#>'{Discovery,Binding}')='string' AND
   ((s#>>'{Discovery,Start}'='0' AND s#>>'{Discovery,Binding}'='') OR
    (s#>>'{Discovery,Start}'<>'0' AND s#>>'{Discovery,Binding}'~'^[0-9a-f]{32}$')) AND
   (s#>>'{Discovery,Section}'<>'summary' OR s#>>'{Discovery,Start}'='0'),false);
 END IF;
 IF s ? 'Discovery' OR s->>'NativeType'='processes' THEN RETURN false; END IF;
 IF s->>'DisplayVersion'='approved-logs/v1' THEN
  RETURN COALESCE(s->>'NativeType'='logs' AND s->>'SourceFormat'='asservat-logs/v1' AND
   public.context_packet_query_uuid(s->>'RawGrantID') AND
   NOT(s ? 'Headers') AND NOT(s ? 'Profile') AND NOT(s ? 'Syscalls') AND NOT(s ? 'Comparison') AND NOT(s ? 'PacketQuery') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   public.capacity_json_fields(s->'Logs',ARRAY['Fragment','Offset','Limit','Binding']) AND
   public.capacity_json_integer(s#>'{Logs,Fragment}',0,67108863) AND public.capacity_json_integer(s#>'{Logs,Offset}',0,4095) AND
   public.capacity_json_integer(s#>'{Logs,Limit}',1,100) AND jsonb_typeof(s#>'{Logs,Binding}')='string' AND
   ((s#>>'{Logs,Fragment}'='0' AND s#>>'{Logs,Offset}'='0' AND s#>>'{Logs,Binding}'='') OR
    ((s#>>'{Logs,Fragment}'<>'0' OR s#>>'{Logs,Offset}'<>'0') AND s#>>'{Logs,Binding}'~'^[0-9a-f]{32}$')),false);
 END IF;
 IF s ? 'Logs' OR s->>'NativeType'='logs' THEN RETURN false; END IF;
 IF s->>'DisplayVersion'='approved-syscall-query/v1' THEN
  RETURN COALESCE(s->>'NativeType'='syscallArguments' AND s->>'SourceFormat'='asservat-syscall-arguments/v1' AND
   public.context_packet_query_uuid(s->>'RawGrantID') AND s#>>'{Syscalls,View}'='raw' AND NOT(s ? 'PacketQuery') AND
   public.context_query_scope_source_valid_legacy133(jsonb_set((s-'RawGrantID') || jsonb_build_object('DisplayVersion','approved-syscall-events/v1'),'{Syscalls,View}','"events"'::jsonb)),false);
 END IF;
 IF s->>'DisplayVersion'='approved-pcap-query/v1' THEN
  RETURN COALESCE(s->>'NativeType' IN ('pcapng','rawPcapng') AND
   ((s->>'NativeType'='pcapng' AND s->>'SourceFormat'='pcapng' AND NOT(s ? 'RawGrantID')) OR
    (s->>'NativeType'='rawPcapng' AND s->>'SourceFormat'='pcapng-raw' AND public.context_packet_query_uuid(s->>'RawGrantID'))) AND
   NOT(s ? 'Headers') AND NOT(s ? 'Profile') AND NOT(s ? 'Syscalls') AND NOT(s ? 'Comparison') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   public.context_packet_query_window_valid(s->'PacketQuery',s->>'NativeType'),false);
 END IF;
 IF s ? 'PacketQuery' OR s ? 'RawGrantID' THEN RETURN false; END IF;
 -- The two fixed saved-packet summaries keep distinct source/display identities.
 IF s->>'NativeType' IN ('pcapng','rawPcapng') THEN
  RETURN COALESCE(NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND NOT (s ? 'Syscalls') AND NOT (s ? 'Comparison') AND
   ((s->>'NativeType'='pcapng' AND s->>'SourceFormat'='pcapng' AND s->>'DisplayVersion'='approved-pcap-summary/v1') OR (s->>'NativeType'='rawPcapng' AND s->>'SourceFormat'='pcapng-raw' AND s->>'DisplayVersion'='approved-raw-pcap-summary/v1')) AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])),false);
 END IF;
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
 SELECT CASE WHEN s->>'DisplayVersion'='approved-processes/v1' THEN 'get_target_discovery' WHEN s->>'DisplayVersion'='approved-logs/v1' THEN 'get_logs' WHEN s->>'DisplayVersion'='approved-syscall-query/v1' THEN 'syscall_query' WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 'pcap_query' WHEN s->>'NativeType' IN ('pcapng','rawPcapng') THEN 'get_pcap_summary' WHEN s ? 'Comparison' THEN 'compare_profiles' WHEN s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN CASE s->'Syscalls'->>'View' WHEN 'summary' THEN 'get_syscall_summary' WHEN 'events' THEN 'get_syscall_events' ELSE NULL END WHEN s->>'NativeType'='httpHeaders' THEN 'get_http_headers' WHEN s->>'NativeType'='pprof' THEN 'get_profile_summary' ELSE 'get_file_excerpt' END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_read_batches(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-processes/v1' THEN 1 WHEN s->>'DisplayVersion'='approved-logs/v1' THEN 2 WHEN s->>'DisplayVersion'='approved-syscall-query/v1' THEN 2 WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 2 WHEN s->>'NativeType' IN ('httpHeaders','pprof','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 1 ELSE 2 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_units(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-processes/v1' THEN 2 WHEN s->>'DisplayVersion'='approved-logs/v1' THEN 20 WHEN s->>'DisplayVersion'='approved-syscall-query/v1' THEN 4 WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 4 WHEN s ? 'Comparison' THEN 20 WHEN s->>'NativeType' IN ('httpHeaders','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 2 WHEN s->>'NativeType'='pprof' THEN 10 ELSE 1 END
$$;
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
 IF NEW.query#>>'{Scope,DisplayVersion}' IN ('approved-pcap-query/v1','approved-syscall-query/v1','approved-logs/v1') THEN
  IF NOT COALESCE(NEW.invocation_key IS NOT NULL AND NEW.request_digest IS NOT NULL AND
   NEW.query#>>'{InvocationKey,Key}'=NEW.invocation_key AND
   NEW.query#>'{InvocationKey,RequestDigest}'=to_jsonb(ARRAY(SELECT get_byte(NEW.request_digest,i) FROM generate_series(0,31)i)) AND
   public.context_packet_query_scope_grant_current(NEW.root_id,NEW.actor,NEW.query->'Scope',NEW.query->'Grant'),false) THEN
   RAISE EXCEPTION 'packet query invocation or grant mismatch' USING ERRCODE='23514'; END IF;
 ELSIF NEW.invocation_key IS NOT NULL OR NEW.request_digest IS NOT NULL OR NEW.query ? 'InvocationKey' OR NEW.query ? 'Grant' THEN
  RAISE EXCEPTION 'unrelated query invocation or grant' USING ERRCODE='23514';
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
  (NEW.query->'Scope'->>'NativeType' IN ('pprof','syscallRecords','syscallArguments','pcapng','rawPcapng','logs','processes') AND ((NEW.query->'Plan'->'Profile'->'Worker'->>'MemoryBytes')::bigint<268435456 OR (NEW.query->'Plan'->'Profile'->'Worker'->>'WorkerTransientBytes')::bigint<268435456)) OR
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
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_target_discovery','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_target_discovery','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
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
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+(CASE WHEN NEW.intent->>'Name' IN ('get_file_excerpt','get_target_discovery','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result','prepare_artifact_download','get_artifact_download') THEN interval '20 seconds' WHEN NEW.intent->>'Name' IN ('request_capture','preview_capture') THEN interval '15 seconds' WHEN NEW.lane='capture' AND NEW.intent->>'Name'='persist_capture_intent' AND EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.id AND public.capture_audit_payload_matches(c,NEW.intent) AND c.group_id IS NOT NULL AND c.group_ordinal IS NOT NULL AND NEW.request_until<=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN interval '15 seconds' ELSE interval '5 seconds' END) OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
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
 AND a.intent->>'Name'=call->>'Tool' AND a.intent->>'Name' IN ('get_file_excerpt','get_target_discovery','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result')
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
 AND a.intent->'Actor'=actor AND a.intent->>'Name' IN ('get_file_excerpt','get_target_discovery','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') AND a.intent->>'InputFormat'='context-query-input/v1'
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
CREATE OR REPLACE FUNCTION project_context_processing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; e jsonb; n timestamptz;
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_catalog'::regclass THEN
  RAISE EXCEPTION 'invalid processing publication source' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF p.initialized_at IS NULL OR n>=p.valid_until OR p.captures>=p.max_captures THEN RAISE EXCEPTION 'processing completeness unavailable' USING ERRCODE='23514'; END IF;
 SELECT convert_from(c.expectation_json,'UTF8')::jsonb INTO STRICT e FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF e ? 'Processes' AND e->>'NativeType' IS DISTINCT FROM 'processes' THEN RAISE EXCEPTION 'unqualified process processing lineage' USING ERRCODE='23514'; END IF;
 IF e ? 'Logs' AND e->>'NativeType' IS DISTINCT FROM 'logs' THEN RAISE EXCEPTION 'unqualified logs processing lineage' USING ERRCODE='23514'; END IF;
 IF NOT COALESCE(e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='processes' AND e->>'DataClass'='metadata' AND
    jsonb_typeof(e->'Processes')='object' AND e#>>'{Processes,ActionID}'=e->>'ActionID' AND
    e#>>'{Processes,Mode}' IN ('podMainProcesses','allPodProcesses') AND
    public.capacity_json_integer(e#>'{Processes,MaxNativeBytes}',1,2097152) AND e#>'{Processes,MaxNativeBytes}'=e#>'{Registration,NativeLimit}' AND
    public.capacity_json_integer(e#>'{Processes,TimeoutMillis}',1,5000) AND length(e#>>'{Processes,Composition}') BETWEEN 1 AND 65536 AND
    NOT(e ? 'Recording') AND NOT(e ? 'Profile') AND NOT(e ? 'Snapshot') AND NOT(e ? 'Logs') AND NOT(e ? 'Lifecycle') AND NOT(e ? 'CompositionGroup') OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='logs' AND e->>'DataClass'='raw' AND
    jsonb_typeof(e->'Logs')='object' AND e#>>'{Logs,ActionID}'=e->>'ActionID' AND e#>>'{Logs,Streams}'='combined' AND
    NOT(e ? 'Recording') AND NOT(e ? 'Profile') AND NOT(e ? 'Snapshot') AND NOT(e ? 'Lifecycle') AND
    public.capacity_json_integer(e#>'{Logs,BeforeMillis}',0,86400000) AND public.capacity_json_integer(e#>'{Logs,AfterMillis}',0,60000) AND public.capacity_json_integer(e#>'{Logs,TimeoutMillis}',1,300000) AND
    (e#>>'{Logs,TimeoutMillis}')::bigint>(e#>>'{Logs,AfterMillis}')::bigint AND
    (e#>>'{Logs,BeforeMillis}')::bigint+(e#>>'{Logs,AfterMillis}')::bigint>0 AND
    public.capacity_json_integer(e#>'{Logs,MaxNativeBytes}',1,67108864) AND e#>'{Logs,MaxNativeBytes}'=e#>'{Registration,NativeLimit}' AND
    (e->>'TriggeredAt')::timestamptz+make_interval(secs=>(e#>>'{Logs,AfterMillis}')::double precision/1000)<(e#>>'{Registration,WriteUntil}')::timestamptz AND
    length(e#>>'{Logs,Composition}')>0 OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pprof','goTrace') AND jsonb_typeof(e->'Profile')='object' AND e->>'DataClass'='raw' AND
    NOT e ? 'Recording' AND NOT e ? 'Snapshot' AND NOT e ? 'Lifecycle' AND NOT e ? 'CompositionGroup' AND
    (e->>'NativeType'='goTrace' AND e#>>'{Profile,Type}'='runtimeTrace' OR e->>'NativeType'='pprof' AND e#>>'{Profile,Type}' IN ('cpu','heap','allocs','goroutine','block','mutex','threadcreate')) AND
    (e#>>'{Profile,MaxBytes}')::bigint=(e#>>'{Registration,NativeLimit}')::bigint AND
    (e#>>'{Profile,TimeoutMillis}')::bigint BETWEEN (e#>>'{Profile,DurationMillis}')::bigint+5000 AND (e#>>'{Profile,DurationMillis}')::bigint+10000 AND
    length(e#>>'{Profile,Composition}')>0 OR
    e->>'ActionID'='pod-status' AND NOT e ? 'NativeType' AND NOT e ? 'Recording' AND NOT e ? 'Logs' OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND jsonb_typeof(e->'Recording')='object' AND (e->>'NativeType'='pcapng' AND e#>>'{Recording,Kind}'='packetCapture' OR e->>'NativeType'='rawPcapng' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='rawPackets' OR e->>'NativeType'='httpHeaders' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='httpHeaders' OR e->>'NativeType'='syscallRecords' AND e#>>'{Recording,Kind}'='syscallTrace' OR e->>'NativeType'='syscallArguments' AND e#>>'{Recording,Kind}'='syscallTrace' AND e#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(e#>'{Recording,Arguments}')='object' AND NOT e ? 'Snapshot' AND NOT e ? 'Profile' AND NOT e ? 'Lifecycle') OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pcapng','syscallRecords') AND jsonb_typeof(e->'Snapshot')='object' AND (NOT e ? 'Recording' OR e->'Recording'='null'::jsonb),false) OR NOT COALESCE(e->>'DataClass'='metadata' AND e->>'NativeType' IS DISTINCT FROM 'logs' AND e->>'NativeType' IS DISTINCT FROM 'rawPcapng' AND e->>'NativeType' IS DISTINCT FROM 'httpHeaders' AND e->>'NativeType' IS DISTINCT FROM 'pprof' AND e->>'NativeType' IS DISTINCT FROM 'goTrace' AND e->>'NativeType' IS DISTINCT FROM 'syscallArguments' OR e->>'DataClass'='raw' AND e->>'NativeType' IN ('rawPcapng','pprof','goTrace','syscallArguments','logs') OR e->>'DataClass'='extract' AND e->>'NativeType'='httpHeaders',false) OR
    (e->>'CaptureUID')::uuid IS DISTINCT FROM NEW.capture_id OR (e#>>'{Registration,Location,ArtifactID}')::uuid IS DISTINCT FROM NEW.artifact_id OR
    (e#>>'{Registration,DeleteBy}')::timestamptz>p.valid_until THEN
  RAISE EXCEPTION 'unqualified processing lineage' USING ERRCODE='23514'; END IF;
 -- Renewing installation capacity does not expand an older restrictive rule's
 -- managed-history coverage. The restriction stays effective after its own
 -- administrative deadline; future matching evidence cannot outlive backing.
 IF EXISTS(SELECT 1 FROM public.processing_rule r WHERE r.root_id=NEW.root_id AND r.state='restricted' AND
    (e#>>'{Registration,DeleteBy}')::timestamptz>r.valid_until AND
    ((r.scope->>'Kind'='artifact' AND r.scope#>>'{Location,ArtifactID}'=NEW.artifact_id::text AND r.scope#>>'{Location,AttemptID}'=e#>>'{Registration,Location,AttemptID}' AND r.scope#>>'{Location,ClusterID}'=e#>>'{Registration,Location,ClusterID}') OR
     (r.scope->>'Kind'='workloadInterval' AND r.scope->>'ClusterID'=e#>>'{Registration,Location,ClusterID}' AND r.scope->>'NamespaceUID'=e->>'NamespaceUID' AND r.scope->>'WorkloadUID'=e->>'WorkloadUID' AND
      (e#>>'{Registration,AnchorAt}')::timestamptz>=(r.scope->>'AcquiredFrom')::timestamptz AND (e#>>'{Registration,AnchorAt}')::timestamptz<(r.scope->>'AcquiredUntil')::timestamptz))) THEN
  RAISE EXCEPTION 'retained processing restriction requires coverage reconciliation' USING ERRCODE='23514'; END IF;
 INSERT INTO public.context_processing(artifact_id,root_id,capture_id,attempt_id,cluster_id,namespace_uid,workload_uid,pod_uid,anchor_at,delete_by,retire_by,origin,parents)
 VALUES(NEW.artifact_id,NEW.root_id,NEW.capture_id,(e#>>'{Registration,Location,AttemptID}')::uuid,(e#>>'{Registration,Location,ClusterID}')::uuid,e->>'NamespaceUID',e->>'WorkloadUID',e->>'PodUID',(e#>>'{Registration,AnchorAt}')::timestamptz,(e#>>'{Registration,DeleteBy}')::timestamptz,p.retire_by,'capture','[]');
 UPDATE public.processing_root SET captures=captures+1 WHERE root_id=NEW.root_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_snapshot_cancel() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.snapshot_cancel_key IS NOT NULL THEN RAISE EXCEPTION 'cancellation follows committed acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.snapshot_cancel_key,NEW.snapshot_cancel_actor,NEW.snapshot_cancel_requested_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_key,OLD.snapshot_cancel_actor,OLD.snapshot_cancel_requested_at) THEN
  IF OLD.snapshot_cancel_key IS NOT NULL OR NEW.snapshot_cancel_key IS NULL OR (jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Snapshot') IS DISTINCT FROM 'object' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Profile') IS DISTINCT FROM 'object' AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='processes' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='metadata' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Processes')='object',false) AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='logs' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Logs')='object',false) AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='syscallArguments' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Kind}'='syscallTrace' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb#>'{Recording,Arguments}')='object',false)) THEN RAISE EXCEPTION 'immutable cancellation request' USING ERRCODE='23514';END IF;
  NEW.snapshot_cancel_requested_at:=clock_timestamp();
 END IF;
 IF ROW(NEW.snapshot_cancel_joined_at,NEW.snapshot_cancel_proof,NEW.snapshot_cancel_proof_digest) IS DISTINCT FROM ROW(OLD.snapshot_cancel_joined_at,OLD.snapshot_cancel_proof,OLD.snapshot_cancel_proof_digest) THEN
  IF OLD.snapshot_cancel_joined_at IS NOT NULL OR NEW.snapshot_cancel_joined_at IS NULL OR NEW.snapshot_cancel_joined_at>clock_timestamp() THEN RAISE EXCEPTION 'immutable cancellation completion' USING ERRCODE='23514';END IF;
  IF NEW.snapshot_cancel_proof IS NULL THEN
   IF EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND started_at IS NOT NULL) THEN RAISE EXCEPTION 'started cancellation needs joined proof' USING ERRCODE='23514';END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND phase='cancelled') THEN RAISE EXCEPTION 'cancellation lacks joined execution' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose Down
-- Retained process identities require this closed contract. No history is erased.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.context_capture WHERE convert_from(expectation_json,'UTF8')::jsonb->>'NativeType'='processes') OR
  EXISTS(SELECT 1 FROM public.context_query WHERE query#>>'{Scope,NativeType}'='processes' OR query#>>'{Scope,DisplayVersion}'='approved-processes/v1') OR
  EXISTS(SELECT 1 FROM public.operation_audit WHERE intent->>'Name'='get_target_discovery') THEN
  RAISE EXCEPTION 'retained process snapshots require schema 142' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_snapshot_cancel() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.snapshot_cancel_key IS NOT NULL THEN RAISE EXCEPTION 'cancellation follows committed acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.snapshot_cancel_key,NEW.snapshot_cancel_actor,NEW.snapshot_cancel_requested_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_key,OLD.snapshot_cancel_actor,OLD.snapshot_cancel_requested_at) THEN
  IF OLD.snapshot_cancel_key IS NOT NULL OR NEW.snapshot_cancel_key IS NULL OR (jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Snapshot') IS DISTINCT FROM 'object' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Profile') IS DISTINCT FROM 'object' AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='logs' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Logs')='object',false) AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='syscallArguments' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Kind}'='syscallTrace' AND convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb#>'{Recording,Arguments}')='object',false)) THEN RAISE EXCEPTION 'immutable cancellation request' USING ERRCODE='23514';END IF;
  NEW.snapshot_cancel_requested_at:=clock_timestamp();
 END IF;
 IF ROW(NEW.snapshot_cancel_joined_at,NEW.snapshot_cancel_proof,NEW.snapshot_cancel_proof_digest) IS DISTINCT FROM ROW(OLD.snapshot_cancel_joined_at,OLD.snapshot_cancel_proof,OLD.snapshot_cancel_proof_digest) THEN
  IF OLD.snapshot_cancel_joined_at IS NOT NULL OR NEW.snapshot_cancel_joined_at IS NULL OR NEW.snapshot_cancel_joined_at>clock_timestamp() THEN RAISE EXCEPTION 'immutable cancellation completion' USING ERRCODE='23514';END IF;
  IF NEW.snapshot_cancel_proof IS NULL THEN
   IF EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND started_at IS NOT NULL) THEN RAISE EXCEPTION 'started cancellation needs joined proof' USING ERRCODE='23514';END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND phase='cancelled') THEN RAISE EXCEPTION 'cancellation lacks joined execution' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_context_processing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.processing_root; e jsonb; n timestamptz;
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_catalog'::regclass THEN
  RAISE EXCEPTION 'invalid processing publication source' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF p.initialized_at IS NULL OR n>=p.valid_until OR p.captures>=p.max_captures THEN RAISE EXCEPTION 'processing completeness unavailable' USING ERRCODE='23514'; END IF;
 SELECT convert_from(c.expectation_json,'UTF8')::jsonb INTO STRICT e FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF e ? 'Logs' AND e->>'NativeType' IS DISTINCT FROM 'logs' THEN RAISE EXCEPTION 'unqualified logs processing lineage' USING ERRCODE='23514'; END IF;
 IF NOT COALESCE(e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='logs' AND e->>'DataClass'='raw' AND
    jsonb_typeof(e->'Logs')='object' AND e#>>'{Logs,ActionID}'=e->>'ActionID' AND e#>>'{Logs,Streams}'='combined' AND
    NOT(e ? 'Recording') AND NOT(e ? 'Profile') AND NOT(e ? 'Snapshot') AND NOT(e ? 'Lifecycle') AND
    public.capacity_json_integer(e#>'{Logs,BeforeMillis}',0,86400000) AND public.capacity_json_integer(e#>'{Logs,AfterMillis}',0,60000) AND public.capacity_json_integer(e#>'{Logs,TimeoutMillis}',1,300000) AND
    (e#>>'{Logs,TimeoutMillis}')::bigint>(e#>>'{Logs,AfterMillis}')::bigint AND
    (e#>>'{Logs,BeforeMillis}')::bigint+(e#>>'{Logs,AfterMillis}')::bigint>0 AND
    public.capacity_json_integer(e#>'{Logs,MaxNativeBytes}',1,67108864) AND e#>'{Logs,MaxNativeBytes}'=e#>'{Registration,NativeLimit}' AND
    (e->>'TriggeredAt')::timestamptz+make_interval(secs=>(e#>>'{Logs,AfterMillis}')::double precision/1000)<(e#>>'{Registration,WriteUntil}')::timestamptz AND
    length(e#>>'{Logs,Composition}')>0 OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pprof','goTrace') AND jsonb_typeof(e->'Profile')='object' AND e->>'DataClass'='raw' AND
    NOT e ? 'Recording' AND NOT e ? 'Snapshot' AND NOT e ? 'Lifecycle' AND NOT e ? 'CompositionGroup' AND
    (e->>'NativeType'='goTrace' AND e#>>'{Profile,Type}'='runtimeTrace' OR e->>'NativeType'='pprof' AND e#>>'{Profile,Type}' IN ('cpu','heap','allocs','goroutine','block','mutex','threadcreate')) AND
    (e#>>'{Profile,MaxBytes}')::bigint=(e#>>'{Registration,NativeLimit}')::bigint AND
    (e#>>'{Profile,TimeoutMillis}')::bigint BETWEEN (e#>>'{Profile,DurationMillis}')::bigint+5000 AND (e#>>'{Profile,DurationMillis}')::bigint+10000 AND
    length(e#>>'{Profile,Composition}')>0 OR
    e->>'ActionID'='pod-status' AND NOT e ? 'NativeType' AND NOT e ? 'Recording' AND NOT e ? 'Logs' OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND jsonb_typeof(e->'Recording')='object' AND (e->>'NativeType'='pcapng' AND e#>>'{Recording,Kind}'='packetCapture' OR e->>'NativeType'='rawPcapng' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='rawPackets' OR e->>'NativeType'='httpHeaders' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='httpHeaders' OR e->>'NativeType'='syscallRecords' AND e#>>'{Recording,Kind}'='syscallTrace' OR e->>'NativeType'='syscallArguments' AND e#>>'{Recording,Kind}'='syscallTrace' AND e#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(e#>'{Recording,Arguments}')='object' AND NOT e ? 'Snapshot' AND NOT e ? 'Profile' AND NOT e ? 'Lifecycle') OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pcapng','syscallRecords') AND jsonb_typeof(e->'Snapshot')='object' AND (NOT e ? 'Recording' OR e->'Recording'='null'::jsonb),false) OR NOT COALESCE(e->>'DataClass'='metadata' AND e->>'NativeType' IS DISTINCT FROM 'logs' AND e->>'NativeType' IS DISTINCT FROM 'rawPcapng' AND e->>'NativeType' IS DISTINCT FROM 'httpHeaders' AND e->>'NativeType' IS DISTINCT FROM 'pprof' AND e->>'NativeType' IS DISTINCT FROM 'goTrace' AND e->>'NativeType' IS DISTINCT FROM 'syscallArguments' OR e->>'DataClass'='raw' AND e->>'NativeType' IN ('rawPcapng','pprof','goTrace','syscallArguments','logs') OR e->>'DataClass'='extract' AND e->>'NativeType'='httpHeaders',false) OR
    (e->>'CaptureUID')::uuid IS DISTINCT FROM NEW.capture_id OR (e#>>'{Registration,Location,ArtifactID}')::uuid IS DISTINCT FROM NEW.artifact_id OR
    (e#>>'{Registration,DeleteBy}')::timestamptz>p.valid_until THEN
  RAISE EXCEPTION 'unqualified processing lineage' USING ERRCODE='23514'; END IF;
 -- Renewing installation capacity does not expand an older restrictive rule's
 -- managed-history coverage. The restriction stays effective after its own
 -- administrative deadline; future matching evidence cannot outlive backing.
 IF EXISTS(SELECT 1 FROM public.processing_rule r WHERE r.root_id=NEW.root_id AND r.state='restricted' AND
    (e#>>'{Registration,DeleteBy}')::timestamptz>r.valid_until AND
    ((r.scope->>'Kind'='artifact' AND r.scope#>>'{Location,ArtifactID}'=NEW.artifact_id::text AND r.scope#>>'{Location,AttemptID}'=e#>>'{Registration,Location,AttemptID}' AND r.scope#>>'{Location,ClusterID}'=e#>>'{Registration,Location,ClusterID}') OR
     (r.scope->>'Kind'='workloadInterval' AND r.scope->>'ClusterID'=e#>>'{Registration,Location,ClusterID}' AND r.scope->>'NamespaceUID'=e->>'NamespaceUID' AND r.scope->>'WorkloadUID'=e->>'WorkloadUID' AND
      (e#>>'{Registration,AnchorAt}')::timestamptz>=(r.scope->>'AcquiredFrom')::timestamptz AND (e#>>'{Registration,AnchorAt}')::timestamptz<(r.scope->>'AcquiredUntil')::timestamptz))) THEN
  RAISE EXCEPTION 'retained processing restriction requires coverage reconciliation' USING ERRCODE='23514'; END IF;
 INSERT INTO public.context_processing(artifact_id,root_id,capture_id,attempt_id,cluster_id,namespace_uid,workload_uid,pod_uid,anchor_at,delete_by,retire_by,origin,parents)
 VALUES(NEW.artifact_id,NEW.root_id,NEW.capture_id,(e#>>'{Registration,Location,AttemptID}')::uuid,(e#>>'{Registration,Location,ClusterID}')::uuid,e->>'NamespaceUID',e->>'WorkloadUID',e->>'PodUID',(e#>>'{Registration,AnchorAt}')::timestamptz,(e#>>'{Registration,DeleteBy}')::timestamptz,p.retire_by,'capture','[]');
 UPDATE public.processing_root SET captures=captures+1 WHERE root_id=NEW.root_id;
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
 AND a.intent->'Actor'=actor AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') AND a.intent->>'InputFormat'='context-query-input/v1'
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
 AND a.intent->>'Name'=call->>'Tool' AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result')
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
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+(CASE WHEN NEW.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result','prepare_artifact_download','get_artifact_download') THEN interval '20 seconds' WHEN NEW.intent->>'Name' IN ('request_capture','preview_capture') THEN interval '15 seconds' WHEN NEW.lane='capture' AND NEW.intent->>'Name'='persist_capture_intent' AND EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.id AND public.capture_audit_payload_matches(c,NEW.intent) AND c.group_id IS NOT NULL AND c.group_ordinal IS NOT NULL AND NEW.request_until<=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN interval '15 seconds' ELSE interval '5 seconds' END) OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
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
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
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
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
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
 IF NEW.query#>>'{Scope,DisplayVersion}' IN ('approved-pcap-query/v1','approved-syscall-query/v1','approved-logs/v1') THEN
  IF NOT COALESCE(NEW.invocation_key IS NOT NULL AND NEW.request_digest IS NOT NULL AND
   NEW.query#>>'{InvocationKey,Key}'=NEW.invocation_key AND
   NEW.query#>'{InvocationKey,RequestDigest}'=to_jsonb(ARRAY(SELECT get_byte(NEW.request_digest,i) FROM generate_series(0,31)i)) AND
   public.context_packet_query_scope_grant_current(NEW.root_id,NEW.actor,NEW.query->'Scope',NEW.query->'Grant'),false) THEN
   RAISE EXCEPTION 'packet query invocation or grant mismatch' USING ERRCODE='23514'; END IF;
 ELSIF NEW.invocation_key IS NOT NULL OR NEW.request_digest IS NOT NULL OR NEW.query ? 'InvocationKey' OR NEW.query ? 'Grant' THEN
  RAISE EXCEPTION 'unrelated query invocation or grant' USING ERRCODE='23514';
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
  (NEW.query->'Scope'->>'NativeType' IN ('pprof','syscallRecords','syscallArguments','pcapng','rawPcapng','logs') AND ((NEW.query->'Plan'->'Profile'->'Worker'->>'MemoryBytes')::bigint<268435456 OR (NEW.query->'Plan'->'Profile'->'Worker'->>'WorkerTransientBytes')::bigint<268435456)) OR
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
CREATE OR REPLACE FUNCTION context_query_units(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-logs/v1' THEN 20 WHEN s->>'DisplayVersion'='approved-syscall-query/v1' THEN 4 WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 4 WHEN s ? 'Comparison' THEN 20 WHEN s->>'NativeType' IN ('httpHeaders','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 2 WHEN s->>'NativeType'='pprof' THEN 10 ELSE 1 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_read_batches(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-logs/v1' THEN 2 WHEN s->>'DisplayVersion'='approved-syscall-query/v1' THEN 2 WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 2 WHEN s->>'NativeType' IN ('httpHeaders','pprof','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 1 ELSE 2 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_begin_tool(s jsonb) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-logs/v1' THEN 'get_logs' WHEN s->>'DisplayVersion'='approved-syscall-query/v1' THEN 'syscall_query' WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 'pcap_query' WHEN s->>'NativeType' IN ('pcapng','rawPcapng') THEN 'get_pcap_summary' WHEN s ? 'Comparison' THEN 'compare_profiles' WHEN s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN CASE s->'Syscalls'->>'View' WHEN 'summary' THEN 'get_syscall_summary' WHEN 'events' THEN 'get_syscall_events' ELSE NULL END WHEN s->>'NativeType'='httpHeaders' THEN 'get_http_headers' WHEN s->>'NativeType'='pprof' THEN 'get_profile_summary' ELSE 'get_file_excerpt' END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_scope_source_valid(s jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb:=s->'Comparison'; b jsonb:=w->'Baseline'; k text; i integer;
BEGIN
 IF s->>'DisplayVersion'='approved-logs/v1' THEN
  RETURN COALESCE(s->>'NativeType'='logs' AND s->>'SourceFormat'='asservat-logs/v1' AND
   public.context_packet_query_uuid(s->>'RawGrantID') AND
   NOT(s ? 'Headers') AND NOT(s ? 'Profile') AND NOT(s ? 'Syscalls') AND NOT(s ? 'Comparison') AND NOT(s ? 'PacketQuery') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   public.capacity_json_fields(s->'Logs',ARRAY['Fragment','Offset','Limit','Binding']) AND
   public.capacity_json_integer(s#>'{Logs,Fragment}',0,67108863) AND public.capacity_json_integer(s#>'{Logs,Offset}',0,4095) AND
   public.capacity_json_integer(s#>'{Logs,Limit}',1,100) AND jsonb_typeof(s#>'{Logs,Binding}')='string' AND
   ((s#>>'{Logs,Fragment}'='0' AND s#>>'{Logs,Offset}'='0' AND s#>>'{Logs,Binding}'='') OR
    ((s#>>'{Logs,Fragment}'<>'0' OR s#>>'{Logs,Offset}'<>'0') AND s#>>'{Logs,Binding}'~'^[0-9a-f]{32}$')),false);
 END IF;
 IF s ? 'Logs' OR s->>'NativeType'='logs' THEN RETURN false; END IF;
 IF s->>'DisplayVersion'='approved-syscall-query/v1' THEN
  RETURN COALESCE(s->>'NativeType'='syscallArguments' AND s->>'SourceFormat'='asservat-syscall-arguments/v1' AND
   public.context_packet_query_uuid(s->>'RawGrantID') AND s#>>'{Syscalls,View}'='raw' AND NOT(s ? 'PacketQuery') AND
   public.context_query_scope_source_valid_legacy133(jsonb_set((s-'RawGrantID') || jsonb_build_object('DisplayVersion','approved-syscall-events/v1'),'{Syscalls,View}','"events"'::jsonb)),false);
 END IF;
 IF s->>'DisplayVersion'='approved-pcap-query/v1' THEN
  RETURN COALESCE(s->>'NativeType' IN ('pcapng','rawPcapng') AND
   ((s->>'NativeType'='pcapng' AND s->>'SourceFormat'='pcapng' AND NOT(s ? 'RawGrantID')) OR
    (s->>'NativeType'='rawPcapng' AND s->>'SourceFormat'='pcapng-raw' AND public.context_packet_query_uuid(s->>'RawGrantID'))) AND
   NOT(s ? 'Headers') AND NOT(s ? 'Profile') AND NOT(s ? 'Syscalls') AND NOT(s ? 'Comparison') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   public.context_packet_query_window_valid(s->'PacketQuery',s->>'NativeType'),false);
 END IF;
 IF s ? 'PacketQuery' OR s ? 'RawGrantID' THEN RETURN false; END IF;
 -- The two fixed saved-packet summaries keep distinct source/display identities.
 IF s->>'NativeType' IN ('pcapng','rawPcapng') THEN
  RETURN COALESCE(NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND NOT (s ? 'Syscalls') AND NOT (s ? 'Comparison') AND
   ((s->>'NativeType'='pcapng' AND s->>'SourceFormat'='pcapng' AND s->>'DisplayVersion'='approved-pcap-summary/v1') OR (s->>'NativeType'='rawPcapng' AND s->>'SourceFormat'='pcapng-raw' AND s->>'DisplayVersion'='approved-raw-pcap-summary/v1')) AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])),false);
 END IF;
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
