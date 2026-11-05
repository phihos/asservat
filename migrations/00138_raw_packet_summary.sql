-- +goose Up
-- ADR-304: fixed approved raw-source summary; original remains raw.
-- Reuse all existing query/audit/key roles and accounting; no new state.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_scope_source_valid(s jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb:=s->'Comparison'; b jsonb:=w->'Baseline'; k text; i integer;
BEGIN
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
 SELECT CASE WHEN s->>'NativeType' IN ('pcapng','rawPcapng') THEN 'get_pcap_summary' WHEN s ? 'Comparison' THEN 'compare_profiles' WHEN s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN CASE s->'Syscalls'->>'View' WHEN 'summary' THEN 'get_syscall_summary' WHEN 'events' THEN 'get_syscall_events' ELSE NULL END WHEN s->>'NativeType'='httpHeaders' THEN 'get_http_headers' WHEN s->>'NativeType'='pprof' THEN 'get_profile_summary' ELSE 'get_file_excerpt' END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_read_batches(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'NativeType' IN ('httpHeaders','pprof','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 1 ELSE 2 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_units(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s ? 'Comparison' THEN 20 WHEN s->>'NativeType' IN ('httpHeaders','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 2 WHEN s->>'NativeType'='pprof' THEN 10 ELSE 1 END
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
  (NEW.query->'Scope'->>'NativeType' IN ('pprof','syscallRecords','syscallArguments','pcapng','rawPcapng') AND ((NEW.query->'Plan'->'Profile'->'Worker'->>'MemoryBytes')::bigint<268435456 OR (NEW.query->'Plan'->'Profile'->'Worker'->>'WorkerTransientBytes')::bigint<268435456)) OR
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

-- +goose Down
-- Audit input is minimised to its digest, so refuse any retained summary audit
-- rather than guessing whether an old get_pcap_summary invocation read raw.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.context_query WHERE query->'Scope'->>'NativeType'='rawPcapng') OR
    EXISTS(SELECT 1 FROM public.operation_audit WHERE intent->>'Name'='get_pcap_summary') THEN
  RAISE EXCEPTION 'raw packet query history cannot be downgraded' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_scope_source_valid(s jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb:=s->'Comparison'; b jsonb:=w->'Baseline'; k text; i integer;
BEGIN
 -- Saved packet metadata has no caller-controlled selection or projection.
 IF s->>'NativeType'='pcapng' THEN
  RETURN COALESCE(NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND NOT (s ? 'Syscalls') AND NOT (s ? 'Comparison') AND
   s->>'SourceFormat'='pcapng' AND s->>'DisplayVersion'='approved-pcap-summary/v1' AND
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
 SELECT CASE WHEN s->>'NativeType'='pcapng' THEN 'get_pcap_summary' WHEN s ? 'Comparison' THEN 'compare_profiles' WHEN s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN CASE s->'Syscalls'->>'View' WHEN 'summary' THEN 'get_syscall_summary' WHEN 'events' THEN 'get_syscall_events' ELSE NULL END WHEN s->>'NativeType'='httpHeaders' THEN 'get_http_headers' WHEN s->>'NativeType'='pprof' THEN 'get_profile_summary' ELSE 'get_file_excerpt' END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_read_batches(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'NativeType' IN ('httpHeaders','pprof','syscallRecords','syscallArguments','pcapng') THEN 1 ELSE 2 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_units(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s ? 'Comparison' THEN 20 WHEN s->>'NativeType' IN ('httpHeaders','syscallRecords','syscallArguments','pcapng') THEN 2 WHEN s->>'NativeType'='pprof' THEN 10 ELSE 1 END
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
  (NEW.query->'Scope'->>'NativeType' IN ('pprof','syscallRecords','syscallArguments','pcapng') AND ((NEW.query->'Plan'->'Profile'->'Worker'->>'MemoryBytes')::bigint<268435456 OR (NEW.query->'Plan'->'Profile'->'Worker'->>'WorkerTransientBytes')::bigint<268435456)) OR
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
