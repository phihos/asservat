-- +goose Up
-- ADR305: one immutable caller-key association, existing grant uses per raw batch.
LOCK TABLE context_query,context_query_batch,access_grant,access_grant_use IN ACCESS EXCLUSIVE MODE;
ALTER TABLE context_query ADD COLUMN invocation_key text, ADD COLUMN request_digest bytea;
ALTER TABLE context_query ADD CONSTRAINT context_query_invocation_pair CHECK(
 (invocation_key IS NULL AND request_digest IS NULL) OR
 (invocation_key IS NOT NULL AND octet_length(invocation_key) BETWEEN 1 AND 128 AND invocation_key!~'[[:cntrl:]]' AND request_digest IS NOT NULL AND octet_length(request_digest)=32 AND request_digest<>decode(repeat('00',32),'hex')));
CREATE UNIQUE INDEX context_query_invocation ON context_query(root_id,principal_key,(actor->>'ClientID'),invocation_key) WHERE invocation_key IS NOT NULL;
ALTER TABLE access_grant_use DROP CONSTRAINT access_grant_use_operation_check;
ALTER TABLE access_grant_use ADD CONSTRAINT access_grant_use_operation_check CHECK(operation IN('download_artifact','pcap_query'));
ALTER TABLE access_grant DROP CONSTRAINT access_grant_scope_kind;
ALTER TABLE access_grant ADD CONSTRAINT access_grant_scope_kind CHECK ((CASE WHEN kind='rawQuery' THEN (kind='rawQuery' AND requester_kind='human' AND request_operation='requestRawAccess'
 AND requester_key IS NOT NULL AND octet_length(requester_key)=32
 AND requester_key=sha256(int4send(octet_length(convert_to(requester_issuer,'UTF8'))) || convert_to(requester_issuer,'UTF8') || int4send(octet_length(convert_to(requester_subject,'UTF8'))) || convert_to(requester_subject,'UTF8') || int4send(octet_length(convert_to(requester_client,'UTF8'))) || convert_to(requester_client,'UTF8') || int4send(5) || convert_to('human','UTF8'))
 AND preview_id IS NULL AND capture_id IS NULL AND cluster_id IS NULL AND namespace_uid IS NULL AND workload_uid IS NULL AND pod_uid IS NULL
 AND policy_uid IS NULL AND policy_acceptance_id IS NULL AND policy_scope IS NULL AND policy_not_after IS NULL
 AND policy_executions_spent=0 AND policy_bytes_spent=0 AND policy_observed_bytes_spent=0 AND policy_observed_events_spent=0
 AND data_class='raw' AND lifetime_seconds BETWEEN 1 AND 28800
 AND result_access IS NULL AND result_access_digest IS NULL AND not_after IS NOT NULL
 AND jsonb_typeof(raw_query)='object'
 AND convert_from(scope,'UTF8')::jsonb=jsonb_build_object('Version','raw-query/v1','Scope',raw_query)
 AND jsonb_typeof(raw_query->'Artifacts')='array' AND jsonb_array_length(raw_query->'Artifacts') BETWEEN 1 AND 64
 AND raw_query->'Operations' IN ('["download_artifact"]'::jsonb,'["pcap_query"]'::jsonb,'["download_artifact","pcap_query"]'::jsonb)
 AND max_artifacts=jsonb_array_length(raw_query->'Artifacts')
 AND max_bytes=(raw_query->>'MaxBytes')::bigint AND max_bytes BETWEEN 1 AND CASE WHEN raw_query->'Operations'='["pcap_query"]'::jsonb THEN 1073741824 ELSE 1099511627776 END
 AND max_operations=(raw_query->>'MaxOperations')::bigint AND max_operations BETWEEN 1 AND 10000
 AND not_after=(raw_query->>'NotAfter')::timestamptz) ELSE (raw_query IS NULL AND cluster_id IS NOT NULL AND namespace_uid IS NOT NULL AND workload_uid IS NOT NULL AND ((
 (kind='adHocCapture' AND requester_kind='human' AND request_operation='requestGrant' AND requester_key IS NULL
  AND preview_id IS NOT NULL AND capture_id IS NOT NULL AND pod_uid IS NOT NULL
  AND policy_uid IS NULL AND policy_acceptance_id IS NULL AND policy_scope IS NULL AND policy_not_after IS NULL
  AND lifetime_seconds BETWEEN 60 AND 28800
  AND policy_executions_spent=0 AND policy_bytes_spent=0 AND policy_observed_bytes_spent=0)
 OR
 (kind='policy' AND request_operation='requestPolicyGrant'
  AND requester_key IS NOT NULL AND octet_length(requester_key)=32
  AND requester_key=sha256(int4send(octet_length(convert_to(requester_issuer,'UTF8'))) || convert_to(requester_issuer,'UTF8') || int4send(octet_length(convert_to(requester_subject,'UTF8'))) || convert_to(requester_subject,'UTF8') || int4send(octet_length(convert_to(requester_client,'UTF8'))) || convert_to(requester_client,'UTF8') || int4send(octet_length(convert_to(requester_kind,'UTF8'))) || convert_to(requester_kind,'UTF8'))
  AND preview_id IS NULL AND capture_id IS NULL AND pod_uid IS NULL
  AND policy_uid IS NOT NULL AND octet_length(policy_uid) BETWEEN 1 AND 64
  AND policy_acceptance_id IS NOT NULL AND policy_scope IS NOT NULL
  AND jsonb_typeof(policy_scope)='object' AND octet_length(policy_scope::text)<=65536
  AND policy_scope ?& ARRAY['Authority','Limits','ApprovalPolicyRef','ApprovalMaxAge','RecipeDigest']
  AND policy_scope#>>'{Authority,PolicyUID}'=policy_uid
  AND policy_scope#>>'{Authority,ClusterID}'=cluster_id::text
  AND policy_scope#>>'{Authority,NamespaceUID}'=namespace_uid
  AND policy_scope#>>'{Authority,WorkloadUID}'=workload_uid
  AND lifetime_seconds BETWEEN 1 AND 31536000
  AND (policy_scope->>'ApprovalMaxAge')::bigint BETWEEN lifetime_seconds::bigint*1000000000 AND 31536000000000000
  AND policy_not_after IS NOT NULL AND policy_not_after>requested_at
  AND policy_not_after<=requested_at+make_interval(secs=>lifetime_seconds)
  AND policy_not_after<=(policy_scope#>>'{Authority,NotAfter}')::timestamptz
  AND result_access IS NULL AND result_access_digest IS NULL AND not_after IS NULL
  AND max_artifacts=0 AND max_bytes=0 AND max_operations=0
  AND artifacts_spent=0 AND bytes_spent=0 AND operations_spent=0
  AND policy_max_executions IS NOT NULL AND policy_max_executions>0
  AND policy_max_bytes IS NOT NULL AND policy_max_bytes>0
  AND policy_max_observed_bytes IS NOT NULL AND policy_max_observed_bytes>=0)
) IS TRUE)) END) IS TRUE);
ALTER TABLE access_grant ADD CONSTRAINT access_grant_followup_operations CHECK(result_access IS NULL OR result_access->'operations' IN ('["download_artifact"]'::jsonb,'["pcap_query"]'::jsonb,'["download_artifact","pcap_query"]'::jsonb));
-- +goose StatementBegin
CREATE FUNCTION context_packet_query_uuid(v text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(v~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND v<>'00000000-0000-0000-0000-000000000000',false)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION context_packet_query_window_valid(w jsonb,native text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE i integer; f text; seen text[]:=ARRAY[]::text[]; ins jsonb; code bigint; k bigint; program bytea:=''::bytea; d bytea;
BEGIN
 IF NOT public.capacity_json_fields(w,ARRAY['Fields','FieldCount','Instructions','ProgramCount','CompilerDigest','ProgramDigest','StartTime','EndTime','HasStart','HasEnd','TCPMask','TCPValue','PrefixOffset','PrefixLength','MaxPackets','MaxScanBytes']) OR
  NOT public.capacity_json_integer(w->'FieldCount',1,32) OR NOT public.capacity_json_integer(w->'ProgramCount',0,256) OR
  NOT public.capacity_json_integer(w->'MaxPackets',1,100) OR NOT public.capacity_json_integer(w->'MaxScanBytes',1,1073741824) OR
  jsonb_typeof(w->'Fields') IS DISTINCT FROM 'array' OR jsonb_array_length(w->'Fields')<>32 OR
  jsonb_typeof(w->'Instructions') IS DISTINCT FROM 'array' OR jsonb_array_length(w->'Instructions')<>256 OR
  jsonb_typeof(w->'HasStart') IS DISTINCT FROM 'boolean' OR jsonb_typeof(w->'HasEnd') IS DISTINCT FROM 'boolean' OR
  NOT public.capacity_json_integer(w->'TCPMask',0,511) OR NOT public.capacity_json_integer(w->'TCPValue',0,511) OR
  ((w->>'TCPValue')::integer & ~(w->>'TCPMask')::integer)<>0 OR
  NOT public.capacity_json_integer(w->'PrefixOffset',0,65535) OR NOT public.capacity_json_integer(w->'PrefixLength',0,64) OR
  (w->>'PrefixOffset')::bigint+(w->>'PrefixLength')::bigint>1500 THEN RETURN false; END IF;
 FOR i IN 0..31 LOOP
  IF jsonb_typeof(w->'Fields'->i) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
  f:=w->'Fields'->>i;
  IF i<(w->>'FieldCount')::integer THEN
   IF f<>ALL(ARRAY['packet_index','packet_time','captured_length','wire_length','source_address','destination_address','source_port','destination_port','protocol','tcp_flags','tcp_seq','tcp_ack','tcp_window','icmp_type','icmp_code','frame_prefix_hex']) OR f=ANY(seen) THEN RETURN false; END IF;
   seen:=array_append(seen,f);
  ELSIF f<>'' THEN RETURN false; END IF;
 END LOOP;
 IF ('frame_prefix_hex'=ANY(seen)) IS DISTINCT FROM ((w->>'PrefixLength')::integer>0) OR
  (NOT('frame_prefix_hex'=ANY(seen)) AND (w->>'PrefixOffset')::integer<>0) OR
  (native<>'rawPcapng' AND (w->>'PrefixLength')::integer<>0) THEN RETURN false; END IF;
 IF NOT (w->>'HasStart')::boolean AND w->>'StartTime'<>'0001-01-01T00:00:00Z' OR
    NOT (w->>'HasEnd')::boolean AND w->>'EndTime'<>'0001-01-01T00:00:00Z' OR
    (w->>'HasStart')::boolean AND (NOT isfinite((w->>'StartTime')::timestamptz) OR (w->>'StartTime')::timestamptz='0001-01-01T00:00:00Z'::timestamptz) OR
    (w->>'HasEnd')::boolean AND (NOT isfinite((w->>'EndTime')::timestamptz) OR (w->>'EndTime')::timestamptz='0001-01-01T00:00:00Z'::timestamptz) OR
    (w->>'HasStart')::boolean AND (w->>'HasEnd')::boolean AND (w->>'EndTime')::timestamptz<=(w->>'StartTime')::timestamptz THEN RETURN false; END IF;
 FOR i IN 0..255 LOOP
  ins:=w->'Instructions'->i;
  IF NOT public.capacity_json_fields(ins,ARRAY['Code','Jt','Jf','K']) OR NOT public.capacity_json_integer(ins->'Code',0,65535) OR
   NOT public.capacity_json_integer(ins->'Jt',0,255) OR NOT public.capacity_json_integer(ins->'Jf',0,255) OR NOT public.capacity_json_integer(ins->'K',0,4294967295) THEN RETURN false; END IF;
  IF i>=(w->>'ProgramCount')::integer THEN
   IF ins<>'{"Code":0,"Jt":0,"Jf":0,"K":0}'::jsonb THEN RETURN false; END IF;
  ELSE
   code:=(ins->>'Code')::bigint; k:=(ins->>'K')::bigint;
   program:=program || decode(lpad(to_hex(code&255),2,'0')||lpad(to_hex((code>>8)&255),2,'0')||lpad(to_hex((ins->>'Jt')::integer),2,'0')||lpad(to_hex((ins->>'Jf')::integer),2,'0')||lpad(to_hex(k&255),2,'0')||lpad(to_hex((k>>8)&255),2,'0')||lpad(to_hex((k>>16)&255),2,'0')||lpad(to_hex((k>>24)&255),2,'0'),'hex');
  END IF;
 END LOOP;
 IF (w->>'ProgramCount')::integer=0 THEN RETURN w->'CompilerDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND w->'ProgramDigest'=to_jsonb(array_fill(0,ARRAY[32])); END IF;
 d:=decode('9237f5bae9dcf3a91823d9963ec43b7c0e2e3374ef2ad57d92c8cd39530f4723','hex');
 IF w->'CompilerDigest' IS DISTINCT FROM to_jsonb(ARRAY(SELECT get_byte(d,i) FROM generate_series(0,31)i)) THEN RETURN false; END IF;
 d:=sha256(program);
 RETURN w->'ProgramDigest'=to_jsonb(ARRAY(SELECT get_byte(d,i) FROM generate_series(0,31)i));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN RETURN false;
END $$;
-- +goose StatementEnd
-- Private exact source/current grant predicate. It returns no review, output or credential.
-- +goose StatementBegin
CREATE FUNCTION context_packet_query_scope_grant_current(r uuid,actor jsonb,s jsonb,binding jsonb) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g public.access_grant; c public.access_grant_child; item jsonb; matched boolean:=false; n timestamptz;
BEGIN
 IF s->>'DisplayVersion' IS DISTINCT FROM 'approved-pcap-query/v1' OR s->>'NativeType'<>'rawPcapng' THEN RETURN binding IS NULL AND NOT(s ? 'RawGrantID'); END IF;
 IF NOT public.capacity_json_fields(binding,ARRAY['ParentID','ChildID']) OR NOT public.context_packet_query_uuid(binding->>'ParentID') OR NOT public.context_packet_query_uuid(binding->>'ChildID') OR binding->>'ParentID' IS DISTINCT FROM s->>'RawGrantID' OR actor->>'Kind' IS DISTINCT FROM 'human' THEN RETURN false; END IF;
 SELECT * INTO g FROM public.access_grant WHERE root_id=r AND id=(binding->>'ParentID')::uuid FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM public.access_grant_child WHERE root_id=r AND id=(binding->>'ChildID')::uuid;
 n:=clock_timestamp();
 IF NOT FOUND OR c.parent_id<>g.id OR c.client_id IS DISTINCT FROM actor->>'ClientID' OR c.artifact_id::text IS DISTINCT FROM s->>'ArtifactID' OR c.capture_id::text IS DISTINCT FROM s->>'CaptureID' OR
  to_jsonb(ARRAY(SELECT get_byte(c.artifact_digest,i) FROM generate_series(0,31)i)) IS DISTINCT FROM s->'Version' OR
  g.decision IS DISTINCT FROM 'approved' OR g.revoked_at IS NOT NULL OR NOT COALESCE(n<g.expires_at,false) OR
  g.requester_kind<>'human' OR g.requester_issuer IS DISTINCT FROM actor->>'Issuer' OR g.requester_subject IS DISTINCT FROM actor->>'Subject' OR
  NOT EXISTS(SELECT 1 FROM public.context_case_locator l WHERE l.root_id=r AND l.case_id::text=s->>'CaseID' AND l.capture_id=c.capture_id AND l.artifact_id=c.artifact_id AND l.cluster_id::text=s->>'ClusterID' AND l.namespace_uid=s->>'NamespaceUID' AND l.workload_uid=s->>'WorkloadUID' AND l.pod_uid=s->>'PodUID') THEN RETURN false; END IF;
 IF g.kind='adHocCapture' THEN
  RETURN COALESCE(g.capture_id=c.capture_id AND g.result_access->'operations' ? 'pcap_query' AND g.result_access->'clientIDs' ? c.client_id AND g.result_access->'actionIDs' ? c.action_id AND g.cluster_id::text=s->>'ClusterID' AND g.namespace_uid=s->>'NamespaceUID' AND g.workload_uid=s->>'WorkloadUID' AND g.pod_uid=s->>'PodUID',false);
 ELSIF g.kind='rawQuery' THEN
  IF g.raw_query->>'CaseID' IS DISTINCT FROM s->>'CaseID' OR g.requester_client IS DISTINCT FROM actor->>'ClientID' OR NOT(g.raw_query->'Operations' ? 'pcap_query') THEN RETURN false; END IF;
  FOR item IN SELECT jsonb_array_elements(g.raw_query->'Artifacts') LOOP
   IF COALESCE(item#>>'{Output,ArtifactID}'=c.artifact_id::text AND item#>>'{Output,CaptureID}'=c.capture_id::text AND item#>>'{Output,ActionID}'=c.action_id AND item#>'{Output,ArtifactDigest}'=s->'Version' AND
     item#>>'{Output,Target,ClusterID}'=s->>'ClusterID' AND item#>>'{Output,Target,NamespaceUID}'=s->>'NamespaceUID' AND item#>>'{Output,Target,WorkloadUID}'=s->>'WorkloadUID' AND item#>>'{Output,Target,PodUID}'=s->>'PodUID' AND n<(item->>'ExpiresAt')::timestamptz,false) THEN matched:=true; END IF;
  END LOOP;
  RETURN matched;
 END IF;
 RETURN false;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN RETURN false;
END $$;
-- +goose StatementEnd
-- The externally callable predicate selects ONLY a real immutable query and its exact batch use.
-- +goose StatementBegin
CREATE FUNCTION context_packet_query_grant_current(r uuid,qid uuid,batch uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE q public.context_query; u public.access_grant_use;
BEGIN
 SELECT * INTO q FROM public.context_query WHERE root_id=r AND id=qid;
 IF NOT FOUND THEN RETURN false; END IF;
 IF NOT public.context_packet_query_scope_grant_current(r,q.actor,q.query->'Scope',q.query->'Grant') THEN RETURN false; END IF;
 IF q.query#>>'{Scope,DisplayVersion}'<>'approved-pcap-query/v1' OR q.query#>>'{Scope,NativeType}'<>'rawPcapng' THEN RETURN true; END IF;
 IF batch IS NULL THEN RETURN true; END IF;
 SELECT * INTO u FROM public.access_grant_use WHERE root_id=r AND id=batch;
 RETURN FOUND AND u.parent_id::text=q.query#>>'{Grant,ParentID}' AND u.child_id::text=q.query#>>'{Grant,ChildID}' AND u.operation='pcap_query' AND u.bytes=24576 AND u.operations=1;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_packet_query_uuid(text),context_packet_query_window_valid(jsonb,text),context_packet_query_scope_grant_current(uuid,jsonb,jsonb,jsonb),context_packet_query_grant_current(uuid,uuid,uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_scope_source_valid(s jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE w jsonb:=s->'Comparison'; b jsonb:=w->'Baseline'; k text; i integer;
BEGIN
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
 SELECT CASE WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 'pcap_query' WHEN s->>'NativeType' IN ('pcapng','rawPcapng') THEN 'get_pcap_summary' WHEN s ? 'Comparison' THEN 'compare_profiles' WHEN s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN CASE s->'Syscalls'->>'View' WHEN 'summary' THEN 'get_syscall_summary' WHEN 'events' THEN 'get_syscall_events' ELSE NULL END WHEN s->>'NativeType'='httpHeaders' THEN 'get_http_headers' WHEN s->>'NativeType'='pprof' THEN 'get_profile_summary' ELSE 'get_file_excerpt' END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_read_batches(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 2 WHEN s->>'NativeType' IN ('httpHeaders','pprof','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 1 ELSE 2 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_units(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 4 WHEN s ? 'Comparison' THEN 20 WHEN s->>'NativeType' IN ('httpHeaders','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 2 WHEN s->>'NativeType'='pprof' THEN 10 ELSE 1 END
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
 IF NEW.query#>>'{Scope,DisplayVersion}'='approved-pcap-query/v1' THEN
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
   IF q.query#>>'{Scope,DisplayVersion}'='approved-pcap-query/v1' AND NOT public.context_packet_query_grant_current(q.root_id,q.id,NEW.id) THEN
    RAISE EXCEPTION 'packet query batch disclosure is not reserved' USING ERRCODE='23514'; END IF;
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
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
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
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+(CASE WHEN NEW.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result','prepare_artifact_download','get_artifact_download') THEN interval '20 seconds' WHEN NEW.intent->>'Name' IN ('request_capture','preview_capture') THEN interval '15 seconds' WHEN NEW.lane='capture' AND NEW.intent->>'Name'='persist_capture_intent' AND EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.id AND public.capture_audit_payload_matches(c,NEW.intent) AND c.group_id IS NOT NULL AND c.group_ordinal IS NOT NULL AND NEW.request_until<=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN interval '15 seconds' ELSE interval '5 seconds' END) OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
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
 AND a.intent->>'Name'=call->>'Tool' AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result')
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
 AND a.intent->'Actor'=actor AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') AND a.intent->>'InputFormat'='context-query-input/v1'
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
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-'allocated') IS DISTINCT FROM (to_jsonb(OLD)-'allocated') OR NEW.allocated-OLD.allocated NOT IN (1,2,4,10,20) THEN RAISE EXCEPTION 'query account mutation denied' USING ERRCODE='23514'; END IF;
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
-- +goose Down
-- No retained new operation can be hidden by a downgrade. Existing scopes/uses stay immutable.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.context_query WHERE invocation_key IS NOT NULL) OR
    EXISTS(SELECT 1 FROM public.operation_audit WHERE intent->>'Name'='pcap_query') OR
    EXISTS(SELECT 1 FROM public.access_grant_use WHERE operation='pcap_query') OR
    EXISTS(SELECT 1 FROM public.access_grant WHERE raw_query->'Operations' ? 'pcap_query' OR result_access->'operations' ? 'pcap_query') THEN
  RAISE EXCEPTION 'packet query history cannot be downgraded' USING ERRCODE='23514'; END IF;
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
 AND a.intent->'Actor'=actor AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') AND a.intent->>'InputFormat'='context-query-input/v1'
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
 AND a.intent->>'Name'=call->>'Tool' AND a.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result')
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
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+(CASE WHEN NEW.intent->>'Name' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result','prepare_artifact_download','get_artifact_download') THEN interval '20 seconds' WHEN NEW.intent->>'Name' IN ('request_capture','preview_capture') THEN interval '15 seconds' WHEN NEW.lane='capture' AND NEW.intent->>'Name'='persist_capture_intent' AND EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.id AND public.capture_audit_payload_matches(c,NEW.intent) AND c.group_id IS NOT NULL AND c.group_ordinal IS NOT NULL AND NEW.request_until<=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN interval '15 seconds' ELSE interval '5 seconds' END) OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
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
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
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
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
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
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_units(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s ? 'Comparison' THEN 20 WHEN s->>'NativeType' IN ('httpHeaders','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 2 WHEN s->>'NativeType'='pprof' THEN 10 ELSE 1 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_read_batches(s jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'NativeType' IN ('httpHeaders','pprof','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 1 ELSE 2 END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION context_query_begin_tool(s jsonb) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN s->>'NativeType' IN ('pcapng','rawPcapng') THEN 'get_pcap_summary' WHEN s ? 'Comparison' THEN 'compare_profiles' WHEN s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN CASE s->'Syscalls'->>'View' WHEN 'summary' THEN 'get_syscall_summary' WHEN 'events' THEN 'get_syscall_events' ELSE NULL END WHEN s->>'NativeType'='httpHeaders' THEN 'get_http_headers' WHEN s->>'NativeType'='pprof' THEN 'get_profile_summary' ELSE 'get_file_excerpt' END
$$;
-- +goose StatementEnd
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
ALTER TABLE access_grant DROP CONSTRAINT access_grant_followup_operations, DROP CONSTRAINT access_grant_scope_kind;
ALTER TABLE access_grant ADD CONSTRAINT access_grant_scope_kind CHECK ((CASE WHEN kind='rawQuery' THEN (kind='rawQuery' AND requester_kind='human' AND request_operation='requestRawAccess'
 AND requester_key IS NOT NULL AND octet_length(requester_key)=32
 AND requester_key=sha256(int4send(octet_length(convert_to(requester_issuer,'UTF8'))) || convert_to(requester_issuer,'UTF8') || int4send(octet_length(convert_to(requester_subject,'UTF8'))) || convert_to(requester_subject,'UTF8') || int4send(octet_length(convert_to(requester_client,'UTF8'))) || convert_to(requester_client,'UTF8') || int4send(5) || convert_to('human','UTF8'))
 AND preview_id IS NULL AND capture_id IS NULL AND cluster_id IS NULL AND namespace_uid IS NULL AND workload_uid IS NULL AND pod_uid IS NULL
 AND policy_uid IS NULL AND policy_acceptance_id IS NULL AND policy_scope IS NULL AND policy_not_after IS NULL
 AND policy_executions_spent=0 AND policy_bytes_spent=0 AND policy_observed_bytes_spent=0 AND policy_observed_events_spent=0
 AND data_class='raw' AND lifetime_seconds BETWEEN 1 AND 28800
 AND result_access IS NULL AND result_access_digest IS NULL AND not_after IS NOT NULL
 AND jsonb_typeof(raw_query)='object'
 AND convert_from(scope,'UTF8')::jsonb=jsonb_build_object('Version','raw-query/v1','Scope',raw_query)
 AND jsonb_typeof(raw_query->'Artifacts')='array' AND jsonb_array_length(raw_query->'Artifacts') BETWEEN 1 AND 64
 AND raw_query->'Operations'='["download_artifact"]'::jsonb
 AND max_artifacts=jsonb_array_length(raw_query->'Artifacts')
 AND max_bytes=(raw_query->>'MaxBytes')::bigint AND max_bytes BETWEEN 1 AND 1099511627776
 AND max_operations=(raw_query->>'MaxOperations')::bigint AND max_operations BETWEEN 1 AND 10000
 AND not_after=(raw_query->>'NotAfter')::timestamptz) ELSE (raw_query IS NULL AND cluster_id IS NOT NULL AND namespace_uid IS NOT NULL AND workload_uid IS NOT NULL AND ((
 (kind='adHocCapture' AND requester_kind='human' AND request_operation='requestGrant' AND requester_key IS NULL
  AND preview_id IS NOT NULL AND capture_id IS NOT NULL AND pod_uid IS NOT NULL
  AND policy_uid IS NULL AND policy_acceptance_id IS NULL AND policy_scope IS NULL AND policy_not_after IS NULL
  AND lifetime_seconds BETWEEN 60 AND 28800
  AND policy_executions_spent=0 AND policy_bytes_spent=0 AND policy_observed_bytes_spent=0)
 OR
 (kind='policy' AND request_operation='requestPolicyGrant'
  AND requester_key IS NOT NULL AND octet_length(requester_key)=32
  AND requester_key=sha256(int4send(octet_length(convert_to(requester_issuer,'UTF8'))) || convert_to(requester_issuer,'UTF8') || int4send(octet_length(convert_to(requester_subject,'UTF8'))) || convert_to(requester_subject,'UTF8') || int4send(octet_length(convert_to(requester_client,'UTF8'))) || convert_to(requester_client,'UTF8') || int4send(octet_length(convert_to(requester_kind,'UTF8'))) || convert_to(requester_kind,'UTF8'))
  AND preview_id IS NULL AND capture_id IS NULL AND pod_uid IS NULL
  AND policy_uid IS NOT NULL AND octet_length(policy_uid) BETWEEN 1 AND 64
  AND policy_acceptance_id IS NOT NULL AND policy_scope IS NOT NULL
  AND jsonb_typeof(policy_scope)='object' AND octet_length(policy_scope::text)<=65536
  AND policy_scope ?& ARRAY['Authority','Limits','ApprovalPolicyRef','ApprovalMaxAge','RecipeDigest']
  AND policy_scope#>>'{Authority,PolicyUID}'=policy_uid
  AND policy_scope#>>'{Authority,ClusterID}'=cluster_id::text
  AND policy_scope#>>'{Authority,NamespaceUID}'=namespace_uid
  AND policy_scope#>>'{Authority,WorkloadUID}'=workload_uid
  AND lifetime_seconds BETWEEN 1 AND 31536000
  AND (policy_scope->>'ApprovalMaxAge')::bigint BETWEEN lifetime_seconds::bigint*1000000000 AND 31536000000000000
  AND policy_not_after IS NOT NULL AND policy_not_after>requested_at
  AND policy_not_after<=requested_at+make_interval(secs=>lifetime_seconds)
  AND policy_not_after<=(policy_scope#>>'{Authority,NotAfter}')::timestamptz
  AND result_access IS NULL AND result_access_digest IS NULL AND not_after IS NULL
  AND max_artifacts=0 AND max_bytes=0 AND max_operations=0
  AND artifacts_spent=0 AND bytes_spent=0 AND operations_spent=0
  AND policy_max_executions IS NOT NULL AND policy_max_executions>0
  AND policy_max_bytes IS NOT NULL AND policy_max_bytes>0
  AND policy_max_observed_bytes IS NOT NULL AND policy_max_observed_bytes>=0)
) IS TRUE)) END) IS TRUE);
ALTER TABLE access_grant_use DROP CONSTRAINT access_grant_use_operation_check;
ALTER TABLE access_grant_use ADD CONSTRAINT access_grant_use_operation_check CHECK(operation='download_artifact');
DROP INDEX context_query_invocation;
ALTER TABLE context_query DROP CONSTRAINT context_query_invocation_pair, DROP COLUMN invocation_key, DROP COLUMN request_digest;
DROP FUNCTION context_packet_query_grant_current(uuid,uuid,uuid),context_packet_query_scope_grant_current(uuid,jsonb,jsonb,jsonb),context_packet_query_window_valid(jsonb,text),context_packet_query_uuid(text);
