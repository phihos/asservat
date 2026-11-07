-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_target_discovery','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_human_input_valid(operation_name text,input_format text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('get_file_excerpt','get_target_discovery','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result') THEN input_format='context-query-input/v1'
 WHEN operation_name='download_artifact_content' THEN input_format='native-content-input/v1'
 WHEN operation_name='persist_capture_intent' THEN input_format IN ('capture-intent/v2','capture-intent-reason/v1')
 WHEN operation_name IN ('initialize_processing','restrict_processing','release_processing') THEN input_format='processing-input/v1'
 WHEN operation_name IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile') THEN input_format IN ('context-input/v1','invalid-input/v1') ELSE false END
$$;
-- +goose StatementEnd
-- Provisional until rebased onto the final process142 baseline. These rows
-- contain only numeric budgets, approved digests, owner fences and controls.
CREATE TABLE live_watch_root (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id),
 installation_id uuid NOT NULL UNIQUE REFERENCES fleet_trust(installation_id),
 issuer_epoch uuid NOT NULL,
 limits_digest bytea NOT NULL CHECK(octet_length(limits_digest)=32),
 limits jsonb NOT NULL CHECK(jsonb_typeof(limits)='object' AND octet_length(limits::text)<=4096)
);
CREATE TABLE live_watch_account (
 root_id uuid NOT NULL REFERENCES live_watch_root(root_id),
 kind text NOT NULL CHECK(kind IN ('installation','principal','workload')),
 account_key bytea NOT NULL CHECK(octet_length(account_key)=32),
 tokens_micro bigint NOT NULL CHECK(tokens_micro>=0),
 refilled_at timestamptz NOT NULL CHECK(isfinite(refilled_at)),
 PRIMARY KEY(root_id,kind,account_key)
);
CREATE TABLE live_watch_control (
 root_id uuid NOT NULL REFERENCES live_watch_root(root_id), id uuid PRIMARY KEY,
 owner_id uuid NOT NULL, fence uuid NOT NULL,
 principal_key bytea NOT NULL CHECK(octet_length(principal_key)=32),
 workload_key bytea NOT NULL CHECK(octet_length(workload_key)=32),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 key_hash bytea NOT NULL CHECK(octet_length(key_hash)=32),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000000),
 state text NOT NULL CHECK(state IN ('Active','Paused','Closed','Expired','AccessLost','Exhausted','Disconnected','SourceEnded')),
 accepted_at timestamptz NOT NULL CHECK(isfinite(accepted_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>accepted_at AND expires_at<=accepted_at+interval '1 hour'),
 idle_until timestamptz NOT NULL CHECK(isfinite(idle_until) AND idle_until>accepted_at AND idle_until<=expires_at),
 output_limit bigint NOT NULL CHECK(output_limit BETWEEN 1 AND 67108864),
 spent bigint NOT NULL CHECK(spent BETWEEN 0 AND output_limit),
 bytes_per_second bigint NOT NULL CHECK(bytes_per_second BETWEEN 1 AND 262144),
 tokens_micro bigint NOT NULL CHECK(tokens_micro>=0),
 refilled_at timestamptz NOT NULL CHECK(isfinite(refilled_at)),
 UNIQUE(root_id,key_hash)
);
CREATE INDEX live_watch_principal ON live_watch_control(root_id,principal_key);
CREATE INDEX live_watch_workload ON live_watch_control(root_id,workload_key);
CREATE INDEX live_watch_expiry ON live_watch_control(root_id,expires_at);

-- +goose StatementBegin
CREATE FUNCTION live_watch_refilled(t bigint,a timestamptz,n timestamptz,rate bigint,burst bigint) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT least(burst::numeric*1000000,t::numeric+greatest(0,floor(extract(epoch FROM n-a)*1000000))*rate::numeric)::bigint
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION live_watch_digest(v jsonb) RETURNS bytea LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE i integer;out bytea:=decode(repeat('00',32),'hex');
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'array' OR jsonb_array_length(v)<>32 THEN RAISE EXCEPTION 'invalid live digest' USING ERRCODE='23514'; END IF;
 FOR i IN 0..31 LOOP
  IF NOT public.capacity_json_integer(v->i,0,255) THEN RAISE EXCEPTION 'invalid live digest' USING ERRCODE='23514'; END IF;
  out:=set_byte(out,i,(v->>i)::integer);
 END LOOP;
 RETURN out;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION live_watch_value(w public.live_watch_control) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('ID',w.id,'OwnerID',w.owner_id,'Fence',w.fence,
 'PrincipalKey',to_jsonb(ARRAY(SELECT get_byte(w.principal_key,g.idx) FROM generate_series(0,31) AS g(idx))),
 'WorkloadKey',to_jsonb(ARRAY(SELECT get_byte(w.workload_key,g.idx) FROM generate_series(0,31) AS g(idx))),
 'RequestDigest',to_jsonb(ARRAY(SELECT get_byte(w.request_digest,g.idx) FROM generate_series(0,31) AS g(idx))),
 'Revision',w.revision,'State',w.state,'AcceptedAt',w.accepted_at,'ExpiresAt',w.expires_at,'IdleUntil',w.idle_until,
 'OutputLimit',w.output_limit,'Spent',w.spent,'BytesPerSecond',w.bytes_per_second)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION live_watch_matches(w public.live_watch_control,c jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE((public.live_watch_value(w)-ARRAY['AcceptedAt','ExpiresAt','IdleUntil'])=(c-ARRAY['AcceptedAt','ExpiresAt','IdleUntil']) AND
 w.accepted_at=(c->>'AcceptedAt')::timestamptz AND w.expires_at=(c->>'ExpiresAt')::timestamptz AND w.idle_until=(c->>'IdleUntil')::timestamptz,false)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION live_watch_configure(r uuid,i uuid,e uuid,d bytea,l jsonb) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.live_watch_root; k text;
BEGIN
 IF octet_length(d)<>32 OR NOT public.capacity_json_fields(l,ARRAY['InstallationSlots','PrincipalSlots','WorkloadSlots','MemoryBytes','InstallationRate','InstallationBurst','PrincipalRate','PrincipalBurst','WorkloadRate','WorkloadBurst','WatchBurst','MaxOutputBytes','MaxRate','MaxDurationSeconds','MaxAccounts','MaxControlRecords']) THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['InstallationSlots','PrincipalSlots','WorkloadSlots'] LOOP IF NOT public.capacity_json_integer(l->k,1,4096) THEN RETURN false; END IF; END LOOP;
 FOREACH k IN ARRAY ARRAY['InstallationRate','PrincipalRate','WorkloadRate'] LOOP IF NOT public.capacity_json_integer(l->k,1,268435456) THEN RETURN false; END IF; END LOOP;
 FOREACH k IN ARRAY ARRAY['InstallationBurst','PrincipalBurst','WorkloadBurst'] LOOP IF NOT public.capacity_json_integer(l->k,24576,1073741824) THEN RETURN false; END IF; END LOOP;
 IF NOT public.capacity_json_integer(l->'MemoryBytes',1048576,4294967296) OR NOT public.capacity_json_integer(l->'WatchBurst',24576,1048576) OR NOT public.capacity_json_integer(l->'MaxOutputBytes',24576,67108864) OR NOT public.capacity_json_integer(l->'MaxRate',1,262144) OR NOT public.capacity_json_integer(l->'MaxDurationSeconds',1,3600) OR NOT public.capacity_json_integer(l->'MaxAccounts',3,1048576) OR NOT public.capacity_json_integer(l->'MaxControlRecords',1,1048576) OR
 (l->>'PrincipalSlots')::bigint>(l->>'InstallationSlots')::bigint OR (l->>'WorkloadSlots')::bigint>(l->>'InstallationSlots')::bigint OR (l->>'MemoryBytes')::bigint<(l->>'InstallationSlots')::bigint*1048576 OR (l->>'MaxControlRecords')::bigint<(l->>'InstallationSlots')::bigint THEN RETURN false; END IF;
 INSERT INTO public.live_watch_root(root_id,installation_id,issuer_epoch,limits_digest,limits) VALUES(r,i,e,d,l) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=i AND issuer_epoch=e AND NOT suspended AND NOT recovery_blocked AND observed_at<=clock_timestamp() AND clock_timestamp()<fresh_until) THEN RETURN false; END IF;
 IF p.installation_id<>i THEN RETURN false; END IF;
 IF p.issuer_epoch=e AND p.limits_digest=d AND p.limits=l THEN RETURN true; END IF;
 -- Issuer advancement is independently current fleet authority, not a reason
 -- to reset limits or shared debt. Numeric replacement waits for all original
 -- receipts and fully refilled accounts to be removed by bounded pruning.
 IF p.limits_digest<>d OR p.limits<>l THEN
  PERFORM public.live_watch_prune(r);
  IF EXISTS(SELECT 1 FROM public.live_watch_control WHERE root_id=r) OR EXISTS(SELECT 1 FROM public.live_watch_account WHERE root_id=r) THEN RETURN false; END IF;
 END IF;
 UPDATE public.live_watch_root SET issuer_epoch=e,limits_digest=d,limits=l WHERE root_id=r;
 RETURN true;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION live_watch_prune(r uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.live_watch_root;n timestamptz;controls bigint;accounts bigint;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 -- Each bounded candidate set is materialized once; DELETE must not rescan a
 -- volatile limited subquery and exceed its stated cap.
 WITH candidates AS MATERIALIZED(SELECT id FROM public.live_watch_control WHERE root_id=r AND expires_at<=n ORDER BY expires_at,id LIMIT 64 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.live_watch_control w USING candidates c WHERE w.id=c.id;
 GET DIAGNOSTICS controls=ROW_COUNT;
 WITH candidates AS MATERIALIZED(SELECT a.kind,a.account_key FROM public.live_watch_account a WHERE a.root_id=r AND a.refilled_at<=n AND
 public.live_watch_refilled(a.tokens_micro,a.refilled_at,n,(p.limits->>(CASE a.kind WHEN 'installation' THEN 'InstallationRate' WHEN 'principal' THEN 'PrincipalRate' ELSE 'WorkloadRate' END))::bigint,(p.limits->>(CASE a.kind WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint)=(p.limits->>(CASE a.kind WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint*1000000 AND
 NOT EXISTS(SELECT 1 FROM public.live_watch_control w WHERE w.root_id=r AND (a.kind='installation' OR a.kind='principal' AND w.principal_key=a.account_key OR a.kind='workload' AND w.workload_key=a.account_key)) ORDER BY a.kind,a.account_key LIMIT 64 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.live_watch_account a USING candidates c WHERE a.root_id=r AND a.kind=c.kind AND a.account_key=c.account_key;
 GET DIAGNOSTICS accounts=ROW_COUNT;
 RETURN jsonb_build_object('controls',controls,'accounts',accounts);
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION live_watch_create(r uuid,o uuid,d bytea,c jsonb,key bytea,bound timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.live_watch_root; w public.live_watch_control; n timestamptz; counts record; k text; a bytea; burst bigint; initial_key bytea;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF o IS NULL OR d IS NULL OR key IS NULL OR bound IS NULL OR NOT isfinite(bound) OR n>=bound OR p.limits_digest<>d OR octet_length(key)<>32 OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=p.installation_id AND issuer_epoch=p.issuer_epoch AND NOT suspended AND NOT recovery_blocked AND observed_at<=n AND n<fresh_until) THEN RAISE EXCEPTION 'live owner or limits unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO w FROM public.live_watch_control WHERE root_id=r AND key_hash=key;
 IF FOUND THEN
  IF w.principal_key<>public.live_watch_digest(c->'PrincipalKey') OR w.request_digest<>public.live_watch_digest(c->'RequestDigest') THEN RAISE EXCEPTION 'live request conflict' USING ERRCODE='23505'; END IF;
  IF w.owner_id<>o THEN RAISE EXCEPTION 'live owner unavailable' USING ERRCODE='23514'; END IF;
  RETURN jsonb_build_object('control',public.live_watch_value(w),'reused',true);
 END IF;
 PERFORM public.live_watch_prune(r);
 IF NOT public.capacity_json_fields(c,ARRAY['ID','OwnerID','Fence','PrincipalKey','WorkloadKey','RequestDigest','Revision','State','AcceptedAt','ExpiresAt','IdleUntil','OutputLimit','Spent','BytesPerSecond']) OR (c->>'OwnerID')::uuid<>o OR (c->>'Revision')::bigint<>1 OR c->>'State'<>'Active' OR (c->>'Spent')::bigint<>0 OR
 (c->>'AcceptedAt')::timestamptz>n OR (c->>'AcceptedAt')::timestamptz<n-interval '5 seconds' OR (c->>'ExpiresAt')::timestamptz<=n OR (c->>'ExpiresAt')::timestamptz>(c->>'AcceptedAt')::timestamptz+make_interval(secs=>(p.limits->>'MaxDurationSeconds')::integer) OR (c->>'IdleUntil')::timestamptz<=n OR (c->>'IdleUntil')::timestamptz>(c->>'AcceptedAt')::timestamptz+interval '30 seconds' OR (c->>'OutputLimit')::bigint>(p.limits->>'MaxOutputBytes')::bigint OR (c->>'BytesPerSecond')::bigint>(p.limits->>'MaxRate')::bigint THEN RAISE EXCEPTION 'invalid initial live control' USING ERRCODE='23514'; END IF;
 SELECT count(*) AS total,count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until) AS active,
 count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until AND principal_key=public.live_watch_digest(c->'PrincipalKey')) AS principal,
 count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until AND workload_key=public.live_watch_digest(c->'WorkloadKey')) AS workload INTO counts FROM public.live_watch_control WHERE root_id=r;
 IF counts.total>=(p.limits->>'MaxControlRecords')::bigint OR counts.active>=(p.limits->>'InstallationSlots')::bigint OR counts.principal>=(p.limits->>'PrincipalSlots')::bigint OR counts.workload>=(p.limits->>'WorkloadSlots')::bigint THEN RAISE EXCEPTION 'live capacity unavailable' USING ERRCODE='54000'; END IF;
 initial_key:=decode(replace(r::text,'-','')||repeat('00',16),'hex');
 FOREACH k IN ARRAY ARRAY['installation','principal','workload'] LOOP
  a:=CASE k WHEN 'installation' THEN initial_key WHEN 'principal' THEN public.live_watch_digest(c->'PrincipalKey') ELSE public.live_watch_digest(c->'WorkloadKey') END;
  IF NOT EXISTS(SELECT 1 FROM public.live_watch_account WHERE root_id=r AND kind=k AND account_key=a) THEN
   IF (SELECT count(*) FROM public.live_watch_account WHERE root_id=r)>=(p.limits->>'MaxAccounts')::bigint THEN RAISE EXCEPTION 'live accounts unavailable' USING ERRCODE='54000'; END IF;
   burst:=(p.limits->>(CASE k WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint;
   INSERT INTO public.live_watch_account VALUES(r,k,a,burst*1000000,n);
  END IF;
 END LOOP;
 INSERT INTO public.live_watch_control(root_id,id,owner_id,fence,principal_key,workload_key,request_digest,key_hash,revision,state,accepted_at,expires_at,idle_until,output_limit,spent,bytes_per_second,tokens_micro,refilled_at)
 VALUES(r,(c->>'ID')::uuid,o,(c->>'Fence')::uuid,public.live_watch_digest(c->'PrincipalKey'),public.live_watch_digest(c->'WorkloadKey'),public.live_watch_digest(c->'RequestDigest'),key,1,'Active',(c->>'AcceptedAt')::timestamptz,(c->>'ExpiresAt')::timestamptz,(c->>'IdleUntil')::timestamptz,(c->>'OutputLimit')::bigint,0,(c->>'BytesPerSecond')::bigint,(p.limits->>'WatchBurst')::bigint*1000000,n) RETURNING * INTO w;
 RETURN jsonb_build_object('control',public.live_watch_value(w),'reused',false);
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION live_watch_change(r uuid,o uuid,d bytea,c jsonb,expected bigint,cost bigint,bound timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.live_watch_root; w public.live_watch_control; n timestamptz; k text; a bytea; bucket public.live_watch_account; rate bigint;burst bigint;available bigint;oldjson jsonb;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT w FROM public.live_watch_control WHERE root_id=r AND id=(c->>'ID')::uuid FOR UPDATE;
 n:=clock_timestamp();oldjson:=public.live_watch_value(w);
 IF o IS NULL OR d IS NULL OR expected IS NULL OR cost IS NULL OR bound IS NULL OR NOT isfinite(bound) OR w.owner_id<>o OR p.limits_digest<>d OR w.revision<>expected OR cost<0 OR cost>24576 OR NOT public.capacity_json_fields(c,ARRAY['ID','OwnerID','Fence','PrincipalKey','WorkloadKey','RequestDigest','Revision','State','AcceptedAt','ExpiresAt','IdleUntil','OutputLimit','Spent','BytesPerSecond']) OR
 (oldjson-ARRAY['Revision','State','Spent','IdleUntil','AcceptedAt','ExpiresAt']) IS DISTINCT FROM (c-ARRAY['Revision','State','Spent','IdleUntil','AcceptedAt','ExpiresAt']) OR w.accepted_at IS DISTINCT FROM (c->>'AcceptedAt')::timestamptz OR w.expires_at IS DISTINCT FROM (c->>'ExpiresAt')::timestamptz OR (c->>'Spent')::bigint<>w.spent+cost OR (c->>'Revision')::bigint NOT IN (w.revision,w.revision+1) OR
 ((c->>'Revision')::bigint=w.revision AND (cost=0 OR c->>'State'<>w.state AND NOT(w.state IN ('Active','Paused','Disconnected') AND c->>'State' IN ('Disconnected','SourceEnded')))) OR ((c->>'Revision')::bigint=w.revision+1 AND cost<>0) OR
 (w.state NOT IN ('Active','Paused','Disconnected') AND (c->>'State'<>w.state OR cost<>0)) OR (c->>'IdleUntil')::timestamptz>w.expires_at OR (c->>'IdleUntil')::timestamptz>n+interval '30 seconds' THEN RAISE EXCEPTION 'live revision or control conflict' USING ERRCODE='23505'; END IF;
 IF c->>'State'<>'Closed' AND (n>=bound OR n>=w.expires_at OR n>=w.idle_until OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=p.installation_id AND issuer_epoch=p.issuer_epoch AND NOT suspended AND NOT recovery_blocked AND observed_at<=n AND n<fresh_until)) THEN RAISE EXCEPTION 'live owner or original bound unavailable' USING ERRCODE='23514'; END IF;
 IF c->>'State'='Closed' AND ((c->>'IdleUntil')::timestamptz<>w.idle_until OR cost<>0) THEN RAISE EXCEPTION 'live close cannot renew or disclose' USING ERRCODE='23514'; END IF;
 IF cost>0 THEN
  IF n<w.refilled_at THEN RAISE EXCEPTION 'live clock unavailable' USING ERRCODE='23514'; END IF;
  available:=public.live_watch_refilled(w.tokens_micro,w.refilled_at,n,w.bytes_per_second,(p.limits->>'WatchBurst')::bigint);
  IF available<cost*1000000 THEN RAISE EXCEPTION 'live watch rate unavailable' USING ERRCODE='54000'; END IF;
  w.tokens_micro:=available-cost*1000000;w.refilled_at:=n;
  FOREACH k IN ARRAY ARRAY['installation','principal','workload'] LOOP
   a:=CASE k WHEN 'installation' THEN decode(replace(r::text,'-','')||repeat('00',16),'hex') WHEN 'principal' THEN w.principal_key ELSE w.workload_key END;
   SELECT * INTO STRICT bucket FROM public.live_watch_account WHERE root_id=r AND kind=k AND account_key=a FOR UPDATE;
   rate:=(p.limits->>(CASE k WHEN 'installation' THEN 'InstallationRate' WHEN 'principal' THEN 'PrincipalRate' ELSE 'WorkloadRate' END))::bigint;
   burst:=(p.limits->>(CASE k WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint;
   IF n<bucket.refilled_at THEN RAISE EXCEPTION 'live clock unavailable' USING ERRCODE='23514'; END IF;
   available:=public.live_watch_refilled(bucket.tokens_micro,bucket.refilled_at,n,rate,burst);
   IF available<cost*1000000 THEN RAISE EXCEPTION 'live aggregate rate unavailable' USING ERRCODE='54000'; END IF;
   UPDATE public.live_watch_account SET tokens_micro=available-cost*1000000,refilled_at=n WHERE root_id=r AND kind=k AND account_key=a;
  END LOOP;
 END IF;
 UPDATE public.live_watch_control SET revision=(c->>'Revision')::bigint,state=c->>'State',spent=(c->>'Spent')::bigint,idle_until=(c->>'IdleUntil')::timestamptz,tokens_micro=w.tokens_micro,refilled_at=w.refilled_at WHERE id=w.id RETURNING * INTO w;
 RETURN public.live_watch_value(w);
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION live_watch_current(r uuid,o uuid,d bytea,c jsonb,bound timestamptz) RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.live_watch_control w JOIN public.live_watch_root p ON p.root_id=w.root_id JOIN public.fleet_current_trust t ON t.installation_id=p.installation_id AND t.issuer_epoch=p.issuer_epoch
 WHERE w.root_id=r AND w.id=(c->>'ID')::uuid AND w.owner_id=o AND p.limits_digest=d AND w.state IN ('Active','Paused','Disconnected','Closed') AND public.live_watch_matches(w,c) AND clock_timestamp()<w.expires_at AND clock_timestamp()<w.idle_until AND clock_timestamp()<bound AND NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until),false)
$$;
-- +goose StatementEnd
-- Routing is only a locator. The exact receiving owner still checks its
-- original in-memory actor/client before any source or disclosure operation.
-- +goose StatementBegin
CREATE FUNCTION live_watch_owner(r uuid,p bytea,i uuid,k bytea)
RETURNS TABLE(installation_id uuid,cluster_id uuid,issuer_epoch uuid,pod_uid uuid,process_epoch uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w public.live_watch_control;n timestamptz:=clock_timestamp();found_owners bigint;
BEGIN
 IF octet_length(p)<>32 OR (i IS NULL)=(k IS NULL) OR (k IS NOT NULL AND octet_length(k)<>32) THEN
  RAISE EXCEPTION 'live owner locator invalid' USING ERRCODE='22023';
 END IF;
 IF i IS NOT NULL THEN
  SELECT c.* INTO w FROM public.live_watch_control c WHERE c.root_id=r AND c.principal_key=p AND c.id=i;
 ELSE
  SELECT c.* INTO w FROM public.live_watch_control c WHERE c.root_id=r AND c.principal_key=p AND c.key_hash=k;
 END IF;
 IF NOT FOUND THEN RETURN; END IF;
 -- A retained closed receipt is routable until its original end; an expired
 -- or unavailable owner never becomes an absent key eligible for local Open.
 IF n>=w.expires_at OR n>=w.idle_until THEN
  RAISE EXCEPTION 'live owner unavailable' USING ERRCODE='55000';
 END IF;
 RETURN QUERY SELECT e.installation_id,e.cluster_id,e.issuer_epoch,e.pod_uid,e.process_epoch
 FROM public.live_watch_root b JOIN public.fleet_current_trust t ON t.installation_id=b.installation_id AND t.issuer_epoch=b.issuer_epoch
 JOIN public.hub_owner_enrollment e ON e.installation_id=b.installation_id AND e.issuer_epoch=b.issuer_epoch AND e.process_epoch=w.owner_id AND e.usage='server'
 WHERE b.root_id=r AND NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=n AND n<t.fresh_until
 AND e.audit_receipt_json IS NOT NULL AND e.retired_at IS NULL AND n<e.hold_until
 AND EXISTS(SELECT 1 FROM public.hub_owner_certificate a WHERE a.enrollment_id=e.id AND a.activated_at IS NOT NULL AND n<a.not_after)
 LIMIT 2;
 GET DIAGNOSTICS found_owners=ROW_COUNT;
 IF found_owners<>1 THEN RAISE EXCEPTION 'live owner unavailable' USING ERRCODE='55000'; END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON live_watch_root,live_watch_account,live_watch_control FROM PUBLIC;
REVOKE ALL ON FUNCTION live_watch_owner(uuid,bytea,uuid,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION live_watch_refilled(bigint,timestamptz,timestamptz,bigint,bigint),live_watch_digest(jsonb),live_watch_value(live_watch_control),live_watch_matches(live_watch_control,jsonb),live_watch_configure(uuid,uuid,uuid,bytea,jsonb),live_watch_prune(uuid),live_watch_create(uuid,uuid,bytea,jsonb,bytea,timestamptz),live_watch_change(uuid,uuid,bytea,jsonb,bigint,bigint,timestamptz),live_watch_current(uuid,uuid,bytea,jsonb,timestamptz) FROM PUBLIC;


-- Retained HTTP snapshots are approved extracts, not packet metadata.
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
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pcapng','syscallRecords') AND jsonb_typeof(e->'Snapshot')='object' AND NOT(e#>'{Snapshot}' ? 'HTTP') AND (NOT e ? 'Recording' OR e->'Recording'='null'::jsonb) OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='httpHeaders' AND e->>'DataClass'='extract' AND jsonb_typeof(e->'Snapshot')='object' AND NOT(e ? 'Recording') AND
    public.capacity_json_fields(e#>'{Snapshot,HTTP}',ARRAY['MaxFlows','MaxHeaderBytes','MaxFlowBytes','MaxTotalBytes','IdleMillis']) AND
    public.capacity_json_integer(e#>'{Snapshot,HTTP,MaxFlows}',1,1024) AND public.capacity_json_integer(e#>'{Snapshot,HTTP,MaxHeaderBytes}',1,32768) AND
    public.capacity_json_integer(e#>'{Snapshot,HTTP,MaxFlowBytes}',1,262144) AND public.capacity_json_integer(e#>'{Snapshot,HTTP,MaxTotalBytes}',1,16777216) AND
    (e#>>'{Snapshot,HTTP,MaxTotalBytes}')::bigint>=(e#>>'{Snapshot,HTTP,MaxFlowBytes}')::bigint AND public.capacity_json_integer(e#>'{Snapshot,HTTP,IdleMillis}',1000,30000) AND
    (CASE WHEN e#>>'{SourceSnapshotManifest,binding}'~'^[A-Za-z0-9+/]+={0,2}$' THEN convert_from(decode(e#>>'{SourceSnapshotManifest,binding}','base64'),'UTF8')::jsonb->>'ObservationGrantID' END)~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false) OR NOT COALESCE(e->>'DataClass'='metadata' AND e->>'NativeType' IS DISTINCT FROM 'logs' AND e->>'NativeType' IS DISTINCT FROM 'rawPcapng' AND e->>'NativeType' IS DISTINCT FROM 'httpHeaders' AND e->>'NativeType' IS DISTINCT FROM 'pprof' AND e->>'NativeType' IS DISTINCT FROM 'goTrace' AND e->>'NativeType' IS DISTINCT FROM 'syscallArguments' OR e->>'DataClass'='raw' AND e->>'NativeType' IN ('rawPcapng','pprof','goTrace','syscallArguments','logs') OR e->>'DataClass'='extract' AND e->>'NativeType'='httpHeaders',false) OR
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
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.policy_recording_source WHERE binding_json->>'ObservationGrantID' IS NOT NULL) OR EXISTS(SELECT 1 FROM public.context_capture WHERE convert_from(expectation_json,'UTF8')::jsonb#>'{Snapshot,HTTP}' IS NOT NULL) OR EXISTS(SELECT 1 FROM live_watch_control) OR EXISTS(SELECT 1 FROM live_watch_account) OR EXISTS(SELECT 1 FROM public.operation_audit WHERE intent->>'Name' IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch')) THEN RAISE EXCEPTION 'retained live controls or charges prevent rollback' USING ERRCODE='23514'; END IF;
END $$;
-- +goose StatementEnd
DROP FUNCTION live_watch_owner(uuid,bytea,uuid,bytea),live_watch_prune(uuid),live_watch_current(uuid,uuid,bytea,jsonb,timestamptz),live_watch_change(uuid,uuid,bytea,jsonb,bigint,bigint,timestamptz),live_watch_create(uuid,uuid,bytea,jsonb,bytea,timestamptz),live_watch_configure(uuid,uuid,uuid,bytea,jsonb),live_watch_matches(live_watch_control,jsonb),live_watch_value(live_watch_control),live_watch_digest(jsonb),live_watch_refilled(bigint,timestamptz,timestamptz,bigint,bigint);
DROP TABLE live_watch_control,live_watch_account,live_watch_root;

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
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_target_discovery','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
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
