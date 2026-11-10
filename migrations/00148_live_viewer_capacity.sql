-- +goose Up
ALTER TABLE live_watch_control ADD COLUMN cluster_key bytea CHECK(octet_length(cluster_key)=32);

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

-- The original six-argument writer remains for rolling upgrades. Its unmapped
-- rows make the per-cluster aggregate unavailable rather than invent a target.
-- +goose StatementBegin
CREATE FUNCTION live_watch_create_cluster(r uuid,o uuid,d bytea,c jsonb,key bytea,bound timestamptz,k bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.live_watch_root; w public.live_watch_control; n timestamptz; counts record; knd text; a bytea; burst bigint; initial_key bytea;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF o IS NULL OR d IS NULL OR key IS NULL OR bound IS NULL OR NOT isfinite(bound) OR n>=bound OR p.limits_digest<>d OR octet_length(key)<>32 OR octet_length(k)<>32 OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=p.installation_id AND issuer_epoch=p.issuer_epoch AND NOT suspended AND NOT recovery_blocked AND observed_at<=n AND n<fresh_until) THEN RAISE EXCEPTION 'live owner or limits unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO w FROM public.live_watch_control WHERE root_id=r AND key_hash=key;
 IF FOUND THEN
  IF w.principal_key<>public.live_watch_digest(c->'PrincipalKey') OR w.request_digest<>public.live_watch_digest(c->'RequestDigest') THEN RAISE EXCEPTION 'live request conflict' USING ERRCODE='23505'; END IF;
  IF w.owner_id<>o OR w.cluster_key IS DISTINCT FROM k THEN RAISE EXCEPTION 'live owner unavailable' USING ERRCODE='23514'; END IF;
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
 FOREACH knd IN ARRAY ARRAY['installation','principal','workload'] LOOP
  a:=CASE knd WHEN 'installation' THEN initial_key WHEN 'principal' THEN public.live_watch_digest(c->'PrincipalKey') ELSE public.live_watch_digest(c->'WorkloadKey') END;
  IF NOT EXISTS(SELECT 1 FROM public.live_watch_account WHERE root_id=r AND kind=knd AND account_key=a) THEN
   IF (SELECT count(*) FROM public.live_watch_account WHERE root_id=r)>=(p.limits->>'MaxAccounts')::bigint THEN RAISE EXCEPTION 'live accounts unavailable' USING ERRCODE='54000'; END IF;
   burst:=(p.limits->>(CASE knd WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint;
   INSERT INTO public.live_watch_account VALUES(r,knd,a,burst*1000000,n);
  END IF;
 END LOOP;
 INSERT INTO public.live_watch_control(root_id,id,owner_id,fence,principal_key,workload_key,request_digest,key_hash,revision,state,accepted_at,expires_at,idle_until,output_limit,spent,bytes_per_second,tokens_micro,refilled_at,cluster_key)
 VALUES(r,(c->>'ID')::uuid,o,(c->>'Fence')::uuid,public.live_watch_digest(c->'PrincipalKey'),public.live_watch_digest(c->'WorkloadKey'),public.live_watch_digest(c->'RequestDigest'),key,1,'Active',(c->>'AcceptedAt')::timestamptz,(c->>'ExpiresAt')::timestamptz,(c->>'IdleUntil')::timestamptz,(c->>'OutputLimit')::bigint,0,(c->>'BytesPerSecond')::bigint,(p.limits->>'WatchBurst')::bigint*1000000,n,k) RETURNING * INTO w;
 RETURN jsonb_build_object('control',public.live_watch_value(w),'reused',false);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_create_cluster(uuid,uuid,bytea,jsonb,bytea,timestamptz,bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_viewers(i uuid,k bytea) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF k IS NULL OR octet_length(k)<>32 OR EXISTS(SELECT 1 FROM public.live_watch_control w JOIN public.live_watch_root b ON b.root_id=w.root_id WHERE b.installation_id=i AND w.cluster_key IS NULL AND w.state IN ('Active','Paused','Disconnected') AND clock_timestamp()<w.expires_at AND clock_timestamp()<w.idle_until) THEN
  RAISE EXCEPTION 'live viewer cluster history unavailable' USING ERRCODE='55000';
 END IF;
 RETURN (SELECT count(DISTINCT w.id)
 FROM public.live_watch_control w
 JOIN public.live_watch_root b ON b.root_id=w.root_id
 JOIN public.fleet_current_trust t ON t.installation_id=b.installation_id AND t.issuer_epoch=b.issuer_epoch
 JOIN public.hub_owner_enrollment e ON e.installation_id=b.installation_id AND e.issuer_epoch=b.issuer_epoch AND e.process_epoch=w.owner_id AND e.usage='server'
 WHERE b.installation_id=i AND w.cluster_key=k
 AND NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until
 AND e.audit_receipt_json IS NOT NULL AND e.retired_at IS NULL AND clock_timestamp()<e.hold_until
 AND EXISTS(SELECT 1 FROM public.hub_owner_certificate a WHERE a.enrollment_id=e.id AND a.activated_at IS NOT NULL AND clock_timestamp()<a.not_after)
 AND w.state IN ('Active','Paused','Disconnected')
 AND clock_timestamp()<w.expires_at AND clock_timestamp()<w.idle_until);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_viewers(uuid,bytea) FROM PUBLIC;

-- +goose Down
DROP FUNCTION public.live_watch_viewers(uuid,bytea);
DROP FUNCTION public.live_watch_create_cluster(uuid,uuid,bytea,jsonb,bytea,timestamptz,bytea);
ALTER TABLE live_watch_control DROP COLUMN cluster_key;
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
