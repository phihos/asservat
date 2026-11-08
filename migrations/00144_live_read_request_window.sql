-- +goose Up
-- Live views read approved extracts: each read holds two authority checks
-- around a bounded node wait, measured at four to six seconds installed.
-- Give the five live operations the existing 20 s evidence read window.
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
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+(CASE WHEN NEW.intent->>'Name' IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','get_file_excerpt','get_target_discovery','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result','prepare_artifact_download','get_artifact_download') THEN interval '20 seconds' WHEN NEW.intent->>'Name' IN ('request_capture','preview_capture') THEN interval '15 seconds' WHEN NEW.lane='capture' AND NEW.intent->>'Name'='persist_capture_intent' AND EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.id AND public.capture_audit_payload_matches(c,NEW.intent) AND c.group_id IS NOT NULL AND c.group_ordinal IS NOT NULL AND NEW.request_until<=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN interval '15 seconds' ELSE interval '5 seconds' END) OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
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

-- +goose Down
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
