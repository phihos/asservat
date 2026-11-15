-- +goose Up
-- ADR-334: connectors authenticate with ServiceAccount tokens. No Go code
-- uses the connector identity lane any more: its tables, views, functions
-- and the 'identity' operation-audit lane are dropped. Unreleased product:
-- existing identity-lane rows are deleted without migration.
DROP TRIGGER aab_connector_reservation_ack ON operation_audit;
DROP TRIGGER connector_reservation_event ON operation_audit;
DROP TRIGGER operation_audit_01_connector_reserve ON operation_audit;
DROP TRIGGER aaa_connector_audit_access ON operation_audit_pool;
DROP TRIGGER aaa_connector_audit_access ON operation_audit_account;
DROP TRIGGER aaa_connector_audit_access ON operation_audit;
DROP TRIGGER aaa_connector_audit_access ON operation_audit_lifecycle;
DROP TRIGGER aaa_connector_audit_access ON operation_audit_history;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE p public.operation_audit_pool; a public.operation_audit_account; n timestamptz;
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
  IF p.paused OR n>=p.valid_until OR n>=NEW.request_until OR n<(NEW.intent->>'CreatedAt')::timestamptz OR NEW.intent_started OR NEW.intent_receipt IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.outcome_started OR NEW.outcome_receipt IS NOT NULL OR
   NOT (NEW.intent ?& ARRAY['ID','RootID','MACVersion','AccountVersion','Name','CreatedAt','RequestUntil','WriteUntil','RetainUntil']) OR public.operation_audit_lane(NEW.intent->>'Name') IS NULL OR NOT public.operation_audit_human_input_valid(NEW.intent->>'Name',NEW.intent->>'InputFormat') OR
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
END $function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION create_operation_audit_lifecycle()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE b jsonb; p jsonb; t public.fleet_current_trust; a public.operation_audit_pool; n timestamptz:=clock_timestamp(); budget interval; horizon interval; proof interval;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid audit lifecycle source' USING ERRCODE='23514'; END IF;
 b:=NEW.intent->'Lifecycle';
 IF b IS NULL THEN RETURN NEW; END IF;
 p:=b->'Policy';
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=(p->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
 n:=clock_timestamp();
 budget:=make_interval(secs=>(p->>'CleanupBudgetSeconds')::double precision);
 horizon:=make_interval(secs=>(p->>'BackupHorizonSeconds')::double precision);
 proof:=make_interval(secs=>(p->>'ProofWindowSeconds')::double precision);
 IF (p ? 'OverdueTerminal' AND p->>'OverdueTerminal' IS DISTINCT FROM 'overdue-original/v1') OR b->>'Protocol' IS DISTINCT FROM 'closed-operation-audit/v1' OR jsonb_typeof(p)<>'object' OR
  NOT(p ?& ARRAY['MaxPurgeLeases','RootID','Lane','InstallationID','StoreID','PolicyID','BackupProfileID','PolicyDigest','BackupProfileDigest','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','ValidUntil']) OR
  (p->>'RootID')::uuid<>NEW.root_id OR p->>'Lane'<>NEW.lane OR (p->>'StoreID')::uuid IS NULL OR (p->>'PolicyID')::uuid IS NULL OR (p->>'BackupProfileID')::uuid IS NULL OR
  jsonb_array_length(p->'PolicyDigest')<>32 OR jsonb_array_length(p->'BackupProfileDigest')<>32 OR
  (p->>'BackingRevision')::bigint<>a.revision OR (p->>'MetadataSlots')::bigint<a.account_limit*a.records_per_account OR (p->>'MetadataSlots')::bigint>1000000000000 OR
  budget<interval '1 second' OR budget>interval '1 day' OR horizon<interval '0 seconds' OR horizon>interval '3660 days' OR proof<interval '1 second' OR proof>interval '3660 days' OR
  (p->>'BackupReservedBytes')::bigint<0 OR (p->>'WALReservedBytes')::bigint<0 OR horizon>interval '0 seconds' AND ((p->>'BackupReservedBytes')::bigint<=0 OR (p->>'WALReservedBytes')::bigint<=0) OR
  n>=(p->>'ValidUntil')::timestamptz OR n>=NEW.request_until OR n>=a.valid_until OR t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR
  (p->>'MaxPurgeLeases')::bigint NOT BETWEEN 2 AND 32 OR
  (b->>'HistoryReleaseAt')::timestamptz<>NEW.retain_until-horizon-budget OR (b->>'HistoryDeleteBy')::timestamptz<>NEW.retain_until-horizon OR
  (b->>'LiveRetireBy')::timestamptz<>NEW.retain_until-2*horizon-budget OR (b->>'CertificatePurgeAt')::timestamptz<>(b->>'LiveRetireBy')::timestamptz-budget OR
  (b->>'OriginalPurgeAt')::timestamptz<>(b->>'CertificatePurgeAt')::timestamptz-proof-budget OR (b->>'OriginalPurgeAt')::timestamptz<=NEW.write_until THEN
  RAISE EXCEPTION 'audit lifecycle backing unavailable' USING ERRCODE='23514'; END IF;
 -- A qualification is an exact accepted layout/profile, with conservative
 -- measured full-transaction bounds. Positive arbitrary byte counts are not a
 -- qualification; source acceptance is deliberately outside this adapter.
 IF p->'History' IS NULL OR NOT public.operation_audit_history_verifier_backed(p->'History'->>'Layout') OR NOT public.operation_audit_history_layout_valid(NEW.lane,p->'History'->>'Layout') OR
   NOT(p->'History' ?& ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
   (p->'History'->>'ID')::uuid IS NULL OR jsonb_array_length(p->'History'->'Digest')<>32 OR
   (p->'History'->>'MaximumRowFootprintBytes')::bigint NOT BETWEEN public.operation_audit_history_minimum_row(p->'History'->>'Layout') AND 16777216 OR
   (p->'History'->>'MaximumTransitionWALBytes')::bigint NOT BETWEEN 131072 AND 67108864 OR
   (p->'History'->>'BackupCopies')::bigint NOT BETWEEN 1 AND 64 OR (p->'History'->>'WALCopies')::bigint NOT BETWEEN 1 AND 64 OR
   (p->>'BackupReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumRowFootprintBytes')::bigint*(p->'History'->>'BackupCopies')::bigint OR
   (p->>'WALReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'WALCopies')::bigint*((p->'History'->>'MaximumTransitionWALBytes')::bigint*(public.operation_audit_history_fixed_transitions(p->'History'->>'Layout')+3*(p->>'MaxPurgeLeases')::bigint)+CASE WHEN p->'History'->>'Layout'='operation-audit-history/v4' THEN 8388608 ELSE 0 END) THEN
   RAISE EXCEPTION 'audit history qualification unavailable' USING ERRCODE='23514'; END IF;

 IF a.history_backing_until IS NOT NULL AND n<a.history_backing_until AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),a.history_profile) THEN
  RAISE EXCEPTION 'residual audit history backing protected' USING ERRCODE='23514'; END IF;
 -- Renewal may refresh a source/revision or increase backing. Outstanding
 -- obligations cannot be moved to a smaller/different backup or account profile.
 IF EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=NEW.root_id AND d.lane=NEW.lane AND
   NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),((d.binding->'Policy') - ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']))) OR
  EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=NEW.root_id AND h.lane=NEW.lane AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),h.history_policy)) THEN
  RAISE EXCEPTION 'outstanding audit history profile mismatch' USING ERRCODE='23514'; END IF;
 IF horizon>interval '0 seconds' THEN
  UPDATE public.operation_audit_pool SET
   history_profile=p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'],
   history_backing_until=GREATEST(history_backing_until,NEW.retain_until)
  WHERE root_id=NEW.root_id AND lane=NEW.lane;
 END IF;
 INSERT INTO public.operation_audit_lifecycle(operation_id,root_id,lane,principal_digest,installation_id,issuer_epoch,postmaster_at,database_oid,binding,original_purge_at,certificate_purge_at,live_retire_by,certificate_verify_attempts)
 VALUES(NEW.id,NEW.root_id,NEW.lane,NEW.principal_digest,t.installation_id,t.issuer_epoch,(SELECT activated_postmaster_at FROM public.fleet_trust WHERE installation_id=t.installation_id),(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),b,(b->>'OriginalPurgeAt')::timestamptz,(b->>'CertificatePurgeAt')::timestamptz,(b->>'LiveRetireBy')::timestamptz,0);
 RETURN NEW;
END $function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text)
 RETURNS text
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
 SELECT CASE WHEN operation_name='persist_capture_intent' THEN 'capture' WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_live_sources','open_live_watch','read_live_watch','update_live_watch','close_live_watch','get_live_capacity','list_diagnostics','list_recordings','preview_recording_save','cancel_capture','preview_capture','request_capture','get_capture','get_case','search_processing_evidence','request_early_erasure','get_processing_erasure','get_processing_report','prepare_artifact_download','get_artifact_download','invalid_operation','download_artifact_content','initialize_processing','restrict_processing','get_file_excerpt','get_target_discovery','get_query_result','activate_policy','get_policy_status','deactivate_policy','create_share','list_shares','revoke_share','explain_access','preview_access_change','list_capture_history','get_capture_settings','transfer_share','stop_future_sharing','preview_retention_change','get_grant','list_reviews','decide_review','revoke_grant','request_policy_grant','request_raw_access','list_capture_profiles','get_capture_profile','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events') THEN 'normal' ELSE NULL END
$function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit_pool()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
 IF TG_OP='INSERT' AND NEW.lane='capture' AND NEW.proof_window_missed=0 AND NEW.accounts=0 AND NEW.history_profile IS NULL AND NEW.history_backing_until IS NULL AND public.capacity_capture_pool_revision(NEW) THEN RETURN NEW;END IF;
 IF TG_OP='UPDATE' AND NEW.lane='capture' AND (to_jsonb(NEW)-ARRAY['revision','valid_until']) IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['revision','valid_until']) AND
  NEW.revision>OLD.revision AND NEW.valid_until>OLD.valid_until AND public.capacity_capture_pool_revision(NEW) THEN RETURN NEW;END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'audit backing retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.proof_window_missed<>0 OR NEW.revision<>1 OR NEW.accounts<>0 OR NEW.history_profile IS NOT NULL OR NEW.history_backing_until IS NOT NULL THEN RAISE EXCEPTION 'invalid initial audit backing' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.proof_window_missed<>OLD.proof_window_missed AND (pg_trigger_depth()<2 OR NEW.proof_window_missed<>LEAST(OLD.proof_window_missed+1,1152921504606846976)) THEN RAISE EXCEPTION 'proof window aggregate is source managed' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.root_id,NEW.lane,NEW.account_version) IS DISTINCT FROM ROW(OLD.root_id,OLD.lane,OLD.account_version) THEN
   RAISE EXCEPTION 'immutable audit backing identity' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.history_profile,NEW.history_backing_until) IS DISTINCT FROM ROW(OLD.history_profile,OLD.history_backing_until) THEN
   IF pg_trigger_depth()<2 OR NEW.history_profile IS NULL OR NEW.history_backing_until IS NULL OR
    OLD.history_backing_until IS NOT NULL AND NEW.history_backing_until<OLD.history_backing_until OR
    OLD.history_profile IS NOT NULL AND NEW.history_profile IS DISTINCT FROM OLD.history_profile AND
     NOT public.operation_audit_profile_covers(NEW.history_profile,OLD.history_profile) AND
     (clock_timestamp()<OLD.history_backing_until OR EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE root_id=OLD.root_id AND lane=OLD.lane) OR EXISTS(SELECT 1 FROM public.operation_audit_history WHERE root_id=OLD.root_id AND lane=OLD.lane)) THEN
    RAISE EXCEPTION 'audit residual backing is source managed' USING ERRCODE='23514'; END IF;
  END IF;
  IF (NEW.account_limit<OLD.account_limit OR NEW.records_per_account<OLD.records_per_account) AND
   ((OLD.history_backing_until IS NOT NULL AND clock_timestamp()<OLD.history_backing_until) OR
    EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE root_id=OLD.root_id AND lane=OLD.lane AND (binding->'Policy'->>'BackupHorizonSeconds')::bigint>0) OR
    EXISTS(SELECT 1 FROM public.operation_audit_history WHERE root_id=OLD.root_id AND lane=OLD.lane)) THEN
   RAISE EXCEPTION 'audit residual backing cannot shrink' USING ERRCODE='23514'; END IF;
  IF NEW.accounts<>OLD.accounts AND (pg_trigger_depth()<2 OR
   (NEW.accounts<>OLD.accounts+1 AND NOT (NEW.accounts=OLD.accounts-1 AND
    (EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=OLD.root_id AND d.lane=OLD.lane AND d.finalization_xid=pg_current_xact_id() AND d.terminal_acknowledged_at IS NOT NULL) OR
     EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=OLD.root_id AND h.lane=OLD.lane AND h.drain_xid=pg_current_xact_id()))))) THEN
   RAISE EXCEPTION 'audit accounts source managed' USING ERRCODE='23514'; END IF;
  IF ROW(NEW.revision,NEW.paused,NEW.valid_until,NEW.account_limit,NEW.records_per_account,NEW.retained_seconds) IS DISTINCT FROM ROW(OLD.revision,OLD.paused,OLD.valid_until,OLD.account_limit,OLD.records_per_account,OLD.retained_seconds) AND
   (NEW.revision<>OLD.revision+1 OR NEW.accounts<>OLD.accounts) THEN RAISE EXCEPTION 'audit backing revision mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND charged>NEW.records_per_account) THEN
  RAISE EXCEPTION 'audit backing below retained spend' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_layout_valid(lane text, layout text)
 RETURNS boolean
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
 SELECT COALESCE((lane IN ('normal','resolution') AND layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3','operation-audit-history/v4')) OR (lane='processing' AND layout='processing-release-history/v1') OR (lane='capture' AND layout IN ('capture-intent-history/v1','capture-intent-history/v2')),false)
$function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_verifier_backed(layout text)
 RETURNS boolean
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
 SELECT COALESCE(layout IN ('operation-audit-history/v3','operation-audit-history/v4','processing-release-history/v1','capture-intent-history/v1','capture-intent-history/v2'),false)
$function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_minimum_row(layout text)
 RETURNS bigint
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
 SELECT CASE WHEN layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3','operation-audit-history/v4','processing-release-history/v1','capture-intent-history/v1','capture-intent-history/v2') THEN 131072 ELSE NULL END::bigint
$function$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_history_fixed_transitions(layout text)
 RETURNS bigint
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
 SELECT CASE layout WHEN 'operation-audit-history/v1' THEN 16 WHEN 'operation-audit-history/v2' THEN 19 WHEN 'operation-audit-history/v3' THEN 21 WHEN 'operation-audit-history/v4' THEN 24 WHEN 'processing-release-history/v1' THEN 32 WHEN 'capture-intent-history/v1' THEN 32 WHEN 'capture-intent-history/v2' THEN 34 ELSE NULL END::bigint
$function$;
-- +goose StatementEnd

DROP VIEW connector_operation_pool, connector_operation_account, connector_operation_audit, connector_operation_lifecycle, connector_operation_history;
-- IF EXISTS only where sqlc cannot resolve a row-type argument.
DROP FUNCTION accept_connector_process(uuid,uuid,jsonb);
DROP FUNCTION activate_connector_credential(uuid,uuid,jsonb,jsonb);
DROP FUNCTION activate_connector_reservations(uuid,uuid,jsonb);
DROP FUNCTION admit_connector_backing_reserved(uuid,jsonb,jsonb,bytea[]);
DROP FUNCTION admit_connector_backing(uuid,jsonb,jsonb);
DROP FUNCTION admit_connector_credential(uuid,jsonb,jsonb,jsonb);
DROP FUNCTION admit_connector_process_reserved(uuid,jsonb,jsonb,jsonb,bytea[]);
DROP FUNCTION admit_connector_process(uuid,jsonb,jsonb,jsonb);
DROP FUNCTION admit_connector_retirement(uuid,uuid,jsonb,timestamp with time zone,timestamp with time zone);
DROP FUNCTION claim_connector_credential(uuid,uuid,jsonb,jsonb);
DROP FUNCTION close_connector_backing_candidate(uuid,uuid);
DROP FUNCTION close_connector_retirement_admission(uuid,uuid);
DROP FUNCTION close_connector_retirement_writer_reference(uuid,uuid);
DROP FUNCTION connector_audit_acknowledge(uuid,jsonb,text,jsonb,jsonb);
DROP FUNCTION connector_audit_current(uuid,uuid);
DROP FUNCTION connector_audit_journal(uuid,jsonb,text,jsonb);
DROP FUNCTION IF EXISTS connector_audit_snapshot(operation_audit);
DROP FUNCTION connector_backing_can_renew(jsonb,jsonb);
DROP FUNCTION IF EXISTS connector_backing_observed(connector_identity_root,connector_identity_profile,jsonb);
DROP FUNCTION connector_identity_login_is_private();
DROP FUNCTION connector_identity_role_ok(uuid,text);
DROP FUNCTION connector_operation_actor_valid(jsonb);
DROP FUNCTION connector_reservation_acknowledged(uuid,uuid);
DROP FUNCTION IF EXISTS connector_retirement_prepaid(operation_audit);
DROP FUNCTION IF EXISTS connector_retirement_row_valid(connector_retirement_ticket);
DROP FUNCTION connector_retirement_set_digest(uuid,uuid);
DROP FUNCTION connector_retirement_ticket_digest(bytea);
DROP FUNCTION connector_retirement_ticket_valid(jsonb);
DROP FUNCTION IF EXISTS connector_ticket_admission_ended(connector_retirement_ticket,timestamp with time zone);
DROP FUNCTION delete_connector_retirement_ticket(uuid,uuid);
DROP FUNCTION detach_connector_identity(uuid,uuid);
DROP FUNCTION fence_connector_identity(uuid,uuid,timestamp with time zone);
DROP FUNCTION finish_connector_operation_history(uuid,text,bytea,timestamp with time zone,timestamp with time zone,uuid);
DROP FUNCTION finish_connector_operation_retirement(uuid,uuid,uuid);
DROP FUNCTION lock_connector_backing_current(uuid,jsonb);
DROP FUNCTION lock_connector_credential_candidate(uuid,jsonb);
DROP FUNCTION lock_connector_process_current(uuid,jsonb,boolean);
DROP FUNCTION promote_connector_backing(uuid,uuid,jsonb);
DROP FUNCTION read_connector_backing_admission(uuid,uuid,jsonb);
DROP FUNCTION read_connector_backing_candidate(uuid,jsonb);
DROP FUNCTION read_connector_credential_attempt(uuid,uuid,jsonb);
DROP FUNCTION read_connector_credential_process(uuid,jsonb);
DROP FUNCTION read_connector_process_admission(uuid,uuid,jsonb);
DROP FUNCTION read_connector_process_backing(uuid,jsonb);
DROP FUNCTION read_connector_process_ticket(uuid,jsonb);
DROP FUNCTION read_connector_retirement(uuid,uuid,timestamp with time zone,timestamp with time zone);
DROP FUNCTION read_connector_successor_cohorts(uuid,jsonb);
DROP FUNCTION reserve_connector_retirement_images(uuid,uuid,bytea[],timestamp with time zone);
DROP FUNCTION restrict_connector_retirement(uuid,uuid,text,jsonb);
DROP FUNCTION stage_connector_identity(uuid,jsonb,jsonb);
DROP FUNCTION store_connector_backing_outcome(uuid,uuid,jsonb,jsonb);
DROP FUNCTION store_connector_credential(uuid,uuid,jsonb,jsonb,jsonb);
DROP FUNCTION store_connector_process_outcome(uuid,uuid,jsonb,jsonb);
DROP FUNCTION store_connector_retirement_outcome(uuid,uuid,jsonb,timestamp with time zone,timestamp with time zone);
DROP TABLE connector_backing_transition, connector_credential_attempt, connector_retirement_ticket, connector_identity_process, connector_identity_profile, connector_identity_root;
DROP FUNCTION check_connector_reservation_event();
DROP FUNCTION check_connector_ticket_acceptance();
DROP FUNCTION guard_connector_audit_access();
DROP FUNCTION guard_connector_backing_transition();
DROP FUNCTION guard_connector_credential_attempt();
DROP FUNCTION guard_connector_identity_process();
DROP FUNCTION guard_connector_identity_profile();
DROP FUNCTION guard_connector_identity_root();
DROP FUNCTION guard_connector_reservation_acknowledgement();
DROP FUNCTION guard_connector_ticket_reservation();
DROP FUNCTION preserve_connector_ticket_backing();

ALTER TABLE operation_audit_history DISABLE TRIGGER USER;
ALTER TABLE operation_audit_lifecycle DISABLE TRIGGER USER;
ALTER TABLE operation_audit DISABLE TRIGGER USER;
ALTER TABLE operation_audit_account DISABLE TRIGGER USER;
ALTER TABLE operation_audit_pool DISABLE TRIGGER USER;
DELETE FROM operation_audit_history WHERE lane='identity';
DELETE FROM operation_audit_lifecycle WHERE lane='identity';
DELETE FROM operation_audit WHERE lane='identity';
DELETE FROM operation_audit_account WHERE lane='identity';
DELETE FROM operation_audit_pool WHERE lane='identity';
ALTER TABLE operation_audit_history ENABLE TRIGGER USER;
ALTER TABLE operation_audit_lifecycle ENABLE TRIGGER USER;
ALTER TABLE operation_audit ENABLE TRIGGER USER;
ALTER TABLE operation_audit_account ENABLE TRIGGER USER;
ALTER TABLE operation_audit_pool ENABLE TRIGGER USER;
ALTER TABLE operation_audit_pool DROP CONSTRAINT operation_audit_pool_lane_check, ADD CONSTRAINT operation_audit_pool_lane_check CHECK (lane IN ('normal','resolution','processing','capture'));
ALTER TABLE operation_audit_lifecycle DROP CONSTRAINT operation_audit_lifecycle_lane_check, ADD CONSTRAINT operation_audit_lifecycle_lane_check CHECK (lane IN ('normal','resolution','processing','capture'));
ALTER TABLE operation_audit_history DROP CONSTRAINT operation_audit_history_lane_check, ADD CONSTRAINT operation_audit_history_lane_check CHECK (lane IN ('normal','resolution','processing','capture'));
ALTER TABLE operation_audit_account DROP CONSTRAINT operation_audit_account_charged, ADD CONSTRAINT operation_audit_account_charged CHECK (charged BETWEEN 0 AND 1000000);
ALTER TABLE operation_audit_pool DROP CONSTRAINT operation_audit_pool_accounts, ADD CONSTRAINT operation_audit_pool_accounts CHECK (accounts BETWEEN 0 AND account_limit);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'the connector identity lane is not restored' USING ERRCODE='0A000'; END $$;
-- +goose StatementEnd
