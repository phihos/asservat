-- +goose Up
-- ADR-332: the connector identity is a standing configuration, valid until
-- replaced. Nothing in an installed system renews the backing, purges the
-- identity audit lane or detaches expired connector processes, so the three
-- finite budgets below ended every connector's enrollment after a fixed
-- time (homelab: one hour after install). They are removed, not renewed:
-- 1. a cohort's retirement ticket admits processes until the backing is
--    replaced, independent of the accepting record's retention;
-- 2. process admission no longer counts earlier process rows (of restarted
--    or rotated processes) against the deployment's retained-process limit;
-- 3. identity-lane audit records are not capped per account, so ordinary
--    connector work and ticket reservations no longer hold back records.
-- +goose StatementBegin
DO $$
DECLARE c text;
BEGIN
 SELECT conname INTO STRICT c FROM pg_catalog.pg_constraint WHERE conrelid='public.connector_retirement_ticket'::regclass AND contype='c'
  AND pg_catalog.pg_get_constraintdef(oid) LIKE '%reserved_at < admission_until%' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%original_purge_at%';
 EXECUTE format('ALTER TABLE public.connector_retirement_ticket DROP CONSTRAINT %I',c);
END $$;
-- +goose StatementEnd
ALTER TABLE connector_retirement_ticket ADD CONSTRAINT connector_retirement_ticket_admission CHECK(reserved_at<admission_until);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION connector_retirement_ticket_valid(t jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb:=t->'Policy'; b jsonb:=t->'Binding'; actor jsonb:=t->'OriginalActor';
 a timestamptz; ordinary_end timestamptz; consume_end timestamptz; retained timestamptz; original_end timestamptz;
BEGIN
 IF jsonb_typeof(t) IS DISTINCT FROM 'object' OR octet_length(t::text)>32768 OR
  NOT(t ?& ARRAY['ID','RootID','AcceptanceID','Binding','OriginalActor','Behavior','ServingSlots','RetainedProcesses','BackingRevision','BackingDigest','AccountVersion','PrincipalDigest','ReservedAt','AdmissionUntil','ConsumeUntil','RetainUntil','OriginalAcceptancePurgeAt','Policy']) OR
  (t-ARRAY['ID','RootID','AcceptanceID','Binding','OriginalActor','Behavior','ServingSlots','RetainedProcesses','BackingRevision','BackingDigest','AccountVersion','PrincipalDigest','ReservedAt','AdmissionUntil','ConsumeUntil','RetainUntil','OriginalAcceptancePurgeAt','Policy'])<>'{}'::jsonb THEN RETURN false;END IF;
 a:=(t->>'ReservedAt')::timestamptz;ordinary_end:=(t->>'AdmissionUntil')::timestamptz;consume_end:=(t->>'ConsumeUntil')::timestamptz;retained:=(t->>'RetainUntil')::timestamptz;
 original_end:=retained-make_interval(secs=>(2*(p->>'BackupHorizonSeconds')::bigint+3*(p->>'CleanupBudgetSeconds')::bigint+(p->>'ProofWindowSeconds')::bigint)::double precision);
 RETURN COALESCE((t->>'ID')::uuid<>(t->>'AcceptanceID')::uuid AND (t->>'RootID')::uuid IS NOT NULL AND
  b->>'Role'='connector' AND b->>'NodeUID'='' AND b->>'NodeBootID'='' AND b->>'CollectorEpoch'='' AND
  (b->>'InstallationID')::uuid=(actor->'Process'->'Binding'->>'InstallationID')::uuid AND (b->>'IssuerEpoch')::uuid=(actor->'Process'->'Binding'->>'IssuerEpoch')::uuid AND
  (b->>'ClusterID')::uuid IS NOT NULL AND (b->>'PeerID')::uuid IS NOT NULL AND
  (actor->'Process'->>'PodUID')::uuid IS NOT NULL AND (actor->'Process'->>'ProcessEpoch')::uuid IS NOT NULL AND
  (actor->'Process'->'Binding'->>'PeerID')::uuid IS NOT NULL AND (actor->'Process'->'Binding'->>'ClusterID')::uuid IS NOT NULL AND
  (t->>'ServingSlots')::bigint BETWEEN 1 AND 16 AND (t->>'RetainedProcesses')::bigint BETWEEN (t->>'ServingSlots')::bigint+1 AND 256 AND
  (t->'Behavior'->>'UID')::uuid IS NOT NULL AND (t->'Behavior'->>'Generation')::bigint BETWEEN 1 AND 2147483647 AND octet_length(public.connector_digest(t->'Behavior'->'Digest'))=32 AND
  (t->>'BackingRevision')::bigint BETWEEN 1 AND 1152921504606846976 AND octet_length(public.connector_digest(t->'BackingDigest'))=32 AND octet_length(public.connector_digest(t->'PrincipalDigest'))=32 AND octet_length(t->>'AccountVersion') BETWEEN 1 AND 64 AND
  p->>'Lane'='identity' AND p->'History'->>'Layout'='connector-operation-history/v2' AND p->>'OverdueTerminal'='overdue-original/v1' AND
  p->>'RootID'=t->>'RootID' AND p->>'InstallationID'=b->>'InstallationID' AND p->>'PolicyID'=t->>'ID' AND p->>'BackingRevision'=t->>'BackingRevision' AND
  (p->>'ValidUntil')::timestamptz=consume_end AND isfinite(a) AND isfinite(ordinary_end) AND isfinite(consume_end) AND isfinite(retained) AND isfinite(original_end) AND
  a<ordinary_end AND consume_end=original_end-interval '30 seconds' AND original_end>a+interval '1 minute' AND
  original_end<retained AND retained<=a+interval '3660 days' AND original_end<=(t->>'OriginalAcceptancePurgeAt')::timestamptz,false);
EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_connector_identity_process() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; backing public.connector_identity_root; event public.operation_audit; n timestamptz; retained bigint;
BEGIN
 IF TG_RELID<>'public.connector_identity_process'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector process boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.serving OR OLD.retired_at IS NULL OR clock_timestamp()<OLD.run_until+interval '1 minute' OR EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.process_id=OLD.id) THEN RAISE EXCEPTION 'connector process still charged' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO STRICT backing FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id FOR UPDATE;
 n:=clock_timestamp();
 IF TG_OP='UPDATE' AND public.connector_identity_role_ok(NEW.root_id,'cleanup') THEN
  IF n<OLD.run_until+interval '1 minute' OR NEW.serving OR NEW.retired_at IS NULL OR OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at OR NEW.client_current_id IS NOT NULL OR NEW.client_previous_id IS NOT NULL OR NEW.server_current_id IS NOT NULL OR NEW.server_previous_id IS NOT NULL OR
   (to_jsonb(NEW)-ARRAY['serving','retired_at','client_current_id','client_previous_id','server_current_id','server_previous_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['serving','retired_at','client_current_id','client_previous_id','server_current_id','server_previous_id']) THEN RAISE EXCEPTION 'connector historical detachment unavailable' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') THEN RAISE EXCEPTION 'connector process journal unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT event FROM public.operation_audit WHERE id=NEW.id AND root_id=NEW.root_id AND lane='identity';
  IF n>=backing.valid_until OR cfg.blocked OR cfg.suspended OR cfg.fenced AND cfg.accepted_id IS NOT NULL OR NEW.accepted_at IS NOT NULL OR NEW.serving OR NEW.retired_at IS NOT NULL OR NEW.client_epoch<>-1 OR NEW.server_epoch<>-1 OR NEW.client_attempts<>0 OR NEW.server_attempts<>0 OR NEW.client_current_id IS NOT NULL OR NEW.client_previous_id IS NOT NULL OR NEW.server_current_id IS NOT NULL OR NEW.server_previous_id IS NOT NULL OR
   event.intent->>'Name' IS DISTINCT FROM 'connector_process_enrollment' OR event.intent->'Process'->'Process' IS DISTINCT FROM NEW.process->'Attested' OR event.intent->'Process'->'Deployment' IS DISTINCT FROM cfg.configuration->'Deployment' OR
   public.connector_digest(event.intent->'Process'->'ClientKeyDigest')<>NEW.client_key OR public.connector_digest(event.intent->'Process'->'ServerKeyDigest')<>NEW.server_key OR
   NOT COALESCE(NEW.process->>'BootstrapID'='' AND NEW.process->'Binding'=cfg.configuration->'Binding' AND NEW.process->'Attested'->'Binding'=cfg.configuration->'Binding' AND (NEW.process->'Attested'->>'PodUID')::uuid=NEW.pod_uid AND (NEW.process->'Attested'->>'ProcessEpoch')::uuid=NEW.process_epoch AND public.connector_digest(NEW.process->'ClientKeyDigest')=NEW.client_key AND public.connector_digest(NEW.process->'ServerKeyDigest')=NEW.server_key AND (NEW.process->>'ClaimedAt')::timestamptz=NEW.claimed_at AND (NEW.process->>'InitialCertificateNotAfter')::timestamptz=NEW.initial_not_after AND (NEW.process->>'RunUntil')::timestamptz=NEW.run_until,false) OR
   ROW(NEW.source_uid,NEW.source_generation,NEW.source_digest) IS DISTINCT FROM ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest) OR NEW.claimed_at<>(event.intent->>'CreatedAt')::timestamptz OR NEW.run_until>(event.intent->'Lifecycle'->>'OriginalPurgeAt')::timestamptz-interval '1 minute' OR n>=event.request_until THEN RAISE EXCEPTION 'connector process admission unavailable' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['accepted_at','serving','retired_at','client_epoch','client_attempts','server_epoch','server_attempts','client_current_id','client_previous_id','server_current_id','server_previous_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['accepted_at','serving','retired_at','client_epoch','client_attempts','server_epoch','server_attempts','client_current_id','client_previous_id','server_current_id','server_previous_id']) OR OLD.accepted_at IS NOT NULL AND NEW.accepted_at IS DISTINCT FROM OLD.accepted_at OR OLD.retired_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'immutable connector process' USING ERRCODE='23514';END IF;
  IF NEW.client_epoch<OLD.client_epoch OR NEW.server_epoch<OLD.server_epoch OR NEW.client_epoch=OLD.client_epoch AND NEW.client_attempts<OLD.client_attempts OR NEW.server_epoch=OLD.server_epoch AND NEW.server_attempts<OLD.server_attempts OR NEW.client_attempts>OLD.client_attempts+1 AND NEW.client_epoch=OLD.client_epoch OR NEW.server_attempts>OLD.server_attempts+1 AND NEW.server_epoch=OLD.server_epoch OR NEW.client_epoch>OLD.client_epoch AND NEW.client_attempts<>1 OR NEW.server_epoch>OLD.server_epoch AND NEW.server_attempts<>1 THEN RAISE EXCEPTION 'connector signing counter reset' USING ERRCODE='23514';END IF;
  IF OLD.accepted_at IS NULL AND NEW.accepted_at IS NOT NULL THEN
   SELECT * INTO STRICT event FROM public.operation_audit WHERE id=NEW.id AND root_id=NEW.root_id;
   IF event.intent_receipt IS NULL OR event.outcome_receipt IS NULL OR event.outcome->>'Status' IS DISTINCT FROM 'success' OR event.outcome->>'Effect' IS DISTINCT FROM 'accepted' OR NEW.accepted_at<n-interval '5 seconds' OR NEW.accepted_at>n OR n>=NEW.run_until THEN RAISE EXCEPTION 'connector process audit unavailable' USING ERRCODE='23514';END IF;
  END IF;
  IF OLD.serving AND NOT NEW.serving AND NEW.retired_at IS NULL OR NEW.retired_at IS NOT NULL AND (NEW.serving OR NEW.retired_at<n-interval '5 seconds' OR NEW.retired_at>n) THEN RAISE EXCEPTION 'connector retirement transition unavailable' USING ERRCODE='23514';END IF;
  IF NEW.serving AND NOT OLD.serving THEN
   IF cfg.fenced OR cfg.blocked OR cfg.suspended OR n>=backing.valid_until OR n>=NEW.run_until OR NOT EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.id=NEW.client_current_id AND a.process_id=NEW.id AND a.usage='client' AND a.activated_at IS NOT NULL AND a.detached_at IS NULL AND n<a.certificate_not_after) OR NOT EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.id=NEW.server_current_id AND a.process_id=NEW.id AND a.usage='server' AND a.activated_at IS NOT NULL AND a.detached_at IS NULL AND n<a.certificate_not_after) THEN RAISE EXCEPTION 'paired connector serving identity unavailable' USING ERRCODE='23514';END IF;
   IF NOT OLD.serving AND (SELECT count(*) FROM public.connector_identity_process c WHERE c.root_id=NEW.root_id AND c.peer_id=NEW.peer_id AND c.serving)>=(cfg.configuration->'Deployment'->>'ServingSlots')::bigint THEN RAISE EXCEPTION 'connector serving slots exhausted' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
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
  IF NEW.lane<>'identity' AND a.charged>=p.records_per_account THEN RAISE EXCEPTION 'audit records exhausted' USING ERRCODE='23514'; END IF;
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
CREATE OR REPLACE FUNCTION preserve_connector_ticket_backing() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.operation_audit_pool; account public.operation_audit_account; reserved bigint; n timestamptz;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector ticket accounting source' USING ERRCODE='23514';END IF;
 IF NEW.lane<>'identity' THEN RETURN NEW;END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') THEN RAISE EXCEPTION 'connector reservation accounting role unavailable' USING ERRCODE='23514';END IF;
 -- The purpose-fixed business entry point locks recovery/root/profile before
 -- reaching the pool. Holding root here also serializes ticket release/consume;
 -- generic callers have no base-table INSERT or callable admission capability.
 PERFORM 1 FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='identity' FOR UPDATE;
 SELECT * INTO account FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane='identity' AND principal_digest=NEW.principal_digest FOR UPDATE;
 SELECT count(*) INTO reserved FROM public.connector_retirement_ticket WHERE root_id=NEW.root_id AND principal_digest=NEW.principal_digest AND admitted_at IS NULL AND closed_unused_at IS NULL;
 n:=clock_timestamp();
 IF n>=NEW.request_until THEN RAISE EXCEPTION 'ordinary connector work cannot spend restrictive reservation' USING ERRCODE='23514';END IF;
 IF NEW.intent->>'Name'='connector_retirement' THEN
  -- Admission atomically converts exactly one pre-existing reservation to its
  -- original audit charge before this INSERT. It is not extra capacity.
  IF NOT EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.id=NEW.id AND t.root_id=NEW.root_id AND t.principal_digest=NEW.principal_digest AND t.retirement_operation=NEW.id AND t.admitted_at=(NEW.intent->>'CreatedAt')::timestamptz AND t.restriction_at IS NOT NULL AND t.superseded_at IS NULL AND t.closed_unused_at IS NULL AND t.admission_closed_at IS NULL AND t.acceptance_reference=t.acceptance_id AND t.ticket=NEW.intent->'RetirementOrigin'->'Ticket' AND public.connector_digest(NEW.intent->'RetirementOrigin'->'TicketDigest')=t.ticket_digest) THEN RAISE EXCEPTION 'connector retirement has no exact prepaid admission' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_connector_ticket_reservation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.connector_identity_root; cfg public.connector_identity_profile; pool public.operation_audit_pool; account public.operation_audit_account; trust public.fleet_current_trust;
 original_policy jsonb; selected_backing jsonb; reserved bigint; n timestamptz; event public.operation_audit; successor public.connector_retirement_ticket;
BEGIN
 IF TG_RELID<>'public.connector_retirement_ticket'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector ticket mutation source' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.activated_at IS NULL AND NEW.activated_at IS NOT NULL OR OLD.superseded_at IS NULL AND NEW.superseded_at IS NOT NULL THEN
   -- Fixed SECURITY DEFINER activation composes current proof before this
   -- trigger. Independently require its exact acknowledged original event and
   -- immutable candidate here; no direct role write can invent a successor.
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
   n:=clock_timestamp();
   IF NOT(public.connector_identity_role_ok(OLD.root_id,'journal') OR public.connector_identity_role_ok(OLD.root_id,'source')) OR
    trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR
    (to_jsonb(NEW)-ARRAY['activated_at','superseded_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['activated_at','superseded_at']) OR
    OLD.restriction_at IS NOT NULL OR OLD.admitted_at IS NOT NULL OR OLD.closed_unused_at IS NOT NULL OR OLD.superseded_at IS NOT NULL OR OLD.admission_closed_at IS NOT NULL OR
    n>=root.valid_until THEN RAISE EXCEPTION 'connector ticket activation authority unavailable' USING ERRCODE='23514';END IF;
   IF OLD.activated_at IS NULL THEN
    SELECT * INTO STRICT event FROM public.operation_audit WHERE id=OLD.acceptance_id AND root_id=OLD.root_id AND lane='identity';
    IF NEW.activated_at<n-interval '5 seconds' OR NEW.activated_at>n OR NEW.superseded_at IS NOT NULL OR n>=OLD.admission_until OR OLD.acceptance_reference IS DISTINCT FROM event.id OR
     NOT public.connector_reservation_acknowledged(OLD.root_id,event.id) OR
     EXISTS(SELECT 1 FROM public.connector_retirement_ticket other WHERE other.root_id=OLD.root_id AND other.peer_id=OLD.peer_id AND other.id<>OLD.id AND other.activated_at IS NOT NULL AND other.superseded_at IS NULL) OR
     NOT COALESCE((event.intent->>'Name'='connector_process_enrollment' AND public.connector_identity_role_ok(OLD.root_id,'journal') AND
       OLD.backing_revision=(root.policy->>'BackingRevision')::bigint AND OLD.backing_digest=root.backing_digest AND
       ROW(OLD.behavior_uid,OLD.behavior_generation,OLD.behavior_digest)=ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest)) OR
      (event.intent->>'Name'='connector_backing_acceptance' AND public.connector_identity_role_ok(OLD.root_id,'source') AND root.pending_id=event.id AND
       OLD.backing_revision=(root.pending_backing->'Policy'->>'BackingRevision')::bigint AND OLD.backing_digest=root.pending_digest AND
       EXISTS(SELECT 1 FROM public.connector_retirement_ticket previous_ticket WHERE previous_ticket.root_id=OLD.root_id AND previous_ticket.peer_id=OLD.peer_id AND previous_ticket.activated_at IS NOT NULL AND previous_ticket.superseded_at=NEW.activated_at AND
        previous_ticket.backing_revision+1=OLD.backing_revision AND previous_ticket.behavior_uid=OLD.behavior_uid AND previous_ticket.behavior_generation=OLD.behavior_generation AND previous_ticket.behavior_digest=OLD.behavior_digest)),false) THEN
     RAISE EXCEPTION 'connector ticket activation differs from original acceptance' USING ERRCODE='23514';END IF;
   ELSE
    SELECT * INTO STRICT successor FROM public.connector_retirement_ticket WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id AND acceptance_id=root.pending_id;
    IF NOT public.connector_identity_role_ok(OLD.root_id,'source') OR NEW.activated_at IS DISTINCT FROM OLD.activated_at OR NEW.superseded_at<n-interval '5 seconds' OR NEW.superseded_at>n OR
     successor.activated_at IS NOT NULL OR successor.admission_closed_at IS NOT NULL OR successor.acceptance_reference IS DISTINCT FROM successor.acceptance_id OR n>=successor.admission_until OR
     successor.restriction_at IS NOT NULL OR successor.admitted_at IS NOT NULL OR successor.closed_unused_at IS NOT NULL OR successor.backing_revision<>OLD.backing_revision+1 OR
     successor.backing_revision<>(root.pending_backing->'Policy'->>'BackingRevision')::bigint OR successor.backing_digest<>root.pending_digest OR
     ROW(successor.behavior_uid,successor.behavior_generation,successor.behavior_digest) IS DISTINCT FROM ROW(OLD.behavior_uid,OLD.behavior_generation,OLD.behavior_digest) OR
     NOT public.connector_reservation_acknowledged(OLD.root_id,successor.acceptance_id) THEN RAISE EXCEPTION 'connector ticket supersession lacks exact acknowledged successor' USING ERRCODE='23514';END IF;
   END IF;
   RETURN NEW;
  END IF;
  IF OLD.restriction_at IS NULL AND NEW.restriction_at IS NOT NULL THEN
   IF NOT public.connector_identity_role_ok(OLD.root_id,'journal') OR OLD.activated_at IS NULL OR OLD.superseded_at IS NOT NULL OR OLD.admitted_at IS NOT NULL OR
    (to_jsonb(NEW)-ARRAY['restriction_at','restriction_source']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['restriction_at','restriction_source']) OR NEW.restriction_source IS NULL THEN RAISE EXCEPTION 'connector restrictive ticket transition unavailable' USING ERRCODE='23514';END IF;
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
   n:=clock_timestamp();
   IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR NEW.restriction_at>n OR NEW.restriction_at<n-interval '5 seconds' OR
    cfg.retirement_ticket IS NOT NULL OR cfg.source_uid<>OLD.behavior_uid OR cfg.backing_revision<>OLD.backing_revision OR cfg.backing_digest<>OLD.backing_digest OR cfg.account_digest<>OLD.principal_digest OR
    NOT COALESCE((NEW.restriction_source->>'Cause'='originalAdmissionEnd' AND n>=OLD.admission_until AND NOT(NEW.restriction_source ? 'RetiringSource') AND
      (ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest)=ROW(OLD.behavior_uid,OLD.behavior_generation,OLD.behavior_digest) OR cfg.suspended AND (cfg.configuration->>'Retiring')::boolean AND cfg.source_generation>OLD.behavior_generation)) OR
     (NEW.restriction_source->>'Cause'='protectedRetiringSource' AND cfg.suspended AND (cfg.configuration->>'Retiring')::boolean AND cfg.source_generation>OLD.behavior_generation AND
      NEW.restriction_source->'RetiringSource'->'Revision'=cfg.configuration->'Revision' AND public.connector_digest(NEW.restriction_source->'RetiringSource'->'CompleteDigest')=cfg.complete_digest),false) THEN RAISE EXCEPTION 'connector restrictive ticket differs from original cohort' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  IF OLD.admitted_at IS NULL AND NEW.admitted_at IS NOT NULL THEN
   IF NOT public.connector_identity_role_ok(OLD.root_id,'journal') OR OLD.activated_at IS NULL OR OLD.superseded_at IS NOT NULL OR OLD.restriction_at IS NULL OR OLD.closed_unused_at IS NOT NULL OR OLD.admission_closed_at IS NOT NULL OR OLD.acceptance_reference IS DISTINCT FROM OLD.acceptance_id OR
    (to_jsonb(NEW)-ARRAY['admitted_at','retirement_operation','retirement_reference']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['admitted_at','retirement_operation','retirement_reference']) OR NEW.retirement_operation IS DISTINCT FROM OLD.id OR NEW.retirement_reference IS DISTINCT FROM OLD.id THEN RAISE EXCEPTION 'connector retirement conversion unavailable' USING ERRCODE='23514';END IF;
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
   n:=clock_timestamp();
   IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR NEW.admitted_at>n OR NEW.admitted_at<n-interval '5 seconds' OR n>=OLD.consume_until OR
    cfg.retirement_ticket IS DISTINCT FROM OLD.id OR cfg.retirement_at IS DISTINCT FROM OLD.restriction_at OR NOT cfg.fenced OR
    NOT public.connector_reservation_acknowledged(OLD.root_id,OLD.acceptance_id) OR EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.id) THEN RAISE EXCEPTION 'connector retirement original conversion interval unavailable' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  IF OLD.audit_dependency_closed_at IS NULL AND NEW.audit_dependency_closed_at IS NOT NULL THEN
   IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.admitted_at IS NULL OR OLD.retirement_reference IS DISTINCT FROM OLD.id OR NEW.retirement_reference IS NOT NULL OR
    (to_jsonb(NEW)-ARRAY['retirement_reference','audit_dependency_closed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['retirement_reference','audit_dependency_closed_at']) THEN RAISE EXCEPTION 'connector writer reference closure unavailable' USING ERRCODE='23514';END IF;
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   PERFORM 1 FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT event FROM public.operation_audit WHERE id=OLD.retirement_reference AND root_id=OLD.root_id AND lane='identity' FOR UPDATE;
   n:=clock_timestamp();
   IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>(OLD.ticket->'Binding'->>'IssuerEpoch')::uuid OR NEW.audit_dependency_closed_at>n OR NEW.audit_dependency_closed_at<n-interval '5 seconds' OR
    event.intent->>'Name' IS DISTINCT FROM 'connector_retirement' OR event.intent->'RetirementOrigin'->'Ticket' IS DISTINCT FROM OLD.ticket OR n<event.write_until THEN RAISE EXCEPTION 'connector writer still admits original effects' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  -- Closure is irreversible, separate from activation and from proving any
  -- admitted audit writer/object absent.
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.admission_closed_at IS NOT NULL OR
   (to_jsonb(NEW)-ARRAY['acceptance_reference','admission_closed_at','closed_unused_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['acceptance_reference','admission_closed_at','closed_unused_at']) OR
   NEW.acceptance_reference IS NOT NULL OR NEW.admission_closed_at IS NULL THEN RAISE EXCEPTION 'connector ticket transition unavailable' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
  PERFORM 1 FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
  PERFORM 1 FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
  n:=clock_timestamp();
  IF trust.recovery_blocked OR trust.suspended OR trust.issuer_epoch<>(OLD.ticket->'Binding'->>'IssuerEpoch')::uuid OR trust.observed_at>n OR n>=trust.fresh_until OR
   NEW.admission_closed_at>n OR NEW.admission_closed_at<n-interval '5 seconds' OR
   NOT public.connector_ticket_admission_ended(OLD,n) OR
   (OLD.admitted_at IS NULL AND (NEW.closed_unused_at IS DISTINCT FROM NEW.admission_closed_at OR EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.id))) OR
   (OLD.admitted_at IS NOT NULL AND NEW.closed_unused_at IS NOT NULL) THEN RAISE EXCEPTION 'connector ticket closure is not proven restrictive' USING ERRCODE='23514';END IF;
  -- A positive unused closure spends no pair. Admitted/unknown pair charges
  -- are untouched; their independent verification/deletion still must finish.
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.admission_closed_at IS NULL OR OLD.acceptance_reference IS NOT NULL OR OLD.retirement_reference IS NOT NULL OR (OLD.admitted_at IS NULL AND OLD.closed_unused_at IS NULL) THEN RAISE EXCEPTION 'connector ticket still admits work or retains audit dependency' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
  PERFORM 1 FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
  SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
  n:=clock_timestamp();original_policy:=OLD.ticket->'Policy';
  IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>(OLD.ticket->'Binding'->>'IssuerEpoch')::uuid OR
   n<OLD.retain_until-make_interval(secs=>((original_policy->>'BackupHorizonSeconds')::bigint+(original_policy->>'CleanupBudgetSeconds')::bigint)::double precision) OR
   EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.id) OR EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE operation_id=OLD.id) OR
   EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=OLD.root_id AND h.lane='identity' AND h.principal_digest=OLD.principal_digest AND h.release_at=OLD.retain_until-make_interval(secs=>((original_policy->>'BackupHorizonSeconds')::bigint+(original_policy->>'CleanupBudgetSeconds')::bigint)::double precision) AND h.delete_by=OLD.retain_until-make_interval(secs=>(original_policy->>'BackupHorizonSeconds')::double precision)) OR
   (OLD.activated_at IS NOT NULL AND OLD.superseded_at IS NULL AND (NOT cfg.fenced OR cfg.retirement_ticket IS DISTINCT FROM OLD.id OR cfg.retirement_at IS DISTINCT FROM OLD.restriction_at)) THEN RAISE EXCEPTION 'connector original ticket history or cohort fence remains unresolved' USING ERRCODE='23514';END IF;
  -- Positive exact history absence above is mandatory: reaching the original
  -- history-release instant alone proves no cleanup. Independent source-row
  -- backing remains reserved through retain_until after this row is deleted.
  -- The profile's separately paid minimal control fence remains. Later
  -- possible leaves keep their own process/audit charges and original dates.
  RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'connector ticket mutation unavailable' USING ERRCODE='23514';END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') OR NOT public.connector_retirement_row_valid(NEW) OR NEW.acceptance_reference IS DISTINCT FROM NEW.acceptance_id OR NEW.admission_closed_at IS NOT NULL OR NEW.activated_at IS NOT NULL OR NEW.superseded_at IS NOT NULL OR NEW.restriction_at IS NOT NULL OR NEW.restriction_source IS NOT NULL OR NEW.admitted_at IS NOT NULL OR NEW.closed_unused_at IS NOT NULL OR NEW.retirement_operation IS NOT NULL OR NEW.retirement_reference IS NOT NULL OR NEW.audit_dependency_closed_at IS NOT NULL THEN RAISE EXCEPTION 'connector reservation source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(NEW.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='identity' FOR UPDATE;
 n:=clock_timestamp();original_policy:=NEW.ticket->'Policy';
 IF NEW.acceptance_id=root.pending_id THEN selected_backing:=root.pending_backing;ELSE selected_backing:=root.backing;END IF;
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.issuer_epoch=root.issuer_epoch AND trust.observed_at<=n AND n<trust.fresh_until AND n<root.valid_until AND n<pool.valid_until AND NOT pool.paused AND
  NEW.reserved_at<=n AND n<NEW.reserved_at+interval '5 seconds' AND n<NEW.admission_until AND
  NEW.ticket->'Binding'=cfg.configuration->'Binding' AND
  ((NEW.acceptance_id IS DISTINCT FROM root.pending_id AND NEW.behavior_uid=cfg.source_uid AND NEW.behavior_generation=cfg.source_generation AND NEW.behavior_digest=cfg.source_digest AND NEW.ticket->'ServingSlots'=cfg.configuration->'Deployment'->'ServingSlots' AND NEW.ticket->'RetainedProcesses'=cfg.configuration->'Deployment'->'RetainedProcesses') OR
   (NEW.acceptance_id=root.pending_id AND NOT COALESCE((cfg.configuration->>'Retiring')::boolean,false) AND EXISTS(SELECT 1 FROM public.connector_retirement_ticket previous_ticket WHERE previous_ticket.root_id=NEW.root_id AND previous_ticket.peer_id=NEW.peer_id AND previous_ticket.activated_at IS NOT NULL AND previous_ticket.superseded_at IS NULL AND previous_ticket.restriction_at IS NULL AND previous_ticket.admitted_at IS NULL AND previous_ticket.closed_unused_at IS NULL AND previous_ticket.backing_revision=(root.policy->>'BackingRevision')::bigint AND previous_ticket.backing_digest=root.backing_digest AND previous_ticket.behavior_uid=NEW.behavior_uid AND previous_ticket.behavior_generation=NEW.behavior_generation AND previous_ticket.behavior_digest=NEW.behavior_digest AND previous_ticket.ticket->'ServingSlots'=NEW.ticket->'ServingSlots' AND previous_ticket.ticket->'RetainedProcesses'=NEW.ticket->'RetainedProcesses' AND previous_ticket.principal_digest=NEW.principal_digest))) AND
  NEW.backing_revision=(selected_backing->'Policy'->>'BackingRevision')::bigint AND NEW.backing_digest=(CASE WHEN NEW.acceptance_id=root.pending_id THEN root.pending_digest ELSE root.backing_digest END) AND
  NEW.admission_until=(selected_backing->'Policy'->>'ValidUntil')::timestamptz AND NEW.ticket->>'AccountVersion'=pool.account_version AND
  (cfg.account_digest IS NULL OR cfg.account_digest=NEW.principal_digest) AND
  (original_policy - ARRAY['PolicyID','PolicyDigest','ValidUntil'])=((selected_backing->'Policy') - ARRAY['PolicyID','PolicyDigest','ValidUntil']) AND
  original_policy->'History'=root.qualification AND original_policy->'History'->>'Layout'='connector-operation-history/v2' AND
  NEW.retain_until=NEW.reserved_at+make_interval(secs=>pool.retained_seconds::double precision),false) THEN RAISE EXCEPTION 'connector reservation original backing unavailable' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM public.operation_audit WHERE id=NEW.acceptance_id) OR
  EXISTS(SELECT 1 FROM public.connector_retirement_ticket old_ticket WHERE old_ticket.root_id=NEW.root_id AND old_ticket.peer_id=NEW.peer_id AND old_ticket.activated_at IS NOT NULL AND old_ticket.superseded_at IS NULL AND (old_ticket.restriction_at IS NOT NULL OR old_ticket.admitted_at IS NOT NULL)) THEN
  RAISE EXCEPTION 'connector reservation acceptance closed or cohort retired' USING ERRCODE='23514';END IF;
 SELECT * INTO account FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane='identity' AND principal_digest=NEW.principal_digest FOR UPDATE;
 IF NOT FOUND THEN
  IF pool.accounts>=pool.account_limit THEN RAISE EXCEPTION 'connector reservation accounts exhausted' USING ERRCODE='23514';END IF;
  UPDATE public.operation_audit_pool SET accounts=accounts+1 WHERE root_id=NEW.root_id AND lane='identity';
  INSERT INTO public.operation_audit_account(root_id,lane,principal_digest) VALUES(NEW.root_id,'identity',NEW.principal_digest) RETURNING * INTO account;
 END IF;
 SELECT count(*) INTO reserved FROM public.connector_retirement_ticket WHERE root_id=NEW.root_id AND principal_digest=NEW.principal_digest AND admitted_at IS NULL AND closed_unused_at IS NULL;
 IF clock_timestamp()>=NEW.reserved_at+interval '5 seconds' OR clock_timestamp()>=trust.fresh_until OR clock_timestamp()>=root.valid_until THEN RAISE EXCEPTION 'connector restrictive reservation capacity or interval unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit_pool() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
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
 IF NEW.lane<>'identity' AND EXISTS(SELECT 1 FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND charged>NEW.records_per_account) THEN
  RAISE EXCEPTION 'audit backing below retained spend' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE connector_retirement_ticket DROP CONSTRAINT connector_retirement_ticket_admission;
ALTER TABLE connector_retirement_ticket ADD CONSTRAINT connector_retirement_ticket_admission CHECK(reserved_at<admission_until AND admission_until<=original_purge_at-interval '1 minute') NOT VALID;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION connector_retirement_ticket_valid(t jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb:=t->'Policy'; b jsonb:=t->'Binding'; actor jsonb:=t->'OriginalActor';
 a timestamptz; ordinary_end timestamptz; consume_end timestamptz; retained timestamptz; original_end timestamptz;
BEGIN
 IF jsonb_typeof(t) IS DISTINCT FROM 'object' OR octet_length(t::text)>32768 OR
  NOT(t ?& ARRAY['ID','RootID','AcceptanceID','Binding','OriginalActor','Behavior','ServingSlots','RetainedProcesses','BackingRevision','BackingDigest','AccountVersion','PrincipalDigest','ReservedAt','AdmissionUntil','ConsumeUntil','RetainUntil','OriginalAcceptancePurgeAt','Policy']) OR
  (t-ARRAY['ID','RootID','AcceptanceID','Binding','OriginalActor','Behavior','ServingSlots','RetainedProcesses','BackingRevision','BackingDigest','AccountVersion','PrincipalDigest','ReservedAt','AdmissionUntil','ConsumeUntil','RetainUntil','OriginalAcceptancePurgeAt','Policy'])<>'{}'::jsonb THEN RETURN false;END IF;
 a:=(t->>'ReservedAt')::timestamptz;ordinary_end:=(t->>'AdmissionUntil')::timestamptz;consume_end:=(t->>'ConsumeUntil')::timestamptz;retained:=(t->>'RetainUntil')::timestamptz;
 original_end:=retained-make_interval(secs=>(2*(p->>'BackupHorizonSeconds')::bigint+3*(p->>'CleanupBudgetSeconds')::bigint+(p->>'ProofWindowSeconds')::bigint)::double precision);
 RETURN COALESCE((t->>'ID')::uuid<>(t->>'AcceptanceID')::uuid AND (t->>'RootID')::uuid IS NOT NULL AND
  b->>'Role'='connector' AND b->>'NodeUID'='' AND b->>'NodeBootID'='' AND b->>'CollectorEpoch'='' AND
  (b->>'InstallationID')::uuid=(actor->'Process'->'Binding'->>'InstallationID')::uuid AND (b->>'IssuerEpoch')::uuid=(actor->'Process'->'Binding'->>'IssuerEpoch')::uuid AND
  (b->>'ClusterID')::uuid IS NOT NULL AND (b->>'PeerID')::uuid IS NOT NULL AND
  (actor->'Process'->>'PodUID')::uuid IS NOT NULL AND (actor->'Process'->>'ProcessEpoch')::uuid IS NOT NULL AND
  (actor->'Process'->'Binding'->>'PeerID')::uuid IS NOT NULL AND (actor->'Process'->'Binding'->>'ClusterID')::uuid IS NOT NULL AND
  (t->>'ServingSlots')::bigint BETWEEN 1 AND 16 AND (t->>'RetainedProcesses')::bigint BETWEEN (t->>'ServingSlots')::bigint+1 AND 256 AND
  (t->'Behavior'->>'UID')::uuid IS NOT NULL AND (t->'Behavior'->>'Generation')::bigint BETWEEN 1 AND 2147483647 AND octet_length(public.connector_digest(t->'Behavior'->'Digest'))=32 AND
  (t->>'BackingRevision')::bigint BETWEEN 1 AND 1152921504606846976 AND octet_length(public.connector_digest(t->'BackingDigest'))=32 AND octet_length(public.connector_digest(t->'PrincipalDigest'))=32 AND octet_length(t->>'AccountVersion') BETWEEN 1 AND 64 AND
  p->>'Lane'='identity' AND p->'History'->>'Layout'='connector-operation-history/v2' AND p->>'OverdueTerminal'='overdue-original/v1' AND
  p->>'RootID'=t->>'RootID' AND p->>'InstallationID'=b->>'InstallationID' AND p->>'PolicyID'=t->>'ID' AND p->>'BackingRevision'=t->>'BackingRevision' AND
  (p->>'ValidUntil')::timestamptz=consume_end AND isfinite(a) AND isfinite(ordinary_end) AND isfinite(consume_end) AND isfinite(retained) AND isfinite(original_end) AND
  a<ordinary_end AND ordinary_end<=original_end-interval '1 minute' AND consume_end=original_end-interval '30 seconds' AND original_end>a+interval '1 minute' AND
  original_end<retained AND retained<=a+interval '3660 days' AND original_end<=(t->>'OriginalAcceptancePurgeAt')::timestamptz,false);
EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_connector_identity_process() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; backing public.connector_identity_root; event public.operation_audit; n timestamptz; retained bigint;
BEGIN
 IF TG_RELID<>'public.connector_identity_process'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector process boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.serving OR OLD.retired_at IS NULL OR clock_timestamp()<OLD.run_until+interval '1 minute' OR EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.process_id=OLD.id) THEN RAISE EXCEPTION 'connector process still charged' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO STRICT backing FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id FOR UPDATE;
 n:=clock_timestamp();
 IF TG_OP='UPDATE' AND public.connector_identity_role_ok(NEW.root_id,'cleanup') THEN
  IF n<OLD.run_until+interval '1 minute' OR NEW.serving OR NEW.retired_at IS NULL OR OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at OR NEW.client_current_id IS NOT NULL OR NEW.client_previous_id IS NOT NULL OR NEW.server_current_id IS NOT NULL OR NEW.server_previous_id IS NOT NULL OR
   (to_jsonb(NEW)-ARRAY['serving','retired_at','client_current_id','client_previous_id','server_current_id','server_previous_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['serving','retired_at','client_current_id','client_previous_id','server_current_id','server_previous_id']) THEN RAISE EXCEPTION 'connector historical detachment unavailable' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') THEN RAISE EXCEPTION 'connector process journal unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT event FROM public.operation_audit WHERE id=NEW.id AND root_id=NEW.root_id AND lane='identity';
  SELECT count(*) INTO retained FROM public.connector_identity_process WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id;
  IF n>=backing.valid_until OR cfg.blocked OR cfg.suspended OR cfg.fenced AND cfg.accepted_id IS NOT NULL OR retained>=(cfg.configuration->'Deployment'->>'RetainedProcesses')::bigint OR NEW.accepted_at IS NOT NULL OR NEW.serving OR NEW.retired_at IS NOT NULL OR NEW.client_epoch<>-1 OR NEW.server_epoch<>-1 OR NEW.client_attempts<>0 OR NEW.server_attempts<>0 OR NEW.client_current_id IS NOT NULL OR NEW.client_previous_id IS NOT NULL OR NEW.server_current_id IS NOT NULL OR NEW.server_previous_id IS NOT NULL OR
   event.intent->>'Name' IS DISTINCT FROM 'connector_process_enrollment' OR event.intent->'Process'->'Process' IS DISTINCT FROM NEW.process->'Attested' OR event.intent->'Process'->'Deployment' IS DISTINCT FROM cfg.configuration->'Deployment' OR
   public.connector_digest(event.intent->'Process'->'ClientKeyDigest')<>NEW.client_key OR public.connector_digest(event.intent->'Process'->'ServerKeyDigest')<>NEW.server_key OR
   NOT COALESCE(NEW.process->>'BootstrapID'='' AND NEW.process->'Binding'=cfg.configuration->'Binding' AND NEW.process->'Attested'->'Binding'=cfg.configuration->'Binding' AND (NEW.process->'Attested'->>'PodUID')::uuid=NEW.pod_uid AND (NEW.process->'Attested'->>'ProcessEpoch')::uuid=NEW.process_epoch AND public.connector_digest(NEW.process->'ClientKeyDigest')=NEW.client_key AND public.connector_digest(NEW.process->'ServerKeyDigest')=NEW.server_key AND (NEW.process->>'ClaimedAt')::timestamptz=NEW.claimed_at AND (NEW.process->>'InitialCertificateNotAfter')::timestamptz=NEW.initial_not_after AND (NEW.process->>'RunUntil')::timestamptz=NEW.run_until,false) OR
   ROW(NEW.source_uid,NEW.source_generation,NEW.source_digest) IS DISTINCT FROM ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest) OR NEW.claimed_at<>(event.intent->>'CreatedAt')::timestamptz OR NEW.run_until>(event.intent->'Lifecycle'->>'OriginalPurgeAt')::timestamptz-interval '1 minute' OR n>=event.request_until THEN RAISE EXCEPTION 'connector process admission unavailable' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['accepted_at','serving','retired_at','client_epoch','client_attempts','server_epoch','server_attempts','client_current_id','client_previous_id','server_current_id','server_previous_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['accepted_at','serving','retired_at','client_epoch','client_attempts','server_epoch','server_attempts','client_current_id','client_previous_id','server_current_id','server_previous_id']) OR OLD.accepted_at IS NOT NULL AND NEW.accepted_at IS DISTINCT FROM OLD.accepted_at OR OLD.retired_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'immutable connector process' USING ERRCODE='23514';END IF;
  IF NEW.client_epoch<OLD.client_epoch OR NEW.server_epoch<OLD.server_epoch OR NEW.client_epoch=OLD.client_epoch AND NEW.client_attempts<OLD.client_attempts OR NEW.server_epoch=OLD.server_epoch AND NEW.server_attempts<OLD.server_attempts OR NEW.client_attempts>OLD.client_attempts+1 AND NEW.client_epoch=OLD.client_epoch OR NEW.server_attempts>OLD.server_attempts+1 AND NEW.server_epoch=OLD.server_epoch OR NEW.client_epoch>OLD.client_epoch AND NEW.client_attempts<>1 OR NEW.server_epoch>OLD.server_epoch AND NEW.server_attempts<>1 THEN RAISE EXCEPTION 'connector signing counter reset' USING ERRCODE='23514';END IF;
  IF OLD.accepted_at IS NULL AND NEW.accepted_at IS NOT NULL THEN
   SELECT * INTO STRICT event FROM public.operation_audit WHERE id=NEW.id AND root_id=NEW.root_id;
   IF event.intent_receipt IS NULL OR event.outcome_receipt IS NULL OR event.outcome->>'Status' IS DISTINCT FROM 'success' OR event.outcome->>'Effect' IS DISTINCT FROM 'accepted' OR NEW.accepted_at<n-interval '5 seconds' OR NEW.accepted_at>n OR n>=NEW.run_until THEN RAISE EXCEPTION 'connector process audit unavailable' USING ERRCODE='23514';END IF;
  END IF;
  IF OLD.serving AND NOT NEW.serving AND NEW.retired_at IS NULL OR NEW.retired_at IS NOT NULL AND (NEW.serving OR NEW.retired_at<n-interval '5 seconds' OR NEW.retired_at>n) THEN RAISE EXCEPTION 'connector retirement transition unavailable' USING ERRCODE='23514';END IF;
  IF NEW.serving AND NOT OLD.serving THEN
   IF cfg.fenced OR cfg.blocked OR cfg.suspended OR n>=backing.valid_until OR n>=NEW.run_until OR NOT EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.id=NEW.client_current_id AND a.process_id=NEW.id AND a.usage='client' AND a.activated_at IS NOT NULL AND a.detached_at IS NULL AND n<a.certificate_not_after) OR NOT EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.id=NEW.server_current_id AND a.process_id=NEW.id AND a.usage='server' AND a.activated_at IS NOT NULL AND a.detached_at IS NULL AND n<a.certificate_not_after) THEN RAISE EXCEPTION 'paired connector serving identity unavailable' USING ERRCODE='23514';END IF;
   IF NOT OLD.serving AND (SELECT count(*) FROM public.connector_identity_process c WHERE c.root_id=NEW.root_id AND c.peer_id=NEW.peer_id AND c.serving)>=(cfg.configuration->'Deployment'->>'ServingSlots')::bigint THEN RAISE EXCEPTION 'connector serving slots exhausted' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
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
CREATE OR REPLACE FUNCTION preserve_connector_ticket_backing() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.operation_audit_pool; account public.operation_audit_account; reserved bigint; n timestamptz;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector ticket accounting source' USING ERRCODE='23514';END IF;
 IF NEW.lane<>'identity' THEN RETURN NEW;END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') THEN RAISE EXCEPTION 'connector reservation accounting role unavailable' USING ERRCODE='23514';END IF;
 -- The purpose-fixed business entry point locks recovery/root/profile before
 -- reaching the pool. Holding root here also serializes ticket release/consume;
 -- generic callers have no base-table INSERT or callable admission capability.
 PERFORM 1 FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='identity' FOR UPDATE;
 SELECT * INTO account FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane='identity' AND principal_digest=NEW.principal_digest FOR UPDATE;
 SELECT count(*) INTO reserved FROM public.connector_retirement_ticket WHERE root_id=NEW.root_id AND principal_digest=NEW.principal_digest AND admitted_at IS NULL AND closed_unused_at IS NULL;
 n:=clock_timestamp();
 IF COALESCE(account.charged,0)+reserved>=pool.records_per_account OR n>=NEW.request_until THEN RAISE EXCEPTION 'ordinary connector work cannot spend restrictive reservation' USING ERRCODE='23514';END IF;
 IF NEW.intent->>'Name'='connector_retirement' THEN
  -- Admission atomically converts exactly one pre-existing reservation to its
  -- original audit charge before this INSERT. It is not extra capacity.
  IF NOT EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.id=NEW.id AND t.root_id=NEW.root_id AND t.principal_digest=NEW.principal_digest AND t.retirement_operation=NEW.id AND t.admitted_at=(NEW.intent->>'CreatedAt')::timestamptz AND t.restriction_at IS NOT NULL AND t.superseded_at IS NULL AND t.closed_unused_at IS NULL AND t.admission_closed_at IS NULL AND t.acceptance_reference=t.acceptance_id AND t.ticket=NEW.intent->'RetirementOrigin'->'Ticket' AND public.connector_digest(NEW.intent->'RetirementOrigin'->'TicketDigest')=t.ticket_digest) THEN RAISE EXCEPTION 'connector retirement has no exact prepaid admission' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_connector_ticket_reservation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.connector_identity_root; cfg public.connector_identity_profile; pool public.operation_audit_pool; account public.operation_audit_account; trust public.fleet_current_trust;
 original_policy jsonb; selected_backing jsonb; reserved bigint; n timestamptz; event public.operation_audit; successor public.connector_retirement_ticket;
BEGIN
 IF TG_RELID<>'public.connector_retirement_ticket'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector ticket mutation source' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.activated_at IS NULL AND NEW.activated_at IS NOT NULL OR OLD.superseded_at IS NULL AND NEW.superseded_at IS NOT NULL THEN
   -- Fixed SECURITY DEFINER activation composes current proof before this
   -- trigger. Independently require its exact acknowledged original event and
   -- immutable candidate here; no direct role write can invent a successor.
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
   n:=clock_timestamp();
   IF NOT(public.connector_identity_role_ok(OLD.root_id,'journal') OR public.connector_identity_role_ok(OLD.root_id,'source')) OR
    trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR
    (to_jsonb(NEW)-ARRAY['activated_at','superseded_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['activated_at','superseded_at']) OR
    OLD.restriction_at IS NOT NULL OR OLD.admitted_at IS NOT NULL OR OLD.closed_unused_at IS NOT NULL OR OLD.superseded_at IS NOT NULL OR OLD.admission_closed_at IS NOT NULL OR
    n>=root.valid_until THEN RAISE EXCEPTION 'connector ticket activation authority unavailable' USING ERRCODE='23514';END IF;
   IF OLD.activated_at IS NULL THEN
    SELECT * INTO STRICT event FROM public.operation_audit WHERE id=OLD.acceptance_id AND root_id=OLD.root_id AND lane='identity';
    IF NEW.activated_at<n-interval '5 seconds' OR NEW.activated_at>n OR NEW.superseded_at IS NOT NULL OR n>=OLD.admission_until OR OLD.acceptance_reference IS DISTINCT FROM event.id OR
     NOT public.connector_reservation_acknowledged(OLD.root_id,event.id) OR
     EXISTS(SELECT 1 FROM public.connector_retirement_ticket other WHERE other.root_id=OLD.root_id AND other.peer_id=OLD.peer_id AND other.id<>OLD.id AND other.activated_at IS NOT NULL AND other.superseded_at IS NULL) OR
     NOT COALESCE((event.intent->>'Name'='connector_process_enrollment' AND public.connector_identity_role_ok(OLD.root_id,'journal') AND
       OLD.backing_revision=(root.policy->>'BackingRevision')::bigint AND OLD.backing_digest=root.backing_digest AND
       ROW(OLD.behavior_uid,OLD.behavior_generation,OLD.behavior_digest)=ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest)) OR
      (event.intent->>'Name'='connector_backing_acceptance' AND public.connector_identity_role_ok(OLD.root_id,'source') AND root.pending_id=event.id AND
       OLD.backing_revision=(root.pending_backing->'Policy'->>'BackingRevision')::bigint AND OLD.backing_digest=root.pending_digest AND
       EXISTS(SELECT 1 FROM public.connector_retirement_ticket previous_ticket WHERE previous_ticket.root_id=OLD.root_id AND previous_ticket.peer_id=OLD.peer_id AND previous_ticket.activated_at IS NOT NULL AND previous_ticket.superseded_at=NEW.activated_at AND
        previous_ticket.backing_revision+1=OLD.backing_revision AND previous_ticket.behavior_uid=OLD.behavior_uid AND previous_ticket.behavior_generation=OLD.behavior_generation AND previous_ticket.behavior_digest=OLD.behavior_digest)),false) THEN
     RAISE EXCEPTION 'connector ticket activation differs from original acceptance' USING ERRCODE='23514';END IF;
   ELSE
    SELECT * INTO STRICT successor FROM public.connector_retirement_ticket WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id AND acceptance_id=root.pending_id;
    IF NOT public.connector_identity_role_ok(OLD.root_id,'source') OR NEW.activated_at IS DISTINCT FROM OLD.activated_at OR NEW.superseded_at<n-interval '5 seconds' OR NEW.superseded_at>n OR
     successor.activated_at IS NOT NULL OR successor.admission_closed_at IS NOT NULL OR successor.acceptance_reference IS DISTINCT FROM successor.acceptance_id OR n>=successor.admission_until OR
     successor.restriction_at IS NOT NULL OR successor.admitted_at IS NOT NULL OR successor.closed_unused_at IS NOT NULL OR successor.backing_revision<>OLD.backing_revision+1 OR
     successor.backing_revision<>(root.pending_backing->'Policy'->>'BackingRevision')::bigint OR successor.backing_digest<>root.pending_digest OR
     ROW(successor.behavior_uid,successor.behavior_generation,successor.behavior_digest) IS DISTINCT FROM ROW(OLD.behavior_uid,OLD.behavior_generation,OLD.behavior_digest) OR
     NOT public.connector_reservation_acknowledged(OLD.root_id,successor.acceptance_id) THEN RAISE EXCEPTION 'connector ticket supersession lacks exact acknowledged successor' USING ERRCODE='23514';END IF;
   END IF;
   RETURN NEW;
  END IF;
  IF OLD.restriction_at IS NULL AND NEW.restriction_at IS NOT NULL THEN
   IF NOT public.connector_identity_role_ok(OLD.root_id,'journal') OR OLD.activated_at IS NULL OR OLD.superseded_at IS NOT NULL OR OLD.admitted_at IS NOT NULL OR
    (to_jsonb(NEW)-ARRAY['restriction_at','restriction_source']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['restriction_at','restriction_source']) OR NEW.restriction_source IS NULL THEN RAISE EXCEPTION 'connector restrictive ticket transition unavailable' USING ERRCODE='23514';END IF;
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
   n:=clock_timestamp();
   IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR NEW.restriction_at>n OR NEW.restriction_at<n-interval '5 seconds' OR
    cfg.retirement_ticket IS NOT NULL OR cfg.source_uid<>OLD.behavior_uid OR cfg.backing_revision<>OLD.backing_revision OR cfg.backing_digest<>OLD.backing_digest OR cfg.account_digest<>OLD.principal_digest OR
    NOT COALESCE((NEW.restriction_source->>'Cause'='originalAdmissionEnd' AND n>=OLD.admission_until AND NOT(NEW.restriction_source ? 'RetiringSource') AND
      (ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest)=ROW(OLD.behavior_uid,OLD.behavior_generation,OLD.behavior_digest) OR cfg.suspended AND (cfg.configuration->>'Retiring')::boolean AND cfg.source_generation>OLD.behavior_generation)) OR
     (NEW.restriction_source->>'Cause'='protectedRetiringSource' AND cfg.suspended AND (cfg.configuration->>'Retiring')::boolean AND cfg.source_generation>OLD.behavior_generation AND
      NEW.restriction_source->'RetiringSource'->'Revision'=cfg.configuration->'Revision' AND public.connector_digest(NEW.restriction_source->'RetiringSource'->'CompleteDigest')=cfg.complete_digest),false) THEN RAISE EXCEPTION 'connector restrictive ticket differs from original cohort' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  IF OLD.admitted_at IS NULL AND NEW.admitted_at IS NOT NULL THEN
   IF NOT public.connector_identity_role_ok(OLD.root_id,'journal') OR OLD.activated_at IS NULL OR OLD.superseded_at IS NOT NULL OR OLD.restriction_at IS NULL OR OLD.closed_unused_at IS NOT NULL OR OLD.admission_closed_at IS NOT NULL OR OLD.acceptance_reference IS DISTINCT FROM OLD.acceptance_id OR
    (to_jsonb(NEW)-ARRAY['admitted_at','retirement_operation','retirement_reference']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['admitted_at','retirement_operation','retirement_reference']) OR NEW.retirement_operation IS DISTINCT FROM OLD.id OR NEW.retirement_reference IS DISTINCT FROM OLD.id THEN RAISE EXCEPTION 'connector retirement conversion unavailable' USING ERRCODE='23514';END IF;
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
   n:=clock_timestamp();
   IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR NEW.admitted_at>n OR NEW.admitted_at<n-interval '5 seconds' OR n>=OLD.consume_until OR
    cfg.retirement_ticket IS DISTINCT FROM OLD.id OR cfg.retirement_at IS DISTINCT FROM OLD.restriction_at OR NOT cfg.fenced OR
    NOT public.connector_reservation_acknowledged(OLD.root_id,OLD.acceptance_id) OR EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.id) THEN RAISE EXCEPTION 'connector retirement original conversion interval unavailable' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  IF OLD.audit_dependency_closed_at IS NULL AND NEW.audit_dependency_closed_at IS NOT NULL THEN
   IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.admitted_at IS NULL OR OLD.retirement_reference IS DISTINCT FROM OLD.id OR NEW.retirement_reference IS NOT NULL OR
    (to_jsonb(NEW)-ARRAY['retirement_reference','audit_dependency_closed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['retirement_reference','audit_dependency_closed_at']) THEN RAISE EXCEPTION 'connector writer reference closure unavailable' USING ERRCODE='23514';END IF;
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   PERFORM 1 FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT event FROM public.operation_audit WHERE id=OLD.retirement_reference AND root_id=OLD.root_id AND lane='identity' FOR UPDATE;
   n:=clock_timestamp();
   IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>(OLD.ticket->'Binding'->>'IssuerEpoch')::uuid OR NEW.audit_dependency_closed_at>n OR NEW.audit_dependency_closed_at<n-interval '5 seconds' OR
    event.intent->>'Name' IS DISTINCT FROM 'connector_retirement' OR event.intent->'RetirementOrigin'->'Ticket' IS DISTINCT FROM OLD.ticket OR n<event.write_until THEN RAISE EXCEPTION 'connector writer still admits original effects' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  -- Closure is irreversible, separate from activation and from proving any
  -- admitted audit writer/object absent.
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.admission_closed_at IS NOT NULL OR
   (to_jsonb(NEW)-ARRAY['acceptance_reference','admission_closed_at','closed_unused_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['acceptance_reference','admission_closed_at','closed_unused_at']) OR
   NEW.acceptance_reference IS NOT NULL OR NEW.admission_closed_at IS NULL THEN RAISE EXCEPTION 'connector ticket transition unavailable' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
  PERFORM 1 FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
  PERFORM 1 FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
  n:=clock_timestamp();
  IF trust.recovery_blocked OR trust.suspended OR trust.issuer_epoch<>(OLD.ticket->'Binding'->>'IssuerEpoch')::uuid OR trust.observed_at>n OR n>=trust.fresh_until OR
   NEW.admission_closed_at>n OR NEW.admission_closed_at<n-interval '5 seconds' OR
   NOT public.connector_ticket_admission_ended(OLD,n) OR
   (OLD.admitted_at IS NULL AND (NEW.closed_unused_at IS DISTINCT FROM NEW.admission_closed_at OR EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.id))) OR
   (OLD.admitted_at IS NOT NULL AND NEW.closed_unused_at IS NOT NULL) THEN RAISE EXCEPTION 'connector ticket closure is not proven restrictive' USING ERRCODE='23514';END IF;
  -- A positive unused closure spends no pair. Admitted/unknown pair charges
  -- are untouched; their independent verification/deletion still must finish.
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.admission_closed_at IS NULL OR OLD.acceptance_reference IS NOT NULL OR OLD.retirement_reference IS NOT NULL OR (OLD.admitted_at IS NULL AND OLD.closed_unused_at IS NULL) THEN RAISE EXCEPTION 'connector ticket still admits work or retains audit dependency' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
  PERFORM 1 FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
  SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
  n:=clock_timestamp();original_policy:=OLD.ticket->'Policy';
  IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>(OLD.ticket->'Binding'->>'IssuerEpoch')::uuid OR
   n<OLD.retain_until-make_interval(secs=>((original_policy->>'BackupHorizonSeconds')::bigint+(original_policy->>'CleanupBudgetSeconds')::bigint)::double precision) OR
   EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.id) OR EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE operation_id=OLD.id) OR
   EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=OLD.root_id AND h.lane='identity' AND h.principal_digest=OLD.principal_digest AND h.release_at=OLD.retain_until-make_interval(secs=>((original_policy->>'BackupHorizonSeconds')::bigint+(original_policy->>'CleanupBudgetSeconds')::bigint)::double precision) AND h.delete_by=OLD.retain_until-make_interval(secs=>(original_policy->>'BackupHorizonSeconds')::double precision)) OR
   (OLD.activated_at IS NOT NULL AND OLD.superseded_at IS NULL AND (NOT cfg.fenced OR cfg.retirement_ticket IS DISTINCT FROM OLD.id OR cfg.retirement_at IS DISTINCT FROM OLD.restriction_at)) THEN RAISE EXCEPTION 'connector original ticket history or cohort fence remains unresolved' USING ERRCODE='23514';END IF;
  -- Positive exact history absence above is mandatory: reaching the original
  -- history-release instant alone proves no cleanup. Independent source-row
  -- backing remains reserved through retain_until after this row is deleted.
  -- The profile's separately paid minimal control fence remains. Later
  -- possible leaves keep their own process/audit charges and original dates.
  RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'connector ticket mutation unavailable' USING ERRCODE='23514';END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') OR NOT public.connector_retirement_row_valid(NEW) OR NEW.acceptance_reference IS DISTINCT FROM NEW.acceptance_id OR NEW.admission_closed_at IS NOT NULL OR NEW.activated_at IS NOT NULL OR NEW.superseded_at IS NOT NULL OR NEW.restriction_at IS NOT NULL OR NEW.restriction_source IS NOT NULL OR NEW.admitted_at IS NOT NULL OR NEW.closed_unused_at IS NOT NULL OR NEW.retirement_operation IS NOT NULL OR NEW.retirement_reference IS NOT NULL OR NEW.audit_dependency_closed_at IS NOT NULL THEN RAISE EXCEPTION 'connector reservation source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(NEW.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='identity' FOR UPDATE;
 n:=clock_timestamp();original_policy:=NEW.ticket->'Policy';
 IF NEW.acceptance_id=root.pending_id THEN selected_backing:=root.pending_backing;ELSE selected_backing:=root.backing;END IF;
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.issuer_epoch=root.issuer_epoch AND trust.observed_at<=n AND n<trust.fresh_until AND n<root.valid_until AND n<pool.valid_until AND NOT pool.paused AND
  NEW.reserved_at<=n AND n<NEW.reserved_at+interval '5 seconds' AND n<NEW.admission_until AND
  NEW.ticket->'Binding'=cfg.configuration->'Binding' AND
  ((NEW.acceptance_id IS DISTINCT FROM root.pending_id AND NEW.behavior_uid=cfg.source_uid AND NEW.behavior_generation=cfg.source_generation AND NEW.behavior_digest=cfg.source_digest AND NEW.ticket->'ServingSlots'=cfg.configuration->'Deployment'->'ServingSlots' AND NEW.ticket->'RetainedProcesses'=cfg.configuration->'Deployment'->'RetainedProcesses') OR
   (NEW.acceptance_id=root.pending_id AND NOT COALESCE((cfg.configuration->>'Retiring')::boolean,false) AND EXISTS(SELECT 1 FROM public.connector_retirement_ticket previous_ticket WHERE previous_ticket.root_id=NEW.root_id AND previous_ticket.peer_id=NEW.peer_id AND previous_ticket.activated_at IS NOT NULL AND previous_ticket.superseded_at IS NULL AND previous_ticket.restriction_at IS NULL AND previous_ticket.admitted_at IS NULL AND previous_ticket.closed_unused_at IS NULL AND previous_ticket.backing_revision=(root.policy->>'BackingRevision')::bigint AND previous_ticket.backing_digest=root.backing_digest AND previous_ticket.behavior_uid=NEW.behavior_uid AND previous_ticket.behavior_generation=NEW.behavior_generation AND previous_ticket.behavior_digest=NEW.behavior_digest AND previous_ticket.ticket->'ServingSlots'=NEW.ticket->'ServingSlots' AND previous_ticket.ticket->'RetainedProcesses'=NEW.ticket->'RetainedProcesses' AND previous_ticket.principal_digest=NEW.principal_digest))) AND
  NEW.backing_revision=(selected_backing->'Policy'->>'BackingRevision')::bigint AND NEW.backing_digest=(CASE WHEN NEW.acceptance_id=root.pending_id THEN root.pending_digest ELSE root.backing_digest END) AND
  NEW.admission_until=(selected_backing->'Policy'->>'ValidUntil')::timestamptz AND NEW.ticket->>'AccountVersion'=pool.account_version AND
  (cfg.account_digest IS NULL OR cfg.account_digest=NEW.principal_digest) AND
  (original_policy - ARRAY['PolicyID','PolicyDigest','ValidUntil'])=((selected_backing->'Policy') - ARRAY['PolicyID','PolicyDigest','ValidUntil']) AND
  original_policy->'History'=root.qualification AND original_policy->'History'->>'Layout'='connector-operation-history/v2' AND
  NEW.retain_until=NEW.reserved_at+make_interval(secs=>pool.retained_seconds::double precision),false) THEN RAISE EXCEPTION 'connector reservation original backing unavailable' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM public.operation_audit WHERE id=NEW.acceptance_id) OR
  EXISTS(SELECT 1 FROM public.connector_retirement_ticket old_ticket WHERE old_ticket.root_id=NEW.root_id AND old_ticket.peer_id=NEW.peer_id AND old_ticket.activated_at IS NOT NULL AND old_ticket.superseded_at IS NULL AND (old_ticket.restriction_at IS NOT NULL OR old_ticket.admitted_at IS NOT NULL)) THEN
  RAISE EXCEPTION 'connector reservation acceptance closed or cohort retired' USING ERRCODE='23514';END IF;
 SELECT * INTO account FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane='identity' AND principal_digest=NEW.principal_digest FOR UPDATE;
 IF NOT FOUND THEN
  IF pool.accounts>=pool.account_limit THEN RAISE EXCEPTION 'connector reservation accounts exhausted' USING ERRCODE='23514';END IF;
  UPDATE public.operation_audit_pool SET accounts=accounts+1 WHERE root_id=NEW.root_id AND lane='identity';
  INSERT INTO public.operation_audit_account(root_id,lane,principal_digest) VALUES(NEW.root_id,'identity',NEW.principal_digest) RETURNING * INTO account;
 END IF;
 SELECT count(*) INTO reserved FROM public.connector_retirement_ticket WHERE root_id=NEW.root_id AND principal_digest=NEW.principal_digest AND admitted_at IS NULL AND closed_unused_at IS NULL;
 IF account.charged+reserved>=pool.records_per_account OR clock_timestamp()>=NEW.reserved_at+interval '5 seconds' OR clock_timestamp()>=trust.fresh_until OR clock_timestamp()>=root.valid_until THEN RAISE EXCEPTION 'connector restrictive reservation capacity or interval unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit_pool() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
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
END $$;
-- +goose StatementEnd
