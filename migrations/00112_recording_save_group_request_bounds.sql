-- +goose Up
-- ADR269: prospective protected manual-group bookkeeping; original proof bounds remain unchanged.
-- +goose StatementBegin
CREATE FUNCTION recording_save_group_window_valid(c public.context_capture,g public.recording_save_group,until_at timestamptz) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s jsonb;e jsonb;q jsonb;
BEGIN
 IF c.group_id IS NULL OR c.group_ordinal IS NULL OR until_at IS NULL OR NOT isfinite(until_at) THEN RETURN false;END IF;
 IF g.id IS DISTINCT FROM c.group_id OR g.root_id IS DISTINCT FROM c.root_id OR cardinality(g.child_ids) NOT BETWEEN 2 AND 16 OR c.group_ordinal<0 OR c.group_ordinal>=cardinality(g.child_ids) THEN RETURN false;END IF;
 s:=convert_from(c.scope_json,'UTF8')::jsonb;e:=convert_from(c.expectation_json,'UTF8')::jsonb;q:=e->'Snapshot';
 RETURN COALESCE(g.child_ids[c.group_ordinal+1]=c.id AND c.scope_json=g.scope_json AND c.scope_digest=g.scope_digest AND sha256(c.scope_json)=c.scope_digest AND
  s->>'schemaVersion'='recording-save/v1' AND s->>'operation'='recordingSave' AND (s->>'captureID')::uuid=g.id AND
  jsonb_typeof(s->'sources')='array' AND jsonb_array_length(s->'sources')=cardinality(g.child_ids) AND
  s->'sources'->c.group_ordinal->>'sourceSessionID'=q->>'SourceID' AND s->'sources'->c.group_ordinal->>'podUID'=e->>'PodUID' AND
  e->'Lifecycle'->>'TriggerKind'='recordingSave' AND (e->>'CaptureUID')::uuid=c.id AND c.created_at=g.accepted_at AND
  (q->>'T0')::timestamptz=g.accepted_at AND (q->>'IssuedAt')::timestamptz=g.accepted_at AND
  (q->>'StartBy')::timestamptz>g.accepted_at AND (q->>'StartBy')::timestamptz<=g.accepted_at+interval '15 seconds' AND
  (q->>'StartBy')::timestamptz<=(q->>'SourceHardUntil')::timestamptz AND (q->>'StartBy')::timestamptz<(q->>'ProcessingUntil')::timestamptz AND
  (q->>'ProcessingUntil')::timestamptz=c.deadline AND (e#>>'{Registration,WriteUntil}')::timestamptz=c.deadline AND
  until_at>c.created_at AND until_at<=(q->>'StartBy')::timestamptz,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION recording_save_group_window_valid(public.context_capture,public.recording_save_group,timestamptz) FROM PUBLIC;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION lock_capture_audit_admission(r uuid,allocation uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp();n timestamptz;until_at timestamptz;root public.capture_audit_root;trust public.fleet_current_trust;pool public.operation_audit_pool;a public.capture_audit_allocation;control public.context_control_account;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'admission') THEN RAISE EXCEPTION 'capture audit admission unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=r AND lane='capture' FOR UPDATE;
 SELECT * INTO STRICT a FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation FOR UPDATE;
 SELECT * INTO STRICT control FROM public.context_control_account WHERE root_id=r AND allocation_id=allocation;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',root.valid_until,trust.fresh_until,pool.valid_until,a.valid_until,(a.policy->>'ValidUntil')::timestamptz);
 IF NOT COALESCE(n<until_at AND trust.observed_at<=n AND NOT trust.recovery_blocked AND NOT trust.suspended AND NOT root.paused AND NOT pool.paused AND NOT a.paused AND a.account_version=pool.account_version AND a.guaranteed_records>=control.full_limit AND a.guaranteed_records<=pool.records_per_account AND (a.policy->>'BackingRevision')::bigint=pool.revision,false) THEN RAISE EXCEPTION 'capture audit backing unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('RootID',r,'AllocationID',allocation,'AccountVersion',a.account_version,'AccountDigest',to_jsonb(ARRAY(SELECT get_byte(a.account_digest,k) FROM generate_series(0,31) k)),'Revision',a.revision,'Records',a.guaranteed_records,'RetainedSeconds',pool.retained_seconds,'Policy',a.policy,'ValidUntil',until_at,'HardUntil',LEAST(root.valid_until,pool.valid_until,a.valid_until,(a.policy->>'ValidUntil')::timestamptz));
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_capture_group() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE g public.recording_save_group;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.group_id,NEW.group_ordinal) IS DISTINCT FROM ROW(OLD.group_id,OLD.group_ordinal) THEN
   RAISE EXCEPTION 'immutable group membership' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM public.recording_save_group WHERE id=NEW.id OR (root_id=NEW.root_id AND request_key=NEW.request_key)) THEN
   RAISE EXCEPTION 'request key already belongs to a group' USING ERRCODE='23514';
  END IF;
  IF NEW.group_id IS NOT NULL THEN
   SELECT * INTO g FROM public.recording_save_group WHERE root_id=NEW.root_id AND id=NEW.group_id;
   IF NOT FOUND OR g.child_ids[NEW.group_ordinal+1] IS DISTINCT FROM NEW.id OR
      g.scope_digest IS DISTINCT FROM NEW.scope_digest OR g.scope_json IS DISTINCT FROM NEW.scope_json OR g.accepted_at IS DISTINCT FROM NEW.created_at THEN
    RAISE EXCEPTION 'unlisted group member' USING ERRCODE='23514';
   END IF;
  END IF;
  IF convert_from(NEW.expectation_json,'UTF8')::jsonb ? 'Snapshot' AND (convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz>NEW.created_at+interval '5 seconds' AND NOT public.recording_save_group_window_valid(NEW,g,(convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN
   RAISE EXCEPTION 'long snapshot window requires exact protected manual group' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reserve_capture_audit(r uuid,capture uuid,i jsonb,capture_digest bytea,original_until timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c public.context_capture;a public.capture_audit_allocation;trust public.fleet_current_trust;root public.capture_audit_root;allocation uuid;observed jsonb;n timestamptz;g public.recording_save_group;
BEGIN
 IF octet_length(i::text)>public.capture_audit_intent_limit(i) OR octet_length(capture_digest)<>32 OR NOT public.capture_audit_role_ok(r,'admission') THEN RAISE EXCEPTION 'capture audit admission unavailable' USING ERRCODE='23514';END IF;
 -- Immutable own INSERT identifies allocation before reacquiring the agreed
 -- prefix. It cannot use a legacy capture or repair a committed missing pair.
 SELECT * INTO STRICT c FROM public.context_capture WHERE id=capture AND root_id=r;
 allocation:=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,AllocationID}')::uuid;
 observed:=public.lock_capture_audit_admission(r,allocation);
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 SELECT * INTO STRICT a FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation;
 IF c.group_id IS NOT NULL THEN SELECT * INTO g FROM public.recording_save_group WHERE id=c.group_id AND root_id=r;END IF;
 n:=clock_timestamp();
 IF NOT COALESCE(c.intent_operation_id=c.id AND c.state='accepted_pending_audit' AND c.intent_acknowledged_at IS NULL AND public.capture_audit_payload_matches(c,i) AND
   i->'Lifecycle'->'Policy'=a.policy AND public.connector_digest(i->'PrincipalDigest')=a.account_digest AND i->>'AccountVersion'=a.account_version AND
   n<original_until AND n<(observed->>'ValidUntil')::timestamptz AND n<(i->>'RequestUntil')::timestamptz AND ((i->>'RequestUntil')::timestamptz<=original_until OR public.recording_save_group_window_valid(c,g,(i->>'RequestUntil')::timestamptz)) AND (i->>'RequestUntil')::timestamptz<=(observed->>'HardUntil')::timestamptz,false) THEN RAISE EXCEPTION 'capture audit binding mismatch' USING ERRCODE='23514';END IF;
 INSERT INTO public.operation_audit(id,root_id,lane,issuer_epoch,principal_digest,intent,request_until,write_until,retain_until)
 VALUES(c.id,r,'capture',trust.issuer_epoch,a.account_digest,i,(i->>'RequestUntil')::timestamptz,(i->>'WriteUntil')::timestamptz,(i->>'RetainUntil')::timestamptz);
 INSERT INTO public.capture_audit_binding(capture_id,root_id,allocation_id,operation_id,capture_digest) VALUES(c.id,r,allocation,c.id,capture_digest);
 IF clock_timestamp()>=LEAST(original_until,(observed->>'ValidUntil')::timestamptz,(i->>'RequestUntil')::timestamptz) THEN RAISE EXCEPTION 'capture audit admission expired' USING ERRCODE='23514';END IF;
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
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+(CASE WHEN NEW.intent->>'Name' IN ('get_file_excerpt','get_query_result','prepare_artifact_download','get_artifact_download') THEN interval '20 seconds' WHEN NEW.intent->>'Name'='request_capture' THEN interval '15 seconds' WHEN NEW.lane='capture' AND NEW.intent->>'Name'='persist_capture_intent' AND EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.id AND public.capture_audit_payload_matches(c,NEW.intent) AND c.group_id IS NOT NULL AND c.group_ordinal IS NOT NULL AND NEW.request_until<=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN interval '15 seconds' ELSE interval '5 seconds' END) OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
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

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE public.recording_save_group,public.context_capture,public.operation_audit IN SHARE MODE;
 IF EXISTS(SELECT 1 FROM public.context_capture c WHERE c.group_id IS NOT NULL AND (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz>c.created_at+interval '5 seconds') OR
    EXISTS(SELECT 1 FROM public.operation_audit a WHERE a.lane='capture' AND a.request_until>(a.intent->>'CreatedAt')::timestamptz+interval '5 seconds') THEN
  RAISE EXCEPTION 'retained long-window manual groups cannot downgrade' USING ERRCODE='23514';
 END IF;
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
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+(CASE WHEN NEW.intent->>'Name' IN ('get_file_excerpt','get_query_result','prepare_artifact_download','get_artifact_download') THEN interval '20 seconds' WHEN NEW.intent->>'Name'='request_capture' THEN interval '15 seconds' ELSE interval '5 seconds' END) OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
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
CREATE OR REPLACE FUNCTION reserve_capture_audit(r uuid,capture uuid,i jsonb,capture_digest bytea,original_until timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c public.context_capture;a public.capture_audit_allocation;trust public.fleet_current_trust;root public.capture_audit_root;allocation uuid;observed jsonb;n timestamptz;
BEGIN
 IF octet_length(i::text)>public.capture_audit_intent_limit(i) OR octet_length(capture_digest)<>32 OR NOT public.capture_audit_role_ok(r,'admission') THEN RAISE EXCEPTION 'capture audit admission unavailable' USING ERRCODE='23514';END IF;
 -- Immutable own INSERT identifies allocation before reacquiring the agreed
 -- prefix. It cannot use a legacy capture or repair a committed missing pair.
 SELECT * INTO STRICT c FROM public.context_capture WHERE id=capture AND root_id=r;
 allocation:=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,AllocationID}')::uuid;
 observed:=public.lock_capture_audit_admission(r,allocation);
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 SELECT * INTO STRICT a FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation;
 n:=clock_timestamp();
 IF NOT COALESCE(c.intent_operation_id=c.id AND c.state='accepted_pending_audit' AND c.intent_acknowledged_at IS NULL AND public.capture_audit_payload_matches(c,i) AND
   i->'Lifecycle'->'Policy'=a.policy AND public.connector_digest(i->'PrincipalDigest')=a.account_digest AND i->>'AccountVersion'=a.account_version AND
   n<original_until AND n<(observed->>'ValidUntil')::timestamptz AND n<(i->>'RequestUntil')::timestamptz AND (i->>'RequestUntil')::timestamptz<=original_until,false) THEN RAISE EXCEPTION 'capture audit binding mismatch' USING ERRCODE='23514';END IF;
 INSERT INTO public.operation_audit(id,root_id,lane,issuer_epoch,principal_digest,intent,request_until,write_until,retain_until)
 VALUES(c.id,r,'capture',trust.issuer_epoch,a.account_digest,i,(i->>'RequestUntil')::timestamptz,(i->>'WriteUntil')::timestamptz,(i->>'RetainUntil')::timestamptz);
 INSERT INTO public.capture_audit_binding(capture_id,root_id,allocation_id,operation_id,capture_digest) VALUES(c.id,r,allocation,c.id,capture_digest);
 IF clock_timestamp()>=LEAST(original_until,(observed->>'ValidUntil')::timestamptz,(i->>'RequestUntil')::timestamptz) THEN RAISE EXCEPTION 'capture audit admission expired' USING ERRCODE='23514';END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_context_capture_group() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.group_id,NEW.group_ordinal) IS DISTINCT FROM ROW(OLD.group_id,OLD.group_ordinal) THEN
   RAISE EXCEPTION 'immutable group membership' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM public.recording_save_group WHERE id=NEW.id OR (root_id=NEW.root_id AND request_key=NEW.request_key)) THEN
   RAISE EXCEPTION 'request key already belongs to a group' USING ERRCODE='23514';
  END IF;
  IF NEW.group_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.recording_save_group g WHERE
    g.root_id=NEW.root_id AND g.id=NEW.group_id AND g.child_ids[NEW.group_ordinal+1]=NEW.id AND
    g.scope_digest=NEW.scope_digest AND g.scope_json=NEW.scope_json AND g.accepted_at=NEW.created_at) THEN
   RAISE EXCEPTION 'unlisted group member' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION lock_capture_audit_admission(r uuid,allocation uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp();n timestamptz;until_at timestamptz;root public.capture_audit_root;trust public.fleet_current_trust;pool public.operation_audit_pool;a public.capture_audit_allocation;control public.context_control_account;
BEGIN
 IF NOT public.capture_audit_role_ok(r,'admission') THEN RAISE EXCEPTION 'capture audit admission unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.capture_audit_root WHERE root_id=r;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=root.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=r AND lane='capture' FOR UPDATE;
 SELECT * INTO STRICT a FROM public.capture_audit_allocation WHERE root_id=r AND allocation_id=allocation FOR UPDATE;
 SELECT * INTO STRICT control FROM public.context_control_account WHERE root_id=r AND allocation_id=allocation;
 n:=clock_timestamp();until_at:=LEAST(started+interval '5 seconds',root.valid_until,trust.fresh_until,pool.valid_until,a.valid_until,(a.policy->>'ValidUntil')::timestamptz);
 IF NOT COALESCE(n<until_at AND trust.observed_at<=n AND NOT trust.recovery_blocked AND NOT trust.suspended AND NOT root.paused AND NOT pool.paused AND NOT a.paused AND a.account_version=pool.account_version AND a.guaranteed_records>=control.full_limit AND a.guaranteed_records<=pool.records_per_account AND (a.policy->>'BackingRevision')::bigint=pool.revision,false) THEN RAISE EXCEPTION 'capture audit backing unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('RootID',r,'AllocationID',allocation,'AccountVersion',a.account_version,'AccountDigest',to_jsonb(ARRAY(SELECT get_byte(a.account_digest,k) FROM generate_series(0,31) k)),'Revision',a.revision,'Records',a.guaranteed_records,'RetainedSeconds',pool.retained_seconds,'Policy',a.policy,'ValidUntil',until_at);
END $$;
-- +goose StatementEnd
DROP FUNCTION recording_save_group_window_valid(public.context_capture,public.recording_save_group,timestamptz);
