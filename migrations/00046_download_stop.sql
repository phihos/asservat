-- +goose Up
-- A stop is prepaid at native-download admission. Expiry never refunds a slot.
-- Historical component sessions have no public stop protocol or invented credit.
ALTER TABLE artifact_download ADD COLUMN stop_protocol text CHECK(stop_protocol IS NULL OR stop_protocol='prepaid-download-stop/v1');
CREATE TABLE download_stop_pool (
 root_id uuid PRIMARY KEY REFERENCES permission_stream(id),
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 store_id uuid NOT NULL, policy_id uuid NOT NULL, backup_profile_id uuid NOT NULL,
 policy_digest bytea NOT NULL CHECK(octet_length(policy_digest)=32),
 backup_profile_digest bytea NOT NULL CHECK(octet_length(backup_profile_digest)=32),
 slots bigint NOT NULL CHECK(slots BETWEEN 1 AND 100000),
 cipher_bytes bigint NOT NULL CHECK(cipher_bytes>=slots*65536),
 key_attempts bigint NOT NULL CHECK(key_attempts>=slots*6),
 backup_bytes bigint NOT NULL CHECK(backup_bytes>=slots*131072),
 wal_bytes bigint NOT NULL CHECK(wal_bytes>=slots*1048576),
 retained_seconds bigint NOT NULL CHECK(retained_seconds BETWEEN 60 AND 316224000),
 backup_horizon_seconds bigint NOT NULL CHECK(backup_horizon_seconds>=0 AND backup_horizon_seconds<retained_seconds),
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 allocated bigint NOT NULL DEFAULT 0 CHECK(allocated>=0 AND allocated<=slots)
);
CREATE TABLE download_stop_backing (
 allocation_id uuid PRIMARY KEY, root_id uuid NOT NULL REFERENCES download_stop_pool(root_id),
 FOREIGN KEY(allocation_id,root_id) REFERENCES download_allocation(id,root_id),
 slots bigint NOT NULL CHECK(slots BETWEEN 1 AND 100000),
 charged bigint NOT NULL DEFAULT 0 CHECK(charged>=0 AND charged<=slots),
 UNIQUE(allocation_id,root_id)
);
CREATE TABLE download_stop (
 download_id uuid PRIMARY KEY, root_id uuid NOT NULL, allocation_id uuid NOT NULL,
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id), issuer_epoch uuid NOT NULL,
 FOREIGN KEY(download_id,root_id) REFERENCES artifact_download(id,root_id),
 FOREIGN KEY(allocation_id,root_id) REFERENCES download_stop_backing(allocation_id,root_id),
 store_id uuid NOT NULL, reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 retain_until timestamptz NOT NULL CHECK(isfinite(retain_until)),
 key_digest bytea CHECK(key_digest IS NULL OR octet_length(key_digest)=32),
 request_id uuid, requested_at timestamptz, write_until timestamptz,
 decision jsonb CHECK(decision IS NULL OR jsonb_typeof(decision)='object' AND octet_length(decision::text)<=8192),
 write_started boolean NOT NULL DEFAULT false,
 lookup_attempts bigint NOT NULL DEFAULT 0 CHECK(lookup_attempts BETWEEN 0 AND 4),
 receipt jsonb CHECK(receipt IS NULL OR jsonb_typeof(receipt)='object' AND octet_length(receipt::text)<=4096),
 CHECK((key_digest IS NULL)=(decision IS NULL) AND (request_id IS NULL)=(decision IS NULL) AND (requested_at IS NULL)=(decision IS NULL) AND (write_until IS NULL)=(decision IS NULL)),
 CHECK(write_until IS NULL OR write_until>requested_at AND write_until<=requested_at+interval '30 seconds' AND write_until<retain_until),
 CHECK(NOT write_started OR decision IS NOT NULL), CHECK(receipt IS NULL OR write_started)
);
CREATE INDEX download_stop_pending ON download_stop(root_id,write_until,download_id) WHERE decision IS NOT NULL AND receipt IS NULL;

-- +goose StatementBegin
CREATE FUNCTION guard_download_stop_pool() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'stop backing retirement requires positive proof' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NEW.allocated<>0 OR NEW.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'invalid initial stop backing' USING ERRCODE='23514';END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['allocated','revision','valid_until']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['allocated','revision','valid_until']) OR NEW.allocated<OLD.allocated OR NEW.allocated<>OLD.allocated AND (pg_trigger_depth()<2 OR NEW.revision<>OLD.revision OR NEW.valid_until<>OLD.valid_until) OR NEW.valid_until<>OLD.valid_until AND (NEW.revision<>OLD.revision+1 OR NEW.allocated<>OLD.allocated OR NEW.valid_until<=clock_timestamp()) OR NEW.valid_until=OLD.valid_until AND NEW.revision<>OLD.revision THEN RAISE EXCEPTION 'immutable stop pool and retained charge' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE FUNCTION guard_download_stop_backing() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.download_stop_pool; a public.download_allocation;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'stop allocation retirement requires positive proof' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT p FROM public.download_stop_pool WHERE root_id=NEW.root_id FOR UPDATE;
  SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id FOR SHARE;
  IF NEW.charged<>0 OR NEW.slots>a.session_limit OR NEW.slots>p.slots-p.allocated OR clock_timestamp()>=p.valid_until THEN RAISE EXCEPTION 'stop backing unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.download_stop_pool SET allocated=allocated+NEW.slots WHERE root_id=NEW.root_id;
 ELSIF (to_jsonb(NEW)-'charged') IS DISTINCT FROM (to_jsonb(OLD)-'charged') OR pg_trigger_depth()<2 OR NEW.charged<>OLD.charged+1 THEN
  RAISE EXCEPTION 'immutable stop backing and charge' USING ERRCODE='23514';
 END IF;RETURN NEW;
END $$;
CREATE FUNCTION guard_download_stop() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE d public.artifact_download; a public.download_stop_backing; p public.download_stop_pool; t public.fleet_current_trust; n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'stop retirement requires writer and backup proof' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT d FROM public.artifact_download WHERE id=NEW.download_id AND root_id=NEW.root_id;
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT a FROM public.download_stop_backing WHERE allocation_id=NEW.allocation_id AND root_id=NEW.root_id FOR UPDATE;
  SELECT * INTO STRICT p FROM public.download_stop_pool WHERE root_id=NEW.root_id;
  IF pg_trigger_depth()<2 OR d.stop_protocol<>'prepaid-download-stop/v1' OR d.allocation_id<>NEW.allocation_id OR d.state<>'Preparing' OR a.charged>=a.slots OR n>=p.valid_until OR NEW.installation_id<>p.installation_id OR NEW.store_id<>p.store_id OR NEW.retain_until<>d.deadline+make_interval(secs=>p.retained_seconds::double precision) OR NEW.decision IS NOT NULL OR NEW.write_started OR NEW.receipt IS NOT NULL OR NEW.lookup_attempts<>0 THEN RAISE EXCEPTION 'stop obligation admission unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.download_stop_backing SET charged=charged+1 WHERE allocation_id=NEW.allocation_id;
 ELSE
  IF ROW(NEW.download_id,NEW.root_id,NEW.allocation_id,NEW.installation_id,NEW.issuer_epoch,NEW.store_id,NEW.reserved_at,NEW.retain_until) IS DISTINCT FROM ROW(OLD.download_id,OLD.root_id,OLD.allocation_id,OLD.installation_id,OLD.issuer_epoch,OLD.store_id,OLD.reserved_at,OLD.retain_until) OR NEW.lookup_attempts<OLD.lookup_attempts OR NEW.lookup_attempts>OLD.lookup_attempts+1 OR NEW.lookup_attempts<>OLD.lookup_attempts AND NOT OLD.write_started OR OLD.write_started AND NOT NEW.write_started OR OLD.receipt IS NOT NULL AND NEW.receipt IS DISTINCT FROM OLD.receipt OR OLD.decision IS NOT NULL AND ROW(NEW.decision,NEW.key_digest,NEW.request_id,NEW.requested_at,NEW.write_until) IS DISTINCT FROM ROW(OLD.decision,OLD.key_digest,OLD.request_id,OLD.requested_at,OLD.write_until) THEN RAISE EXCEPTION 'immutable stop decision or spend' USING ERRCODE='23514';END IF;
  IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
   IF (SELECT count(*) FROM jsonb_object_keys(NEW.decision))<>11 OR NOT (NEW.decision ?& ARRAY['Protocol','RootID','DownloadID','RequestID','StoreID','Actor','KeyDigest','State','RequestedAt','WriteUntil','RetainUntil']) OR NEW.requested_at<NEW.reserved_at OR NEW.requested_at>n OR NEW.requested_at<n-interval '5 seconds' OR NEW.write_until<=n OR NEW.write_started OR NEW.receipt IS NOT NULL OR d.state NOT IN ('Completed','Cancelled','Expired','Denied','Failed') OR
    NEW.decision->>'Protocol'<>'prepaid-download-stop/v1' OR (NEW.decision->>'RootID')::uuid<>NEW.root_id OR (NEW.decision->>'DownloadID')::uuid<>NEW.download_id OR (NEW.decision->>'RequestID')::uuid<>NEW.request_id OR (NEW.decision->>'StoreID')::uuid<>NEW.store_id OR
    NEW.decision->'KeyDigest' IS DISTINCT FROM to_jsonb(ARRAY(SELECT get_byte(NEW.key_digest,i) FROM generate_series(0,31) AS i)) OR NEW.decision->>'State' NOT IN ('Cancelled','AlreadyTerminal') OR NEW.decision->>'State'='Cancelled' AND d.state<>'Cancelled' OR
    (NEW.decision->>'RequestedAt')::timestamptz<>NEW.requested_at OR (NEW.decision->>'WriteUntil')::timestamptz<>NEW.write_until OR (NEW.decision->>'RetainUntil')::timestamptz<>NEW.retain_until OR NEW.decision->'Actor' IS DISTINCT FROM d.scope_json->'Principal' THEN
    RAISE EXCEPTION 'invalid stop decision' USING ERRCODE='23514';END IF;
  END IF;
  IF (NOT OLD.write_started AND NEW.write_started) OR NEW.lookup_attempts<>OLD.lookup_attempts OR (OLD.receipt IS NULL AND NEW.receipt IS NOT NULL) THEN
   SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id FOR SHARE;
   n:=clock_timestamp();
   IF t.recovery_blocked OR t.suspended OR t.issuer_epoch<>NEW.issuer_epoch OR n>=t.fresh_until THEN RAISE EXCEPTION 'stop audit recovery unavailable' USING ERRCODE='23514';END IF;
  END IF;
  IF NOT OLD.write_started AND NEW.write_started AND n>=NEW.write_until THEN RAISE EXCEPTION 'stop write attempt ended' USING ERRCODE='23514';END IF;
  IF n>=NEW.retain_until THEN RAISE EXCEPTION 'stop audit retention ended' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE FUNCTION guard_download_stop_protocol() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.stop_protocol IS DISTINCT FROM OLD.stop_protocol THEN RAISE EXCEPTION 'immutable download stop protocol' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE FUNCTION reserve_download_stop() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.download_stop_pool; t public.fleet_current_trust;
BEGIN
 IF NEW.stop_protocol IS NOT NULL THEN
  SELECT * INTO STRICT p FROM public.download_stop_pool WHERE root_id=NEW.root_id;
  SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=p.installation_id FOR SHARE;
  IF t.recovery_blocked OR t.suspended OR clock_timestamp()>=t.fresh_until THEN RAISE EXCEPTION 'stop reservation recovery unavailable' USING ERRCODE='23514';END IF;
  INSERT INTO public.download_stop(download_id,root_id,allocation_id,installation_id,issuer_epoch,store_id,retain_until) VALUES(NEW.id,NEW.root_id,NEW.allocation_id,p.installation_id,t.issuer_epoch,p.store_id,NEW.deadline+make_interval(secs=>p.retained_seconds::double precision));
 END IF;RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_download_stop_protocol(),guard_download_stop_pool(),guard_download_stop_backing(),guard_download_stop(),reserve_download_stop() FROM PUBLIC;
CREATE TRIGGER download_stop_pool_guard BEFORE INSERT OR UPDATE OR DELETE ON download_stop_pool FOR EACH ROW EXECUTE FUNCTION guard_download_stop_pool();
CREATE TRIGGER download_stop_backing_guard BEFORE INSERT OR UPDATE OR DELETE ON download_stop_backing FOR EACH ROW EXECUTE FUNCTION guard_download_stop_backing();
CREATE TRIGGER download_stop_guard BEFORE INSERT OR UPDATE OR DELETE ON download_stop FOR EACH ROW EXECUTE FUNCTION guard_download_stop();
CREATE TRIGGER download_stop_protocol_guard BEFORE UPDATE ON artifact_download FOR EACH ROW EXECUTE FUNCTION guard_download_stop_protocol();
CREATE TRIGGER download_stop_reservation AFTER INSERT ON artifact_download FOR EACH ROW EXECUTE FUNCTION reserve_download_stop();

-- Existing audited metadata contracts: two additional normal operations.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_operation_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
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
   NOT (NEW.intent ?& ARRAY['ID','RootID','MACVersion','AccountVersion','Name','CreatedAt','RequestUntil','WriteUntil','RetainUntil']) OR NEW.intent->>'Name' NOT IN ('list_diagnostics','preview_capture','request_capture','resolve_capture_request','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation') OR
   (NEW.intent->>'ID')::uuid<>NEW.id OR (NEW.intent->>'RootID')::uuid<>NEW.root_id OR NEW.intent->>'AccountVersion'<>p.account_version OR
   NEW.request_until<>(NEW.intent->>'RequestUntil')::timestamptz OR NEW.write_until<>(NEW.intent->>'WriteUntil')::timestamptz OR NEW.retain_until<>(NEW.intent->>'RetainUntil')::timestamptz OR
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '5 seconds' OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
   NEW.retain_until>(NEW.intent->>'CreatedAt')::timestamptz+make_interval(secs=>p.retained_seconds::double precision) OR
   NEW.lane<>(CASE WHEN NEW.intent->>'Name'='resolve_capture_request' THEN 'resolution' ELSE 'normal' END) THEN
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
  IF NEW.intent ? 'Lifecycle' AND NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.operation_id=NEW.id AND
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
