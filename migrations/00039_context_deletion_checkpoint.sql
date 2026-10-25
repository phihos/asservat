-- +goose Up
-- Historical rows deliberately have no positive writer protocol or completion.
ALTER TABLE context_execution ADD COLUMN writer_protocol text
 CHECK(writer_protocol IS NULL OR writer_protocol='closed-small-context/v1');
CREATE TABLE context_writer_completion (
 capture_id uuid PRIMARY KEY REFERENCES context_execution(capture_id),
 root_id uuid NOT NULL, attempt_id uuid NOT NULL UNIQUE REFERENCES custody_attempt(id),
 FOREIGN KEY(capture_id,root_id) REFERENCES context_capture(id,root_id),
 registration_digest bytea NOT NULL CHECK(octet_length(registration_digest)=32),
 expectation_digest bytea NOT NULL CHECK(octet_length(expectation_digest)=32),
 copies_digest bytea NOT NULL CHECK(octet_length(copies_digest)=32),
 execution_digest bytea NOT NULL CHECK(octet_length(execution_digest)=32),
 completion_digest bytea NOT NULL CHECK(octet_length(completion_digest)=32),
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id), issuer_epoch uuid NOT NULL,
 postmaster_at timestamptz NOT NULL CHECK(isfinite(postmaster_at)), database_oid oid NOT NULL,
 stored_at timestamptz NOT NULL CHECK(isfinite(stored_at)),
 closed_at timestamptz NOT NULL CHECK(isfinite(closed_at) AND closed_at>=stored_at),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE context_deletion_checkpoint (
 attempt_id uuid PRIMARY KEY REFERENCES context_writer_completion(attempt_id),
 root_id uuid NOT NULL, capture_id uuid NOT NULL UNIQUE REFERENCES context_writer_completion(capture_id),
 FOREIGN KEY(capture_id,root_id) REFERENCES context_capture(id,root_id),
 store_id uuid NOT NULL,
 registration_digest bytea NOT NULL CHECK(octet_length(registration_digest)=32),
 writer_digest bytea NOT NULL CHECK(octet_length(writer_digest)=32),
 record_digest bytea NOT NULL CHECK(octet_length(record_digest)=32),
 record_json bytea NOT NULL CHECK(octet_length(record_json) BETWEEN 1 AND 8192),
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id), issuer_epoch uuid NOT NULL,
 postmaster_at timestamptz NOT NULL CHECK(isfinite(postmaster_at)), database_oid oid NOT NULL,
 purge_fence bigint NOT NULL CHECK(purge_fence>0),
 purged_at timestamptz NOT NULL CHECK(isfinite(purged_at)),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 audit_receipt_json bytea CHECK(audit_receipt_json IS NULL OR octet_length(audit_receipt_json) BETWEEN 1 AND 8192),
 audit_acknowledged_at timestamptz,
 finalization_xid xid8,
 CHECK((audit_receipt_json IS NULL)=(audit_acknowledged_at IS NULL))
);
-- +goose StatementBegin
CREATE FUNCTION guard_context_writer_protocol() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.writer_protocol IS DISTINCT FROM 'closed-small-context/v1' THEN
  RAISE EXCEPTION 'new API executions require positive writer protocol' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.writer_protocol IS DISTINCT FROM OLD.writer_protocol THEN
  RAISE EXCEPTION 'immutable writer protocol' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_writer_protocol() FROM PUBLIC;
CREATE TRIGGER context_writer_protocol_guard BEFORE INSERT OR UPDATE ON context_execution FOR EACH ROW EXECUTE FUNCTION guard_context_writer_protocol();
-- +goose StatementBegin
CREATE FUNCTION guard_context_writer_completion() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE e public.context_execution; a public.custody_attempt;
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_writer_completion'::regclass OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'immutable writer completion' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT e FROM public.context_execution WHERE capture_id=NEW.capture_id AND root_id=NEW.root_id;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 IF e.writer_protocol IS DISTINCT FROM 'closed-small-context/v1' OR e.phase<>'stored' OR a.state IN ('deleting','deleted') OR e.attempt_id<>a.id OR e.expectation_digest<>NEW.expectation_digest OR e.copies_digest<>NEW.copies_digest OR a.request_digest<>NEW.registration_digest OR (convert_from(e.process_json,'UTF8')::jsonb)->>'InstallationID' IS DISTINCT FROM NEW.installation_id::text OR (convert_from(e.process_json,'UTF8')::jsonb)->>'IssuerEpoch' IS DISTINCT FROM NEW.issuer_epoch::text OR e.completed_at<>NEW.stored_at OR NEW.closed_at>clock_timestamp() OR NEW.recorded_at>clock_timestamp() OR NEW.stored_at>=a.write_until OR NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id AND issuer_epoch=NEW.issuer_epoch AND NOT recovery_blocked AND NOT suspended AND fresh_until>clock_timestamp()) THEN
  RAISE EXCEPTION 'writer completion lacks exact positive execution' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_writer_completion() FROM PUBLIC;
CREATE TRIGGER context_writer_completion_guard BEFORE INSERT OR UPDATE OR DELETE ON context_writer_completion FOR EACH ROW EXECUTE FUNCTION guard_context_writer_completion();
-- +goose StatementBegin
CREATE FUNCTION require_context_writer_completion() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_execution'::regclass OR TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'invalid writer source' USING ERRCODE='23514'; END IF;
 IF NEW.writer_protocol='closed-small-context/v1' AND NEW.phase='stored' AND NOT EXISTS(SELECT 1 FROM public.context_writer_completion WHERE capture_id=NEW.capture_id AND root_id=NEW.root_id AND attempt_id=NEW.attempt_id AND copies_digest=NEW.copies_digest) THEN
  RAISE EXCEPTION 'positive stored outcome requires joined writer completion' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_context_writer_completion() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER context_writer_completion_required AFTER UPDATE ON context_execution DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_context_writer_completion();
-- +goose StatementBegin
CREATE FUNCTION guard_context_deletion_checkpoint() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w public.context_writer_completion; a public.custody_attempt;
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_deletion_checkpoint'::regclass OR TG_OP='DELETE' THEN RAISE EXCEPTION 'invalid deletion checkpoint change' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.attempt_id,NEW.root_id,NEW.capture_id,NEW.store_id,NEW.registration_digest,NEW.writer_digest,NEW.record_digest,NEW.record_json,NEW.installation_id,NEW.issuer_epoch,NEW.postmaster_at,NEW.database_oid,NEW.purge_fence,NEW.purged_at,NEW.recorded_at) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.root_id,OLD.capture_id,OLD.store_id,OLD.registration_digest,OLD.writer_digest,OLD.record_digest,OLD.record_json,OLD.installation_id,OLD.issuer_epoch,OLD.postmaster_at,OLD.database_oid,OLD.purge_fence,OLD.purged_at,OLD.recorded_at) OR OLD.audit_acknowledged_at IS NOT NULL AND ROW(NEW.audit_receipt_json,NEW.audit_acknowledged_at) IS DISTINCT FROM ROW(OLD.audit_receipt_json,OLD.audit_acknowledged_at) THEN RAISE EXCEPTION 'immutable deletion result and audit' USING ERRCODE='23514'; END IF;

  IF OLD.finalization_xid IS NOT NULL AND NEW.finalization_xid IS DISTINCT FROM OLD.finalization_xid OR NEW.finalization_xid IS DISTINCT FROM OLD.finalization_xid AND (OLD.audit_acknowledged_at IS NULL OR NEW.finalization_xid IS DISTINCT FROM pg_current_xact_id()) THEN RAISE EXCEPTION 'invalid one-use finalization transaction' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT * INTO STRICT w FROM public.context_writer_completion WHERE attempt_id=NEW.attempt_id;
  SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
  IF w.root_id<>NEW.root_id OR w.capture_id<>NEW.capture_id OR w.completion_digest<>NEW.writer_digest OR w.registration_digest<>NEW.registration_digest OR w.installation_id<>NEW.installation_id OR w.issuer_epoch<>NEW.issuer_epoch OR w.postmaster_at<>NEW.postmaster_at OR w.database_oid<>NEW.database_oid OR a.request_digest<>NEW.registration_digest OR a.state<>'deleting' OR a.deletion_fence<>NEW.purge_fence OR a.lease_until<=clock_timestamp() OR NEW.purged_at<a.effective_expires_at OR NEW.purged_at<w.closed_at OR NEW.purged_at>clock_timestamp() OR NEW.audit_acknowledged_at IS NOT NULL OR NEW.audit_receipt_json IS NOT NULL OR NEW.finalization_xid IS NOT NULL OR NOT EXISTS(SELECT 1 FROM public.custody_allocation ca JOIN public.custody_pool cp ON cp.id=ca.pool_id WHERE ca.id=a.allocation_id AND cp.store_id=NEW.store_id) THEN RAISE EXCEPTION 'deletion result lacks exact fenced purge' USING ERRCODE='23514'; END IF;
 END IF;
 IF NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id AND issuer_epoch=NEW.issuer_epoch AND NOT recovery_blocked AND NOT suspended AND fresh_until>clock_timestamp()) THEN RAISE EXCEPTION 'deletion checkpoint incarnation unavailable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_deletion_checkpoint() FROM PUBLIC;
CREATE TRIGGER context_deletion_checkpoint_guard BEFORE INSERT OR UPDATE OR DELETE ON context_deletion_checkpoint FOR EACH ROW EXECUTE FUNCTION guard_context_deletion_checkpoint();
-- +goose StatementBegin
CREATE FUNCTION require_audited_context_deletion() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE d public.context_deletion_checkpoint; f public.fleet_current_trust;
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.custody_attempt'::regclass OR TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'invalid deletion source' USING ERRCODE='23514'; END IF;
 IF NEW.state<>'deleted' OR OLD.state='deleted' OR NOT EXISTS(SELECT 1 FROM public.context_execution WHERE attempt_id=NEW.id AND writer_protocol='closed-small-context/v1') THEN RETURN NEW; END IF;
 SELECT * INTO d FROM public.context_deletion_checkpoint WHERE attempt_id=NEW.id AND audit_acknowledged_at IS NOT NULL;
 IF NOT FOUND OR OLD.state<>'deleting' OR d.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR d.registration_digest<>NEW.request_digest OR d.purge_fence>NEW.deletion_fence THEN
  RAISE EXCEPTION 'positive context deletion requires independent acknowledged audit' USING ERRCODE='23514';
 END IF;
 -- Only the dedicated finalizer may set the transaction-local persisted marker.
 -- It holds recovery first; legacy/direct mutation fails above before acquiring
 -- a reverse-order lock. Recheck the exact already-held recovery row here.
 SELECT * INTO f FROM public.fleet_current_trust WHERE installation_id=d.installation_id FOR SHARE;
 IF NOT FOUND OR d.issuer_epoch<>f.issuer_epoch OR f.recovery_blocked OR f.suspended OR f.fresh_until<=clock_timestamp() OR NOT public.incarnation_current(d.postmaster_at) OR d.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) THEN
  RAISE EXCEPTION 'positive context deletion requires current incarnation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_audited_context_deletion() FROM PUBLIC;
CREATE TRIGGER custody_context_deletion_guard BEFORE UPDATE ON custody_attempt FOR EACH ROW EXECUTE FUNCTION require_audited_context_deletion();

-- +goose StatementBegin
CREATE FUNCTION require_completed_context_finalization() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_deletion_checkpoint'::regclass OR TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'invalid finalization source' USING ERRCODE='23514'; END IF;
 IF NEW.finalization_xid IS NOT NULL AND OLD.finalization_xid IS NULL AND (NEW.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR NOT EXISTS(SELECT 1 FROM public.custody_attempt WHERE id=NEW.attempt_id AND state='deleted')) THEN
  RAISE EXCEPTION 'finalization marker requires same-transaction deletion' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_completed_context_finalization() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER context_finalization_completed AFTER UPDATE ON context_deletion_checkpoint DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_completed_context_finalization();
