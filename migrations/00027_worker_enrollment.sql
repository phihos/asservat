-- +goose Up
CREATE TABLE download_worker_enrollment (
 worker_id uuid PRIMARY KEY REFERENCES download_worker(id),
 enrollment_json bytea NOT NULL CHECK(octet_length(enrollment_json) BETWEEN 1 AND 32768),
 audit_receipt_json bytea CHECK(octet_length(audit_receipt_json) BETWEEN 1 AND 8192)
);
CREATE TABLE download_worker_certificate (
 id uuid PRIMARY KEY,
 worker_id uuid NOT NULL REFERENCES download_worker_enrollment(worker_id),
 epoch integer NOT NULL CHECK(epoch BETWEEN 0 AND 23),
 ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 2),
 attempt_json bytea NOT NULL CHECK(octet_length(attempt_json) BETWEEN 1 AND 65536),
 certificate_json bytea CHECK(octet_length(certificate_json) BETWEEN 1 AND 49152),
 certificate_sha256 bytea CHECK(octet_length(certificate_sha256)=32),
 audit_receipt_json bytea CHECK(octet_length(audit_receipt_json) BETWEEN 1 AND 8192),
 activated_at timestamptz,
 CHECK((certificate_json IS NULL)=(certificate_sha256 IS NULL)),
 CHECK(audit_receipt_json IS NULL OR certificate_json IS NOT NULL),
 CHECK(activated_at IS NULL OR audit_receipt_json IS NOT NULL),
 UNIQUE(worker_id,epoch,ordinal)
);
CREATE UNIQUE INDEX download_worker_certificate_digest ON download_worker_certificate(certificate_sha256) WHERE certificate_sha256 IS NOT NULL;
-- +goose StatementBegin
CREATE FUNCTION guard_worker_enrollment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.worker_id,NEW.enrollment_json) IS DISTINCT FROM ROW(OLD.worker_id,OLD.enrollment_json)
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json) THEN
  RAISE EXCEPTION 'worker enrollment and acknowledged audit are immutable';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER worker_enrollment_guard BEFORE UPDATE ON download_worker_enrollment FOR EACH ROW EXECUTE FUNCTION guard_worker_enrollment();
-- +goose StatementBegin
CREATE FUNCTION guard_worker_certificate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.worker_id,NEW.epoch,NEW.ordinal,NEW.attempt_json) IS DISTINCT FROM ROW(OLD.id,OLD.worker_id,OLD.epoch,OLD.ordinal,OLD.attempt_json)
 OR (OLD.certificate_json IS NOT NULL AND ROW(NEW.certificate_json,NEW.certificate_sha256) IS DISTINCT FROM ROW(OLD.certificate_json,OLD.certificate_sha256))
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json) THEN
  RAISE EXCEPTION 'worker certificate attempt and consumed results are immutable';
 END IF;
 IF OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at THEN
  RAISE EXCEPTION 'worker certificate activation is immutable';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER worker_certificate_guard BEFORE UPDATE ON download_worker_certificate FOR EACH ROW EXECUTE FUNCTION guard_worker_certificate();
-- No destructive down or expiry-based allowance reset.
