-- +goose Up
ALTER TABLE fleet_bootstrap
 ADD COLUMN claim_acknowledged_at timestamptz,
 ADD COLUMN claim_audit_digest bytea CHECK(octet_length(claim_audit_digest)=32),
 ADD COLUMN claim_object_key text CHECK(octet_length(claim_object_key) BETWEEN 1 AND 1024),
 ADD COLUMN claim_object_version text CHECK(octet_length(claim_object_version)<=1024),
 ADD COLUMN claim_object_etag text CHECK(octet_length(claim_object_etag) BETWEEN 1 AND 256),
 ADD COLUMN claim_object_bytes bigint CHECK(claim_object_bytes BETWEEN 1 AND 131072),
 ADD COLUMN claim_object_sha256 bytea CHECK(octet_length(claim_object_sha256)=32),
 ADD CHECK(claim_acknowledged_at IS NULL OR claimed_at IS NOT NULL),
 ADD CHECK((claim_acknowledged_at IS NULL)=(claim_audit_digest IS NULL)),
 ADD CHECK((claim_acknowledged_at IS NULL)=(claim_object_key IS NULL)),
 ADD CHECK((claim_acknowledged_at IS NULL)=(claim_object_version IS NULL)),
 ADD CHECK((claim_acknowledged_at IS NULL)=(claim_object_etag IS NULL)),
 ADD CHECK((claim_acknowledged_at IS NULL)=(claim_object_bytes IS NULL)),
 ADD CHECK((claim_acknowledged_at IS NULL)=(claim_object_sha256 IS NULL));

-- +goose StatementBegin
CREATE FUNCTION guard_enrollment_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.claim_acknowledged_at IS NOT NULL AND
    ROW(NEW.claim_acknowledged_at,NEW.claim_audit_digest,NEW.claim_object_key,NEW.claim_object_version,
        NEW.claim_object_etag,NEW.claim_object_bytes,NEW.claim_object_sha256)
    IS DISTINCT FROM
    ROW(OLD.claim_acknowledged_at,OLD.claim_audit_digest,OLD.claim_object_key,OLD.claim_object_version,
        OLD.claim_object_etag,OLD.claim_object_bytes,OLD.claim_object_sha256) THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='enrollment audit receipt is immutable';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER enrollment_receipt_guard BEFORE UPDATE ON fleet_bootstrap
 FOR EACH ROW EXECUTE FUNCTION guard_enrollment_receipt();
