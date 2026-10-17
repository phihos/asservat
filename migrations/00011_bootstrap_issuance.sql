-- +goose Up
ALTER TABLE fleet_bootstrap_intent
 ADD COLUMN credential_recorded_at timestamptz,
 ADD COLUMN credential_sha256 bytea CHECK(octet_length(credential_sha256)=32),
 ADD COLUMN credential_version smallint CHECK(credential_version=1),
 ADD COLUMN audit_acknowledged_at timestamptz,
 ADD COLUMN audit_digest bytea CHECK(octet_length(audit_digest)=32),
 ADD COLUMN audit_object_key text CHECK(octet_length(audit_object_key) BETWEEN 1 AND 1024),
 ADD COLUMN audit_object_version text CHECK(octet_length(audit_object_version)<=1024),
 ADD COLUMN audit_object_etag text CHECK(octet_length(audit_object_etag) BETWEEN 1 AND 256),
 ADD COLUMN audit_object_bytes bigint CHECK(audit_object_bytes BETWEEN 1 AND 131072),
 ADD COLUMN audit_object_sha256 bytea CHECK(octet_length(audit_object_sha256)=32),
 ADD COLUMN issued_at timestamptz,
 ADD CHECK((credential_recorded_at IS NULL)=(credential_sha256 IS NULL)),
 ADD CHECK((credential_recorded_at IS NULL)=(credential_version IS NULL)),
 ADD CHECK(audit_acknowledged_at IS NULL OR credential_recorded_at IS NOT NULL),
 ADD CHECK((audit_acknowledged_at IS NULL)=(audit_digest IS NULL)),
 ADD CHECK((audit_acknowledged_at IS NULL)=(audit_object_key IS NULL)),
 ADD CHECK((audit_acknowledged_at IS NULL)=(audit_object_version IS NULL)),
 ADD CHECK((audit_acknowledged_at IS NULL)=(audit_object_etag IS NULL)),
 ADD CHECK((audit_acknowledged_at IS NULL)=(audit_object_bytes IS NULL)),
 ADD CHECK((audit_acknowledged_at IS NULL)=(audit_object_sha256 IS NULL)),
 ADD CHECK(issued_at IS NULL OR (audit_acknowledged_at IS NOT NULL AND issued_at>=not_before AND issued_at<not_after));
ALTER TABLE fleet_bootstrap DROP CONSTRAINT fleet_bootstrap_issue_audit_version_check;
ALTER TABLE fleet_bootstrap ADD CHECK(octet_length(issue_audit_version)<=1024);

-- +goose StatementBegin
CREATE FUNCTION guard_bootstrap_issuance() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.credential_recorded_at IS NOT NULL OR NEW.audit_acknowledged_at IS NOT NULL OR NEW.issued_at IS NOT NULL THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='bootstrap intent must start unissued';
  END IF;
  RETURN NEW;
 END IF;
 IF (OLD.credential_recorded_at IS NOT NULL AND ROW(NEW.credential_recorded_at,NEW.credential_sha256,NEW.credential_version)
 IS DISTINCT FROM ROW(OLD.credential_recorded_at,OLD.credential_sha256,OLD.credential_version))
 OR (OLD.audit_acknowledged_at IS NOT NULL AND ROW(NEW.audit_acknowledged_at,NEW.audit_digest,NEW.audit_object_key,NEW.audit_object_version,NEW.audit_object_etag,NEW.audit_object_bytes,NEW.audit_object_sha256)
 IS DISTINCT FROM ROW(OLD.audit_acknowledged_at,OLD.audit_digest,OLD.audit_object_key,OLD.audit_object_version,OLD.audit_object_etag,OLD.audit_object_bytes,OLD.audit_object_sha256))
 OR (OLD.issued_at IS NOT NULL AND NEW.issued_at IS DISTINCT FROM OLD.issued_at) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='bootstrap issuance receipts are immutable';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER bootstrap_issuance_guard BEFORE INSERT OR UPDATE ON fleet_bootstrap_intent
 FOR EACH ROW EXECUTE FUNCTION guard_bootstrap_issuance();
