-- +goose Up
-- Two finite, nonrefundable provider attempts per original bootstrap. Public
-- certificate DER is minimized control metadata; no private key is stored.
CREATE TABLE fleet_certificate_issue (
 installation_id uuid NOT NULL,
 bootstrap_id uuid NOT NULL,
 ordinal smallint NOT NULL CHECK(ordinal IN (1,2)),
 id uuid NOT NULL,
 trust_uid text NOT NULL CHECK(octet_length(trust_uid) BETWEEN 1 AND 64),
 trust_generation bigint NOT NULL CHECK(trust_generation BETWEEN 1 AND 2147483647),
 trust_digest bytea NOT NULL CHECK(octet_length(trust_digest)=32),
 started_at timestamptz NOT NULL,
 sign_before timestamptz NOT NULL,
 CHECK(sign_before>started_at AND sign_before<=started_at+interval '5 seconds'),
 signed_at timestamptz,
 certificate_json bytea CHECK(octet_length(certificate_json) BETWEEN 1 AND 49152),
 certificate_sha256 bytea CHECK(octet_length(certificate_sha256)=32),
 certificate_not_before timestamptz,
 certificate_not_after timestamptz,
 CHECK((signed_at IS NULL)=(certificate_json IS NULL)),
 CHECK((signed_at IS NULL)=(certificate_sha256 IS NULL)),
 CHECK((signed_at IS NULL)=(certificate_not_before IS NULL)),
 CHECK((signed_at IS NULL)=(certificate_not_after IS NULL)),
 CHECK(signed_at IS NULL OR (signed_at>=started_at AND signed_at<sign_before)),
 CHECK(certificate_not_after>certificate_not_before AND certificate_not_after<=certificate_not_before+interval '1 hour'),
 audit_acknowledged_at timestamptz,
 audit_digest bytea CHECK(octet_length(audit_digest)=32),
 audit_object_key text CHECK(octet_length(audit_object_key) BETWEEN 1 AND 1024),
 audit_object_version text CHECK(octet_length(audit_object_version)<=1024),
 audit_object_etag text CHECK(octet_length(audit_object_etag) BETWEEN 1 AND 256),
 audit_object_bytes bigint CHECK(audit_object_bytes BETWEEN 1 AND 131072),
 audit_object_sha256 bytea CHECK(octet_length(audit_object_sha256)=32),
 CHECK(audit_acknowledged_at IS NULL OR signed_at IS NOT NULL),
 CHECK((audit_acknowledged_at IS NULL)=(audit_digest IS NULL)),
 CHECK((audit_acknowledged_at IS NULL)=(audit_object_key IS NULL)),
 CHECK((audit_acknowledged_at IS NULL)=(audit_object_version IS NULL)),
 CHECK((audit_acknowledged_at IS NULL)=(audit_object_etag IS NULL)),
 CHECK((audit_acknowledged_at IS NULL)=(audit_object_bytes IS NULL)),
 CHECK((audit_acknowledged_at IS NULL)=(audit_object_sha256 IS NULL)),
 activated_at timestamptz,
 CHECK(activated_at IS NULL OR audit_acknowledged_at IS NOT NULL),
 PRIMARY KEY(installation_id,bootstrap_id,ordinal),
 UNIQUE(installation_id,id),
 FOREIGN KEY(installation_id,bootstrap_id) REFERENCES fleet_bootstrap(installation_id,id)
);

-- Empty version is meaningful on a qualified unversioned backend. Exact
-- authenticated key/digest and immutable ciphertext remain required.
ALTER TABLE fleet_peer DROP CONSTRAINT fleet_peer_audit_object_version_check;
ALTER TABLE fleet_peer ADD CHECK(octet_length(audit_object_version)<=1024);

-- +goose StatementBegin
CREATE FUNCTION guard_certificate_issue() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.signed_at IS NOT NULL OR NEW.audit_acknowledged_at IS NOT NULL OR NEW.activated_at IS NOT NULL THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='certificate issue must start unsigned';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.installation_id,NEW.bootstrap_id,NEW.ordinal,NEW.id,NEW.trust_uid,NEW.trust_generation,NEW.trust_digest,NEW.started_at,NEW.sign_before)
    IS DISTINCT FROM ROW(OLD.installation_id,OLD.bootstrap_id,OLD.ordinal,OLD.id,OLD.trust_uid,OLD.trust_generation,OLD.trust_digest,OLD.started_at,OLD.sign_before)
    OR (OLD.signed_at IS NOT NULL AND ROW(NEW.signed_at,NEW.certificate_json,NEW.certificate_sha256,NEW.certificate_not_before,NEW.certificate_not_after)
    IS DISTINCT FROM ROW(OLD.signed_at,OLD.certificate_json,OLD.certificate_sha256,OLD.certificate_not_before,OLD.certificate_not_after))
    OR (OLD.audit_acknowledged_at IS NOT NULL AND ROW(NEW.audit_acknowledged_at,NEW.audit_digest,NEW.audit_object_key,NEW.audit_object_version,NEW.audit_object_etag,NEW.audit_object_bytes,NEW.audit_object_sha256)
    IS DISTINCT FROM ROW(OLD.audit_acknowledged_at,OLD.audit_digest,OLD.audit_object_key,OLD.audit_object_version,OLD.audit_object_etag,OLD.audit_object_bytes,OLD.audit_object_sha256))
    OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='certificate issue history is immutable';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER certificate_issue_guard BEFORE INSERT OR UPDATE ON fleet_certificate_issue
 FOR EACH ROW EXECUTE FUNCTION guard_certificate_issue();
