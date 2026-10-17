-- +goose Up
-- Semantic verification and public-catalog authority are separate from the
-- generic ciphertext custody status. Neither table contains native evidence.
ALTER TABLE context_capture ADD CONSTRAINT context_capture_root_identity UNIQUE(id,root_id);
CREATE TABLE context_verification (
 capture_id uuid PRIMARY KEY, root_id uuid NOT NULL,
 FOREIGN KEY(capture_id,root_id) REFERENCES context_capture(id,root_id),
 expectation_digest bytea NOT NULL CHECK(octet_length(expectation_digest)=32),
 copies_digest bytea NOT NULL CHECK(octet_length(copies_digest)=32),
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
 authority_digest bytea NOT NULL CHECK(octet_length(authority_digest)=32),
 permission_epoch uuid NOT NULL, permission_sequence bigint NOT NULL CHECK(permission_sequence>0),
 verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 audit_acknowledged_at timestamptz,
 audit_digest bytea CHECK(octet_length(audit_digest)=32),
 audit_object_key text CHECK(octet_length(audit_object_key) BETWEEN 1 AND 256),
 audit_object_version text CHECK(octet_length(audit_object_version)<=1024),
 audit_object_etag text CHECK(octet_length(audit_object_etag) BETWEEN 1 AND 256),
 audit_object_bytes bigint CHECK(audit_object_bytes BETWEEN 1 AND 131072),
 audit_object_sha256 bytea CHECK(octet_length(audit_object_sha256)=32),
 CHECK ((audit_acknowledged_at IS NULL)=(audit_digest IS NULL) AND
 (audit_acknowledged_at IS NULL)=(audit_object_key IS NULL) AND
 (audit_acknowledged_at IS NULL)=(audit_object_version IS NULL) AND
 (audit_acknowledged_at IS NULL)=(audit_object_etag IS NULL) AND
 (audit_acknowledged_at IS NULL)=(audit_object_bytes IS NULL) AND
 (audit_acknowledged_at IS NULL)=(audit_object_sha256 IS NULL))
);
-- +goose StatementBegin
CREATE FUNCTION protect_context_verification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.capture_id,NEW.root_id,NEW.expectation_digest,NEW.copies_digest,NEW.intent_digest,NEW.authority_digest,NEW.permission_epoch,NEW.permission_sequence,NEW.verified_at) IS DISTINCT FROM
 ROW(OLD.capture_id,OLD.root_id,OLD.expectation_digest,OLD.copies_digest,OLD.intent_digest,OLD.authority_digest,OLD.permission_epoch,OLD.permission_sequence,OLD.verified_at) THEN
  RAISE EXCEPTION 'immutable context verification' USING ERRCODE='23514';
 END IF;
 IF OLD.audit_acknowledged_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'immutable context verification audit' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER context_verification_immutable BEFORE UPDATE ON context_verification FOR EACH ROW EXECUTE FUNCTION protect_context_verification();

CREATE TABLE context_catalog (
 artifact_id uuid PRIMARY KEY,
 capture_id uuid NOT NULL UNIQUE REFERENCES context_verification(capture_id),
 root_id uuid NOT NULL,
 FOREIGN KEY(capture_id,root_id) REFERENCES context_capture(id,root_id),
 published_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX context_catalog_by_root ON context_catalog(root_id,published_at,artifact_id);
