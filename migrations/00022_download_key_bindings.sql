-- +goose Up
-- Private, finite child authority of an already prepaid and audited download
-- batch. This is not a permission configuration resource or a bearer grant.
CREATE TABLE download_key_binding (
 batch_id uuid PRIMARY KEY REFERENCES download_batch(id),
 session_id uuid NOT NULL REFERENCES artifact_download(id),
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 key_id text NOT NULL CHECK(key_id ~ '^[a-zA-Z0-9_-]{1,128}$'),
 peer_id uuid NOT NULL,
 certificate_sha256 bytea NOT NULL CHECK(octet_length(certificate_sha256)=32),
 authority_json bytea NOT NULL CHECK(octet_length(authority_json) BETWEEN 1 AND 65536),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 valid_until timestamptz NOT NULL,
 used_roles smallint NOT NULL DEFAULT 0 CHECK(used_roles BETWEEN 0 AND 7),
 CHECK(valid_until>created_at AND valid_until<=created_at+interval '5 seconds')
);
-- +goose StatementBegin
CREATE FUNCTION guard_download_key_spend() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.used_roles & OLD.used_roles) <> OLD.used_roles THEN
  RAISE EXCEPTION 'download key spend cannot decrease';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER download_key_spend BEFORE UPDATE ON download_key_binding
FOR EACH ROW EXECUTE FUNCTION guard_download_key_spend();
-- Rows share the bounded parent batch history and never restore spent slots.
-- No destructive down: retained accounting needs reviewed retirement.
