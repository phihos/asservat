-- +goose Up
-- Browser configuration is Kubernetes-owned. A missing/stale projection must
-- not preserve the fixture-era boolean as permission to use a session.
ALTER TABLE browser_session_root
 ADD COLUMN source_uid text CHECK(source_uid IS NULL OR octet_length(source_uid) BETWEEN 1 AND 64),
 ADD COLUMN source_generation bigint CHECK(source_generation IS NULL OR source_generation BETWEEN 1 AND 2147483647),
 ADD COLUMN source_digest bytea CHECK(source_digest IS NULL OR octet_length(source_digest)=32),
 ADD COLUMN observed_at timestamptz,
 ADD COLUMN fresh_until timestamptz,
 ADD COLUMN issuer text CHECK(issuer IS NULL OR octet_length(issuer) BETWEEN 1 AND 2048),
 ADD COLUMN client_id text CHECK(client_id IS NULL OR octet_length(client_id) BETWEEN 1 AND 256),
 ADD COLUMN origin text CHECK(origin IS NULL OR octet_length(origin) BETWEEN 1 AND 2048),
 ADD COLUMN max_lifetime_seconds integer CHECK(max_lifetime_seconds IS NULL OR max_lifetime_seconds BETWEEN 60 AND 86400),
 ADD CONSTRAINT browser_settings_complete CHECK(
  (source_uid IS NULL AND source_generation IS NULL AND source_digest IS NULL AND observed_at IS NULL AND fresh_until IS NULL AND issuer IS NULL AND client_id IS NULL AND origin IS NULL AND max_lifetime_seconds IS NULL) OR
  (source_uid IS NOT NULL AND source_generation IS NOT NULL AND source_digest IS NOT NULL AND observed_at IS NOT NULL AND fresh_until IS NOT NULL AND issuer IS NOT NULL AND client_id IS NOT NULL AND origin IS NOT NULL AND max_lifetime_seconds IS NOT NULL AND fresh_until>observed_at AND fresh_until<=observed_at+interval '5 seconds')
 );
UPDATE browser_session_root SET enabled=false;
CREATE TABLE browser_session_epoch (
 root_id uuid NOT NULL REFERENCES browser_session_root(id),
 epoch uuid NOT NULL,
 source_generation bigint NOT NULL CHECK(source_generation BETWEEN 0 AND 2147483647),
 PRIMARY KEY(root_id,epoch)
);
INSERT INTO browser_session_epoch(root_id,epoch,source_generation) SELECT id,epoch,0 FROM browser_session_root;
-- Existing unqualified roots are fenced. Their ephemeral login/session state
-- is revoked on the first qualified settings acceptance; evidence is untouched.
