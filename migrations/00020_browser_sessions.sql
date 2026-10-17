-- +goose Up
-- Protected bootstrap creates the root/epoch and finite ceilings. Runtime
-- credentials cannot create/change this configuration. Restore rotates epoch.
CREATE TABLE browser_session_root (
 id uuid PRIMARY KEY,
 epoch uuid NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 max_logins integer NOT NULL CHECK(max_logins BETWEEN 1 AND 10000),
 max_sessions integer NOT NULL CHECK(max_sessions BETWEEN 1 AND 100000),
 max_logout_events integer NOT NULL CHECK(max_logout_events BETWEEN 1 AND 100000)
);
CREATE TABLE browser_login (
 root_id uuid NOT NULL REFERENCES browser_session_root(id),
 epoch uuid NOT NULL,
 id bytea NOT NULL CHECK(octet_length(id)=32),
 browser bytea NOT NULL CHECK(octet_length(browser)=32),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 1 AND 262144),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(root_id,id),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
);
CREATE INDEX browser_login_expiry ON browser_login(root_id,expires_at);
CREATE TABLE browser_session (
 root_id uuid NOT NULL REFERENCES browser_session_root(id),
 epoch uuid NOT NULL,
 id bytea NOT NULL CHECK(octet_length(id)=32),
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 client_id text NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 256),
 subject text NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 256),
 provider_session text NOT NULL CHECK(octet_length(provider_session) BETWEEN 1 AND 256),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 1 AND 262144),
 created_at timestamptz NOT NULL,
 authenticated_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 refresh_at timestamptz NOT NULL,
 version bigint NOT NULL CHECK(version>0),
 refresh_claim bytea CHECK(refresh_claim IS NULL OR octet_length(refresh_claim)=32),
 claim_until timestamptz,
 PRIMARY KEY(root_id,id),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours'),
 CHECK(authenticated_at<=created_at),
 CHECK(refresh_at>created_at AND refresh_at<=expires_at),
 CHECK((refresh_claim IS NULL)=(claim_until IS NULL))
);
CREATE INDEX browser_session_expiry ON browser_session(root_id,expires_at);
CREATE INDEX browser_session_subject ON browser_session(root_id,issuer,client_id,subject);
CREATE INDEX browser_session_provider ON browser_session(root_id,issuer,client_id,provider_session);
CREATE TABLE browser_logout (
 root_id uuid NOT NULL REFERENCES browser_session_root(id),
 epoch uuid NOT NULL,
 id bytea NOT NULL CHECK(octet_length(id)=32),
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 client_id text NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 256),
 subject text NOT NULL CHECK(octet_length(subject)<=256),
 provider_session text NOT NULL CHECK(octet_length(provider_session)<=256),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(root_id,id),
 CHECK(subject<>'' OR provider_session<>''),
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '25 hours')
);
CREATE INDEX browser_logout_expiry ON browser_logout(root_id,expires_at);
-- Credentials are short-lived operational state, never immutable evidence.
-- No down migration may restore consumed login/refresh credentials.
