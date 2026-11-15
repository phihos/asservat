-- +goose Up
-- ADR-335 D8: browser sessions without roots, epochs, a settings projection or
-- count caps. A session ends at created_at plus the configured maximum
-- lifetime or after the inactivity timeout since last_used_at. Existing
-- login and session state is dropped; users sign in again.
DROP FUNCTION IF EXISTS guard_browser_session_owner_capacity() CASCADE;
DROP TABLE IF EXISTS browser_logout, browser_session, browser_login, browser_session_epoch, browser_session_root;
CREATE TABLE browser_login (
 id bytea PRIMARY KEY CHECK(octet_length(id)=32),
 browser bytea NOT NULL CHECK(octet_length(browser)=32),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 1 AND 262144),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
);
CREATE INDEX browser_login_expiry ON browser_login(expires_at);
CREATE TABLE browser_session (
 id bytea PRIMARY KEY CHECK(octet_length(id)=32),
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 client_id text NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 256),
 subject text NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 256),
 provider_session text NOT NULL CHECK(octet_length(provider_session) BETWEEN 1 AND 256),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 1 AND 262144),
 created_at timestamptz NOT NULL,
 authenticated_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 last_used_at timestamptz NOT NULL,
 refresh_at timestamptz NOT NULL,
 version bigint NOT NULL CHECK(version>0),
 refresh_claim bytea CHECK(refresh_claim IS NULL OR octet_length(refresh_claim)=32),
 claim_until timestamptz,
 CHECK(expires_at>created_at),
 CHECK(authenticated_at<=created_at),
 CHECK(refresh_at>created_at AND refresh_at<=expires_at),
 CHECK((refresh_claim IS NULL)=(claim_until IS NULL))
);
CREATE INDEX browser_session_expiry ON browser_session(expires_at);
CREATE INDEX browser_session_subject ON browser_session(issuer,client_id,subject);
CREATE INDEX browser_session_provider ON browser_session(issuer,client_id,provider_session);
CREATE TABLE browser_logout (
 id bytea PRIMARY KEY CHECK(octet_length(id)=32),
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 client_id text NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 256),
 subject text NOT NULL CHECK(octet_length(subject)<=256),
 provider_session text NOT NULL CHECK(octet_length(provider_session)<=256),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 CHECK(subject<>'' OR provider_session<>''),
 CHECK(expires_at>issued_at)
);
CREATE INDEX browser_logout_expiry ON browser_logout(expires_at);
-- No Down: session roots and epochs are not restored. A re-Up after a
-- downgrade probe recreates the empty tables, as in 00167.
