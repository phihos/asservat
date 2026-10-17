-- +goose Up
-- Pre-authorized one-use bootstrap slots. Issuance/audit producer is separate;
-- the claim role can neither create slots nor activate fleet_peer authority.
CREATE TABLE fleet_bootstrap (
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 peer_id uuid NOT NULL,
 issuer_epoch uuid NOT NULL,
 secret_sha256 bytea NOT NULL CHECK(octet_length(secret_sha256)=32),
 not_before timestamptz NOT NULL,
 not_after timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 issue_authority_digest bytea NOT NULL CHECK(octet_length(issue_authority_digest)=32),
 issue_audit_id uuid NOT NULL,
 issue_audit_key text NOT NULL CHECK(octet_length(issue_audit_key) BETWEEN 1 AND 1024),
 issue_audit_version text NOT NULL CHECK(octet_length(issue_audit_version) BETWEEN 1 AND 1024),
 issue_audit_sha256 bytea NOT NULL CHECK(octet_length(issue_audit_sha256)=32),
 claimed_at timestamptz,
 public_key_sha256 bytea CHECK(octet_length(public_key_sha256)=32),
 CHECK((claimed_at IS NULL)=(public_key_sha256 IS NULL)),
 CHECK(not_after>not_before AND not_after<=not_before+interval '5 minutes'),
 CHECK(claimed_at IS NULL OR (claimed_at>=not_before AND claimed_at<not_after)),
 PRIMARY KEY(installation_id,id),
 UNIQUE(installation_id,peer_id),
 UNIQUE(installation_id,secret_sha256)
);
-- A used or uncertain slot is never made unclaimed or refunded by expiry.

-- +goose StatementBegin
CREATE FUNCTION guard_bootstrap_claim() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.claimed_at IS NOT NULL OR NEW.public_key_sha256 IS NOT NULL THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='bootstrap must start unclaimed';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.installation_id,NEW.id,NEW.cluster_id,NEW.peer_id,NEW.issuer_epoch,NEW.secret_sha256,
        NEW.not_before,NEW.not_after,NEW.issue_authority_digest,NEW.issue_audit_id,
        NEW.issue_audit_key,NEW.issue_audit_version,NEW.issue_audit_sha256)
    IS DISTINCT FROM
    ROW(OLD.installation_id,OLD.id,OLD.cluster_id,OLD.peer_id,OLD.issuer_epoch,OLD.secret_sha256,
        OLD.not_before,OLD.not_after,OLD.issue_authority_digest,OLD.issue_audit_id,
        OLD.issue_audit_key,OLD.issue_audit_version,OLD.issue_audit_sha256)
    OR (OLD.revoked AND NOT NEW.revoked)
    OR (OLD.claimed_at IS NOT NULL AND
        ROW(NEW.claimed_at,NEW.public_key_sha256) IS DISTINCT FROM ROW(OLD.claimed_at,OLD.public_key_sha256)) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='bootstrap binding and consumed claim are immutable';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER bootstrap_claim_guard BEFORE INSERT OR UPDATE ON fleet_bootstrap
 FOR EACH ROW EXECUTE FUNCTION guard_bootstrap_claim();
