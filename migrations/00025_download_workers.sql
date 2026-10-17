-- +goose Up
CREATE TABLE download_worker (
 id uuid PRIMARY KEY,
 session_id uuid NOT NULL REFERENCES artifact_download(id),
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 allocation_id uuid NOT NULL REFERENCES download_allocation(id),
 principal_key bytea NOT NULL CHECK(octet_length(principal_key)=32),
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 1024),
 intent_json bytea NOT NULL CHECK(octet_length(intent_json) BETWEEN 1 AND 65536),
 run_until timestamptz NOT NULL,
 audit_receipt_json bytea CHECK(octet_length(audit_receipt_json) BETWEEN 1 AND 8192),
 claimed_at timestamptz,
 job_json bytea CHECK(octet_length(job_json) BETWEEN 1 AND 8192),
 binding_json bytea CHECK(octet_length(binding_json) BETWEEN 1 AND 16384),
 termination_json bytea CHECK(octet_length(termination_json) BETWEEN 1 AND 32768),
 retired_proof_json bytea CHECK(octet_length(retired_proof_json) BETWEEN 1 AND 32768),
 CHECK(claimed_at IS NULL OR audit_receipt_json IS NOT NULL),
 CHECK(job_json IS NULL OR claimed_at IS NOT NULL),
 CHECK(binding_json IS NULL OR job_json IS NOT NULL),
 CHECK(termination_json IS NULL OR binding_json IS NOT NULL),
 CHECK(retired_proof_json IS NULL OR termination_json IS NOT NULL),
 UNIQUE(session_id,generation)
);
CREATE UNIQUE INDEX one_live_download_worker ON download_worker(session_id) WHERE retired_proof_json IS NULL;
CREATE INDEX download_worker_capacity ON download_worker(installation_id,allocation_id,principal_key) WHERE retired_proof_json IS NULL;
-- +goose StatementBegin
CREATE FUNCTION guard_download_worker() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.session_id,NEW.root_id,NEW.installation_id,NEW.allocation_id,NEW.principal_key,NEW.generation,NEW.intent_json,NEW.run_until)
 IS DISTINCT FROM ROW(OLD.id,OLD.session_id,OLD.root_id,OLD.installation_id,OLD.allocation_id,OLD.principal_key,OLD.generation,OLD.intent_json,OLD.run_until)
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json)
 OR (OLD.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at)
 OR (OLD.job_json IS NOT NULL AND NEW.job_json IS DISTINCT FROM OLD.job_json)
 OR (OLD.binding_json IS NOT NULL AND NEW.binding_json IS DISTINCT FROM OLD.binding_json)
 OR (OLD.termination_json IS NOT NULL AND NEW.termination_json IS DISTINCT FROM OLD.termination_json)
 OR (OLD.retired_proof_json IS NOT NULL AND NEW.retired_proof_json IS DISTINCT FROM OLD.retired_proof_json) THEN
  RAISE EXCEPTION 'download worker identity and consumed transitions are immutable';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER download_worker_guard BEFORE UPDATE ON download_worker FOR EACH ROW EXECUTE FUNCTION guard_download_worker();
-- No destructive down or expiry-based capacity refund.
