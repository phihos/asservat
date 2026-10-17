-- +goose Up
CREATE TABLE download_worker_configuration (
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 cluster_id uuid NOT NULL,
 source_uid uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 2147483647),
 observed_at timestamptz NOT NULL,
 fresh_until timestamptz NOT NULL CHECK(fresh_until<=observed_at+interval '5 seconds'),
 PRIMARY KEY(installation_id,cluster_id,source_uid)
);
CREATE TABLE download_worker_configuration_revision (
 installation_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 source_uid uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 2147483647),
 snapshot_json bytea NOT NULL CHECK(octet_length(snapshot_json) BETWEEN 1 AND 16384),
 audit_receipt_json bytea CHECK(octet_length(audit_receipt_json) BETWEEN 1 AND 8192),
 PRIMARY KEY(installation_id,cluster_id,source_uid,generation),
 FOREIGN KEY(installation_id,cluster_id,source_uid) REFERENCES download_worker_configuration
);
-- +goose StatementBegin
CREATE FUNCTION guard_worker_configuration_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.installation_id,NEW.cluster_id,NEW.source_uid,NEW.generation,NEW.snapshot_json)
 IS DISTINCT FROM ROW(OLD.installation_id,OLD.cluster_id,OLD.source_uid,OLD.generation,OLD.snapshot_json)
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json) THEN
  RAISE EXCEPTION 'worker configuration revision and audit are immutable';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER worker_configuration_revision_guard BEFORE UPDATE ON download_worker_configuration_revision FOR EACH ROW EXECUTE FUNCTION guard_worker_configuration_revision();
-- +goose StatementBegin
CREATE FUNCTION guard_worker_configuration_head() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.installation_id,NEW.cluster_id,NEW.source_uid) IS DISTINCT FROM ROW(OLD.installation_id,OLD.cluster_id,OLD.source_uid)
 OR NEW.generation<OLD.generation OR NEW.observed_at<OLD.observed_at THEN
  RAISE EXCEPTION 'worker configuration identity and revision cannot roll back';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER worker_configuration_head_guard BEFORE UPDATE ON download_worker_configuration FOR EACH ROW EXECUTE FUNCTION guard_worker_configuration_head();
-- No destructive down: accepted revision history cannot be reset by rollback.
