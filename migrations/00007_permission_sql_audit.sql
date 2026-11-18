-- +goose Up
-- The first accepted sequence initializes an epoch. This schema break also
-- prevents an older writer from resetting or reading the new projection.
ALTER TABLE permission_stream DROP COLUMN initial_audit_id;
-- A replay returns the original controller deadline, even after a renewal.
ALTER TABLE permission_acceptance ADD COLUMN lease_until timestamptz;
UPDATE permission_stream SET suspended=true, lease_until=statement_timestamp(), observed_at=NULL, fresh_until=NULL;
-- Object receipts on historical events remain readable. New events commit
-- with their mutation and never enter a publication queue.
DROP INDEX authority_audit_pending;
ALTER TABLE authority_audit DROP CONSTRAINT authority_audit_record_check;

-- Assignments already carry durable activation/retirement event IDs. Keep
-- the source and scope as observed at each end even after a basis changes.
CREATE TABLE permission_basis_change (
 event_id uuid NOT NULL REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED,
 basis_key text NOT NULL, retired boolean NOT NULL,
 uid text NOT NULL, kind text NOT NULL, generation bigint NOT NULL,
 spec_digest bytea NOT NULL, scope_digest bytea NOT NULL,
 cluster_id uuid NOT NULL, namespace_uid text NOT NULL, workload_uids text[] NOT NULL,
 effect text NOT NULL, not_after timestamptz, automation_json jsonb,
 PRIMARY KEY(event_id,basis_key,retired)
);
CREATE INDEX permission_assignment_activation ON permission_assignment(activation_audit_id,basis_key);
CREATE INDEX permission_assignment_retirement ON permission_assignment(retirement_audit_id,basis_key) WHERE retirement_audit_id IS NOT NULL;
