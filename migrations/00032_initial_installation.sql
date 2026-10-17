-- +goose Up
-- One retained attempt per dedicated installation database. No reset or default
-- activation, including when upgrading an existing installation.
CREATE TABLE fleet_initial_activation (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 installation_id uuid NOT NULL UNIQUE,
 claim_id uuid NOT NULL UNIQUE,
 record_json bytea NOT NULL CHECK (octet_length(record_json) BETWEEN 1 AND 8192),
 audit_receipt_json bytea CHECK (octet_length(audit_receipt_json) BETWEEN 1 AND 8192),
 activated_at timestamptz,
 CHECK (activated_at IS NULL OR audit_receipt_json IS NOT NULL)
);
