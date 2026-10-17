-- +goose Up
-- A guard installed today is not proof of the origin of yesterday's values.
-- Existing rows intentionally require requalification once after this upgrade.
ALTER TABLE permission_stream ADD COLUMN initial_audit_id uuid
 REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
UPDATE permission_stream SET suspended=true, fresh_until=NULL, observed_at=NULL;
-- No destructive down: bootstrap provenance is part of accepted authority.
