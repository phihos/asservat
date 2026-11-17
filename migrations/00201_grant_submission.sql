-- +goose Up
-- ADR-335 D5: approval submits the reviewed request itself. An ad hoc grant
-- stores the request_capture input with the requester's verified groups,
-- scopes, identity policy revision and the end of their authentication.
-- Approval uses these groups only before that end. No Down: the statement
-- can be reapplied.
ALTER TABLE access_grant ADD COLUMN IF NOT EXISTS submission jsonb;
