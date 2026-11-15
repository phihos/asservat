-- ADR-235 capture-time shares.

-- name: ReadCaptureShare :one
-- Existence of the share that publication materialized from a capture's
-- sharing instruction; no recipient or management field is read.
SELECT id FROM evidence_share WHERE root_id=$1 AND id=$2;
