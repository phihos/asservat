-- +goose Up
-- Existing children have no attestation and are rejected, not backfilled with
-- fabricated authority. New insertion always supplies this bounded proof.
ALTER TABLE download_key_binding ADD COLUMN worker_proof_json bytea
 CHECK(worker_proof_json IS NULL OR octet_length(worker_proof_json) BETWEEN 1 AND 16384);
-- In-flight unqualified children expire naturally without refunding spend.
-- No destructive downgrade or proof renewal.
