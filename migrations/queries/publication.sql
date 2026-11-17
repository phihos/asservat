-- name: ReadPublicationCapture :one
SELECT * FROM context_capture WHERE id=$1 AND root_id=$2;

-- name: ReadContextCatalog :one
SELECT * FROM context_catalog WHERE capture_id=$1 AND root_id=$2;

-- name: InsertContextCatalog :one
-- REQ-EVD-001: one-step publication in the stored-outcome transaction.
INSERT INTO context_catalog(artifact_id,capture_id,root_id,copies_digest,native_bytes,acquisition_started_at,acquisition_completed_at)
VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *;

-- name: ReadPublishedContext :one
SELECT sqlc.embed(c), sqlc.embed(cat), a.effective_expires_at, a.effective_delete_by
FROM context_catalog cat JOIN context_capture c ON c.id=cat.capture_id AND c.root_id=cat.root_id
JOIN custody_attempt a ON a.id=c.attempt_id AND a.artifact_id=cat.artifact_id
WHERE cat.artifact_id=$1 AND cat.root_id=$2
AND a.state='stored_unpublished' AND clock_timestamp()<a.effective_expires_at AND a.copies_digest=cat.copies_digest;
