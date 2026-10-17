-- name: ReadPublicationCapture :one
SELECT * FROM context_capture WHERE id=$1 AND root_id=$2;

-- name: ReadContextVerification :one
SELECT * FROM context_verification WHERE capture_id=$1 AND root_id=$2;

-- name: LockContextVerification :one
SELECT * FROM context_verification WHERE capture_id=$1 AND root_id=$2 FOR UPDATE;

-- name: InsertContextVerification :one
INSERT INTO context_verification(capture_id,root_id,expectation_digest,copies_digest,intent_digest,authority_digest,permission_epoch,permission_sequence)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *;

-- name: AcknowledgeContextVerification :execrows
UPDATE context_verification SET audit_acknowledged_at=clock_timestamp(),audit_digest=$3,audit_object_key=$4,audit_object_version=$5,audit_object_etag=$6,audit_object_bytes=$7,audit_object_sha256=$8
WHERE capture_id=$1 AND root_id=$2 AND audit_acknowledged_at IS NULL;

-- name: ReadContextCatalog :one
SELECT * FROM context_catalog WHERE capture_id=$1 AND root_id=$2;

-- name: InsertContextCatalog :one
INSERT INTO context_catalog(artifact_id,capture_id,root_id) VALUES($1,$2,$3) RETURNING *;

-- name: ReadPublishedContext :one
SELECT c.*, v.verified_at, v.expectation_digest, v.copies_digest, cat.published_at, a.effective_expires_at, a.effective_delete_by
FROM context_catalog cat JOIN context_capture c ON c.id=cat.capture_id AND c.root_id=cat.root_id
JOIN context_verification v ON v.capture_id=c.id AND v.root_id=c.root_id
JOIN custody_attempt a ON a.id=c.attempt_id AND a.artifact_id=cat.artifact_id
WHERE cat.artifact_id=$1 AND cat.root_id=$2 AND v.audit_acknowledged_at IS NOT NULL
AND a.state='stored_unpublished' AND clock_timestamp()<a.effective_expires_at AND a.copies_digest=v.copies_digest;
