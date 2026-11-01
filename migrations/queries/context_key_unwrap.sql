-- name: ShareContextKeyUnwrapExecution :one
-- ADR-181: the stored execution, its accepted expectation and whether its
-- capture is already published, held for one verification unwrap decision.
SELECT e.capture_id, e.root_id, e.attempt_id, e.expectation_digest, e.phase, c.expectation_json, c.snapshot_coverage, c.snapshot_coverage_digest, c.snapshot_expectation_digest,
 EXISTS(SELECT 1 FROM context_catalog k WHERE k.capture_id=e.capture_id) AS published
FROM context_execution e
JOIN context_capture c ON c.id=e.capture_id AND c.root_id=e.root_id
WHERE e.attempt_id=$1 AND e.root_id=$2
FOR SHARE OF e;

-- name: LockContextKeyUnwrap :one
SELECT attempt_id, root_id, unwraps
FROM context_key_unwrap WHERE attempt_id=$1 AND root_id=$2
FOR UPDATE;

-- name: InsertContextKeyUnwrap :execrows
INSERT INTO context_key_unwrap(attempt_id,root_id,last_certificate_sha256,unwraps)
VALUES($1,$2,$3,1) ON CONFLICT (attempt_id) DO NOTHING;

-- name: SpendContextKeyUnwrap :execrows
UPDATE context_key_unwrap SET unwraps=unwraps+1, last_certificate_sha256=$3
WHERE attempt_id=$1 AND root_id=$2 AND unwraps<12;

-- name: ListContextPublicationQueue :many
-- ADR-181: stored API context executions whose capture is not yet published,
-- oldest completion first. A listing confers no publication authority.
SELECT e.capture_id, e.attempt_id, e.copies_json
FROM context_execution e
WHERE e.root_id=$1 AND e.phase='stored'
 AND NOT EXISTS(SELECT 1 FROM context_catalog k WHERE k.capture_id=e.capture_id)
ORDER BY e.completed_at, e.capture_id
LIMIT $2;
