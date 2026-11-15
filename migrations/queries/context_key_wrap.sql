-- name: ShareContextKeyWrapExecution :one
-- ADR-176: the prepared execution and its accepted expectation, held for the
-- duration of one wrap decision. Phase and object identity cannot change.
SELECT e.capture_id, e.root_id, e.attempt_id, e.process_json, e.expectation_digest, e.not_after, e.phase, e.object_uid, c.expectation_json
FROM context_execution e
JOIN context_capture c ON c.id=e.capture_id AND c.root_id=e.root_id
WHERE e.attempt_id=$1 AND e.root_id=$2
FOR SHARE OF e;

-- name: LockContextKeyWrap :one
-- certificate_sha256 names the presenting peer: a key client's leaf, or a
-- connector's cluster (ADR-334).
SELECT attempt_id, root_id, certificate_sha256, used_roles
FROM context_key_wrap WHERE attempt_id=$1 AND root_id=$2
FOR UPDATE;

-- name: InsertContextKeyWrap :execrows
INSERT INTO context_key_wrap(attempt_id,root_id,certificate_sha256,used_roles)
VALUES($1,$2,$3,$4) ON CONFLICT (attempt_id) DO NOTHING;

-- name: SpendContextKeyWrapRole :execrows
UPDATE context_key_wrap SET used_roles=used_roles|sqlc.arg(role_mask)::smallint
WHERE attempt_id=$1 AND root_id=$2 AND certificate_sha256=$3 AND (used_roles&sqlc.arg(role_mask)::smallint)=0;
