-- name: ShareContextKeyWrapExecution :one
-- ADR-176: the prepared execution and its accepted expectation, held for the
-- duration of one wrap decision. Phase and object identity cannot change.
SELECT e.capture_id, e.root_id, e.attempt_id, e.process_json, e.expectation_digest, e.not_after, e.phase, e.object_uid, c.expectation_json
FROM context_execution e
JOIN context_capture c ON c.id=e.capture_id AND c.root_id=e.root_id
WHERE e.attempt_id=$1 AND e.root_id=$2
FOR SHARE OF e;

-- name: ReadActivatedConnectorClientLeaf :one
-- The presenting certificate must be an activated, attached connector client
-- leaf of a serving, unretired process.
SELECT p.pod_uid, p.process_epoch, prof.cluster_id, prof.installation_id, a.certificate_not_after
FROM connector_credential_attempt a
JOIN connector_identity_process p ON p.id=a.process_id AND p.root_id=a.root_id
JOIN connector_identity_profile prof ON prof.root_id=a.root_id AND prof.peer_id=a.peer_id
WHERE a.root_id=$1 AND a.certificate_digest=$2 AND a.usage='client' AND a.activated_at IS NOT NULL AND a.detached_at IS NULL
 AND p.serving AND p.retired_at IS NULL;

-- name: LockContextKeyWrap :one
SELECT attempt_id, root_id, certificate_sha256, used_roles
FROM context_key_wrap WHERE attempt_id=$1 AND root_id=$2
FOR UPDATE;

-- name: InsertContextKeyWrap :execrows
INSERT INTO context_key_wrap(attempt_id,root_id,certificate_sha256,used_roles)
VALUES($1,$2,$3,$4) ON CONFLICT (attempt_id) DO NOTHING;

-- name: SpendContextKeyWrapRole :execrows
UPDATE context_key_wrap SET used_roles=used_roles|sqlc.arg(role_mask)::smallint
WHERE attempt_id=$1 AND root_id=$2 AND certificate_sha256=$3 AND (used_roles&sqlc.arg(role_mask)::smallint)=0;
