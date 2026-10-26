-- ADR-232 concrete evidence shares.

-- name: LockShareArtifact :exec
-- Serializes share creation per artifact so the active-share cap holds.
SELECT pg_advisory_xact_lock(hashtextextended('evidence_share:' || @artifact_key::text, 0));

-- name: ReadShareByKey :one
SELECT * FROM evidence_share WHERE root_id=$1 AND creator_issuer=$2 AND creator_subject=$3 AND idempotency_key=$4;

-- name: CountActiveShares :one
SELECT count(*) FROM evidence_share WHERE root_id=$1 AND artifact_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp();

-- name: InsertShare :one
-- The artifact, case and target come from the published case route, never
-- only from the caller.
INSERT INTO evidence_share(id,root_id,artifact_id,case_id,cluster_id,namespace_uid,workload_uid,pod_uid,version,creator_issuer,creator_subject,creator_client,management,recipients,recipient_keys,idempotency_key,request_digest,expires_at)
SELECT @id::uuid, r.root_id, r.artifact_id, r.case_id, r.cluster_id, r.namespace_uid, r.workload_uid, r.pod_uid, @version::bytea, @creator_issuer, @creator_subject, @creator_client::text,
 @management::jsonb, @recipients::jsonb, @recipient_keys::text[], @idempotency_key::text, @request_digest::bytea, @expires_at::timestamptz
FROM context_case_locator r
WHERE r.root_id=sqlc.arg(root_id)::uuid AND r.artifact_id=sqlc.arg(artifact_id)::uuid AND r.case_id=sqlc.arg(case_id)::uuid AND r.cluster_id=sqlc.arg(cluster_id)::uuid
 AND r.namespace_uid=sqlc.arg(namespace_uid)::text AND r.workload_uid=sqlc.arg(workload_uid)::text AND r.pod_uid=sqlc.arg(pod_uid)::text
 AND @expires_at::timestamptz>clock_timestamp() AND @expires_at::timestamptz<=clock_timestamp()+interval '7 days'
RETURNING *;

-- name: ReadRecipientShares :many
-- Keyed by (artifact, the caller's own user/group keys); at most the cap.
SELECT * FROM evidence_share WHERE root_id=$1 AND artifact_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND recipient_keys && sqlc.arg(keys)::text[]
ORDER BY created_at, id LIMIT 32;

-- name: ListOwnedShares :many
-- Shares the caller created, in every phase, plus unrevoked, unexpired shares
-- pinning a management assignment of a user or group subject of the caller
-- (ADR-232 increment 4; each pattern is a one-element array
-- [{"Kind","Issuer","SubjectID"}]). Candidates only: the service lists a team
-- share only while the caller holds a pinned assignment that is still current.
SELECT * FROM evidence_share WHERE root_id=sqlc.arg(root_id)
 AND ((creator_issuer=sqlc.arg(creator_issuer) AND creator_subject=sqlc.arg(creator_subject))
  OR (revoked_at IS NULL AND expires_at>clock_timestamp() AND management @> ANY(sqlc.arg(managers)::jsonb[])))
ORDER BY created_at DESC, id LIMIT sqlc.arg(row_limit);

-- name: ReadShare :one
SELECT * FROM evidence_share WHERE root_id=$1 AND id=$2;

-- name: ListReceivedShares :many
SELECT * FROM evidence_share WHERE root_id=$1 AND recipient_keys && sqlc.arg(keys)::text[] AND revoked_at IS NULL AND expires_at>clock_timestamp()
ORDER BY created_at DESC, id LIMIT @row_limit;

-- name: ReadShareForUpdate :one
SELECT * FROM evidence_share WHERE root_id=$1 AND id=$2 FOR UPDATE;

-- name: RevokeShare :one
UPDATE evidence_share SET revoked_at=clock_timestamp(), revoke_key=$3, revision=2
WHERE root_id=$1 AND id=$2 AND revoked_at IS NULL RETURNING *;
