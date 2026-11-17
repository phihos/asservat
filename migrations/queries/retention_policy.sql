-- ADR-330 D12: the current EvidenceRetentionPolicy set and its effect on
-- stored deadlines.

-- name: ListRetentionPolicies :many
SELECT uid,name,generation,digest,policy FROM retention_policy ORDER BY uid;

-- The follower holds the retention advisory lock exclusively while it
-- changes and applies policies; admissions hold it shared (00190).
-- name: LockRetentionPolicies :exec
SELECT pg_advisory_xact_lock(hashtext('asservat.retention_policy'));

-- name: UpsertRetentionPolicy :exec
INSERT INTO retention_policy(uid,name,generation,digest,policy,effect)
VALUES(sqlc.arg(uid),sqlc.arg(name),sqlc.arg(generation),sqlc.arg(digest),sqlc.arg(policy),sqlc.arg(effect))
ON CONFLICT(uid) DO UPDATE SET name=EXCLUDED.name,generation=EXCLUDED.generation,digest=EXCLUDED.digest,
 policy=EXCLUDED.policy,effect=EXCLUDED.effect,updated_at=clock_timestamp();

-- name: DeleteRetentionPolicy :exec
DELETE FROM retention_policy WHERE uid=$1;

-- name: ApplyRetentionEffect :execrows
UPDATE custody_attempt a SET effective_expires_at=e.expires_at,effective_delete_by=e.delete_by
FROM retention_policy_effect(sqlc.arg(effect)::jsonb) e
WHERE a.id=e.attempt_id AND (e.expires_at<a.effective_expires_at OR e.delete_by<a.effective_delete_by);

-- name: InsertRetentionPolicyEvent :exec
INSERT INTO retention_policy_event(uid,name,generation,digest,change,shortened) VALUES($1,$2,$3,$4,$5,$6);

-- ADR-240: one aggregate over stored deadlines for a proposal.
-- name: PreviewRetentionEffects :one
SELECT retention_preview(sqlc.arg(effects)::jsonb)::jsonb AS groups;
