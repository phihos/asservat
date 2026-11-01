-- name: LockNextRetentionCatchup :one
SELECT j.* FROM retention_catchup j JOIN retention_checkpoint c ON c.id=j.checkpoint_id
WHERE c.root_id=$1 AND c.cluster_id=$2 AND c.namespace_uid=$3 AND j.completed_at IS NULL
ORDER BY c.sequence LIMIT 1 FOR UPDATE OF j;

-- name: ListRetentionCatchupContexts :many
SELECT a.id,a.cluster_id,a.artifact_id FROM custody_attempt a
WHERE a.id IN (
 SELECT c.attempt_id FROM context_capture c WHERE c.root_id=$1 AND c.created_at<=$2
 UNION ALL
 SELECT h.attempt_id FROM capture_history_parameter h WHERE h.root_id=$1 AND h.created_at<=$2
) AND a.state<>'deleted'
AND (sqlc.narg(after_attempt)::uuid IS NULL OR a.id>sqlc.narg(after_attempt)::uuid)
AND (sqlc.arg(hub)::boolean OR a.cluster_id=sqlc.arg(cluster_id)::uuid)
ORDER BY a.id LIMIT sqlc.arg(page_limit);

-- name: AdvanceRetentionCatchup :exec
UPDATE retention_catchup SET after_attempt=$2,visited=visited+$3,shortened=shortened+$4,
 completed_at=CASE WHEN sqlc.arg(complete)::boolean THEN clock_timestamp() ELSE NULL END
WHERE checkpoint_id=$1;

-- name: InsertRetentionCatchupEffect :exec
INSERT INTO retention_catchup_effect(checkpoint_id,attempt_id,decision_id) VALUES($1,$2,$3);

-- name: RetentionDecisionID :one
SELECT gen_random_uuid()::uuid AS id;
