-- name: InsertContextPreview :exec
INSERT INTO context_preview(id,root_id,capture_id,attempt_id,actor_key,principal_key,blueprint_json,blueprint_sha256,created_at,deadline)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: FindContextPreview :one
SELECT * FROM context_preview WHERE root_id=$1 AND id=$2 AND actor_key=$3;

-- name: CountContextPreviews :one
SELECT count(*) FROM (
 SELECT p.id FROM context_preview AS p WHERE p.root_id=$1 AND p.deadline>clock_timestamp()
 UNION ALL
 SELECT f.preview_id FROM context_preview_fence AS f WHERE f.root_id=$1 AND f.expires_at>clock_timestamp()
 LIMIT 1000
) AS bounded;

-- name: CountPrincipalContextPreviews :one
SELECT count(*) FROM (
 SELECT p.id FROM context_preview AS p WHERE p.root_id=$1 AND p.principal_key=$2 AND p.deadline>clock_timestamp()
 UNION ALL
 SELECT f.preview_id FROM context_preview_fence AS f WHERE f.root_id=$1 AND f.principal_key=$2 AND f.expires_at>clock_timestamp()
 LIMIT 10
) AS bounded;

-- name: DeleteExpiredContextPreviews :execrows
DELETE FROM context_preview WHERE id IN (
 SELECT expired.id FROM context_preview AS expired WHERE expired.root_id=$1 AND expired.deadline<=clock_timestamp()
 ORDER BY expired.deadline,expired.id LIMIT 1000
);

-- name: FindContextPreviewFence :one
SELECT * FROM context_preview_fence WHERE root_id=$1 AND preview_id=$2 AND actor_key=$3 AND expires_at>clock_timestamp();

-- name: InsertContextPreviewFence :one
INSERT INTO context_preview_fence(root_id,preview_id,actor_key,principal_key,request_key,submission_digest,created_at,expires_at)
VALUES($1,$2,$3,$4,$5,$6,clock_timestamp(),clock_timestamp()+interval '5 minutes') RETURNING *;

-- name: CloseContextPreview :execrows
UPDATE context_preview SET closed_at=clock_timestamp(),closed_request_key=$4,closed_submission_digest=$5
WHERE root_id=$1 AND id=$2 AND actor_key=$3 AND closed_at IS NULL;

-- name: DeleteExpiredContextPreviewFences :execrows
DELETE FROM context_preview_fence WHERE (root_id,preview_id,actor_key) IN (
 SELECT f.root_id,f.preview_id,f.actor_key FROM context_preview_fence AS f WHERE f.root_id=$1 AND f.expires_at<=clock_timestamp()
 ORDER BY f.expires_at,f.preview_id LIMIT 1000
);
