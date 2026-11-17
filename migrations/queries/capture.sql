-- name: ShareContextStorage :one
SELECT * FROM context_storage_binding WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND workload_uid=$4 FOR SHARE;

-- name: LockContextStorage :one
SELECT * FROM context_storage_binding WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND workload_uid=$4 FOR UPDATE;

-- name: InsertContextStorage :exec
INSERT INTO context_storage_binding(root_id,cluster_id,namespace_uid,workload_uid,allocation_id,source_uid,source_generation,source_digest,observed_at,fresh_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: RefreshContextStorage :exec
UPDATE context_storage_binding SET observed_at=$5,fresh_until=$6 WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND workload_uid=$4;

-- name: FindContextCapture :one
SELECT * FROM context_capture WHERE root_id=$1 AND request_key=$2;

-- name: ReadExactCaptureIntent :one
SELECT * FROM context_capture WHERE root_id=$1 AND id=$2;

-- name: LockContextCapture :one
SELECT * FROM context_capture WHERE id=$1 AND root_id=$2 FOR UPDATE;

-- name: InsertContextCapture :one
INSERT INTO context_capture(id,root_id,request_key,submission_digest,scope_digest,scope_json,expectation_json,pod_pin_json,attempt_id,permission_epoch,permission_sequence,identity_policy_uid,identity_policy_generation,identity_policy_digest,deadline,preview_id,share_instruction,repeated_from_capture_id,repeated_from_expires_at,created_at,group_id,group_ordinal,reason,target_labels)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,COALESCE(sqlc.narg(accepted_at)::timestamptz,clock_timestamp()),sqlc.narg(group_id)::uuid,sqlc.narg(group_ordinal)::smallint,sqlc.narg(reason)::text,sqlc.narg(target_labels)::jsonb) RETURNING *;

-- name: FindContextCaptureByPreview :one
SELECT * FROM context_capture WHERE root_id=$1 AND preview_id=$2;

-- name: FindLegacyContextPreviewCapture :many
SELECT * FROM context_capture WHERE root_id=$1 AND preview_id IS NULL AND submission_digest=$2
 AND convert_from(scope_json,'UTF8')::jsonb #>> '{executor,issuer}' = sqlc.arg(issuer)::text
 AND convert_from(scope_json,'UTF8')::jsonb #>> '{executor,subject}' = sqlc.arg(subject)::text
 AND convert_from(scope_json,'UTF8')::jsonb #>> '{executor,clientID}' = sqlc.arg(client)::text
 AND convert_from(scope_json,'UTF8')::jsonb #>> '{executor,identityType}' = sqlc.arg(kind)::text
 LIMIT 2;
