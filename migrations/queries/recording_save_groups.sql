-- name: InsertRecordingGroupPreview :exec
INSERT INTO context_preview(id,root_id,capture_id,attempt_id,actor_key,principal_key,blueprint_json,blueprint_sha256,created_at,deadline,preview_kind,reason_envelope)
VALUES($1,$2,$3,NULL,$4,$5,$6,$7,$8,$9,'recordingSaveGroup',sqlc.narg(reason_envelope)::bytea);

-- name: InsertRecordingSaveGroup :one
INSERT INTO recording_save_group(id,root_id,preview_id,request_key,submission_digest,scope_digest,scope_json,policy_uid,acceptance_id,allocation_id,child_ids,accepted_at,deadline)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *;

-- name: FindRecordingSaveGroup :one
SELECT * FROM recording_save_group WHERE root_id=$1 AND request_key=$2;

-- name: FindRecordingSaveGroupByPreview :one
SELECT * FROM recording_save_group WHERE root_id=$1 AND preview_id=$2;

-- name: ReadRecordingSaveGroup :one
SELECT * FROM recording_save_group WHERE root_id=$1 AND id=$2;

-- name: LockRecordingSaveGroup :one
SELECT * FROM recording_save_group WHERE root_id=$1 AND id=$2 FOR UPDATE;

-- name: ReadRecordingSaveGroupChildren :many
SELECT * FROM context_capture WHERE root_id=$1 AND group_id=$2 ORDER BY group_ordinal;

-- name: RequestRecordingSaveGroupCancellation :one
UPDATE recording_save_group SET cancel_requested_at=clock_timestamp(),cancel_request_key=$3,progress_revision=progress_revision+1
WHERE root_id=$1 AND id=$2 AND cancel_requested_at IS NULL AND progress_revision=$4 RETURNING *;

-- name: ReadRecordingGroupHistoryFacts :one
-- Metadata only; progress cannot read object locators or unwrap history keys.
SELECT h.state,h.visible,h.summary_expires_at,a.state AS custody_state,a.effective_expires_at
FROM capture_history_parameter h JOIN custody_attempt a ON a.id=h.attempt_id
WHERE h.root_id=$1 AND h.capture_id=$2;
