-- name: InsertDownloadControlAllocation :one
INSERT INTO download_control_allocation(id,root_id,audit_store_id,response_limit,window_limit,audit_byte_limit,valid_until,audit_write_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *;
-- name: ReadDownloadControlAllocation :one
SELECT * FROM download_control_allocation WHERE id=$1 AND root_id=$2;
-- name: InsertDownloadResponse :one
INSERT INTO download_response(id,root_id,session_id,owner_id,generation,plan_json,reserved_windows,started_at,until_at,lease_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *;
-- name: LockDownloadResponse :one
SELECT * FROM download_response WHERE id=$1 AND session_id=$2 AND root_id=$3 FOR UPDATE;
-- name: ReadDownloadResponse :one
SELECT * FROM download_response WHERE id=$1 AND session_id=$2 AND root_id=$3;
-- name: CurrentDownloadResponse :one
SELECT * FROM download_response WHERE session_id=$1 AND root_id=$2 ORDER BY generation DESC LIMIT 1;
-- name: LeaseDownloadResponse :one
UPDATE download_response SET lease_sequence=lease_sequence+1,lease_until=$4 WHERE id=$1 AND session_id=$2 AND root_id=$3 RETURNING *;
-- name: CloseDownloadResponse :one
UPDATE download_response SET closed=true WHERE id=$1 AND session_id=$2 AND root_id=$3 AND owner_id=$4 RETURNING *;
-- name: InsertDownloadWindow :one
INSERT INTO download_window(id,response_id,session_id,ordinal,intent_json) VALUES($1,$2,$3,$4,$5) RETURNING *;
-- name: LockDownloadWindow :one
SELECT * FROM download_window WHERE id=$1 AND response_id=$2 AND session_id=$3 FOR UPDATE;
-- name: AcknowledgeDownloadWindowIntent :execrows
UPDATE download_window SET intent_receipt=$4,intent_completion=$5 WHERE id=$1 AND response_id=$2 AND session_id=$3 AND intent_receipt IS NULL;
-- name: RecordDownloadWindowOutcome :execrows
UPDATE download_window SET outcome_json=$4 WHERE id=$1 AND response_id=$2 AND session_id=$3 AND outcome_json IS NULL;
-- name: AcknowledgeDownloadWindowOutcome :execrows
UPDATE download_window SET outcome_receipt=$4,outcome_completion=$5 WHERE id=$1 AND response_id=$2 AND session_id=$3 AND outcome_receipt IS NULL;

-- name: ReadDownloadSessionControl :one
SELECT sqlc.embed(c), s.capacity_account_id, s.capacity_backing, s.capacity_backing_digest, s.deadline AS session_deadline FROM artifact_download s
JOIN download_control_allocation c ON c.id=s.allocation_id AND c.root_id=s.root_id
WHERE s.id=$1 AND s.root_id=$2;
