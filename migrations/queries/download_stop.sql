-- name: ReadDownloadStopPool :one
SELECT * FROM download_stop_pool WHERE root_id=$1;
-- name: InsertDownloadStopPool :exec
INSERT INTO download_stop_pool(root_id,installation_id,store_id,policy_id,backup_profile_id,policy_digest,backup_profile_digest,slots,cipher_bytes,key_attempts,backup_bytes,wal_bytes,retained_seconds,backup_horizon_seconds,valid_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15);
-- name: RenewDownloadStopPool :execrows
UPDATE download_stop_pool SET revision=revision+1,valid_until=$3 WHERE root_id=$1 AND revision=$2;
-- name: ReadDownloadStopBacking :one
SELECT * FROM download_stop_backing WHERE allocation_id=$1 AND root_id=$2;
-- name: InsertDownloadStopBacking :exec
INSERT INTO download_stop_backing(allocation_id,root_id,slots) VALUES($1,$2,$3);
-- name: ReadDownloadStop :one
SELECT * FROM download_stop WHERE download_id=$1 AND root_id=$2;
-- name: LockDownloadStop :one
SELECT * FROM download_stop WHERE download_id=$1 AND root_id=$2 FOR UPDATE;
-- name: FreezeDownloadStop :one
UPDATE download_stop SET key_digest=$3,request_id=$4,requested_at=$5,write_until=$6,decision=$7 WHERE download_id=$1 AND root_id=$2 AND decision IS NULL RETURNING *;
-- name: ClaimDownloadStopWrite :execrows
UPDATE download_stop SET write_started=true WHERE download_id=$1 AND root_id=$2 AND decision=$3 AND NOT write_started AND clock_timestamp()<write_until;
-- name: ChargeDownloadStopLookup :execrows
UPDATE download_stop SET lookup_attempts=lookup_attempts+1 WHERE download_id=$1 AND root_id=$2 AND decision=$3 AND write_started AND receipt IS NULL AND lookup_attempts<4 AND clock_timestamp()<retain_until;
-- name: AcknowledgeDownloadStop :execrows
UPDATE download_stop SET receipt=$4 WHERE download_id=$1 AND root_id=$2 AND decision=$3 AND write_started AND receipt IS NULL AND clock_timestamp()<retain_until;
-- name: ListPendingDownloadStops :many
SELECT pending.* FROM download_stop AS pending WHERE pending.root_id=$1 AND pending.decision IS NOT NULL AND pending.receipt IS NULL AND pending.lookup_attempts<4 AND clock_timestamp()<pending.retain_until AND (pending.write_started OR clock_timestamp()<pending.write_until) AND NOT EXISTS(SELECT 1 FROM download_stop_lifecycle AS lifecycle WHERE lifecycle.download_id=pending.download_id AND (lifecycle.closed_at IS NOT NULL OR clock_timestamp()>=lifecycle.original_purge_at)) ORDER BY pending.write_started,pending.lookup_attempts,pending.write_until,pending.download_id LIMIT 16;

-- name: FenceDownloadStopState :execrows
UPDATE artifact_download SET state=$3 WHERE id=$1 AND root_id=$2;
