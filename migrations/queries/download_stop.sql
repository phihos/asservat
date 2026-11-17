-- name: ReadDownloadStop :one
SELECT * FROM artifact_download_stop WHERE download_id=$1 AND root_id=$2;
-- name: InsertDownloadStop :one
INSERT INTO artifact_download_stop(download_id,root_id,request_id,key_digest,state) VALUES($1,$2,$3,$4,$5) RETURNING *;
-- name: FenceDownloadStopState :execrows
UPDATE artifact_download SET state=$3 WHERE id=$1 AND root_id=$2;
