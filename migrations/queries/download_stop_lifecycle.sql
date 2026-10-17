-- name: ConfigureDownloadStopLifecycle :execrows
UPDATE download_stop_pool SET lifecycle_policy=$2 WHERE root_id=$1 AND lifecycle_policy IS NULL;
-- name: LockDownloadStopPool :one
SELECT * FROM download_stop_pool WHERE root_id=$1 FOR UPDATE;
-- name: LockDownloadStopBacking :one
SELECT * FROM download_stop_backing WHERE allocation_id=$1 AND root_id=$2 FOR UPDATE;
-- name: ReadDownloadStopLifecycle :one
SELECT * FROM download_stop_lifecycle WHERE download_id=$1 AND root_id=$2;
-- name: LockDownloadStopLifecycle :one
SELECT * FROM download_stop_lifecycle WHERE download_id=$1 AND root_id=$2 FOR UPDATE;
-- name: RecordDownloadStopCompletion :execrows
UPDATE download_stop_lifecycle SET original_completion=$3 WHERE download_id=$1 AND root_id=$2 AND original_completion IS NULL;
-- name: CloseDownloadStopLifecycle :execrows
UPDATE download_stop_lifecycle SET closed_at=$3,mode=$4 WHERE download_id=$1 AND root_id=$2 AND closed_at IS NULL;
-- name: SelectOverdueDownloadStop :execrows
UPDATE download_stop_lifecycle SET overdue_selected_at=$3 WHERE download_id=$1 AND root_id=$2 AND overdue_selected_at IS NULL AND NOT certificate_started;
-- name: LeaseDownloadStopPurge :execrows
UPDATE download_stop_lifecycle SET lease=$3,lease_fence=lease_fence+1 WHERE download_id=$1 AND root_id=$2 AND finalization_xid IS NULL;
-- name: RecordDownloadStopRetirement :execrows
UPDATE download_stop_lifecycle SET retirement=$3 WHERE download_id=$1 AND root_id=$2 AND retirement IS NULL;
-- name: ClaimDownloadStopCertificate :execrows
UPDATE download_stop_lifecycle SET certificate_started=true WHERE download_id=$1 AND root_id=$2 AND NOT certificate_started AND retirement=$3;
-- name: RecordDownloadStopCertificateCompletion :execrows
UPDATE download_stop_lifecycle SET certificate_completion=$3 WHERE download_id=$1 AND root_id=$2 AND certificate_completion IS NULL;
-- name: AcknowledgeDownloadStopCertificate :execrows
UPDATE download_stop_lifecycle SET certificate_receipt=$3,certificate_acknowledged_at=$4 WHERE download_id=$1 AND root_id=$2 AND certificate_receipt IS NULL;
-- name: RecordTerminalDownloadStopPurge :execrows
UPDATE download_stop_lifecycle SET terminal_purge=$3 WHERE download_id=$1 AND root_id=$2 AND terminal_purge IS NULL;
-- name: AcknowledgeDownloadStopAbsence :execrows
UPDATE download_stop_lifecycle SET terminal_acknowledged_at=$3 WHERE download_id=$1 AND root_id=$2 AND terminal_acknowledged_at IS NULL;
-- name: FinishDownloadStopRetirement :one
SELECT finish_download_stop_retirement($1,$2,$3)::boolean AS retired;
-- name: ListDueDownloadStopHistory :many
SELECT * FROM download_stop_history WHERE root_id=$1 AND clock_timestamp()>=eligible_at ORDER BY eligible_at,allocation_id LIMIT 16;
-- name: FinishDownloadStopHistory :one
SELECT records::bigint AS records,overdue::boolean AS overdue FROM finish_download_stop_history($1,$2,$3,$4,$5,$6);

-- name: ClaimDownloadStopCertificateVerification :execrows
UPDATE download_stop_lifecycle SET certificate_verify_attempts=certificate_verify_attempts+1 WHERE download_id=$1 AND root_id=$2 AND retirement=$3 AND certificate_completion IS NOT NULL AND certificate_receipt IS NULL AND certificate_verify_attempts<2;
