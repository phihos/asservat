-- name: LatestDownloadWorker :one
SELECT * FROM download_worker WHERE session_id=$1 AND root_id=$2 ORDER BY generation DESC LIMIT 1;

-- name: LockDownloadWorker :one
SELECT * FROM download_worker WHERE id=$1 AND root_id=$2 FOR UPDATE;

-- name: DownloadWorkerCapacity :one
SELECT count(*)::bigint AS total,
 count(*) FILTER (WHERE allocation_id=$2)::bigint AS workload,
 count(*) FILTER (WHERE principal_key=$3)::bigint AS principal
FROM download_worker WHERE installation_id=$1 AND retired_proof_json IS NULL;

-- name: InsertDownloadWorker :exec
INSERT INTO download_worker(id,session_id,root_id,installation_id,allocation_id,principal_key,generation,intent_json,run_until)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: AuditDownloadWorker :execrows
UPDATE download_worker SET audit_receipt_json=$3 WHERE id=$1 AND root_id=$2 AND audit_receipt_json IS NULL;

-- name: ClaimDownloadWorker :execrows
UPDATE download_worker SET claimed_at=clock_timestamp() WHERE id=$1 AND root_id=$2 AND audit_receipt_json IS NOT NULL AND claimed_at IS NULL AND retired_proof_json IS NULL;

-- name: RecordDownloadWorkerJob :execrows
UPDATE download_worker SET job_json=$3 WHERE id=$1 AND root_id=$2 AND claimed_at IS NOT NULL AND job_json IS NULL;

-- name: BindDownloadWorker :execrows
UPDATE download_worker SET binding_json=$3 WHERE id=$1 AND root_id=$2 AND job_json IS NOT NULL AND binding_json IS NULL AND retired_proof_json IS NULL;

-- name: RetireDownloadWorker :execrows
UPDATE download_worker SET retired_proof_json=$3 WHERE id=$1 AND root_id=$2 AND termination_json IS NOT NULL AND retired_proof_json IS NULL;

-- name: ConfirmDownloadWorkerTermination :execrows
UPDATE download_worker SET termination_json=$3 WHERE id=$1 AND root_id=$2 AND binding_json IS NOT NULL AND termination_json IS NULL;
