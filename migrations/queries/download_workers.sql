-- name: LatestDownloadWorker :one
SELECT * FROM download_worker WHERE session_id=$1 AND root_id=$2 ORDER BY generation DESC LIMIT 1;

-- name: LockDownloadWorker :one
SELECT * FROM download_worker WHERE id=$1 AND root_id=$2 FOR UPDATE;

-- Both purposes count under the same permission-root lock. Match workload
-- identity rather than purpose-specific allocation IDs; unknown work stays paid.
-- name: AcquisitionWorkerCapacity :one
SELECT count(*)::bigint AS total,
 count(*) FILTER (WHERE coalesce(d.cluster_id,q.cluster_id)=sqlc.arg(cluster_id)
   AND coalesce(d.namespace_uid,q.namespace_uid)=sqlc.arg(namespace_uid)
   AND coalesce(d.workload_uid,q.workload_uid)=sqlc.arg(workload_uid))::bigint AS workload,
 count(*) FILTER (WHERE w.principal_key=sqlc.arg(principal_key))::bigint AS principal
FROM download_worker w
LEFT JOIN download_allocation d ON d.id=w.allocation_id
LEFT JOIN context_query_allocation q ON q.id=w.query_allocation_id
WHERE w.installation_id=sqlc.arg(installation_id) AND w.retired_proof_json IS NULL AND w.abandoned_at IS NULL;

-- name: ReadQueryAcquisitionWorker :one
SELECT * FROM download_worker WHERE query_id=$1 AND root_id=$2;

-- name: InsertQueryAcquisitionWorker :exec
INSERT INTO download_worker(id,query_id,root_id,installation_id,query_allocation_id,principal_key,generation,intent_json,run_until)
VALUES($1,$2,$3,$4,$5,$6,1,$7,$8);

-- name: InsertDownloadWorker :exec
INSERT INTO download_worker(id,session_id,root_id,installation_id,allocation_id,principal_key,generation,intent_json,run_until)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: AuditDownloadWorker :execrows
UPDATE download_worker SET audit_receipt_json=$3 WHERE id=$1 AND root_id=$2 AND audit_receipt_json IS NULL;

-- name: ClaimDownloadWorker :execrows
UPDATE download_worker SET claimed_at=clock_timestamp() WHERE id=$1 AND root_id=$2 AND audit_receipt_json IS NOT NULL AND claimed_at IS NULL AND retired_proof_json IS NULL AND abandoned_at IS NULL;

-- name: RecordDownloadWorkerJob :execrows
UPDATE download_worker SET job_json=$3 WHERE id=$1 AND root_id=$2 AND claimed_at IS NOT NULL AND job_json IS NULL;

-- name: BindDownloadWorker :execrows
UPDATE download_worker SET binding_json=$3 WHERE id=$1 AND root_id=$2 AND job_json IS NOT NULL AND binding_json IS NULL AND retired_proof_json IS NULL;

-- name: RetireDownloadWorker :execrows
UPDATE download_worker SET retired_proof_json=$3 WHERE id=$1 AND root_id=$2 AND termination_json IS NOT NULL AND retired_proof_json IS NULL;

-- name: ConfirmDownloadWorkerTermination :execrows
UPDATE download_worker SET termination_json=$3 WHERE id=$1 AND root_id=$2 AND binding_json IS NOT NULL AND termination_json IS NULL;

-- name: ExpiredQueryAcquisitionWorkers :many
SELECT * FROM download_worker
WHERE root_id=$1 AND installation_id=$2 AND query_id IS NOT NULL
 AND retired_proof_json IS NULL AND abandoned_at IS NULL AND run_until<=clock_timestamp()
ORDER BY run_until,id LIMIT 16;

-- name: AbandonUnclaimedQueryWorker :execrows
UPDATE download_worker SET abandoned_at=clock_timestamp()
WHERE id=$1 AND root_id=$2 AND query_id IS NOT NULL AND claimed_at IS NULL
 AND run_until<=clock_timestamp() AND abandoned_at IS NULL;

-- Native download workers can end before run_until; cleanup still requires
-- positive Kubernetes termination evidence for each exact bound row.
-- name: UnretiredBoundDownloadWorkers :many
SELECT * FROM download_worker
WHERE root_id=$1 AND installation_id=$2 AND session_id IS NOT NULL AND binding_json IS NOT NULL
 AND retired_proof_json IS NULL AND abandoned_at IS NULL
ORDER BY run_until,id LIMIT 16;
