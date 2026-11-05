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
   AND coalesce(d.workload_uid,q.workload_uid)=sqlc.arg(workload_uid)
   OR b.cluster_id=sqlc.arg(cluster_id) AND b.namespace_uid=sqlc.arg(namespace_uid) AND b.workload_uid=sqlc.arg(workload_uid))::bigint AS workload,
 count(*) FILTER (WHERE w.principal_key=sqlc.arg(principal_key))::bigint AS principal
FROM download_worker w
LEFT JOIN download_allocation d ON d.id=w.allocation_id
LEFT JOIN context_query_allocation q ON q.id=w.query_allocation_id
LEFT JOIN context_query_allocation b ON b.id=w.baseline_query_allocation_id
WHERE w.installation_id=sqlc.arg(installation_id) AND w.retired_proof_json IS NULL AND w.abandoned_at IS NULL;

-- name: ReadQueryAcquisitionWorker :one
SELECT * FROM download_worker WHERE query_id=$1 AND root_id=$2;

-- name: InsertQueryAcquisitionWorker :exec
INSERT INTO download_worker(id,query_id,root_id,installation_id,query_allocation_id,principal_key,generation,intent_json,run_until,baseline_query_allocation_id)
VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,$9);

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
SELECT w.* FROM download_worker w
WHERE w.root_id=$1 AND w.installation_id=$2 AND w.query_id IS NOT NULL
 AND w.retired_proof_json IS NULL AND w.abandoned_at IS NULL
 AND (w.run_until<=clock_timestamp() OR EXISTS (
 SELECT 1 FROM context_query q
 JOIN context_query_batch b ON b.query_id=q.id AND b.generation=1
 JOIN context_query_worker cw ON cw.query_id=q.id
 WHERE q.id=w.query_id AND q.root_id=w.root_id AND q.worker_id=w.id
 AND w.claimed_at IS NOT NULL AND w.binding_json IS NOT NULL
 AND q.query=(convert_from(w.intent_json,'UTF8')::jsonb)->'Query'
 AND context_query_read_batches(q.query->'Scope')=1
 AND q.generation=1 AND q.active_batch IS NULL AND NOT q.uncertain
 AND b.claim_id=b.id AND b.closed AND b.native_closed
 AND b.batch->'Worker'=cw.binding
 AND cw.binding->>'WorkerID'=w.id::text
 AND cw.binding->>'PodUID'=(convert_from(w.binding_json,'UTF8')::jsonb)->>'PodUID'
 AND b.native_authority->'Scope'=q.query->'Scope'
 AND b.native_operation->'Reference'->>'QueryID'=q.id::text
 AND b.native_operation->'Reference'->>'WorkerID'=w.id::text
 AND b.native_operation->'Reference'->>'OperationID'=b.id::text
 AND b.native_operation->'Reference'->>'Fence'=b.generation::text
 AND b.native_operation->>'ParentID'=b.id::text
 AND b.native_operation->>'Generation'=b.generation::text
 AND b.native_operation->>'WorkerPodUID'=cw.binding->>'PodUID'
))
ORDER BY w.run_until,w.id LIMIT 16;

-- Fresh confirmation under the caller's existing exact worker-row lock.
-- Logical exhaustion is not physical termination and never frees a slot.
-- name: QueryAcquisitionWorkerExhausted :one
SELECT EXISTS (
 SELECT 1 FROM context_query q
 JOIN context_query_batch b ON b.query_id=q.id AND b.generation=1
 JOIN context_query_worker cw ON cw.query_id=q.id
 WHERE q.id=w.query_id AND q.root_id=w.root_id AND q.worker_id=w.id
 AND w.claimed_at IS NOT NULL AND w.binding_json IS NOT NULL
 AND q.query=(convert_from(w.intent_json,'UTF8')::jsonb)->'Query'
 AND context_query_read_batches(q.query->'Scope')=1
 AND q.generation=1 AND q.active_batch IS NULL AND NOT q.uncertain
 AND b.claim_id=b.id AND b.closed AND b.native_closed
 AND b.batch->'Worker'=cw.binding
 AND cw.binding->>'WorkerID'=w.id::text
 AND cw.binding->>'PodUID'=(convert_from(w.binding_json,'UTF8')::jsonb)->>'PodUID'
 AND b.native_authority->'Scope'=q.query->'Scope'
 AND b.native_operation->'Reference'->>'QueryID'=q.id::text
 AND b.native_operation->'Reference'->>'WorkerID'=w.id::text
 AND b.native_operation->'Reference'->>'OperationID'=b.id::text
 AND b.native_operation->'Reference'->>'Fence'=b.generation::text
 AND b.native_operation->>'ParentID'=b.id::text
 AND b.native_operation->>'Generation'=b.generation::text
 AND b.native_operation->>'WorkerPodUID'=cw.binding->>'PodUID'
) AS exhausted FROM download_worker w
WHERE w.root_id=$1 AND w.id=$2 AND w.query_id IS NOT NULL;

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
