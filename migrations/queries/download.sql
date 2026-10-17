-- name: InsertDownloadAllocation :one
INSERT INTO download_allocation(id,root_id,cluster_id,namespace_uid,workload_uid,output_limit,read_limit,session_limit,valid_until)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *;

-- name: LockDownloadAllocation :one
SELECT * FROM download_allocation WHERE id=$1 AND root_id=$2 FOR UPDATE;

-- name: ChargeDownloadAllocation :execrows
UPDATE download_allocation SET reserved_output=reserved_output+$3,reserved_read=reserved_read+$4,reserved_sessions=reserved_sessions+1 WHERE id=$1 AND root_id=$2;

-- name: FindDownloadSession :one
SELECT * FROM artifact_download WHERE root_id=$1 AND actor_key=$2 AND idempotency_digest=$3;

-- name: ReadDownloadSession :one
SELECT * FROM artifact_download WHERE id=$1 AND root_id=$2;

-- name: LockDownloadSession :one
SELECT * FROM artifact_download WHERE id=$1 AND root_id=$2 FOR UPDATE;

-- name: InsertDownloadSession :one
INSERT INTO artifact_download(id,root_id,allocation_id,artifact_id,principal_key,actor_key,idempotency_digest,request_digest,scope_json,deadline,output_limit,read_limit,request_limit,stop_protocol)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,sqlc.narg(stop_protocol)) RETURNING *;

-- name: UpdateDownloadSession :execrows
UPDATE artifact_download SET state=$3,charged_output=$4,charged_read=$5,requests=$6,emitted_bytes=$7,generation=$8,active_batch=$9
WHERE id=$1 AND root_id=$2;

-- name: DownloadStreams :one
SELECT count(*)::bigint AS total,count(*) FILTER(WHERE s.principal_key=$2)::bigint AS principal
FROM artifact_download s
WHERE s.root_id=$1 AND (
 EXISTS(SELECT 1 FROM download_batch b WHERE b.id=s.active_batch AND b.lease_until>clock_timestamp() AND b.outcome_json IS NULL)
 OR EXISTS(SELECT 1 FROM download_response r WHERE r.session_id=s.id AND r.generation=s.generation AND NOT r.closed AND r.lease_until>clock_timestamp())
);

-- name: InsertDownloadBatch :one
INSERT INTO download_batch(id,session_id,generation,intent_json,lease_until) VALUES($1,$2,$3,$4,$5) RETURNING *;

-- name: LockDownloadBatch :one
SELECT * FROM download_batch WHERE id=$1 AND session_id=$2 FOR UPDATE;

-- name: ReadDownloadBatch :one
SELECT * FROM download_batch WHERE id=$1 AND session_id=$2;

-- name: AcknowledgeDownloadIntent :execrows
UPDATE download_batch SET audit_acknowledged_at=clock_timestamp(),audit_receipt_json=$3 WHERE id=$1 AND session_id=$2 AND audit_acknowledged_at IS NULL;

-- name: SetDownloadOutcome :execrows
UPDATE download_batch SET outcome_json=$3 WHERE id=$1 AND session_id=$2 AND outcome_json IS NULL;

-- name: AcknowledgeDownloadOutcome :execrows
UPDATE download_batch SET outcome_acknowledged_at=clock_timestamp(),outcome_receipt_json=$3 WHERE id=$1 AND session_id=$2 AND outcome_acknowledged_at IS NULL;

-- name: AcknowledgeDownloadState :execrows
UPDATE artifact_download SET state=$3 WHERE id=$1 AND root_id=$2;
