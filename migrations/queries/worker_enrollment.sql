-- name: ReadWorkerEnrollment :one
SELECT * FROM download_worker_enrollment WHERE worker_id=$1;

-- name: InsertWorkerEnrollment :exec
INSERT INTO download_worker_enrollment(worker_id,enrollment_json) VALUES($1,$2);

-- name: AcknowledgeWorkerEnrollment :execrows
UPDATE download_worker_enrollment SET audit_receipt_json=$2 WHERE worker_id=$1 AND audit_receipt_json IS NULL;

-- name: ReadWorkerCertificateEpoch :many
SELECT * FROM download_worker_certificate WHERE worker_id=$1 AND epoch=$2 ORDER BY ordinal;

-- name: ReadWorkerCertificate :one
SELECT * FROM download_worker_certificate WHERE id=$1 AND worker_id=$2;

-- name: InsertWorkerCertificateAttempt :exec
INSERT INTO download_worker_certificate(id,worker_id,epoch,ordinal,attempt_json) VALUES($1,$2,$3,$4,$5);

-- name: StoreWorkerCertificate :execrows
UPDATE download_worker_certificate SET certificate_json=$3,certificate_sha256=$4 WHERE id=$1 AND worker_id=$2 AND certificate_json IS NULL;

-- name: AcknowledgeWorkerCertificate :execrows
UPDATE download_worker_certificate SET audit_receipt_json=$3 WHERE id=$1 AND worker_id=$2 AND certificate_json IS NOT NULL AND audit_receipt_json IS NULL;

-- name: ActivateWorkerCertificate :execrows
UPDATE download_worker_certificate SET activated_at=clock_timestamp() WHERE id=$1 AND worker_id=$2 AND audit_receipt_json IS NOT NULL AND activated_at IS NULL;

-- name: ReadActiveWorkerCertificate :one
SELECT * FROM download_worker_certificate WHERE worker_id=$1 AND certificate_sha256=$2 AND activated_at IS NOT NULL;
