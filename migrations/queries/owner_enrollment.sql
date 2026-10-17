-- name: ReadOwnerEnrollment :one
SELECT * FROM hub_owner_enrollment WHERE installation_id=$1 AND cluster_id=$2 AND issuer_epoch=$3 AND pod_uid=$4 AND process_epoch=$5 AND usage=$6;

-- name: ReadOwnerEnrollmentID :one
SELECT * FROM hub_owner_enrollment WHERE id=$1 AND installation_id=$2 AND cluster_id=$3;

-- name: CountOwnerEnrollments :one
SELECT count(*) AS total,count(*) FILTER(WHERE pod_uid=$3) AS pod FROM hub_owner_enrollment WHERE installation_id=$1 AND cluster_id=$2;

-- name: InsertOwnerEnrollment :exec
INSERT INTO hub_owner_enrollment(id,installation_id,cluster_id,issuer_epoch,pod_uid,process_epoch,usage,enrollment_json,created_at,hold_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: AcknowledgeOwnerEnrollment :execrows
UPDATE hub_owner_enrollment SET audit_receipt_json=$2 WHERE id=$1 AND audit_receipt_json IS NULL;

-- name: ReadOwnerCertificateEpoch :many
SELECT * FROM hub_owner_certificate WHERE enrollment_id=$1 AND epoch=$2 ORDER BY ordinal;

-- name: ReadOwnerCertificate :one
SELECT * FROM hub_owner_certificate WHERE id=$1 AND enrollment_id=$2;

-- name: InsertOwnerCertificateAttempt :exec
INSERT INTO hub_owner_certificate(id,enrollment_id,epoch,ordinal,not_after,attempt_json) VALUES($1,$2,$3,$4,$5,$6);

-- name: StoreOwnerCertificate :execrows
UPDATE hub_owner_certificate SET certificate_json=$3,certificate_sha256=$4 WHERE id=$1 AND enrollment_id=$2 AND certificate_json IS NULL;

-- name: AcknowledgeOwnerCertificate :execrows
UPDATE hub_owner_certificate SET audit_receipt_json=$3 WHERE id=$1 AND enrollment_id=$2 AND certificate_json IS NOT NULL AND audit_receipt_json IS NULL;

-- name: ActivateOwnerCertificate :execrows
UPDATE hub_owner_certificate SET activated_at=clock_timestamp() WHERE id=$1 AND enrollment_id=$2 AND audit_receipt_json IS NOT NULL AND activated_at IS NULL;

-- name: ReadActiveOwnerCertificate :one
SELECT * FROM hub_owner_certificate WHERE enrollment_id=$1 AND certificate_sha256=$2 AND activated_at IS NOT NULL;

-- name: RetireOwnerEnrollment :execrows
UPDATE hub_owner_enrollment SET retired_at=clock_timestamp() WHERE id=$1 AND installation_id=$2 AND cluster_id=$3 AND retired_at IS NULL;

-- name: PruneOwnerCertificates :execrows
DELETE FROM hub_owner_certificate USING hub_owner_enrollment e WHERE enrollment_id=e.id AND e.installation_id=$1 AND e.cluster_id=$2 AND not_after+interval '1 minute'<=clock_timestamp();

-- name: PruneOwnerEnrollments :execrows
DELETE FROM hub_owner_enrollment WHERE installation_id=$1 AND cluster_id=$2 AND hold_until<=clock_timestamp() AND NOT EXISTS(SELECT FROM hub_owner_certificate WHERE enrollment_id=hub_owner_enrollment.id);
