-- name: InsertWorkerConfiguration :exec
INSERT INTO download_worker_configuration(installation_id,cluster_id,source_uid,generation,observed_at,fresh_until)
VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING;

-- name: LockWorkerConfiguration :one
SELECT * FROM download_worker_configuration WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 FOR UPDATE;

-- name: ShareWorkerConfiguration :one
SELECT * FROM download_worker_configuration WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 FOR SHARE;

-- name: ReadWorkerConfigurationRevision :one
SELECT * FROM download_worker_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4;

-- name: InsertWorkerConfigurationRevision :exec
INSERT INTO download_worker_configuration_revision(installation_id,cluster_id,source_uid,generation,snapshot_json)
VALUES($1,$2,$3,$4,$5);

-- name: CountWorkerConfigurationRevisions :one
SELECT count(*) FROM download_worker_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3;

-- name: ObserveWorkerConfiguration :exec
UPDATE download_worker_configuration SET generation=$4,observed_at=$5,fresh_until=$6 WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3;

-- name: FenceWorkerConfiguration :exec
UPDATE download_worker_configuration SET fresh_until=least(fresh_until,clock_timestamp())
WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND observed_at<=$4;

-- name: AcknowledgeWorkerConfiguration :execrows
UPDATE download_worker_configuration_revision SET audit_receipt_json=$5
WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4 AND audit_receipt_json IS NULL;
