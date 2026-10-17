-- name: InsertOwnerConfiguration :execrows
INSERT INTO hub_owner_configuration(installation_id,cluster_id,source_uid,generation,observed_at,fresh_until)
VALUES($1,$2,$3,0,$4,$4) ON CONFLICT DO NOTHING;

-- name: LockOwnerConfiguration :one
SELECT * FROM hub_owner_configuration WHERE installation_id=$1 AND cluster_id=$2 FOR UPDATE;

-- name: ShareOwnerConfiguration :one
SELECT * FROM hub_owner_configuration WHERE installation_id=$1 AND cluster_id=$2 FOR SHARE;

-- name: ReadOwnerConfigurationRevision :one
SELECT * FROM hub_owner_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4;

-- name: InsertOwnerConfigurationRevision :exec
INSERT INTO hub_owner_configuration_revision(installation_id,cluster_id,source_uid,generation,snapshot_json)
VALUES($1,$2,$3,$4,$5);

-- name: CountOwnerConfigurationRevisions :one
SELECT count(*) FROM hub_owner_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3;

-- name: ObserveOwnerConfiguration :exec
UPDATE hub_owner_configuration SET generation=$4,observed_at=$5,fresh_until=$6
WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3;

-- name: FenceOwnerConfiguration :exec
UPDATE hub_owner_configuration SET observed_at=$4,fresh_until=least(fresh_until,$4::timestamptz)
WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND observed_at<=$4;

-- name: AcknowledgeOwnerConfiguration :execrows
UPDATE hub_owner_configuration_revision SET audit_receipt_json=$5
WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4 AND audit_receipt_json IS NULL;
