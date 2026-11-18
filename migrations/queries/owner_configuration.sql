-- name: InsertOwnerConfiguration :execrows
INSERT INTO hub_owner_configuration(installation_id,cluster_id,source_uid,generation,observed_at,fresh_until)
VALUES($1,$2,$3,0,statement_timestamp(),statement_timestamp()) ON CONFLICT DO NOTHING;

-- name: LockOwnerConfiguration :one
SELECT * FROM hub_owner_configuration WHERE installation_id=$1 AND cluster_id=$2 FOR UPDATE;

-- name: ShareOwnerConfiguration :one
SELECT * FROM hub_owner_configuration WHERE installation_id=$1 AND cluster_id=$2 FOR SHARE;

-- name: ReadOwnerConfigurationRevision :one
SELECT installation_id,cluster_id,source_uid,generation,snapshot_json FROM hub_owner_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4;

-- name: InsertOwnerConfigurationRevision :exec
INSERT INTO hub_owner_configuration_revision(installation_id,cluster_id,source_uid,generation,snapshot_json)
VALUES($1,$2,$3,$4,$5);

-- name: ObserveOwnerConfiguration :exec
UPDATE hub_owner_configuration SET source_version=$4,generation=$5,observed_at=clock_timestamp(),fresh_until=$6
WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3;

-- name: FenceOwnerConfiguration :execrows
UPDATE hub_owner_configuration SET source_version=$4,observed_at=statement_timestamp(),fresh_until=statement_timestamp()
WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3;
