-- name: InsertLocalKeyConfiguration :exec
INSERT INTO local_key_configuration(installation_id,purpose,key_id,snapshot_json)
VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING;

-- name: LockLocalKeyConfiguration :one
SELECT snapshot_json FROM local_key_configuration
WHERE installation_id=$1 AND purpose=$2 AND key_id=$3 FOR UPDATE;

-- name: UpdateLocalKeyConfiguration :exec
UPDATE local_key_configuration SET snapshot_json=$4
WHERE installation_id=$1 AND purpose=$2 AND key_id=$3;

-- name: ReadLocalKeyVersions :many
SELECT version,fingerprint FROM local_key_version
WHERE installation_id=$1 AND purpose=$2 AND key_id=$3 ORDER BY version LIMIT 17;

-- name: InsertLocalKeyVersion :exec
INSERT INTO local_key_version(installation_id,purpose,key_id,version,fingerprint)
VALUES($1,$2,$3,$4,$5);
