-- name: ReadDownloadKeyBinding :one
SELECT * FROM download_key_binding WHERE batch_id=$1 AND root_id=$2;

-- name: LockDownloadKeyBinding :one
SELECT * FROM download_key_binding WHERE batch_id=$1 AND root_id=$2 FOR UPDATE;

-- name: InsertDownloadKeyBinding :exec
INSERT INTO download_key_binding(batch_id,session_id,root_id,installation_id,key_id,peer_id,certificate_sha256,authority_json,valid_until,worker_proof_json)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: SpendDownloadKeyRole :execrows
UPDATE download_key_binding SET used_roles=used_roles | sqlc.arg(role_mask)::smallint
WHERE batch_id=$1 AND root_id=$2 AND (used_roles & sqlc.arg(role_mask)::smallint)=0;
