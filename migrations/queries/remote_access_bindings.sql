-- name: StoreRemoteAccessBindings :execrows
-- An older delivery never replaces a newer one; unchanged bindings keep
-- their stored bytes.
INSERT INTO remote_access_binding_delivery(root_id,cluster_id,observed_at,digest,bindings)
VALUES($1,$2,$3,$4,$5)
ON CONFLICT(root_id,cluster_id) DO UPDATE SET observed_at=excluded.observed_at,digest=excluded.digest,
 bindings=CASE WHEN remote_access_binding_delivery.digest=excluded.digest THEN remote_access_binding_delivery.bindings ELSE excluded.bindings END
WHERE remote_access_binding_delivery.observed_at<excluded.observed_at;

-- name: ListRemoteAccessBindingDigests :many
SELECT cluster_id,observed_at,digest FROM remote_access_binding_delivery WHERE root_id=$1 ORDER BY cluster_id LIMIT 64;

-- name: ReadRemoteAccessBindings :one
SELECT observed_at,digest,bindings FROM remote_access_binding_delivery WHERE root_id=$1 AND cluster_id=$2;

-- name: ReadRemoteAccessBindingDigest :one
SELECT digest FROM remote_access_binding_delivery WHERE root_id=$1 AND cluster_id=$2;
