-- name: StoreRemoteAccessBindings :execrows
-- An older delivery never replaces a newer one; unchanged bindings keep
-- their stored bytes.
INSERT INTO remote_access_binding_delivery(root_id,cluster_id,observed_at,digest,bindings)
VALUES($1,$2,$3,$4,$5)
ON CONFLICT(root_id,cluster_id) DO UPDATE SET observed_at=excluded.observed_at,digest=excluded.digest,
 bindings=CASE WHEN remote_access_binding_delivery.digest=excluded.digest THEN remote_access_binding_delivery.bindings ELSE excluded.bindings END
WHERE remote_access_binding_delivery.observed_at<excluded.observed_at
 OR (remote_access_binding_delivery.observed_at=excluded.observed_at AND remote_access_binding_delivery.digest<>excluded.digest);

-- name: ListRemoteAccessBindings :many
-- Compare the reader's cached digests within the same database snapshot.
-- Only a missing or changed delivery returns its potentially large document.
WITH cached AS (
 SELECT unnest(sqlc.arg(cluster_ids)::uuid[]) AS cluster_id,
        unnest(sqlc.arg(digests)::bytea[]) AS digest
)
SELECT d.cluster_id, d.observed_at, d.digest,
       (CASE WHEN d.digest IS DISTINCT FROM c.digest THEN d.bindings END)::bytea AS bindings
FROM remote_access_binding_delivery d LEFT JOIN cached c USING (cluster_id)
WHERE d.root_id=sqlc.arg(root_id) ORDER BY d.cluster_id;

-- name: ReadRemoteAccessBindingDigest :one
SELECT digest FROM remote_access_binding_delivery WHERE root_id=$1 AND cluster_id=$2;
