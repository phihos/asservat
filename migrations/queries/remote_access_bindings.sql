-- name: InsertRemoteAccessBindings :one
INSERT INTO remote_access_binding_delivery(root_id,cluster_id,observed_at,digest,bindings,unavailable)
VALUES ($1,$2,statement_timestamp(),$3,$4,$5)
ON CONFLICT(root_id,cluster_id) DO NOTHING RETURNING revision;

-- name: ReplaceRemoteAccessBindings :one
-- Every completed exchange, including confirmation, advances the same token.
-- A deletion followed by a new observation also has a distinct revision.
UPDATE remote_access_binding_delivery SET
 observed_at=statement_timestamp(),revision=DEFAULT,
 unavailable=CASE WHEN digest=sqlc.arg(digest) THEN unavailable ELSE sqlc.arg(unavailable) END,
 bindings=CASE WHEN digest=sqlc.arg(digest) THEN bindings ELSE sqlc.arg(bindings) END,
 digest=sqlc.arg(digest)
WHERE root_id=sqlc.arg(root_id) AND cluster_id=sqlc.arg(cluster_id)
 AND revision=sqlc.arg(previous) RETURNING revision;

-- name: ListRemoteAccessBindings :many
-- Compare the reader's cached digests within the same database snapshot.
-- Only a missing or changed delivery returns its potentially large document.
WITH cached AS (
 SELECT unnest(sqlc.arg(cluster_ids)::uuid[]) AS cluster_id,
        unnest(sqlc.arg(digests)::bytea[]) AS digest
)
SELECT d.cluster_id, d.observed_at, d.digest, d.unavailable,
       (CASE WHEN d.digest IS DISTINCT FROM c.digest THEN d.bindings END)::bytea AS bindings
FROM remote_access_binding_delivery d LEFT JOIN cached c USING (cluster_id)
WHERE d.root_id=sqlc.arg(root_id) ORDER BY d.cluster_id;

-- name: ReadRemoteAccessBindingDigest :one
SELECT digest, revision FROM remote_access_binding_delivery
WHERE root_id=$1 AND cluster_id=$2;
