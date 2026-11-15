-- name: ObserveContextStorage :one
-- Bindings are standing rows; the read is the observation, current for the
-- domain's thirty-second storage interval.
SELECT b.root_id,b.cluster_id,b.namespace_uid,b.workload_uid,b.allocation_id,
 b.source_uid,b.source_generation,b.source_digest,date_trunc('microseconds',clock_timestamp())::timestamptz AS observed_at,
 (date_trunc('microseconds',clock_timestamp())+interval '30 seconds')::timestamptz AS fresh_until,
 a.revision AS allocation_revision,a.valid_until AS allocation_valid_until,
 a.paused AS allocation_paused,a.service_class,
 p.store_id,p.revision AS pool_revision,p.valid_until AS pool_valid_until,
 p.paused AS pool_paused
FROM context_storage_binding b
JOIN custody_allocation a ON a.id=b.allocation_id
JOIN custody_pool p ON p.id=a.pool_id
WHERE b.root_id=$1 AND b.cluster_id=$2 AND b.namespace_uid=$3 AND b.workload_uid=$4;
