-- Private first-context runtime selects only the sole original worker/metadata
-- attempt. The second row detects incompatible replacement/re-preparation; it
-- never chooses a newer successful row after an uncertain original operation.
-- name: ReadContextDownloadWorkers :many
SELECT * FROM download_worker WHERE session_id=$1 AND root_id=$2 ORDER BY generation ASC LIMIT 2;

-- name: ReadFirstContextDownloadBatches :many
SELECT * FROM download_batch WHERE session_id=$1 ORDER BY generation ASC LIMIT 2;

-- At most two attempts per epoch, and at most the current/previous live epoch.
-- Historical activated rows do not become current peer or Pod proof.
-- name: ReadContextWorkerCertificates :many
SELECT * FROM download_worker_certificate WHERE worker_id=sqlc.arg(worker_id) AND epoch IN (sqlc.arg(current_epoch)::integer,sqlc.arg(previous_epoch)::integer) AND activated_at IS NOT NULL ORDER BY epoch DESC,ordinal DESC LIMIT 5;

-- name: ReadContextDownloadAllocations :many
-- Count matching live allocations before checking their backing. A missing or
-- unsupported backing must not silently select a different allocation.
SELECT * FROM download_allocation
WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND workload_uid=$4
 AND clock_timestamp()<valid_until
ORDER BY id LIMIT 2;

-- name: ReadFirstContextResponseWindows :many
-- The first context response has exactly one <=4096-byte window. A second row
-- detects incompatible data; a closed owner is never substituted for outcome.
-- Caller holds the original session lock, shared with outcome/ack writers.
SELECT * FROM download_window WHERE response_id=$1 AND session_id=$2 ORDER BY ordinal LIMIT 2;
