-- name: RecordSourceSnapshotCompletion :one
UPDATE context_capture SET snapshot_coverage=$3,snapshot_coverage_digest=$4,snapshot_expectation_digest=$5
WHERE root_id=$1 AND id=$2 AND snapshot_coverage IS NULL RETURNING *;

-- name: ReadAPIExecutionPublication :one
SELECT sqlc.embed(e),sqlc.embed(c) FROM context_execution e
JOIN context_capture c ON c.root_id=e.root_id AND c.id=e.capture_id
WHERE e.root_id=$1 AND e.capture_id=$2;
