-- name: RecordSourceSnapshotCompletion :one
UPDATE context_capture SET snapshot_coverage=$3,snapshot_coverage_digest=$4,snapshot_expectation_digest=$5
WHERE root_id=$1 AND id=$2 AND snapshot_coverage IS NULL RETURNING *;
