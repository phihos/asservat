-- name: ReadAPIExecution :one
SELECT * FROM context_execution WHERE root_id=$1 AND capture_id=$2;

-- name: LockAPIExecution :one
SELECT * FROM context_execution WHERE root_id=$1 AND capture_id=$2 FOR UPDATE;

-- name: InsertAPIExecution :one
INSERT INTO context_execution(root_id,capture_id,attempt_id,binding_json,process_json,expectation_digest,not_before,not_after,writer_protocol)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *;

-- name: BindAPIStart :one
UPDATE context_execution SET object_uid=$3 WHERE root_id=$1 AND capture_id=$2 AND phase='prepared' AND object_uid IS NULL RETURNING *;

-- name: RecordAPIStart :one
UPDATE context_execution SET phase='started',started_at=$3 WHERE root_id=$1 AND capture_id=$2 AND phase='prepared' AND object_uid IS NOT NULL RETURNING *;

-- name: RecordAPIOutcome :one
UPDATE context_execution SET phase=$3,acquired_at=$4,completed_at=$5,copies_json=$6,copies_digest=$7 WHERE root_id=$1 AND capture_id=$2 AND phase='started' RETURNING *;

-- name: ListStartedRecordings :many
-- ADR-248: started manual recordings (pcapng expectations) whose start is at
-- or before the given instant, oldest first, for the hub's collect loop.
SELECT e.capture_id FROM context_execution e JOIN context_capture c ON c.id=e.capture_id AND c.root_id=e.root_id
WHERE e.root_id=$1 AND e.phase='started' AND e.started_at<=$2 AND convert_from(c.expectation_json,'UTF8')::jsonb->>'NativeType'='pcapng'
ORDER BY e.started_at LIMIT $3;
