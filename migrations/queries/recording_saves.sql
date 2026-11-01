-- name: ListRecordingCandidates :many
SELECT sqlc.embed(s),p.name AS policy_name FROM policy_recording_source s JOIN policy_source p
 ON p.root_id=s.root_id AND p.policy_uid=s.policy_uid AND p.active_id=s.acceptance_id
WHERE s.root_id=$1 AND s.cluster_id=$2 AND s.namespace_uid=$3 AND s.workload_uid=$4
 AND NOT p.deleted AND NOT p.suspended AND s.slot_released_at IS NULL
 AND (sqlc.arg(policy_filter)::text='' OR s.policy_uid=sqlc.arg(policy_filter))
 AND (sqlc.narg(after_id)::uuid IS NULL OR s.id>sqlc.narg(after_id)::uuid)
ORDER BY s.id LIMIT 101;

-- name: ReadRecordingSources :many
SELECT sqlc.embed(s),p.name AS policy_name FROM policy_recording_source s JOIN policy_source p
 ON p.root_id=s.root_id AND p.policy_uid=s.policy_uid AND p.active_id=s.acceptance_id
WHERE s.root_id=$1 AND s.cluster_id=$2 AND s.namespace_uid=$3 AND s.workload_uid=$4
 AND s.id=ANY(sqlc.arg(source_ids)::uuid[]) AND NOT p.deleted AND NOT p.suspended AND s.slot_released_at IS NULL
ORDER BY s.id LIMIT 100;

-- name: InsertRecordingSelection :exec
INSERT INTO recording_selection_set(id,root_id,actor_key,principal_key,cluster_id,namespace_uid,workload_uid,references_json,created_at,expires_at,policy_uid,after_source_id,has_more)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13);

-- name: ReadRecordingSelection :one
SELECT * FROM recording_selection_set WHERE root_id=$1 AND id=$2 AND actor_key=$3 AND expires_at>clock_timestamp();

-- name: DeleteExpiredRecordingSelections :execrows
DELETE FROM recording_selection_set WHERE id IN (
 SELECT r.id FROM recording_selection_set r WHERE r.root_id=$1 AND r.expires_at<=clock_timestamp() ORDER BY r.expires_at,r.id LIMIT 1000
);

-- name: InsertRecordingSaveReservation :exec
INSERT INTO recording_save_reservation(capture_id,root_id,policy_uid,acceptance_id,grant_id,reserved_bytes,accepted_at,processing_until)
VALUES($1,$2,$3,$4,$5,$6,$7,$8);

-- name: ReadRecordingSaveReservation :one
SELECT * FROM recording_save_reservation WHERE root_id=$1 AND capture_id=$2;

-- name: RequestSnapshotCancellation :one
UPDATE context_capture SET snapshot_cancel_key=$3,snapshot_cancel_actor=$4,snapshot_cancel_requested_at=clock_timestamp()
WHERE root_id=$1 AND id=$2 AND snapshot_cancel_requested_at IS NULL AND progress_revision=$5 RETURNING *;

-- name: RecordUnstartedSnapshotCancellation :one
UPDATE context_capture c SET snapshot_cancel_joined_at=clock_timestamp()
WHERE c.root_id=$1 AND c.id=$2 AND c.snapshot_cancel_requested_at IS NOT NULL AND c.snapshot_cancel_joined_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM context_execution e WHERE e.root_id=$1 AND e.capture_id=$2 AND e.started_at IS NOT NULL) RETURNING *;

-- name: RecordSnapshotCancellation :one
UPDATE context_capture SET snapshot_cancel_joined_at=$3,snapshot_cancel_proof=$4,snapshot_cancel_proof_digest=$5
WHERE root_id=$1 AND id=$2 AND snapshot_cancel_requested_at IS NOT NULL AND snapshot_cancel_joined_at IS NULL RETURNING *;
