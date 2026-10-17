-- name: InsertRetentionSource :exec
INSERT INTO retention_source(root_id,cluster_id,namespace_uid,hub,protection_digest,epoch,lease_until)
VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+interval '30 seconds') ON CONFLICT DO NOTHING;

-- name: LockRetentionSource :one
SELECT * FROM retention_source WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 FOR UPDATE;

-- name: InsertRetentionEpoch :exec
INSERT INTO retention_source_epoch(root_id,cluster_id,namespace_uid,epoch) VALUES($1,$2,$3,$4);

-- name: StartRetentionSource :one
UPDATE retention_source SET epoch=$4,lease_until=clock_timestamp()+interval '30 seconds',suspended=false,observed_sequence=NULL,observed_at=NULL,fresh_until=NULL
WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND recovery_blocked=false RETURNING *;

-- name: RenewRetentionSource :one
UPDATE retention_source SET lease_until=clock_timestamp()+interval '30 seconds'
WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND epoch=$4 AND suspended=false AND recovery_blocked=false AND lease_until>clock_timestamp() RETURNING lease_until;

-- name: SuspendRetentionSource :exec
UPDATE retention_source SET suspended=true,lease_until=clock_timestamp(),observed_sequence=NULL,observed_at=NULL,fresh_until=NULL
WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND epoch=$4;

-- name: AdvanceRetentionSource :exec
UPDATE retention_source SET sequence=$4,watch_cursor=$5,observed_sequence=NULL,observed_at=NULL,fresh_until=NULL WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3;

-- name: AdvanceRetentionCursor :exec
UPDATE retention_source SET watch_cursor=$4 WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3;

-- name: ObserveRetentionSource :exec
UPDATE retention_source SET observed_sequence=sequence,observed_at=$4,fresh_until=$5 WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3;

-- name: InvalidateRetentionObservation :exec
UPDATE retention_source SET observed_sequence=NULL,observed_at=NULL,fresh_until=NULL WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3;

-- name: RecordRetentionListCursor :exec
UPDATE retention_source SET list_cursor=$4 WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3;

-- name: ShareRetentionSource :one
SELECT * FROM retention_source WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 FOR SHARE;

-- name: RetentionSourceCaughtUp :one
SELECT NOT EXISTS (
 SELECT 1 FROM retention_checkpoint c LEFT JOIN retention_catchup j ON j.checkpoint_id=c.id
 WHERE c.root_id=$1 AND c.cluster_id=$2 AND c.namespace_uid=$3
 AND (c.audit_acknowledged_at IS NULL OR j.checkpoint_id IS NULL OR j.completed_at IS NULL
 OR EXISTS(SELECT 1 FROM retention_catchup_effect e JOIN retention_decision d ON d.id=e.decision_id
 WHERE e.checkpoint_id=c.id AND d.audit_acknowledged_at IS NULL))
) AS complete;

-- name: ReadRetentionCheckpoint :one
SELECT * FROM retention_checkpoint WHERE id=$1 AND root_id=$2;

-- name: LockRetentionCheckpoint :one
SELECT * FROM retention_checkpoint WHERE id=$1 AND root_id=$2 FOR UPDATE;

-- name: ReadCurrentRetentionCheckpoint :one
SELECT * FROM retention_checkpoint WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND sequence=$4;

-- name: InsertRetentionCheckpoint :exec
INSERT INTO retention_checkpoint(id,root_id,cluster_id,namespace_uid,epoch,sequence,transition_digest,transition_json,record_digest,record_json,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11);

-- name: PendingRetentionCheckpoints :many
SELECT * FROM retention_checkpoint WHERE root_id=$1 AND audit_acknowledged_at IS NULL ORDER BY created_at,id LIMIT $2;

-- name: AcknowledgeRetentionCheckpoint :exec
UPDATE retention_checkpoint SET audit_acknowledged_at=clock_timestamp(),audit_receipt=$3 WHERE id=$1 AND root_id=$2 AND audit_acknowledged_at IS NULL;
