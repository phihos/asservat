-- name: ReadRetainedContext :one
SELECT c.* FROM context_capture c WHERE c.root_id=$1 AND c.attempt_id=$2;
-- name: ReadRetentionDecision :one
SELECT * FROM retention_decision WHERE id=$1 AND root_id=$2;
-- name: LockRetentionDecision :one
SELECT * FROM retention_decision WHERE id=$1 AND root_id=$2 FOR UPDATE;
-- name: InsertRetentionDecision :exec
INSERT INTO retention_decision(id,root_id,attempt_id,sequence,previous_expires_at,previous_delete_by,expires_at,delete_by,decision_digest,decision_json)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);
-- name: TightenAttempt :execrows
UPDATE custody_attempt SET retention_sequence=$2,effective_expires_at=$3,effective_delete_by=$4 WHERE id=$1;
-- name: PendingRetentionDecisions :many
SELECT * FROM retention_decision WHERE root_id=$1 AND audit_acknowledged_at IS NULL ORDER BY recorded_at,id LIMIT 64;
-- name: AcknowledgeRetentionDecision :execrows
UPDATE retention_decision SET audit_acknowledged_at=clock_timestamp(),audit_receipt_json=$3 WHERE id=$1 AND root_id=$2 AND audit_acknowledged_at IS NULL;

-- name: ReadAttemptRetentionDecision :one
SELECT * FROM retention_decision WHERE attempt_id=$1 AND root_id=$2 AND sequence=$3;
