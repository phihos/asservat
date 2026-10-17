-- name: LockOperationLifecycleAccount :one
SELECT * FROM operation_audit_account WHERE root_id=$1 AND lane=$2 AND principal_digest=$3 FOR UPDATE;
-- name: ReadOperationForLifecycle :one
SELECT * FROM operation_audit WHERE root_id=$1 AND id=$2;
-- name: LockOperationLifecycle :one
SELECT * FROM operation_audit_lifecycle WHERE root_id=$1 AND operation_id=$2 FOR UPDATE;
-- name: CompleteOperationIntent :execrows
UPDATE operation_audit_lifecycle SET intent_completion=$3 WHERE root_id=$1 AND operation_id=$2 AND intent_completion IS NULL;
-- name: CompleteOperationOutcome :execrows
UPDATE operation_audit_lifecycle SET outcome_completion=$3 WHERE root_id=$1 AND operation_id=$2 AND outcome_completion IS NULL;
-- name: LeaseOperationPurge :execrows
UPDATE operation_audit_lifecycle SET lease=$3,lease_fence=$4 WHERE root_id=$1 AND operation_id=$2;
-- name: SaveOriginalOperationPurge :execrows
UPDATE operation_audit_lifecycle SET retirement=$3 WHERE root_id=$1 AND operation_id=$2 AND retirement IS NULL;
-- name: ClaimOperationCertificate :execrows
UPDATE operation_audit_lifecycle SET certificate_started=true WHERE root_id=$1 AND operation_id=$2 AND NOT certificate_started;
-- name: CompleteOperationCertificate :execrows
UPDATE operation_audit_lifecycle SET certificate_completion=$3 WHERE root_id=$1 AND operation_id=$2 AND certificate_started AND certificate_completion IS NULL;
-- name: AckOperationCertificate :execrows
UPDATE operation_audit_lifecycle SET certificate_receipt=$3,certificate_acknowledged_at=clock_timestamp() WHERE root_id=$1 AND operation_id=$2 AND certificate_receipt IS NULL;
-- name: SaveTerminalOperationPurge :execrows
UPDATE operation_audit_lifecycle SET terminal_purge=$3 WHERE root_id=$1 AND operation_id=$2;
-- name: AckTerminalOperationPurge :execrows
UPDATE operation_audit_lifecycle SET terminal_acknowledged_at=clock_timestamp() WHERE root_id=$1 AND operation_id=$2 AND terminal_acknowledged_at IS NULL;
-- name: FinishOperationRetirement :one
SELECT finish_operation_audit_retirement($1,$2,$3)::boolean;

-- name: DueOperationAuditHistory :many
SELECT root_id,lane,principal_digest,release_at,delete_by
FROM operation_audit_history WHERE root_id=$1 AND lane=$2 AND eligible_at<=clock_timestamp()
ORDER BY eligible_at,release_at,delete_by,principal_digest LIMIT 16;
-- name: FinishOperationHistory :one
SELECT records::bigint,overdue::boolean FROM finish_operation_audit_history($1,$2,$3,$4,$5,$6);

-- name: ClaimOperationCertificateVerification :execrows
UPDATE operation_audit_lifecycle SET certificate_verify_attempts=certificate_verify_attempts+1
WHERE root_id=$1 AND operation_id=$2 AND certificate_verify_attempts<2 AND certificate_receipt IS NULL;
