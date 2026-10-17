-- name: ConnectorLockOperationLifecycleAccount :one
SELECT * FROM connector_operation_account WHERE root_id=$1 AND lane=$2 AND principal_digest=$3 FOR UPDATE;

-- name: ConnectorReadOperationForLifecycle :one
SELECT * FROM connector_operation_audit WHERE root_id=$1 AND id=$2;

-- name: ConnectorLockOperationLifecycle :one
SELECT * FROM connector_operation_lifecycle WHERE root_id=$1 AND operation_id=$2 FOR UPDATE;

-- name: ConnectorCompleteOperationIntent :execrows
UPDATE connector_operation_lifecycle SET intent_completion=$3 WHERE root_id=$1 AND operation_id=$2 AND intent_completion IS NULL;

-- name: ConnectorCompleteOperationOutcome :execrows
UPDATE connector_operation_lifecycle SET outcome_completion=$3 WHERE root_id=$1 AND operation_id=$2 AND outcome_completion IS NULL;

-- name: ConnectorLeaseOperationPurge :execrows
UPDATE connector_operation_lifecycle SET lease=$3,lease_fence=$4 WHERE root_id=$1 AND operation_id=$2;

-- name: ConnectorSaveOriginalOperationPurge :execrows
UPDATE connector_operation_lifecycle SET retirement=$3 WHERE root_id=$1 AND operation_id=$2 AND retirement IS NULL;

-- name: ConnectorClaimOperationCertificate :execrows
UPDATE connector_operation_lifecycle SET certificate_started=true WHERE root_id=$1 AND operation_id=$2 AND NOT certificate_started;

-- name: ConnectorCompleteOperationCertificate :execrows
UPDATE connector_operation_lifecycle SET certificate_completion=$3 WHERE root_id=$1 AND operation_id=$2 AND certificate_started AND certificate_completion IS NULL;

-- name: ConnectorAckOperationCertificate :execrows
UPDATE connector_operation_lifecycle SET certificate_receipt=$3,certificate_acknowledged_at=clock_timestamp() WHERE root_id=$1 AND operation_id=$2 AND certificate_receipt IS NULL;

-- name: ConnectorSaveTerminalOperationPurge :execrows
UPDATE connector_operation_lifecycle SET terminal_purge=$3 WHERE root_id=$1 AND operation_id=$2;

-- name: ConnectorAckTerminalOperationPurge :execrows
UPDATE connector_operation_lifecycle SET terminal_acknowledged_at=clock_timestamp() WHERE root_id=$1 AND operation_id=$2 AND terminal_acknowledged_at IS NULL;

-- name: ConnectorDueOperationAuditHistory :many
SELECT root_id,lane,principal_digest,release_at,delete_by
FROM connector_operation_history WHERE root_id=$1 AND lane=$2 AND eligible_at<=clock_timestamp()
ORDER BY eligible_at,release_at,delete_by,principal_digest LIMIT 16;

-- name: ConnectorClaimOperationCertificateVerification :execrows
UPDATE connector_operation_lifecycle SET certificate_verify_attempts=certificate_verify_attempts+1
WHERE root_id=$1 AND operation_id=$2 AND certificate_verify_attempts<2 AND certificate_receipt IS NULL;


-- name: ConnectorLeaseOverdueOperationPurge :execrows
UPDATE connector_operation_lifecycle SET overdue_selected_at=COALESCE(overdue_selected_at,$3),lease=$4,lease_fence=$5 WHERE root_id=$1 AND operation_id=$2;

-- name: ConnectorSaveOverdueOperationPurge :execrows
UPDATE connector_operation_lifecycle SET overdue_purge=$3 WHERE root_id=$1 AND operation_id=$2 AND overdue_selected_at IS NOT NULL AND overdue_purge IS NULL;


-- name: ConnectorLockOperationAuditPool :one
SELECT * FROM connector_operation_pool WHERE root_id=$1 AND lane=$2 FOR UPDATE;
-- name: ConnectorLockOperationAudit :one
SELECT * FROM connector_operation_audit WHERE id=$1 AND root_id=$2 FOR UPDATE;
-- name: ConnectorFinishOperationRetirement :one
SELECT finish_connector_operation_retirement(sqlc.arg(r)::uuid,sqlc.arg(i)::uuid,sqlc.arg(installation)::uuid)::boolean;
-- name: ConnectorFinishOperationHistory :one
SELECT records::bigint,overdue::boolean FROM finish_connector_operation_history(sqlc.arg(r)::uuid,sqlc.arg(l)::text,sqlc.arg(p)::bytea,sqlc.arg(releases)::timestamptz,sqlc.arg(deletes)::timestamptz,sqlc.arg(installation)::uuid);
