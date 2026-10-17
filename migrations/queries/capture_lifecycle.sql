-- name: CaptureLockOperationLifecycleAccount :one
SELECT * FROM capture_operation_account WHERE root_id=$1 AND lane=$2 AND principal_digest=$3 FOR UPDATE;

-- name: CaptureReadOperationForLifecycle :one
SELECT * FROM capture_operation_audit WHERE root_id=$1 AND id=$2;

-- name: CaptureLockOperationLifecycle :one
SELECT * FROM capture_operation_lifecycle WHERE root_id=$1 AND operation_id=$2 FOR UPDATE;

-- name: CaptureCompleteOperationIntent :execrows
UPDATE capture_operation_lifecycle SET intent_completion=$3 WHERE root_id=$1 AND operation_id=$2 AND intent_completion IS NULL;

-- name: CaptureCompleteOperationOutcome :execrows
UPDATE capture_operation_lifecycle SET outcome_completion=$3 WHERE root_id=$1 AND operation_id=$2 AND outcome_completion IS NULL;

-- name: CaptureLeaseOperationPurge :execrows
UPDATE capture_operation_lifecycle SET lease=$3,lease_fence=$4 WHERE root_id=$1 AND operation_id=$2;

-- name: CaptureSaveOriginalOperationPurge :execrows
UPDATE capture_operation_lifecycle SET retirement=$3 WHERE root_id=$1 AND operation_id=$2 AND retirement IS NULL;

-- name: CaptureClaimOperationCertificate :execrows
UPDATE capture_operation_lifecycle SET certificate_started=true WHERE root_id=$1 AND operation_id=$2 AND NOT certificate_started;

-- name: CaptureCompleteOperationCertificate :execrows
UPDATE capture_operation_lifecycle SET certificate_completion=$3 WHERE root_id=$1 AND operation_id=$2 AND certificate_started AND certificate_completion IS NULL;

-- name: CaptureAckOperationCertificate :execrows
UPDATE capture_operation_lifecycle SET certificate_receipt=$3,certificate_acknowledged_at=clock_timestamp() WHERE root_id=$1 AND operation_id=$2 AND certificate_receipt IS NULL;

-- name: CaptureSaveTerminalOperationPurge :execrows
UPDATE capture_operation_lifecycle SET terminal_purge=$3 WHERE root_id=$1 AND operation_id=$2;

-- name: CaptureAckTerminalOperationPurge :execrows
UPDATE capture_operation_lifecycle SET terminal_acknowledged_at=clock_timestamp() WHERE root_id=$1 AND operation_id=$2 AND terminal_acknowledged_at IS NULL;

-- name: CaptureDueOperationAuditHistory :many
SELECT root_id,lane,principal_digest,release_at,delete_by
FROM capture_operation_history WHERE root_id=$1 AND lane=$2 AND eligible_at<=clock_timestamp()
ORDER BY eligible_at,release_at,delete_by,principal_digest LIMIT 16;

-- name: CaptureClaimOperationCertificateVerification :execrows
UPDATE capture_operation_lifecycle SET certificate_verify_attempts=certificate_verify_attempts+1
WHERE root_id=$1 AND operation_id=$2 AND certificate_verify_attempts<2 AND certificate_receipt IS NULL;


-- name: CaptureLeaseOverdueOperationPurge :execrows
UPDATE capture_operation_lifecycle SET overdue_selected_at=COALESCE(overdue_selected_at,$3),lease=$4,lease_fence=$5 WHERE root_id=$1 AND operation_id=$2;

-- name: CaptureSaveOverdueOperationPurge :execrows
UPDATE capture_operation_lifecycle SET overdue_purge=$3 WHERE root_id=$1 AND operation_id=$2 AND overdue_selected_at IS NOT NULL AND overdue_purge IS NULL;


-- name: CaptureLockOperationAuditPool :one
SELECT * FROM capture_operation_pool WHERE root_id=$1 AND lane=$2 FOR UPDATE;
-- name: CaptureLockOperationAudit :one
SELECT * FROM capture_operation_audit WHERE id=$1 AND root_id=$2 FOR UPDATE;
-- name: CaptureFinishOperationRetirement :one
SELECT finish_capture_operation_retirement(sqlc.arg(r)::uuid,sqlc.arg(i)::uuid,sqlc.arg(installation)::uuid)::boolean;
-- name: CaptureFinishOperationHistory :one
SELECT records::bigint,overdue::boolean FROM finish_capture_operation_history(sqlc.arg(r)::uuid,sqlc.arg(l)::text,sqlc.arg(p)::bytea,sqlc.arg(releases)::timestamptz,sqlc.arg(deletes)::timestamptz,sqlc.arg(installation)::uuid);

-- name: CaptureDueOperationLifecycles :many
-- Selection is scheduling only. The exact row transaction independently locks
-- current recovery and rechecks original lifecycle/closure before every effect.
SELECT operation_id FROM capture_operation_lifecycle
WHERE root_id=sqlc.arg(root_id)::uuid
  AND operation_id>sqlc.arg(after_id)::uuid
  AND original_purge_at<=clock_timestamp()
ORDER BY operation_id LIMIT 16;
