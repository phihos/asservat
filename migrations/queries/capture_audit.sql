-- name: LockCaptureAuditAdmission :one
SELECT lock_capture_audit_admission(sqlc.arg(root_id)::uuid,sqlc.arg(allocation_id)::uuid)::jsonb;

-- name: ReserveCaptureAudit :exec
SELECT reserve_capture_audit(sqlc.arg(root_id)::uuid,sqlc.arg(capture_id)::uuid,sqlc.arg(intent_value)::jsonb,sqlc.arg(capture_digest)::bytea,sqlc.arg(original_until)::timestamptz);

-- name: ReadCaptureOperation :one
SELECT read_capture_operation(sqlc.arg(root_id)::uuid,sqlc.arg(operation_id)::uuid)::jsonb;

-- name: CaptureAuditJournal :one
SELECT capture_audit_journal(sqlc.arg(root_id)::uuid,sqlc.arg(intent_value)::jsonb,sqlc.arg(verb)::text,sqlc.narg(outcome_value)::jsonb)::jsonb;

-- name: CaptureAuditAcknowledge :one
SELECT capture_audit_acknowledge(sqlc.arg(root_id)::uuid,sqlc.arg(intent_value)::jsonb,sqlc.arg(phase)::text,sqlc.narg(completion_value)::jsonb,sqlc.narg(receipt_value)::jsonb,sqlc.narg(read_claim)::jsonb)::jsonb;

-- name: ClaimCaptureReconciliation :one
SELECT claim_capture_reconciliation(sqlc.arg(root_id)::uuid,sqlc.arg(intent_value)::jsonb,sqlc.arg(phase)::text)::jsonb;

-- name: AcknowledgeCapturePair :one
SELECT acknowledge_capture_pair(sqlc.arg(root_id)::uuid,sqlc.arg(intent_value)::jsonb);

-- name: ConfigureCaptureAuditBacking :one
SELECT configure_capture_audit_backing(sqlc.arg(root_id)::uuid,sqlc.arg(pool_value)::jsonb,sqlc.arg(account_value)::jsonb,sqlc.arg(observed_at)::timestamptz,sqlc.arg(fresh_until)::timestamptz);

-- name: ReadCaptureOperationIntent :one
-- Original intent view deliberately excludes later completion observations.
SELECT *,NULL::bytea AS snapshot_coverage,NULL::bytea AS snapshot_coverage_digest,NULL::bytea AS snapshot_expectation_digest FROM capture_operation_intents WHERE root_id=$1 AND id=$2;
