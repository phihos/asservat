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
SELECT v.*,NULL::bytea AS snapshot_coverage,NULL::bytea AS snapshot_coverage_digest,NULL::bytea AS snapshot_expectation_digest,NULL::bytea AS snapshot_cancel_key,NULL::bytea AS snapshot_cancel_actor,NULL::timestamptz AS snapshot_cancel_requested_at,NULL::timestamptz AS snapshot_cancel_joined_at,NULL::bytea AS snapshot_cancel_proof,NULL::bytea AS snapshot_cancel_proof_digest,g.group_id,g.group_ordinal FROM capture_operation_intents v LEFT JOIN LATERAL (SELECT  CASE WHEN convert_from(v.scope_json,'UTF8')::jsonb->>'schemaVersion'='recording-save/v1' AND jsonb_array_length(convert_from(v.scope_json,'UTF8')::jsonb->'sources')>1
 THEN (convert_from(v.scope_json,'UTF8')::jsonb->>'captureID')::uuid ELSE NULL::uuid END AS group_id,
 CASE WHEN convert_from(v.scope_json,'UTF8')::jsonb->>'schemaVersion'='recording-save/v1' AND jsonb_array_length(convert_from(v.scope_json,'UTF8')::jsonb->'sources')>1
 THEN (SELECT (m.ordinality-1)::smallint FROM jsonb_array_elements(convert_from(v.scope_json,'UTF8')::jsonb->'sources') WITH ORDINALITY m(value,ordinality)
 WHERE m.value->>'sourceSessionID'=convert_from(v.expectation_json,'UTF8')::jsonb#>>'{Snapshot,SourceID}') ELSE (-1)::smallint END AS group_ordinal) g ON true WHERE v.root_id=$1 AND v.id=$2;

-- name: ReadCaptureReason :one
SELECT read_capture_reason(sqlc.arg(root_id)::uuid,sqlc.arg(capture_id)::uuid)::jsonb;
