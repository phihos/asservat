-- name: LockOperationAuditPool :one
SELECT * FROM operation_audit_pool WHERE root_id=$1 AND lane=$2 FOR UPDATE;
-- name: InsertOperationAuditPool :exec
INSERT INTO operation_audit_pool(root_id,lane,account_version,revision,valid_until,account_limit,records_per_account,retained_seconds,paused)
VALUES($1,$2,$3,1,$4,$5,$6,$7,$8);
-- name: ConfigureOperationAuditPool :execrows
UPDATE operation_audit_pool SET revision=revision+1,valid_until=$3,account_limit=$4,retained_seconds=$5,paused=$6,records_per_account=sqlc.arg(records_per_account)
WHERE root_id=$1 AND lane=$2 AND revision=sqlc.arg(expected_revision);
-- name: ReadOperationAuditAccount :one
SELECT * FROM operation_audit_account WHERE root_id=$1 AND lane=$2 AND principal_digest=$3;
-- name: LockOperationAudit :one
SELECT * FROM operation_audit WHERE id=$1 AND root_id=$2 FOR UPDATE;
-- name: InsertOperationAudit :one
INSERT INTO operation_audit(id,root_id,lane,principal_digest,intent,request_until,write_until,retain_until,issuer_epoch)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *;
-- name: ClaimOperationIntent :execrows
UPDATE operation_audit SET intent_started=true WHERE id=$1 AND root_id=$2 AND NOT intent_started;
-- name: ClaimOperationOutcome :execrows
UPDATE operation_audit SET outcome_started=true WHERE id=$1 AND root_id=$2 AND NOT outcome_started AND outcome IS NOT NULL AND intent_receipt IS NOT NULL;
-- name: FreezeOperationOutcome :one
UPDATE operation_audit SET outcome=$3 WHERE id=$1 AND root_id=$2 AND outcome IS NULL AND intent_receipt IS NOT NULL RETURNING *;
-- name: AckOperationIntent :execrows
UPDATE operation_audit SET intent_receipt=$3 WHERE id=$1 AND root_id=$2 AND intent_started AND intent_receipt IS NULL;
-- name: AckOperationOutcome :execrows
UPDATE operation_audit SET outcome_receipt=$3 WHERE id=$1 AND root_id=$2 AND outcome_started AND outcome_receipt IS NULL;
