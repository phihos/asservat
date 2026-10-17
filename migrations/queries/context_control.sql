-- name: LockContextControlPool :one
SELECT * FROM context_control_pool WHERE root_id=$1 FOR UPDATE;
-- name: InsertContextControlPool :one
INSERT INTO context_control_pool(root_id,configured,revision,valid_until,full_limit,replay_limit,paused)
 VALUES($1,true,$2,$3,$4,$5,$6) RETURNING *;
-- name: ConfigureContextControlPool :one
UPDATE context_control_pool SET configured=true,revision=$2,valid_until=$3,full_limit=$4,replay_limit=$5,paused=$6
 WHERE root_id=$1 AND revision=sqlc.arg(expected_revision) RETURNING *;
-- name: LockContextControlAccount :one
SELECT * FROM context_control_account WHERE root_id=$1 AND allocation_id=$2 FOR UPDATE;
-- name: InsertContextControlAccount :one
INSERT INTO context_control_account(root_id,allocation_id,configured,revision,valid_until,full_limit,replay_limit,paused)
 VALUES($1,$2,true,$3,$4,$5,$6,$7) RETURNING *;
-- name: ConfigureContextControlAccount :one
UPDATE context_control_account SET configured=true,revision=$3,valid_until=$4,full_limit=$5,replay_limit=$6,paused=$7
 WHERE root_id=$1 AND allocation_id=$2 AND revision=sqlc.arg(expected_revision) RETURNING *;
-- name: FindContextControlBinding :one
SELECT * FROM context_storage_binding WHERE root_id=$1 AND allocation_id=$2 FOR SHARE;
-- name: InsertContextControlCharge :exec
INSERT INTO context_control_charge(capture_id,root_id,allocation_id) VALUES($1,$2,$3);
-- name: ObserveContextRetirementDependencies :one
SELECT c.id,c.root_id,a.state AS custody_state,c.intent_acknowledged_at,
 NOT EXISTS(SELECT 1 FROM context_verification v WHERE v.capture_id=c.id AND v.audit_acknowledged_at IS NOT NULL) AS verification_audit_pending,
 NOT EXISTS(SELECT 1 FROM context_execution e WHERE e.capture_id=c.id AND e.phase='stored') AS execution_unresolved,
 EXISTS(SELECT 1 FROM custody_copy p WHERE p.attempt_id=a.id AND p.ciphertext_sha256 IS NOT NULL) AS retained_copy_receipts,
 EXISTS(SELECT 1 FROM artifact_download d WHERE d.artifact_id=a.artifact_id) AS download_dependents,
 EXISTS(SELECT 1 FROM retention_decision d WHERE d.attempt_id=a.id AND d.audit_acknowledged_at IS NULL) AS retention_audit_pending,
 EXISTS(SELECT 1 FROM retention_checkpoint p JOIN retention_catchup r ON r.checkpoint_id=p.id WHERE p.root_id=c.root_id AND r.completed_at IS NULL) AS retention_catchup_pending
 FROM context_capture c JOIN custody_attempt a ON a.id=c.attempt_id
 WHERE c.root_id=$1 AND c.id=$2;
