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
