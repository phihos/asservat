-- name: ReadContextDatabaseIncarnation :one
SELECT activated_postmaster_at AS postmaster_at, activated_database_oid AS database_oid FROM fleet_trust WHERE installation_id=$1;
-- name: InsertContextWriterCompletion :exec
INSERT INTO context_writer_completion(root_id,capture_id,attempt_id,registration_digest,expectation_digest,copies_digest,execution_digest,completion_digest,installation_id,issuer_epoch,postmaster_at,database_oid,stored_at,closed_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14);
-- name: ReadContextWriterCompletion :one
SELECT * FROM context_writer_completion WHERE root_id=$1 AND attempt_id=$2;
-- name: ReadContextDeletion :one
SELECT * FROM context_deletion_checkpoint WHERE root_id=$1 AND attempt_id=$2;
-- name: LockContextDeletion :one
SELECT * FROM context_deletion_checkpoint WHERE root_id=$1 AND attempt_id=$2 FOR UPDATE;
-- name: InsertContextDeletion :exec
INSERT INTO context_deletion_checkpoint(root_id,capture_id,attempt_id,store_id,registration_digest,writer_digest,record_digest,record_json,installation_id,issuer_epoch,postmaster_at,database_oid,purge_fence,purged_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14);
-- name: AcknowledgeContextDeletion :execrows
UPDATE context_deletion_checkpoint SET audit_receipt_json=$3,audit_acknowledged_at=clock_timestamp() WHERE root_id=$1 AND attempt_id=$2 AND audit_acknowledged_at IS NULL;

-- name: ContextRequiresPositiveDeletion :one
SELECT EXISTS(SELECT 1 FROM context_execution WHERE attempt_id=$1 AND writer_protocol='closed-small-context/v1');
-- name: ClaimContextFinalization :execrows
UPDATE context_deletion_checkpoint SET finalization_xid=pg_current_xact_id() WHERE root_id=$1 AND attempt_id=$2 AND audit_acknowledged_at IS NOT NULL AND finalization_xid IS NULL;
