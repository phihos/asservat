-- name: LockPool :one
SELECT * FROM custody_pool WHERE id = $1 FOR UPDATE;
-- name: FindPool :one
SELECT pool_id FROM custody_allocation WHERE id = $1;
-- name: LockAllocation :one
SELECT * FROM custody_allocation WHERE id = $1 FOR UPDATE;
-- name: LockAttempt :one
SELECT * FROM custody_attempt WHERE id = $1 FOR UPDATE;
-- name: ReadAttempt :one
SELECT * FROM custody_attempt WHERE id = $1;
-- name: ReadCopies :many
SELECT * FROM custody_copy WHERE attempt_id = $1 ORDER BY role;
-- name: CurrentTime :one
SELECT clock_timestamp()::timestamptz;
-- name: Overdue :one
SELECT EXISTS (SELECT 1 FROM custody_attempt WHERE allocation_id = $1 AND state <> 'deleted' AND effective_delete_by <= $2);
-- name: Charge :execrows
UPDATE custody_allocation SET charged_bytes = charged_bytes + $2, charged_objects = charged_objects + 4
WHERE id = $1 AND $2 <= byte_limit - charged_bytes AND 4 <= object_limit - charged_objects;
-- name: ReleaseCharge :execrows
UPDATE custody_allocation SET charged_bytes = charged_bytes - $2, charged_objects = charged_objects - 4
WHERE id = $1 AND charged_bytes >= $2 AND charged_objects >= 4;
-- name: InsertAttempt :exec
INSERT INTO custody_attempt (id,cluster_id,artifact_id,allocation_id,request_digest,pool_revision,allocation_revision,native_limit,reserved_bytes,anchor_at,write_until,expires_at,delete_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13);
-- name: InsertCopy :exec
INSERT INTO custody_copy(attempt_id,role,byte_limit) VALUES ($1,$2,$3);
-- name: StoreCopy :exec
UPDATE custody_copy SET ciphertext_bytes=$3,ciphertext_sha256=$4,etag=$5,version_id=$6 WHERE attempt_id=$1 AND role=$2;
-- name: MarkStored :exec
UPDATE custody_attempt SET state='stored_unpublished',copies_digest=$2 WHERE id=$1;
-- name: InsertEvent :exec
INSERT INTO custody_event(attempt_id,phase) VALUES ($1,$2) ON CONFLICT DO NOTHING;
-- name: ClaimDeletion :one
UPDATE custody_attempt SET state='deleting',deletion_fence=deletion_fence+1,lease_until=$2 WHERE id=$1 RETURNING deletion_fence;
-- name: MarkDeleted :exec
UPDATE custody_attempt SET state='deleted',deleted_at=$2,lease_until=NULL WHERE id=$1;
-- name: ClearReceipts :exec
UPDATE custody_copy SET ciphertext_bytes=NULL,ciphertext_sha256=NULL,etag=NULL,version_id=NULL WHERE attempt_id=$1;
-- name: BackAllocation :execrows
UPDATE custody_pool SET allocated_bytes=allocated_bytes+$2,allocated_objects=allocated_objects+$3
WHERE id=$1 AND $2 <= byte_limit-allocated_bytes AND $3 <= object_limit-allocated_objects;
-- name: InsertAllocation :exec
INSERT INTO custody_allocation(id,pool_id,scope_id,service_class,revision,valid_until,byte_limit,object_limit) VALUES ($1,$2,$3,$4,$5,$6,$7,$8);
