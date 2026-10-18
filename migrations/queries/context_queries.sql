-- name: LockContextQueryBacking :one
SELECT * FROM context_query_backing WHERE root_id=$1 FOR UPDATE;

-- name: LockContextQueryAllocation :one
SELECT * FROM context_query_allocation WHERE id=$1 AND root_id=$2 FOR UPDATE;

-- name: LockContextQueryPrincipal :one
SELECT * FROM context_query_principal WHERE root_id=$1 AND principal_key=$2 FOR UPDATE;

-- name: InsertContextQueryPrincipal :one
INSERT INTO context_query_principal(id,root_id,principal_key,allocated) VALUES($1,$2,$3,0) RETURNING *;

-- name: LockContextQuery :one
SELECT * FROM context_query WHERE id=$1 AND root_id=$2 FOR UPDATE;

-- name: ReadContextQuery :one
SELECT * FROM context_query WHERE id=$1 AND root_id=$2 AND actor=$3;

-- name: InsertContextQuery :one
INSERT INTO context_query(id,root_id,allocation_id,account_id,principal_key,actor,query,initial_request,operation_id,worker_id,created_at,deadline,cleanup_until,retire_by,issuer_epoch,postmaster_at,database_oid)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *;

-- name: ReadContextQueryCall :one
SELECT * FROM context_query_call WHERE operation_id=$1 AND query_id=$2;

-- name: InsertContextQueryCall :exec
INSERT INTO context_query_call(operation_id,query_id,request,is_poll) VALUES($1,$2,$3,$4);

-- name: ReadContextQueryWorker :one
SELECT * FROM context_query_worker WHERE query_id=$1;

-- name: LockContextQueryBatch :one
SELECT * FROM context_query_batch WHERE id=$1 AND query_id=$2 FOR UPDATE;

-- name: InsertContextQueryBatch :one
INSERT INTO context_query_batch(id,query_id,operation_id,generation,batch) VALUES($1,$2,$3,$4,$5) RETURNING *;

-- name: ClaimContextQueryBatch :execrows
UPDATE context_query_batch SET claim_id=$3 WHERE id=$1 AND query_id=$2 AND claim_id IS NULL AND NOT closed;

-- name: CloseContextQueryBatch :execrows
UPDATE context_query_batch SET closed=true WHERE id=$1 AND query_id=$2 AND claim_id IS NOT NULL AND NOT closed;

-- name: ReadContextQueryInvocation :one
SELECT sqlc.embed(a),sqlc.embed(l) FROM operation_audit a JOIN operation_audit_lifecycle l ON l.operation_id=a.id AND l.root_id=a.root_id
WHERE a.id=$1 AND a.root_id=$2 AND a.lane='normal' AND l.lane='normal' FOR SHARE OF a,l;

-- name: ContextQueryCaseExists :one
SELECT EXISTS(SELECT 1 FROM context_case_locator WHERE root_id=$1 AND case_id=$2 AND capture_id=$3 AND artifact_id=$4);
