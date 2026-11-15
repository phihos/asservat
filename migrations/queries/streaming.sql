-- name: ChargeStreaming :one
SELECT capacity_charge(sqlc.arg(id)::uuid,sqlc.arg(charged_bytes)::bigint,sqlc.arg(charged_objects)::bigint)::boolean AS charged;

-- name: ReleaseStreamingTemporary :one
SELECT capacity_release(sqlc.arg(id)::uuid,sqlc.arg(charged_bytes)::bigint,sqlc.arg(charged_objects)::bigint)::boolean AS released;

-- name: InsertStream :exec
INSERT INTO custody_stream(attempt_id,writer_epoch,plan_digest,temporary_bytes,temporary_objects,state) VALUES($1,$2,$3,$4,$5,$6);

-- name: LockStream :one
SELECT * FROM custody_stream WHERE attempt_id = $1 FOR UPDATE;

-- name: UpdateStream :execrows
UPDATE custody_stream SET state = $2, revision = revision + 1, released_at = $4 WHERE attempt_id = $1 AND revision = $3;

-- name: InsertPendingStream :exec
INSERT INTO custody_stream(attempt_id,temporary_bytes,temporary_objects,state) VALUES($1,$2,$3,$4);

-- name: BindPendingStream :execrows
UPDATE custody_stream SET writer_epoch=$2,plan_digest=$3,revision=revision+1
WHERE attempt_id=$1 AND writer_epoch IS NULL AND plan_digest IS NULL AND released_at IS NULL;
