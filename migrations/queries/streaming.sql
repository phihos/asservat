-- name: ChargeStreaming :execrows
UPDATE custody_allocation SET charged_bytes = charged_bytes + $2, charged_objects = charged_objects + $3
WHERE id = $1 AND $2 <= byte_limit - charged_bytes AND $3 <= object_limit - charged_objects;

-- name: ReleaseStreamingTemporary :execrows
UPDATE custody_allocation SET charged_bytes = charged_bytes - $2, charged_objects = charged_objects - $3
WHERE id = $1 AND charged_bytes >= $2 AND charged_objects >= $3;

-- name: InsertStream :exec
INSERT INTO custody_stream(attempt_id,writer_epoch,plan_digest,temporary_bytes,temporary_objects,state) VALUES($1,$2,$3,$4,$5,$6);

-- name: LockStream :one
SELECT * FROM custody_stream WHERE attempt_id = $1 FOR UPDATE;

-- name: UpdateStream :execrows
UPDATE custody_stream SET state = $2, revision = revision + 1, released_at = $4 WHERE attempt_id = $1 AND revision = $3;
