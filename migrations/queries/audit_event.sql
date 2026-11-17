-- name: InsertAuditEvent :exec
-- REQ-AUT-005: one append-only row; callers in an effect transaction pass
-- that transaction's queries.
INSERT INTO audit_event(event_id,operation_id,kind,operation,issuer,subject,client_id,identity_type,input_digest,status,reason,effect,case_ids,artifact_ids,capture_ids,share_ids,grant_ids,reservation_id,output_bytes,output_digest)
VALUES(sqlc.arg(event_id),sqlc.arg(operation_id),sqlc.arg(kind),sqlc.arg(operation),sqlc.arg(issuer),sqlc.arg(subject),sqlc.arg(client_id),sqlc.arg(identity_type),sqlc.narg(input_digest),sqlc.arg(status),sqlc.arg(reason),sqlc.arg(effect),sqlc.arg(case_ids)::text[],sqlc.arg(artifact_ids)::text[],sqlc.arg(capture_ids)::text[],sqlc.arg(share_ids)::text[],sqlc.arg(grant_ids)::text[],sqlc.narg(reservation_id),sqlc.arg(output_bytes),sqlc.narg(output_digest));
