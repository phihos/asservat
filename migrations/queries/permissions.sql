-- name: InsertPermissionStream :exec
INSERT INTO permission_stream(id,epoch,trust_digest,lease_until)
VALUES($1,$2,$3,clock_timestamp()+interval '30 seconds') ON CONFLICT(id) DO NOTHING;

-- name: LockPermissionStream :one
SELECT * FROM permission_stream WHERE id=$1 FOR UPDATE;

-- name: SharePermissionStream :one
SELECT * FROM permission_stream WHERE id=$1 FOR SHARE;

-- name: ResetPermissionStream :exec
UPDATE permission_stream SET epoch=$2,sequence=0,initial_audit_id=CASE WHEN trust_digest=$3 THEN initial_audit_id ELSE NULL END,trust_digest=$3,projection_digest=NULL,lease_until=clock_timestamp()+interval '30 seconds',observed_at=NULL,fresh_until=NULL,suspended=true WHERE id=$1;

-- name: InitializePermissionStream :exec
UPDATE permission_stream SET initial_audit_id=$2 WHERE id=$1 AND initial_audit_id IS NULL;

-- name: RenewPermissionStream :one
UPDATE permission_stream SET lease_until=clock_timestamp()+interval '30 seconds' WHERE id=$1 AND epoch=$2 AND lease_until>clock_timestamp() RETURNING lease_until;

-- name: SuspendPermissionStream :exec
UPDATE permission_stream SET suspended=true,lease_until=clock_timestamp(),fresh_until=NULL,observed_at=NULL WHERE id=$1;

-- name: UpdatePermissionStream :exec
-- ADR-200 revision (2026-10-23): the live lease holder's accepted observation
-- also keeps the lease at least until that observation's 30-second lifetime.
UPDATE permission_stream SET sequence=$2,projection_digest=$3,observed_at=$4,fresh_until=$5,lease_until=GREATEST(lease_until,$5),suspended=false WHERE id=$1;

-- name: ReadPermissionAcceptance :one
SELECT * FROM permission_acceptance WHERE request_id=$1;

-- name: InsertPermissionAcceptance :exec
INSERT INTO permission_acceptance(request_id,stream_id,epoch,sequence,request_digest,audit_id,assignments,retired) VALUES($1,$2,$3,$4,$5,$6,$7,$8);

-- name: ListPermissionBases :many
SELECT b.* FROM permission_basis b WHERE b.stream_id=$1 AND EXISTS (SELECT 1 FROM permission_assignment a WHERE a.stream_id=b.stream_id AND a.basis_key=b.basis_key AND a.retired_at IS NULL) ORDER BY b.basis_key LIMIT 1025;

-- name: UpsertPermissionBasis :exec
INSERT INTO permission_basis(stream_id,basis_key,uid,kind,generation,resource_version,spec_digest,scope_digest,cluster_id,namespace_uid,workload_uids,effect,not_after,seen_sequence,observation_version,automation_json,automation_audit_id)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
ON CONFLICT(stream_id,basis_key) DO UPDATE SET generation=EXCLUDED.generation,resource_version=EXCLUDED.resource_version,spec_digest=EXCLUDED.spec_digest,scope_digest=EXCLUDED.scope_digest,workload_uids=EXCLUDED.workload_uids,effect=EXCLUDED.effect,not_after=EXCLUDED.not_after,seen_sequence=EXCLUDED.seen_sequence,observation_version=EXCLUDED.observation_version,automation_json=EXCLUDED.automation_json,automation_audit_id=EXCLUDED.automation_audit_id;

-- name: SelectAutomationBasis :many
SELECT b.*, a.acknowledged_at FROM permission_basis b
JOIN authority_audit a ON a.id=b.automation_audit_id
WHERE b.stream_id=$1 AND b.uid=$2 AND b.kind='AccessBinding'
AND b.cluster_id=$3 AND b.namespace_uid=$4 AND b.effect='Allow'
AND (cardinality(b.workload_uids)=0 OR $5::text=ANY(b.workload_uids))
ORDER BY b.basis_key LIMIT 2;

-- name: ListCurrentPermissionAssignments :many
SELECT * FROM permission_assignment WHERE stream_id=$1 AND retired_at IS NULL ORDER BY id LIMIT 4097;

-- name: InsertPermissionAssignment :one
INSERT INTO permission_assignment(id,stream_id,basis_key,subject_kind,issuer,subject_id,role,basis_digest,activation_audit_id)
VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8) RETURNING *;

-- name: RetirePermissionAssignment :exec
UPDATE permission_assignment SET retired_at=clock_timestamp(),retirement_audit_id=$2 WHERE id=$1 AND retired_at IS NULL;

-- name: RetirePermissionStream :execrows
UPDATE permission_assignment SET retired_at=clock_timestamp(),retirement_audit_id=$2 WHERE stream_id=$1 AND retired_at IS NULL;

-- name: InsertAuthorityAudit :exec
INSERT INTO authority_audit(id,stream_id,epoch,sequence,event_kind,event_digest,record) VALUES($1,$2,$3,$4,$5,$6,$7);

-- name: SelectPermissionAssignments :many
SELECT a.*, b.uid AS source_uid,b.kind AS source_kind,b.effect,b.not_after,b.seen_sequence, au.acknowledged_at,
au.object_key,au.object_version,au.object_etag,au.object_bytes,au.object_sha256
FROM permission_assignment a JOIN permission_basis b ON a.stream_id=b.stream_id AND a.basis_key=b.basis_key
LEFT JOIN authority_audit au ON au.id=a.activation_audit_id AND au.stream_id=a.stream_id
WHERE a.stream_id=$1 AND a.retired_at IS NULL AND b.cluster_id=$2 AND b.namespace_uid=$3
AND (cardinality(b.workload_uids)=0 OR $4::text=ANY(b.workload_uids)) ORDER BY a.id LIMIT 257;

-- name: ReadAuthorityAudit :one
SELECT * FROM authority_audit WHERE id=$1;

-- name: ListAuthorityAudit :many
SELECT * FROM authority_audit WHERE stream_id=$1 AND acknowledged_at IS NULL ORDER BY created_at,id LIMIT 2;

-- name: LockAuthorityAudit :one
SELECT * FROM authority_audit WHERE id=$1 FOR UPDATE;

-- name: AcknowledgeAuthorityAudit :execrows
UPDATE authority_audit SET acknowledged_at=clock_timestamp(),object_key=$2,object_version=$3,object_etag=$4,object_bytes=$5,object_sha256=$6 WHERE id=$1 AND acknowledged_at IS NULL;

-- name: ReadPermissionChangeRecord :one
-- ADR-242: the authority event of the stream's current acceptance, which
-- carries the accepted namespace observation.
SELECT record FROM authority_audit WHERE stream_id=$1 AND epoch=$2 AND sequence=$3 AND event_kind='permission-change';
