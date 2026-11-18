-- name: LockPermissionWriter :exec
SELECT pg_advisory_xact_lock(hashtextextended('asservat.permissions/' || sqlc.arg(stream_id)::uuid::text, 0));

-- name: CheckPermissionConstraints :exec
SET CONSTRAINTS ALL IMMEDIATE;

-- name: InsertPermissionStream :exec
INSERT INTO permission_stream(id,epoch,trust_digest,lease_until)
VALUES($1,$2,$3,clock_timestamp()+interval '30 seconds') ON CONFLICT(id) DO NOTHING;

-- name: LockPermissionStream :one
SELECT * FROM permission_stream WHERE id=$1 FOR NO KEY UPDATE;

-- name: SharePermissionStream :one
SELECT * FROM permission_stream WHERE id=$1 FOR SHARE;

-- name: ReadPermissionStreamClock :one
SELECT sqlc.embed(permission_stream),clock_timestamp()::timestamptz AS read_at
FROM permission_stream WHERE id=$1;

-- name: ResetPermissionStream :exec
UPDATE permission_stream SET epoch=$2,sequence=0,trust_digest=$3,projection_digest=NULL,lease_until=clock_timestamp()+interval '30 seconds',observed_at=NULL,fresh_until=NULL,suspended=true WHERE id=$1;

-- name: RenewPermissionStream :one
UPDATE permission_stream SET lease_until=statement_timestamp()+interval '30 seconds',
 observed_at=CASE WHEN sqlc.arg(observing)::boolean THEN statement_timestamp() ELSE observed_at END,
 fresh_until=CASE WHEN sqlc.arg(observing)::boolean THEN statement_timestamp()+interval '30 seconds' ELSE fresh_until END
WHERE id=sqlc.arg(id) AND epoch=sqlc.arg(epoch) AND lease_until>clock_timestamp()
 AND (NOT sqlc.arg(observing)::boolean OR (NOT suspended AND sequence=sqlc.arg(sequence)))
RETURNING lease_until;

-- name: SuspendPermissionStream :exec
UPDATE permission_stream SET suspended=true,lease_until=clock_timestamp(),fresh_until=NULL,observed_at=NULL WHERE id=$1;

-- name: UpdatePermissionStream :one
-- ADR-200 revision (2026-10-23): the live lease holder's accepted observation
-- also keeps the lease at least until that observation's 30-second lifetime.
UPDATE permission_stream SET sequence=$2,projection_digest=$3,observed_at=$4,fresh_until=$5,unavailable_clusters=COALESCE(sqlc.arg(unavailable_clusters)::text[], '{}'),lease_until=GREATEST(lease_until,$5),suspended=false WHERE id=$1 RETURNING lease_until;

-- name: ReadPermissionAcceptance :one
SELECT * FROM permission_acceptance WHERE request_id=$1;

-- name: InsertPermissionAcceptance :exec
INSERT INTO permission_acceptance(request_id,stream_id,epoch,sequence,request_digest,audit_id,assignments,retired,lease_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: ListPermissionBases :many
-- Select each current basis key once. Looking for a matching assignment for
-- every basis can repeatedly scan the same assignment set on stale statistics.
SELECT b.* FROM (SELECT DISTINCT a.basis_key FROM permission_assignment a
 WHERE a.stream_id=$1 AND a.retired_at IS NULL) current_keys
CROSS JOIN LATERAL (SELECT * FROM permission_basis b
 WHERE b.stream_id=$1 AND b.basis_key=current_keys.basis_key LIMIT 1) b;

-- name: UpsertPermissionBases :exec
INSERT INTO permission_basis(stream_id,basis_key,uid,kind,generation,resource_version,spec_digest,scope_digest,cluster_id,namespace_uid,workload_uids,effect,not_after,seen_sequence,observation_version,automation_json,automation_audit_id)
SELECT sqlc.arg(stream_id),r.key,r.uid,r.kind,r.generation,r.rv,decode(r.spec,'hex'),decode(r.scope,'hex'),r.cluster,r.namespace,coalesce(r.workloads,'{}'),r.effect,r.expiry,sqlc.arg(sequence),r.observation,r.automation,
 CASE WHEN r.automation IS NOT NULL THEN sqlc.arg(event_id)::uuid END
FROM jsonb_to_recordset(sqlc.arg(bases)::jsonb) AS r(key text, uid text, kind text, generation bigint, rv text, spec text, scope text, cluster uuid, namespace text, workloads text[], effect text, expiry timestamptz, observation text, automation jsonb)
ON CONFLICT(stream_id,basis_key) DO UPDATE SET generation=EXCLUDED.generation,resource_version=EXCLUDED.resource_version,spec_digest=EXCLUDED.spec_digest,scope_digest=EXCLUDED.scope_digest,workload_uids=EXCLUDED.workload_uids,effect=EXCLUDED.effect,not_after=EXCLUDED.not_after,seen_sequence=EXCLUDED.seen_sequence,observation_version=EXCLUDED.observation_version,automation_json=EXCLUDED.automation_json,automation_audit_id=EXCLUDED.automation_audit_id;

-- name: SelectAutomationBasis :many
SELECT b.* FROM permission_basis b
JOIN authority_audit a ON a.id=b.automation_audit_id AND a.stream_id=b.stream_id AND a.sequence=b.seen_sequence
WHERE b.stream_id=$1 AND b.uid=$2 AND b.kind='AccessBinding'
AND b.cluster_id=$3 AND b.namespace_uid=$4 AND b.effect='Allow'
AND (cardinality(b.workload_uids)=0 OR $5::text=ANY(b.workload_uids) OR EXISTS(SELECT 1 FROM workload_name w WHERE w.cluster_id=b.cluster_id AND w.workload_uid=$5::text AND w.ref=ANY(b.workload_uids)))
ORDER BY b.basis_key LIMIT 2;

-- name: ListCurrentPermissionAssignments :many
SELECT * FROM permission_assignment WHERE stream_id=$1 AND retired_at IS NULL ORDER BY id;

-- name: InsertPermissionAssignments :exec
INSERT INTO permission_assignment(id,stream_id,basis_key,subject_kind,issuer,subject_id,role,basis_digest,activation_audit_id)
SELECT gen_random_uuid(),b.stream_id,b.basis_key,m.kind,m.issuer,m.subject,m.role,b.spec_digest,sqlc.arg(event_id)
FROM (SELECT unnest(sqlc.arg(bases)::text[]) AS basis,unnest(sqlc.arg(kinds)::text[]) AS kind,unnest(sqlc.arg(issuers)::text[]) AS issuer,unnest(sqlc.arg(subjects)::text[]) AS subject,unnest(sqlc.arg(roles)::text[]) AS role) m
JOIN permission_basis b ON b.stream_id=sqlc.arg(stream_id) AND b.basis_key=m.basis;

-- name: RecordPermissionBasisChanges :exec
INSERT INTO permission_basis_change(event_id,basis_key,retired,uid,kind,generation,spec_digest,scope_digest,cluster_id,namespace_uid,workload_uids,effect,not_after,automation_json)
SELECT sqlc.arg(event_id),basis_key,sqlc.arg(retired),uid,kind,generation,spec_digest,scope_digest,cluster_id,namespace_uid,workload_uids,effect,not_after,automation_json
FROM permission_basis WHERE stream_id=sqlc.arg(stream_id) AND basis_key=ANY(sqlc.arg(keys)::text[]);

-- name: RetirePermissionAssignments :exec
UPDATE permission_assignment SET retired_at=clock_timestamp(),retirement_audit_id=sqlc.arg(audit_id) WHERE id=ANY(sqlc.arg(ids)::uuid[]) AND retired_at IS NULL;

-- name: RetirePermissionStream :execrows
UPDATE permission_assignment SET retired_at=clock_timestamp(),retirement_audit_id=$2 WHERE stream_id=$1 AND retired_at IS NULL;

-- name: InsertAuthorityAudit :exec
INSERT INTO authority_audit(id,stream_id,epoch,sequence,event_kind,event_digest,record) VALUES($1,$2,$3,$4,$5,$6,$7);

-- name: SelectPermissionAssignments :many
SELECT a.*, b.uid AS source_uid,b.kind AS source_kind,b.effect,b.not_after,b.seen_sequence
FROM permission_assignment a JOIN permission_basis b ON a.stream_id=b.stream_id AND a.basis_key=b.basis_key
WHERE a.stream_id=$1 AND a.retired_at IS NULL AND b.cluster_id=$2 AND b.namespace_uid IN ($3,'*')
AND (cardinality(b.workload_uids)=0 OR $4::text=ANY(b.workload_uids) OR EXISTS(SELECT 1 FROM workload_name w WHERE w.cluster_id=b.cluster_id AND w.workload_uid=$4::text AND w.ref=ANY(b.workload_uids))) ORDER BY a.id;

-- name: ReadAuthorityAudit :one
SELECT * FROM authority_audit WHERE id=$1;

-- name: ReadPermissionChangeRecord :one
-- ADR-242: the authority event of the stream's current acceptance, which
-- carries the accepted namespace observation.
SELECT record FROM authority_audit WHERE stream_id=$1 AND epoch=$2 AND sequence=$3 AND event_kind='permission-change';

-- name: RememberWorkloadName :exec
-- ADR-335 D4: a resolved workload's kind and name never change with its UID.
INSERT INTO workload_name(cluster_id,workload_uid,ref) VALUES($1,$2,$3) ON CONFLICT DO NOTHING;
