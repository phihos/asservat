-- name: ListPermissionReviewSources :many
-- ADR-245: every accepted decision-time source row of a stream, current or not.
SELECT * FROM permission_review_source WHERE stream_id=$1 ORDER BY uid LIMIT 65;

-- name: UpsertPermissionReviewSource :exec
INSERT INTO permission_review_source(stream_id,uid,epoch,seen_sequence,generation,resource_version,spec_digest,authority_digest,cluster_id,role,source_json,accepted_audit_id)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT(stream_id,uid) DO UPDATE SET epoch=EXCLUDED.epoch,seen_sequence=EXCLUDED.seen_sequence,generation=EXCLUDED.generation,resource_version=EXCLUDED.resource_version,spec_digest=EXCLUDED.spec_digest,authority_digest=EXCLUDED.authority_digest,cluster_id=EXCLUDED.cluster_id,role=EXCLUDED.role,source_json=EXCLUDED.source_json,accepted_audit_id=EXCLUDED.accepted_audit_id;

-- name: DeletePermissionReviewSource :exec
DELETE FROM permission_review_source WHERE stream_id=$1 AND uid=$2;

-- name: RetirePermissionReviewSource :execrows
UPDATE permission_review_assignment SET retired_at=clock_timestamp(),retirement_audit_id=$3 WHERE stream_id=$1 AND source_uid=$2 AND retired_at IS NULL;

-- name: RetirePermissionReviewStream :execrows
UPDATE permission_review_assignment SET retired_at=clock_timestamp(),retirement_audit_id=$2 WHERE stream_id=$1 AND retired_at IS NULL;

-- name: DeletePermissionReviewSources :exec
DELETE FROM permission_review_source WHERE stream_id=$1;

-- name: CurrentPermissionReviewSources :many
-- The current, acknowledged decision-time sources of one cluster.
SELECT rs.*, au.object_key,au.object_version,au.object_etag,au.object_bytes,au.object_sha256,au.acknowledged_at
FROM permission_review_source rs JOIN authority_audit au ON au.id=rs.accepted_audit_id AND au.stream_id=rs.stream_id
WHERE rs.stream_id=$1 AND rs.epoch=$2 AND rs.seen_sequence=$3 AND rs.cluster_id=$4 AND au.acknowledged_at IS NOT NULL
ORDER BY rs.uid LIMIT 5;

-- name: LockPermissionReviewSource :one
SELECT * FROM permission_review_source WHERE stream_id=$1 AND uid=$2 FOR SHARE;

-- name: InsertPermissionReviewAssignment :exec
INSERT INTO permission_review_assignment(id,stream_id,source_uid,issuer,subject_id,role,basis_digest)
VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6)
ON CONFLICT(stream_id,source_uid,issuer,subject_id) WHERE retired_at IS NULL DO NOTHING;

-- name: CurrentPermissionReviewAssignment :one
SELECT * FROM permission_review_assignment WHERE stream_id=$1 AND source_uid=$2 AND issuer=$3 AND subject_id=$4 AND retired_at IS NULL;

-- name: CountPermissionReviewAssignments :one
SELECT count(*) FROM permission_review_assignment WHERE stream_id=$1 AND source_uid=$2 AND retired_at IS NULL;

-- name: UpsertPermissionReviewDecision :exec
INSERT INTO permission_review_decision(assignment_id,pod_uid,cluster_id,namespace_name,namespace_uid,workload_kind,workload_name,workload_uid,pod_name,decided_at,fresh_until)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT(assignment_id,pod_uid) DO UPDATE SET decided_at=EXCLUDED.decided_at,fresh_until=EXCLUDED.fresh_until
WHERE permission_review_decision.decided_at<=EXCLUDED.decided_at AND permission_review_decision.cluster_id=EXCLUDED.cluster_id AND permission_review_decision.namespace_uid=EXCLUDED.namespace_uid AND permission_review_decision.workload_uid=EXCLUDED.workload_uid;

-- name: EndPermissionReviewDecision :exec
-- A refusal ends the current decision at once; it records no new target.
UPDATE permission_review_decision SET decided_at=GREATEST(decided_at,$3),fresh_until=GREATEST(decided_at,$3)
WHERE assignment_id=$1 AND pod_uid=$2;

-- name: PrunePermissionReviewDecisions :exec
-- Keeps the 1,024 most recently decided Pods of one assignment.
DELETE FROM permission_review_decision x WHERE x.assignment_id=sqlc.arg(assignment_id)::uuid AND x.pod_uid NOT IN (
 SELECT d.pod_uid FROM permission_review_decision d WHERE d.assignment_id=sqlc.arg(assignment_id)::uuid ORDER BY d.decided_at DESC,d.pod_uid LIMIT 1024);

-- name: SelectPermissionReviews :many
-- The fresh decision-time allows of one exact Pod, newest first.
SELECT a.id,a.issuer,a.subject_id,a.role,a.basis_digest,a.source_uid,d.decided_at,d.fresh_until,rs.accepted_audit_id,
au.acknowledged_at,au.object_key,au.object_version,au.object_etag,au.object_bytes,au.object_sha256
FROM permission_review_decision d JOIN permission_review_assignment a ON a.id=d.assignment_id
JOIN permission_review_source rs ON rs.stream_id=a.stream_id AND rs.uid=a.source_uid
LEFT JOIN authority_audit au ON au.id=rs.accepted_audit_id AND au.stream_id=rs.stream_id
WHERE a.stream_id=$1 AND a.retired_at IS NULL AND rs.epoch=$2 AND rs.seen_sequence=$3
AND d.cluster_id=$4 AND d.namespace_uid=$5 AND d.workload_uid=$6 AND d.pod_uid=$7 AND d.fresh_until>clock_timestamp()
ORDER BY d.decided_at DESC,a.id LIMIT 32;

-- name: SelectRecordedReviews :many
-- One principal's recorded review targets of one exact Pod.
SELECT a.source_uid,d.* FROM permission_review_decision d JOIN permission_review_assignment a ON a.id=d.assignment_id
WHERE a.stream_id=$1 AND a.retired_at IS NULL AND a.issuer=$2 AND a.subject_id=$3
AND d.cluster_id=$4 AND d.namespace_uid=$5 AND d.workload_uid=$6 AND d.pod_uid=$7
ORDER BY a.source_uid LIMIT 5;

-- name: SelectRecordedCaptureReviews :many
-- One principal's recorded review targets of the Pod of one capture.
SELECT a.source_uid,d.* FROM permission_review_decision d JOIN permission_review_assignment a ON a.id=d.assignment_id
JOIN context_capture c ON c.root_id=a.stream_id AND d.pod_uid=convert_from(c.pod_pin_json,'UTF8')::jsonb->>'UID' AND d.namespace_uid=convert_from(c.pod_pin_json,'UTF8')::jsonb->>'NamespaceUID'
WHERE a.stream_id=$1 AND c.id=$2 AND a.retired_at IS NULL AND a.issuer=$3 AND a.subject_id=$4
ORDER BY a.source_uid LIMIT 5;

-- name: GetPermissionReviewDecision :one
SELECT * FROM permission_review_decision WHERE assignment_id=$1 AND pod_uid=$2 FOR UPDATE;

-- name: SelectRecordedPreviewReviews :many
-- One principal's recorded review targets of the Pod of one of its own
-- previews, closed or not; nothing else of the preview.
SELECT a.source_uid,d.* FROM permission_review_decision d JOIN permission_review_assignment a ON a.id=d.assignment_id
JOIN context_preview p ON p.root_id=a.stream_id AND d.pod_uid=convert_from(p.blueprint_json,'UTF8')::jsonb->'Target'->>'PodUID' AND d.namespace_uid=convert_from(p.blueprint_json,'UTF8')::jsonb->'Target'->'Namespace'->>'UID'
WHERE a.stream_id=$1 AND p.id=$2 AND p.actor_key=$3 AND a.retired_at IS NULL AND a.issuer=$4 AND a.subject_id=$5
ORDER BY a.source_uid LIMIT 5;

-- name: SelectPreviewReviewAssignments :many
-- ADR-245 preview: the current assignments a decision-time source minted, per
-- recorded workload, with their newest decision; at most 1,001 rows.
SELECT a.id,a.issuer,a.subject_id,a.role,a.basis_digest,d.cluster_id,d.namespace_uid,d.workload_uid,
max(d.fresh_until)::timestamptz AS fresh_until,max(d.decided_at)::timestamptz AS decided_at
FROM permission_review_assignment a JOIN permission_review_decision d ON d.assignment_id=a.id
JOIN permission_review_source rs ON rs.stream_id=a.stream_id AND rs.uid=a.source_uid
JOIN authority_audit au ON au.id=rs.accepted_audit_id AND au.stream_id=rs.stream_id
WHERE a.stream_id=$1 AND a.source_uid=$2 AND a.retired_at IS NULL AND rs.epoch=$3 AND rs.seen_sequence=$4 AND au.acknowledged_at IS NOT NULL
GROUP BY a.id,a.issuer,a.subject_id,a.role,a.basis_digest,d.cluster_id,d.namespace_uid,d.workload_uid
ORDER BY d.cluster_id,d.namespace_uid,d.workload_uid,a.id LIMIT 1001;
