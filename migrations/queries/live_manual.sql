-- Existing accepted finite executions only. These reads cannot arm a source,
-- renew a permit, supply a node identity or create a live SQL session.
-- name: ReadLiveManualTarget :one
SELECT (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,Location,ClusterID}')::text AS cluster_id,
 (convert_from(c.expectation_json,'UTF8')::jsonb->>'NamespaceUID')::text AS namespace_uid,
 (convert_from(c.expectation_json,'UTF8')::jsonb->>'WorkloadUID')::text AS workload_uid,
 (convert_from(c.expectation_json,'UTF8')::jsonb->>'PodUID')::text AS pod_uid
FROM context_capture c JOIN context_execution e ON e.root_id=c.root_id AND e.capture_id=c.id AND e.attempt_id=c.attempt_id
WHERE c.root_id=sqlc.arg(root_id)::uuid AND c.id=sqlc.arg(capture_id)::uuid
 AND c.state='intent_audited' AND e.phase='started' AND c.snapshot_cancel_requested_at IS NULL
 AND jsonb_typeof(convert_from(c.expectation_json,'UTF8')::jsonb->'Recording')='object'
 AND convert_from(c.scope_json,'UTF8')::jsonb#>>'{executor,identityType}'='human';

-- name: ReadLiveManualWorks :many
SELECT sqlc.embed(c),sqlc.embed(e)
FROM context_capture c JOIN context_execution e ON e.root_id=c.root_id AND e.capture_id=c.id AND e.attempt_id=c.attempt_id
WHERE c.root_id=sqlc.arg(root_id)::uuid AND c.id=ANY(sqlc.arg(capture_ids)::uuid[])
 AND c.state='intent_audited' AND e.phase='started' AND c.snapshot_cancel_requested_at IS NULL
 AND jsonb_typeof(convert_from(c.expectation_json,'UTF8')::jsonb->'Recording')='object'
 AND convert_from(c.scope_json,'UTF8')::jsonb#>>'{executor,identityType}'='human'
ORDER BY c.id;

-- name: ListLiveManualWorks :many
SELECT sqlc.embed(c),sqlc.embed(e)
FROM context_capture c JOIN context_execution e ON e.root_id=c.root_id AND e.capture_id=c.id AND e.attempt_id=c.attempt_id
WHERE c.root_id=sqlc.arg(root_id)::uuid
 AND (sqlc.narg(after_capture_id)::uuid IS NULL OR c.id>sqlc.narg(after_capture_id)::uuid)
 AND c.state='intent_audited' AND e.phase='started' AND c.snapshot_cancel_requested_at IS NULL
 AND jsonb_typeof(convert_from(c.expectation_json,'UTF8')::jsonb->'Recording')='object'
 AND convert_from(c.scope_json,'UTF8')::jsonb#>>'{executor,identityType}'='human'
 AND convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,Location,ClusterID}'=sqlc.arg(cluster_id)::text
 AND convert_from(c.expectation_json,'UTF8')::jsonb->>'NamespaceUID'=sqlc.arg(namespace_uid)::text
 AND convert_from(c.expectation_json,'UTF8')::jsonb->>'WorkloadUID'=sqlc.arg(workload_uid)::text
ORDER BY c.id LIMIT sqlc.arg(page_limit)::integer;
