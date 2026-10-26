-- ADR-228 restart-triggered policy captures.

-- name: ReadPolicySourceRow :one
SELECT * FROM policy_source WHERE root_id=$1 AND policy_uid=$2;

-- name: ListPolicyWatermarks :many
SELECT pod_uid, restarts FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2 ORDER BY pod_uid LIMIT 257;

-- name: DeletePolicyWatermarks :exec
DELETE FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2;

-- name: InsertPolicyWatermarks :exec
INSERT INTO policy_pod_watermark(root_id,policy_uid,pod_uid,restarts)
SELECT @root_id::uuid, @policy_uid::text, unnest(@pod_uids::text[]), unnest(@restarts::bigint[]);

-- name: LockPolicyWindow :one
INSERT INTO policy_workload_window(root_id,cluster_id,workload_uid,policy_uid,tat) VALUES($1,$2,$3,$4,$5)
ON CONFLICT(root_id,cluster_id,workload_uid,policy_uid) DO UPDATE SET tat=policy_workload_window.tat RETURNING tat;

-- name: UpdatePolicyWindow :exec
UPDATE policy_workload_window SET tat=$5 WHERE root_id=$1 AND cluster_id=$2 AND workload_uid=$3 AND policy_uid=$4;

-- name: SpendPolicyExecution :execrows
UPDATE policy_acceptance SET executions_spent=executions_spent+1
WHERE root_id=$1 AND id=$2 AND executions_spent<(record#>>'{Authority,Limits,MaxExecutions}')::bigint;

-- name: InsertPolicyOccurrence :execrows
INSERT INTO policy_occurrence(id,root_id,policy_uid,acceptance_id,cluster_id,workload_uid,pod_uid,restarts)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(root_id,policy_uid,pod_uid,restarts) DO NOTHING;

-- name: CountPolicySuppression :exec
INSERT INTO policy_suppression(root_id,policy_uid,reason,first_at,last_at,count) VALUES($1,$2,$3,$4,$4,$5)
ON CONFLICT(root_id,policy_uid,reason) DO UPDATE SET last_at=GREATEST(policy_suppression.last_at,EXCLUDED.last_at),
 count=LEAST(2147483647,policy_suppression.count+EXCLUDED.count);

-- name: LinkPolicyOccurrence :execrows
UPDATE policy_occurrence SET capture_id=$3, outcome='captured' WHERE root_id=$1 AND id=$2 AND outcome IS NULL;

-- name: RefusePolicyOccurrence :execrows
UPDATE policy_occurrence SET outcome='refused' WHERE root_id=$1 AND id=$2 AND outcome IS NULL;

-- name: ReadPolicyOccurrence :one
SELECT * FROM policy_occurrence WHERE root_id=$1 AND id=$2;

-- name: ListPolicyOccurrences :many
SELECT * FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 ORDER BY created_at DESC, id LIMIT 8;

-- name: CountPolicyOccurrences :one
SELECT count(*)::bigint AS total, count(capture_id)::bigint AS captured FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2;

-- name: ListPolicySuppressions :many
SELECT * FROM policy_suppression WHERE root_id=$1 AND policy_uid=$2 ORDER BY reason;

-- name: CountPolicyWatermarks :one
SELECT count(*)::bigint FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2;

-- name: ListActivePolicies :many
SELECT s.policy_uid, s.name, s.namespace_uid FROM policy_source s JOIN policy_acceptance a ON a.id=s.active_id AND a.root_id=s.root_id
WHERE s.root_id=$1 AND NOT s.deleted AND (a.record#>>'{Authority,NotAfter}')::timestamptz>clock_timestamp()
ORDER BY s.policy_uid LIMIT 65;

-- name: CountActiveClusterPolicies :one
SELECT count(*)::bigint FROM policy_source s JOIN policy_acceptance a ON a.id=s.active_id AND a.root_id=s.root_id
WHERE s.root_id=$1 AND s.policy_uid<>$2 AND NOT s.deleted AND a.record#>>'{Authority,ClusterID}'=$3::text
AND (a.record#>>'{Authority,NotAfter}')::timestamptz>clock_timestamp();

-- name: FindAutomationBases :many
SELECT b.uid, b.generation, b.spec_digest FROM permission_basis b
WHERE b.stream_id=$1 AND b.kind='AccessBinding' AND b.effect='Allow' AND b.automation_json IS NOT NULL
AND b.cluster_id=$2 AND b.namespace_uid=$3 AND (cardinality(b.workload_uids)=0 OR $4::text=ANY(b.workload_uids))
ORDER BY b.basis_key LIMIT 2;

-- name: FindPolicyOccurrence :one
SELECT id FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3 AND restarts=$4;
