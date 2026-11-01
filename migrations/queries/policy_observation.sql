-- ADR-261: recovery reads the immutable once-only tuple, never current aliases.
-- The existing capture/authority locks serialize first insertion and both pools.
-- name: ReadPolicyObservation :one
SELECT * FROM policy_observation_session WHERE root_id=$1 AND capture_id=$2;

-- name: CountActivePolicyObservations :one
SELECT count(*) FROM policy_observation_session
WHERE root_id=$1 AND acceptance_id=$2 AND ended_at IS NULL AND lease_until>clock_timestamp();

-- name: SpendPolicyObservedBytes :execrows
UPDATE policy_acceptance SET observed_bytes_spent=observed_bytes_spent+sqlc.arg(bytes)::bigint
WHERE root_id=sqlc.arg(root_id)::uuid AND id=sqlc.arg(id)::uuid
 AND executions_spent>0 AND sqlc.arg(bytes)::bigint>0
 AND observed_bytes_spent<=(record#>>'{Authority,Limits,MaxObservedBytes}')::bigint-sqlc.arg(bytes)::bigint;

-- name: SpendPolicyGrantObservedBytes :execrows
UPDATE access_grant SET policy_observed_bytes_spent=policy_observed_bytes_spent+sqlc.arg(bytes)::bigint
WHERE root_id=sqlc.arg(root_id)::uuid AND id=sqlc.arg(id)::uuid AND kind='policy'
 AND decision='approved' AND revoked_at IS NULL AND clock_timestamp()<policy_not_after
 AND sqlc.arg(bytes)::bigint>0 AND policy_observed_bytes_spent<=policy_max_observed_bytes-sqlc.arg(bytes)::bigint;

-- name: InsertPolicyObservation :one
INSERT INTO policy_observation_session(id,root_id,policy_uid,acceptance_id,grant_id,capture_id,attempt_id,fence,
 action_id,pod_uid,node_uid,boot_id,collector_pod_uid,collector_epoch,expectation_digest,program_digest,binding_scope,accounting_rule,
 source_observed_at,source_fresh_until,started_at,session_until,lease_until,start_by,duration_millis,sequence,credit,max_bytes_per_second)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$22,$23,$24,1,$25,$26)
RETURNING *;

-- name: RetirePolicyObservation :execrows
DELETE FROM policy_observation_session WHERE root_id=$1 AND capture_id=$2;
