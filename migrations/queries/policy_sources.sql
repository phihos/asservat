-- name: ReadPolicyRecordingSource :one
SELECT * FROM policy_recording_source WHERE root_id=$1 AND id=$2 FOR SHARE;
-- name: FindPolicyRecordingSource :one
SELECT * FROM policy_recording_source WHERE root_id=$1 AND policy_uid=$2 AND action_id=$3 AND pod_uid=$4 AND slot_released_at IS NULL FOR SHARE;
-- name: InsertPolicyRecordingSource :one
INSERT INTO policy_recording_source(root_id,id,fence,policy_uid,acceptance_id,action_id,cluster_id,namespace_uid,workload_uid,pod_uid,allocation_id,binding_json,started_at,hard_until,start_by,initial_leaf_until,initial_credit,credit,bytes_per_second,source_audience_json,source_audience_digest,source_target_json)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22) RETURNING *;
-- name: IncreasePolicyRecordingSourceCredit :one
UPDATE policy_recording_source SET credit=credit+sqlc.arg(additional_credit)::bigint WHERE root_id=$1 AND id=$2 AND credit=sqlc.arg(expected_credit) AND ended_at IS NULL AND hard_until>clock_timestamp() AND sqlc.arg(additional_credit)::bigint>0 AND credit<=9223372036854775807-sqlc.arg(additional_credit)::bigint RETURNING *;
-- name: SpendPolicySourceObservedBytes :execrows
UPDATE policy_acceptance SET observed_bytes_spent=observed_bytes_spent+sqlc.arg(bytes)::bigint
WHERE root_id=$1 AND id=$2 AND sqlc.arg(bytes)::bigint>0 AND observed_bytes_spent<=(record#>>'{Authority,Limits,MaxObservedBytes}')::bigint-sqlc.arg(bytes)::bigint;
-- name: EndPolicyRecordingSource :execrows
UPDATE policy_recording_source SET ended_at=clock_timestamp() WHERE root_id=$1 AND id=$2 AND ended_at IS NULL;
-- name: ReleaseEndedPolicySourceSlots :execrows
UPDATE policy_recording_source dst SET slot_released_at=clock_timestamp() WHERE (dst.root_id,dst.id) IN (SELECT s.root_id,s.id FROM policy_recording_source s WHERE s.root_id=$1 AND s.ended_at IS NOT NULL AND s.slot_released_at IS NULL AND s.ended_at+interval '30 seconds'<=clock_timestamp() ORDER BY s.ended_at,s.id LIMIT 64);
-- name: ListPolicyRecordingSources :many
SELECT * FROM policy_recording_source WHERE root_id=$1 AND policy_uid=$2 AND slot_released_at IS NULL ORDER BY action_id,pod_uid LIMIT 1025;
-- name: CountPolicyRecordingSources :one
SELECT count(*) AS source_count,COALESCE(sum(bytes_per_second),0)::bigint AS input_rate FROM policy_recording_source WHERE root_id=$1 AND allocation_id=$2 AND slot_released_at IS NULL;
-- name: ReadPolicySourceResourceSelection :one
SELECT s.accepted_revision,s.accepted_snapshot,s.accepted_digest,s.observed_at,s.fresh_until,s.suspended,w.policy_uid
FROM capacity_source s JOIN capacity_workload w ON w.root_id=s.root_id
WHERE s.root_id=$1 AND w.allocation_id=$2 AND w.ready_at IS NOT NULL AND w.mutation_xid IS NULL FOR SHARE OF s,w;
-- name: EndInactivePolicyRecordingSources :many
UPDATE policy_recording_source dst SET ended_at=clock_timestamp() WHERE (dst.root_id,dst.id) IN (
 SELECT s.root_id,s.id FROM policy_recording_source s WHERE s.root_id=$1 AND s.ended_at IS NULL AND (s.hard_until<=clock_timestamp() OR NOT EXISTS (
 SELECT 1 FROM policy_source p WHERE p.root_id=s.root_id AND p.policy_uid=s.policy_uid AND p.active_id=s.acceptance_id AND NOT p.deleted AND NOT p.suspended)) ORDER BY s.id LIMIT 64) RETURNING *;
