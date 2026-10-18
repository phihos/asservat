-- name: ReadContextQueryCapacitySource :one
SELECT read_context_query_capacity_source(sqlc.arg(root_id)::uuid,sqlc.arg(recovery)::jsonb)::jsonb;
-- name: AcceptContextQueryCapacity :one
SELECT accept_context_query_capacity(sqlc.arg(root_id)::uuid,sqlc.arg(proposal)::jsonb,sqlc.arg(observation)::jsonb)::jsonb;
-- name: SuspendContextQueryCapacity :exec
SELECT suspend_context_query_capacity(sqlc.arg(root_id)::uuid,sqlc.arg(observed)::timestamptz);
-- name: AllocateContextQueryCapacity :one
SELECT allocate_context_query_capacity(sqlc.arg(root_id)::uuid,sqlc.arg(acceptance_id)::uuid,sqlc.arg(cluster_id)::uuid,sqlc.arg(namespace_uid)::text,sqlc.arg(workload_uid)::text,sqlc.arg(new_id)::uuid)::uuid;
-- name: ReadContextQueryCapacityPlan :one
SELECT read_context_query_capacity_plan(sqlc.arg(root_id)::uuid,sqlc.arg(acceptance_id)::uuid,sqlc.arg(cluster_id)::uuid,sqlc.arg(namespace_uid)::text,sqlc.arg(workload_uid)::text,sqlc.arg(actor)::jsonb,sqlc.arg(principal_key)::bytea,sqlc.arg(proposed_account)::uuid)::jsonb;
-- name: LockContextQueryCapacity :one
SELECT lock_context_query_capacity(sqlc.arg(root_id)::uuid,sqlc.arg(acceptance_id)::uuid)::boolean;
-- name: ContextQueryCapacityAllocationCurrent :one
SELECT context_query_capacity_allocation_current(sqlc.arg(root_id)::uuid,sqlc.arg(allocation_id)::uuid)::boolean;
