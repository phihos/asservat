-- name: ReadSharedContextQueryPlan :one
SELECT read_shared_context_query_plan(sqlc.arg(root_id)::uuid,sqlc.arg(cluster_id)::uuid,sqlc.arg(namespace_uid)::text,sqlc.arg(workload_uid)::text,sqlc.arg(actor)::jsonb,sqlc.arg(principal_key)::bytea,sqlc.arg(proposed_account)::uuid,sqlc.arg(path)::jsonb)::jsonb;
-- name: LockContextQueryCapacity :one
SELECT lock_context_query_capacity(sqlc.arg(root_id)::uuid,sqlc.arg(acceptance_id)::uuid)::boolean;
-- name: ContextQueryCapacityAllocationCurrent :one
SELECT context_query_capacity_allocation_current(sqlc.arg(root_id)::uuid,sqlc.arg(allocation_id)::uuid)::boolean;
-- name: ContextQuerySharedProfileCurrent :one
SELECT context_query_shared_profile_current(sqlc.arg(root_id)::uuid,sqlc.arg(profile)::jsonb)::boolean;
