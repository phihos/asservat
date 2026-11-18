-- name: WithdrawRemoteBindings :exec
SELECT public.withdraw_remote_bindings(sqlc.arg(root_id)::uuid, sqlc.arg(active_clusters)::uuid[]);
