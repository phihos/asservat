-- name: NotifyConnectorWork :exec
SELECT pg_notify('asservat_connector_work', sqlc.arg(hint)::text);

-- name: NotifyConnectorReady :exec
SELECT pg_notify('asservat_connector_work', sqlc.arg(cluster_id)::text);
