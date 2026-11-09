-- name: ConfigureLiveWatch :one
SELECT live_watch_configure(sqlc.arg(root_id)::uuid,sqlc.arg(installation_id)::uuid,sqlc.arg(issuer_epoch)::uuid,sqlc.arg(limits_digest)::bytea,sqlc.arg(limits)::jsonb)::boolean;
-- name: CreateLiveWatch :one
SELECT live_watch_create(sqlc.arg(root_id)::uuid,sqlc.arg(owner_id)::uuid,sqlc.arg(limits_digest)::bytea,sqlc.arg(control)::jsonb,sqlc.arg(key_hash)::bytea,sqlc.arg(original_until)::timestamptz)::jsonb;
-- name: ChangeLiveWatch :one
SELECT live_watch_change(sqlc.arg(root_id)::uuid,sqlc.arg(owner_id)::uuid,sqlc.arg(limits_digest)::bytea,sqlc.arg(control)::jsonb,sqlc.arg(expected_revision)::bigint,sqlc.arg(cost)::bigint,sqlc.arg(original_until)::timestamptz)::jsonb;
-- name: CurrentLiveWatch :one
SELECT live_watch_current(sqlc.arg(root_id)::uuid,sqlc.arg(owner_id)::uuid,sqlc.arg(limits_digest)::bytea,sqlc.arg(control)::jsonb,sqlc.arg(original_until)::timestamptz)::boolean;

-- name: PruneLiveWatch :one
SELECT live_watch_prune(sqlc.arg(root_id)::uuid)::jsonb;

-- name: LookupLiveWatchOwner :one
SELECT installation_id::uuid,cluster_id::uuid,issuer_epoch::uuid,pod_uid::uuid,process_epoch::uuid FROM live_watch_owner(sqlc.arg(root_id)::uuid,sqlc.arg(principal_key)::bytea,sqlc.narg(watch_id)::uuid,sqlc.narg(key_hash)::bytea);

-- name: ReadLiveControl :one
SELECT live_watch_read_control(sqlc.arg(root_id)::uuid,sqlc.arg(principal_key)::bytea,sqlc.arg(watch_id)::uuid);

-- name: CloseLiveControl :one
SELECT live_watch_close_control(sqlc.arg(root_id)::uuid,sqlc.arg(principal_key)::bytea,sqlc.arg(watch_id)::uuid,sqlc.arg(expected_revision)::bigint,sqlc.arg(fence)::uuid);
