-- name: ObserveFleetAdministration :one
SELECT public.observe_fleet_administration(sqlc.arg(installation_id)::uuid,
 sqlc.arg(semantic_version)::bigint,sqlc.arg(postmaster_at)::timestamptz,
 sqlc.arg(database_oid)::oid,sqlc.arg(basis_until)::timestamptz,
 sqlc.arg(issuer_epoch)::uuid,sqlc.arg(source_uid)::text,sqlc.arg(source_generation)::bigint,
 sqlc.arg(source_digest)::bytea,sqlc.arg(suspended)::boolean,
 sqlc.arg(observed_at)::timestamptz,sqlc.arg(fresh_until)::timestamptz)::integer AS disposition;

-- name: FenceFleetObservation :one
SELECT public.fence_fleet_observation(sqlc.arg(installation_id)::uuid,
 sqlc.arg(semantic_version)::bigint,sqlc.arg(postmaster_at)::timestamptz,
 sqlc.arg(database_oid)::oid,sqlc.arg(observation_started)::timestamptz)::boolean AS fenced;

-- name: ReadFleetTrust :one
SELECT * FROM fleet_current_trust WHERE installation_id=$1;

-- name: ShareFleetTrust :one
SELECT * FROM fleet_current_trust WHERE installation_id=$1 FOR SHARE;
