-- name: ReadPeerRegistration :many
-- One statement snapshot, no replica and no side effects. observed_start is
-- supplied from a DB clock read BEFORE this potentially blocking lookup.
SELECT t.issuer_epoch AS current_epoch,t.source_uid,t.source_generation,t.source_digest,
 t.suspended,t.recovery_blocked,t.observed_at,t.fresh_until,
 p.cluster_id,p.issuer_epoch,p.role,p.revision,p.enabled,p.not_after AS peer_not_after,
 p.audit_id,p.audit_object_key,p.audit_object_version,p.audit_object_sha256,
 c.certificate_sha256,c.not_before,c.not_after
FROM fleet_current_trust t JOIN fleet_peer p USING(installation_id)
 JOIN fleet_peer_certificate c USING(installation_id,peer_id)
WHERE t.installation_id=$1 AND p.peer_id=$2
ORDER BY c.slot LIMIT 3;

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
