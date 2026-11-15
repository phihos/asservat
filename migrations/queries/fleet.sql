-- name: ReadFleetTrust :one
SELECT * FROM fleet_current_trust WHERE installation_id=$1;

-- name: ShareFleetTrust :one
SELECT * FROM fleet_current_trust WHERE installation_id=$1 FOR SHARE;
