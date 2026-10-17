-- name: ReadBrowserRefreshPauseSession :one
-- Caller already holds LockBrowserRoot; session/owner writers take either
-- that lock or its shared counterpart. This observation needs no session UPDATE
-- privilege and cannot mint a new identity or extend a lease.
SELECT * FROM browser_session WHERE root_id=$1 AND epoch=$2 AND id=$3;
-- name: ReadBrowserRefreshOwner :one
SELECT * FROM browser_refresh_owner WHERE root_id=$1 AND session_id=$2;
-- name: LockBrowserRefreshOwner :one
SELECT * FROM browser_refresh_owner WHERE root_id=$1 AND session_id=$2 FOR UPDATE;
-- name: InsertBrowserRefreshOwner :one
INSERT INTO browser_refresh_owner(root_id,session_id,epoch,owner_id,generation,installation_id,cluster_id,pod_uid,process_epoch,actor_key,provider_session_key,session_created_at,authenticated_at,session_expires_at,started_at,lease_until)
VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *;
-- name: ReassignJoinedBrowserRefreshOwner :one
UPDATE browser_refresh_owner SET owner_id=$4,generation=generation+1,installation_id=$5,cluster_id=$6,pod_uid=$7,process_epoch=$8,started_at=$9,lease_until=$10,session_expires_at=$11,joined_at=NULL,claim=NULL,claim_version=NULL,claim_until=NULL,claim_joined_at=NULL,claim_download_id=NULL,claim_response_id=NULL,claim_response_owner=NULL,claim_response_generation=NULL
WHERE root_id=$1 AND session_id=$2 AND owner_id=$3 AND joined_at IS NOT NULL RETURNING *;
-- name: RenewBrowserRefreshOwner :one
UPDATE browser_refresh_owner SET lease_until=greatest(lease_until,$5) WHERE root_id=$1 AND session_id=$2 AND owner_id=$3 AND generation=$4 AND joined_at IS NULL RETURNING *;
-- name: BindBrowserRefreshClaim :one
UPDATE browser_refresh_owner SET claim=$5,claim_version=$6,claim_until=$7,claim_joined_at=NULL,claim_download_id=$8,claim_response_id=$9,claim_response_owner=$10,claim_response_generation=$11
WHERE root_id=$1 AND session_id=$2 AND owner_id=$3 AND generation=$4 AND joined_at IS NULL RETURNING *;
-- name: JoinBrowserRefreshClaim :one
UPDATE browser_refresh_owner SET claim_joined_at=coalesce(claim_joined_at,$7) WHERE root_id=$1 AND session_id=$2 AND owner_id=$3 AND generation=$4 AND claim=$5 AND claim_version=$6 RETURNING *;
-- name: JoinBrowserRefreshOwner :one
UPDATE browser_refresh_owner SET joined_at=coalesce(joined_at,$5) WHERE root_id=$1 AND session_id=$2 AND owner_id=$3 AND generation=$4 RETURNING *;
-- name: DeleteJoinedBrowserRefreshOwner :execrows
DELETE FROM browser_refresh_owner o WHERE o.root_id=$1 AND o.session_id=$2 AND o.owner_id=$3 AND o.generation=$4 AND o.joined_at IS NOT NULL
AND NOT EXISTS(SELECT 1 FROM browser_session s WHERE s.root_id=$1 AND s.id=$2);
-- name: ReadBrowserRefreshConsumer :one
SELECT * FROM browser_refresh_consumer WHERE download_id=$1;
-- name: LockBrowserRefreshConsumer :one
SELECT * FROM browser_refresh_consumer WHERE download_id=$1 FOR UPDATE;
-- name: InsertBrowserRefreshConsumer :one
INSERT INTO browser_refresh_consumer(download_id,download_root_id,first_admitted_at,grace_until,hard_until,actor_key,owner_id,owner_generation)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *;
-- name: AttachBrowserRefreshConsumer :one
UPDATE browser_refresh_consumer SET owner_id=$2,owner_generation=$3 WHERE download_id=$1 AND owner_id IS NULL RETURNING *;
-- name: DetachBrowserRefreshConsumer :execrows
UPDATE browser_refresh_consumer SET owner_id=NULL,owner_generation=NULL WHERE download_id=$1 AND owner_id=$2 AND owner_generation=$3;
-- name: ReadBrowserRefreshConsumers :many
SELECT * FROM browser_refresh_consumer WHERE owner_id=$1 AND owner_generation=$2 ORDER BY download_id LIMIT 17;
-- name: ReadCurrentBrowserRefreshResponse :one
SELECT r.* FROM download_response r JOIN artifact_download d ON d.id=r.session_id AND d.root_id=r.root_id
WHERE r.session_id=$1 AND r.root_id=$2 AND r.generation=d.generation AND NOT r.closed
AND d.state NOT IN ('Completed','Cancelled','Expired','Denied','Failed') AND clock_timestamp()<r.lease_until AND clock_timestamp()<r.until_at AND clock_timestamp()<d.deadline;
-- name: ReadBrowserRefreshPauseResponse :one
SELECT r.* FROM download_response r JOIN artifact_download d ON d.id=r.session_id AND d.root_id=r.root_id
WHERE r.id=$1 AND r.session_id=$2 AND r.owner_id=$3 AND r.generation=$4 AND r.generation=d.generation AND NOT r.closed
AND d.state NOT IN ('Completed','Cancelled','Expired','Denied','Failed') AND clock_timestamp()<r.until_at AND clock_timestamp()<d.deadline;
