-- name: InsertPolicySource :exec
INSERT INTO policy_source(root_id,policy_uid,installation_id,cluster_id,namespace_uid,name,generation,spec_digest,resource_version,observed_at,fresh_until,deleted,suspended,collection_digest,authored_grant_ref)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(root_id,policy_uid) DO NOTHING;

-- name: LockPolicySource :one
SELECT * FROM policy_source WHERE root_id=$1 AND policy_uid=$2 FOR UPDATE;

-- name: SharePolicySource :one
SELECT * FROM policy_source WHERE root_id=$1 AND policy_uid=$2 FOR SHARE;

-- name: UpdatePolicySource :exec
UPDATE policy_source SET generation=$3,spec_digest=$4,resource_version=$5,observed_at=$6,fresh_until=$7,deleted=$8,suspended=$9,intent_version=CASE WHEN collection_digest=$10 AND generation>=($3::bigint-1) THEN intent_version ELSE intent_version+1 END,collection_digest=$10,
 grant_attachment_id=CASE WHEN authored_grant_ref=$11 THEN grant_attachment_id ELSE NULL END,authored_grant_ref=$11 WHERE root_id=$1 AND policy_uid=$2;

-- name: ActivatePolicyAcceptance :execrows
UPDATE policy_source SET creator_json=COALESCE(creator_json,$3),active_id=$4 WHERE root_id=$1 AND policy_uid=$2;

-- name: FindPolicyNonce :one
SELECT * FROM policy_acceptance WHERE root_id=$1 AND nonce=$2;

-- name: ReadPolicyAcceptance :one
SELECT * FROM policy_acceptance WHERE root_id=$1 AND id=$2;

-- name: InsertPolicyAcceptance :one
INSERT INTO policy_acceptance(id,root_id,policy_uid,generation,nonce,request_digest,record_digest,record,accepted_at,scope_digest)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *;

-- name: PendingPolicyAcceptances :many
SELECT * FROM policy_acceptance WHERE root_id=$1 AND acknowledged_at IS NULL ORDER BY accepted_at,id LIMIT 2;

-- name: LockPolicyAcceptance :one
SELECT * FROM policy_acceptance WHERE root_id=$1 AND id=$2 FOR UPDATE;

-- name: AcknowledgePolicyAcceptance :execrows
UPDATE policy_acceptance SET acknowledged_at=clock_timestamp(),receipt_json=$3 WHERE root_id=$1 AND id=$2 AND acknowledged_at IS NULL;

-- name: NewPolicyAcceptanceID :one
SELECT gen_random_uuid()::uuid AS id;

-- name: FindPolicyScope :one
SELECT id FROM policy_acceptance WHERE root_id=$1 AND policy_uid=$2 AND scope_digest=$3;
