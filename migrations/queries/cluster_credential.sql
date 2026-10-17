-- name: LockClusterEnrollmentLineage :one
SELECT * FROM cluster_enrollment_lineage WHERE root_id=$1 AND peer_id=$2 AND retired_at IS NULL FOR UPDATE;

-- name: ReadClusterEnrollmentCredential :one
SELECT * FROM cluster_enrollment_credential WHERE lineage_id=$1 AND generation=$2;

-- name: RetireClusterEnrollmentLineage :execrows
UPDATE cluster_enrollment_lineage SET retired_at=$2 WHERE lineage_id=$1 AND retired_at IS NULL;

-- name: InsertClusterEnrollmentLineage :exec
INSERT INTO cluster_enrollment_lineage(lineage_id,root_id,peer_id,installation_id,cluster_id,validity_seconds,rotation_seconds,current_generation,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,1,$8);

-- name: InsertClusterEnrollmentCredential :exec
INSERT INTO cluster_enrollment_credential(lineage_id,generation,public_key,issued_at,valid_until) VALUES($1,$2,$3,$4,$5);

-- name: SupersedeClusterEnrollmentCredential :execrows
UPDATE cluster_enrollment_credential SET superseded_at=$3,successor_digest=$4
WHERE lineage_id=$1 AND generation=$2 AND superseded_at IS NULL;

-- name: AdvanceClusterEnrollmentLineage :execrows
UPDATE cluster_enrollment_lineage SET current_generation=current_generation+1
WHERE lineage_id=$1 AND current_generation=$2 AND fenced IS NULL AND retired_at IS NULL;

-- name: MarkClusterEnrollmentFirstUse :execrows
UPDATE cluster_enrollment_credential SET first_used_at=$3
WHERE lineage_id=$1 AND generation=$2 AND first_used_at IS NULL AND superseded_at IS NULL;

-- name: FenceClusterEnrollmentLineage :execrows
UPDATE cluster_enrollment_lineage SET fenced=$2,fenced_at=$3 WHERE lineage_id=$1 AND fenced IS NULL;

-- name: ReadClusterEnrollmentProfile :one
SELECT installation_id,cluster_id FROM connector_identity_profile WHERE root_id=$1 AND peer_id=$2;
