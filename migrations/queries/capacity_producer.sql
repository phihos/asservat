-- name: ApplyCapacity :one
SELECT capacity_apply(sqlc.arg(root_id)::uuid,sqlc.arg(cluster_id)::uuid,sqlc.arg(namespace_uid)::text,sqlc.arg(account_version)::text,sqlc.arg(qualification)::jsonb,sqlc.arg(settings_value)::jsonb)::jsonb AS applied;

-- name: EnrollCapacity :one
SELECT capacity_enroll(sqlc.arg(root_id)::uuid,sqlc.arg(cluster_id)::uuid,sqlc.arg(namespace_uid)::text,sqlc.arg(workload_uid)::text,sqlc.arg(allocation_id)::uuid,sqlc.arg(download_allocation_id)::uuid,sqlc.arg(account_digest)::bytea)::uuid AS allocation_id;

-- name: ReadCapacityAccount :one
SELECT allocation_id FROM capacity_account WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND workload_uid=$4;

-- name: ReadCapacityAuditProfiles :one
SELECT read_capacity_audit_profiles(sqlc.arg(root_id)::uuid,sqlc.arg(installation_id)::uuid,sqlc.arg(qualification_id)::uuid,sqlc.arg(qualification_digest)::bytea,sqlc.arg(account_version)::text,sqlc.arg(observed_at)::timestamptz,sqlc.arg(fresh_until)::timestamptz)::jsonb AS profiles;

-- name: ReadManagedCapacityAdmission :one
SELECT capacity_managed_admission_until(sqlc.arg(root_id)::uuid,sqlc.arg(allocation_id)::uuid,sqlc.arg(kind)::text,clock_timestamp())::timestamptz AS until_at;

-- name: CapacityExpensiveAdmits :one
SELECT capacity_expensive_admits(sqlc.arg(allocation_id)::uuid)::boolean AS admits;
