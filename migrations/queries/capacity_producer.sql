-- name: ReadCapacityPermissionScopes :one
SELECT read_capacity_permission_scopes(sqlc.arg(root_id)::uuid,sqlc.arg(recovery_value)::jsonb)::jsonb AS scope_json;

-- name: ReadCapacityRecovery :one
SELECT read_capacity_recovery(sqlc.arg(root_id)::uuid,sqlc.arg(observed_at)::timestamptz,sqlc.arg(fresh_until)::timestamptz)::jsonb AS recovery;

-- name: ReadCapacityRuntimeScope :one
SELECT read_capacity_runtime_scope(sqlc.arg(root_id)::uuid,sqlc.arg(expected_value)::jsonb,sqlc.arg(qualification_value)::jsonb,sqlc.arg(observed_at)::timestamptz,sqlc.arg(fresh_until)::timestamptz)::timestamptz AS until_at;

-- name: ReadCapacitySourceRevision :one
SELECT read_capacity_source_revision(sqlc.arg(root_id)::uuid,sqlc.arg(recovery_value)::jsonb)::bigint AS revision;

-- name: AcceptCapacitySource :one
SELECT accept_capacity_source(sqlc.arg(root_id)::uuid,sqlc.arg(expected_revision)::bigint,sqlc.arg(observation_value)::jsonb,sqlc.arg(protection_value)::jsonb,sqlc.arg(recovery_value)::jsonb,sqlc.arg(qualification_id)::uuid,sqlc.arg(qualification_digest)::bytea)::jsonb AS acceptance;

-- name: InvalidateCapacitySource :one
SELECT invalidate_capacity_source(sqlc.arg(root_id)::uuid,sqlc.arg(expected_revision)::bigint,sqlc.arg(recovery_value)::jsonb,sqlc.arg(observed_at)::timestamptz,sqlc.arg(fresh_until)::timestamptz)::boolean AS invalidated;

-- name: ReadCapacityEnrollment :one
SELECT read_capacity_enrollment(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(source_canonical)::bytea)::jsonb AS enrollment;

-- name: ReadCapacityCaptureEnrollment :one
SELECT read_capacity_capture_enrollment(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(source_canonical)::bytea)::jsonb AS enrollment;

-- name: ReadCapacityAuditProfiles :one
SELECT read_capacity_audit_profiles(sqlc.arg(root_id)::uuid,sqlc.arg(installation_id)::uuid,sqlc.arg(qualification_id)::uuid,sqlc.arg(qualification_digest)::bytea,sqlc.arg(account_version)::text,sqlc.arg(observed_at)::timestamptz,sqlc.arg(fresh_until)::timestamptz)::jsonb AS profiles;

-- name: ReadCapacityRoot :one
SELECT read_capacity_root(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea)::jsonb AS result;

-- name: ReserveCapacityRoot :one
SELECT reserve_capacity_root(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(attempt_id)::uuid)::jsonb AS result;

-- name: BackCapacityRoot :one
SELECT back_capacity_root(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(expected_value)::jsonb)::jsonb AS result;

-- name: PublishCapacityRoot :one
SELECT publish_capacity_root(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(expected_value)::jsonb)::jsonb AS result;

-- name: ReadManagedCapacityAdmission :one
SELECT capacity_managed_admission_until(sqlc.arg(root_id)::uuid,sqlc.arg(allocation_id)::uuid,sqlc.arg(kind)::text,clock_timestamp())::timestamptz AS until_at;

-- name: ReserveCapacityEnrollment :one
SELECT reserve_capacity_enrollment(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(source_canonical)::bytea,sqlc.arg(account_id)::uuid,sqlc.arg(attempt_id)::uuid,sqlc.arg(allocation_id)::uuid,sqlc.arg(download_allocation_id)::uuid,sqlc.arg(account_digest)::bytea)::jsonb AS enrollment;

-- name: BackCapacityEnrollment :one
SELECT back_capacity_enrollment(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(source_canonical)::bytea,sqlc.arg(expected_value)::jsonb)::jsonb AS enrollment;

-- name: ContinueCapacityCapture :one
SELECT continue_capacity_capture(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(source_canonical)::bytea,sqlc.arg(expected_value)::jsonb)::jsonb AS enrollment;

-- name: PublishCapacityEnrollment :one
SELECT publish_capacity_enrollment(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(source_canonical)::bytea,sqlc.arg(expected_value)::jsonb)::jsonb AS enrollment;

-- name: ContinueCapacityPublication :one
SELECT continue_capacity_publication(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(source_canonical)::bytea,sqlc.arg(expected_value)::jsonb)::jsonb AS enrollment;

-- name: RenewCapacityRoot :one
SELECT renew_capacity_root(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(expected_value)::jsonb)::jsonb AS result;

-- name: RefreshCapacityEnrollment :one
SELECT refresh_capacity_enrollment(sqlc.arg(root_id)::uuid,sqlc.arg(observation_value)::jsonb,sqlc.arg(plan_canonical)::bytea,sqlc.arg(pool_canonical)::bytea,sqlc.arg(source_canonical)::bytea,sqlc.arg(expected_value)::jsonb)::jsonb AS enrollment;

-- name: ReadCapacityClusterQualifications :one
SELECT read_capacity_cluster_qualifications(sqlc.arg(root_id)::uuid)::jsonb AS qualifications;

-- name: QualifyCapacityCluster :one
SELECT qualify_capacity_cluster(sqlc.arg(root_id)::uuid,sqlc.arg(cluster_id)::uuid,sqlc.arg(peer_id)::uuid,sqlc.arg(issuer_epoch)::uuid,sqlc.arg(guard_digest)::bytea,sqlc.arg(guard_keys)::jsonb)::boolean AS inserted;
