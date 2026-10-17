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

-- name: LockFleetTrust :one
SELECT * FROM fleet_current_trust WHERE installation_id=$1 FOR UPDATE;

-- name: LockBootstrap :one
SELECT * FROM fleet_bootstrap WHERE installation_id=$1 AND id=$2 FOR UPDATE;

-- name: ClaimBootstrap :one
UPDATE fleet_bootstrap SET claimed_at=clock_timestamp(),public_key_sha256=$3
WHERE installation_id=$1 AND id=$2 AND claimed_at IS NULL
RETURNING *;

-- name: PendingEnrollmentClaims :many
SELECT * FROM fleet_bootstrap WHERE installation_id=$1 AND claimed_at IS NOT NULL
 AND claim_acknowledged_at IS NULL ORDER BY claimed_at,id LIMIT 2;

-- name: AcknowledgeEnrollmentClaim :execrows
UPDATE fleet_bootstrap SET claim_acknowledged_at=clock_timestamp(),claim_audit_digest=$3,
 claim_object_key=$4,claim_object_version=$5,claim_object_etag=$6,claim_object_bytes=$7,claim_object_sha256=$8
WHERE installation_id=$1 AND id=$2 AND claimed_at IS NOT NULL AND claim_acknowledged_at IS NULL;

-- name: ReadCertificateIssues :many
SELECT * FROM fleet_certificate_issue WHERE installation_id=$1 AND bootstrap_id=$2 ORDER BY ordinal LIMIT 3;

-- name: InsertCertificateIssue :exec
INSERT INTO fleet_certificate_issue(installation_id,bootstrap_id,ordinal,id,trust_uid,trust_generation,trust_digest,started_at,sign_before)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: StoreConnectorCertificate :execrows
UPDATE fleet_certificate_issue SET signed_at=clock_timestamp(),certificate_json=$3,certificate_sha256=$4,
 certificate_not_before=$5,certificate_not_after=$6
WHERE installation_id=$1 AND id=$2 AND signed_at IS NULL AND clock_timestamp()<sign_before;

-- name: PendingEnrollmentCertificates :many
SELECT * FROM fleet_certificate_issue WHERE installation_id=$1 AND signed_at IS NOT NULL
 AND audit_acknowledged_at IS NULL ORDER BY signed_at,id LIMIT 2;

-- name: AcknowledgeEnrollmentCertificate :execrows
UPDATE fleet_certificate_issue SET audit_acknowledged_at=clock_timestamp(),audit_digest=$3,
 audit_object_key=$4,audit_object_version=$5,audit_object_etag=$6,audit_object_bytes=$7,audit_object_sha256=$8
WHERE installation_id=$1 AND id=$2 AND signed_at IS NOT NULL AND audit_acknowledged_at IS NULL;

-- name: InsertEnrolledPeer :exec
INSERT INTO fleet_peer(installation_id,peer_id,cluster_id,issuer_epoch,role,revision,enabled,not_after,audit_id,audit_object_key,audit_object_version,audit_object_sha256)
VALUES($1,$2,$3,$4,'connector',1,true,$5,$6,$7,$8,$9);

-- name: InsertEnrolledCertificate :exec
INSERT INTO fleet_peer_certificate(installation_id,peer_id,slot,certificate_sha256,not_before,not_after)
VALUES($1,$2,0,$3,$4,$5);

-- name: ActivateCertificateIssue :execrows
UPDATE fleet_certificate_issue SET activated_at=clock_timestamp()
WHERE installation_id=$1 AND id=$2 AND audit_acknowledged_at IS NOT NULL AND activated_at IS NULL;

-- name: LockEnrolledPeer :one
SELECT * FROM fleet_peer WHERE installation_id=$1 AND peer_id=$2 FOR UPDATE;

-- name: ReadEnrolledCertificates :many
SELECT * FROM fleet_peer_certificate WHERE installation_id=$1 AND peer_id=$2 ORDER BY slot LIMIT 3;

-- name: FindBootstrapIntent :one
SELECT * FROM fleet_bootstrap_intent WHERE installation_id=$1 AND actor_digest=$2 AND key_digest=$3;

-- name: CountBootstrapReservations :one
WITH reservations AS (
 SELECT i.id,i.not_after FROM fleet_bootstrap_intent i WHERE i.installation_id=$1
 UNION ALL SELECT b.id,b.not_after FROM fleet_bootstrap b WHERE b.installation_id=$1
)
SELECT count(DISTINCT id) AS history_count,
 count(DISTINCT CASE WHEN not_after>sqlc.arg(check_time)::timestamptz THEN id END) AS active_count
FROM reservations;

-- name: CountReservedClusters :one
SELECT count(*) FROM (
 SELECT p.cluster_id FROM fleet_peer p WHERE p.installation_id=$1
 UNION SELECT i.cluster_id FROM fleet_bootstrap_intent i WHERE i.installation_id=$1 AND i.not_after>$2
 UNION SELECT b.cluster_id FROM fleet_bootstrap b WHERE b.installation_id=$1 AND b.not_after>$2
) clusters;

-- name: InsertBootstrapIntent :one
INSERT INTO fleet_bootstrap_intent(installation_id,id,actor_digest,key_digest,request_digest,actor_json,
 identity_uid,identity_generation,identity_digest,trust_uid,trust_generation,trust_digest,
 cluster_id,peer_id,issuer_epoch,delivery_profile,display_name,region,not_before,not_after)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
RETURNING *;

-- name: LockBootstrapIntent :one
SELECT * FROM fleet_bootstrap_intent WHERE installation_id=$1 AND id=$2 FOR UPDATE;

-- name: RecordBootstrapCredential :one
UPDATE fleet_bootstrap_intent SET credential_recorded_at=clock_timestamp(),credential_sha256=$3,credential_version=1
WHERE installation_id=$1 AND id=$2 AND credential_recorded_at IS NULL RETURNING *;

-- name: PendingBootstrapIssues :many
SELECT * FROM fleet_bootstrap_intent WHERE installation_id=$1 AND credential_recorded_at IS NOT NULL
 AND audit_acknowledged_at IS NULL ORDER BY credential_recorded_at,id LIMIT 2;

-- name: AcknowledgeBootstrapIssue :execrows
UPDATE fleet_bootstrap_intent SET audit_acknowledged_at=clock_timestamp(),audit_digest=$3,
 audit_object_key=$4,audit_object_version=$5,audit_object_etag=$6,audit_object_bytes=$7,audit_object_sha256=$8
WHERE installation_id=$1 AND id=$2 AND credential_recorded_at IS NOT NULL AND audit_acknowledged_at IS NULL;

-- name: CreateIssuedBootstrap :exec
INSERT INTO fleet_bootstrap(installation_id,id,cluster_id,peer_id,issuer_epoch,secret_sha256,not_before,not_after,
 issue_authority_digest,issue_audit_id,issue_audit_key,issue_audit_version,issue_audit_sha256)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$2,$10,$11,$12);

-- name: MarkBootstrapIssued :execrows
UPDATE fleet_bootstrap_intent SET issued_at=clock_timestamp()
WHERE installation_id=$1 AND id=$2 AND audit_acknowledged_at IS NOT NULL AND issued_at IS NULL;

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
