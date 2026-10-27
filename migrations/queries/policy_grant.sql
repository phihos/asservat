-- A fixed-size digest locates a request; every full principal field and the
-- original input digest is independently compared by the adapter.
-- name: ReadPolicyGrantByKey :one
SELECT * FROM access_grant WHERE root_id=sqlc.arg(root_id)::uuid AND kind='policy'
 AND requester_key=sha256(int4send(octet_length(sqlc.arg(requester_issuer)::text)) || textsend(sqlc.arg(requester_issuer)::text)
  || int4send(octet_length(sqlc.arg(requester_subject)::text)) || textsend(sqlc.arg(requester_subject)::text)
  || int4send(octet_length(sqlc.arg(requester_client)::text)) || textsend(sqlc.arg(requester_client)::text)
  || int4send(octet_length(sqlc.arg(requester_kind)::text)) || textsend(sqlc.arg(requester_kind)::text))
 AND request_operation='requestPolicyGrant' AND idempotency_key=sqlc.arg(idempotency_key)::text;

-- name: InsertPolicyGrant :one
INSERT INTO access_grant(id,root_id,kind,cluster_id,namespace_uid,workload_uid,execution_digest,review_digest,data_class,reasons,review,scope,
 requester_issuer,requester_subject,requester_client,requester_kind,request_operation,lifetime_seconds,
 idempotency_key,request_digest,requested_at,review_until,policy_uid,policy_acceptance_id,policy_scope,policy_not_after)
SELECT sqlc.arg(id)::uuid,sqlc.arg(root_id)::uuid,'policy',sqlc.arg(cluster_id)::uuid,sqlc.arg(namespace_uid)::text,sqlc.arg(workload_uid)::text,
 sqlc.arg(execution_digest)::bytea,sqlc.arg(review_digest)::bytea,sqlc.arg(data_class)::text,sqlc.arg(reasons)::jsonb,sqlc.arg(review)::bytea,sqlc.arg(scope)::bytea,
 sqlc.arg(requester_issuer)::text,sqlc.arg(requester_subject)::text,sqlc.arg(requester_client)::text,sqlc.arg(requester_kind)::text,'requestPolicyGrant',sqlc.arg(lifetime_seconds)::integer,
 sqlc.arg(idempotency_key)::text,sqlc.arg(request_digest)::bytea,t.n,t.n+interval '1 hour',sqlc.arg(policy_uid)::text,sqlc.arg(policy_acceptance_id)::uuid,sqlc.arg(policy_scope)::jsonb,
 LEAST(t.n+make_interval(secs=>sqlc.arg(lifetime_seconds)::integer),sqlc.arg(authority_not_after)::timestamptz,t.n+make_interval(secs=>s.max_age_seconds))
FROM (SELECT clock_timestamp() AS n) t JOIN policy_grant_settings s ON s.root_id=sqlc.arg(root_id)::uuid
WHERE s.issuer=sqlc.arg(requester_issuer)::text AND s.fresh_until>t.n
 AND s.source_uid=sqlc.arg(settings_uid)::text AND s.source_generation=sqlc.arg(settings_generation)::bigint AND s.source_digest=sqlc.arg(settings_digest)::bytea
 AND sqlc.arg(authority_not_after)::timestamptz>t.n
RETURNING access_grant.*;

-- The permission root serializes first insert, accepted-setting updates and
-- policy request/admission. All reads keep the source's original interval.
-- name: ReadPolicyGrantSettings :one
SELECT * FROM policy_grant_settings WHERE root_id=$1;

-- name: WritePolicyGrantSettings :exec
INSERT INTO policy_grant_settings(root_id,installation_id,issuer,source_uid,source_generation,source_digest,observed_at,fresh_until,default_age_seconds,max_age_seconds,renewal_notice_seconds)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT(root_id) DO UPDATE SET issuer=EXCLUDED.issuer,source_uid=EXCLUDED.source_uid,source_generation=EXCLUDED.source_generation,
 source_digest=EXCLUDED.source_digest,observed_at=EXCLUDED.observed_at,fresh_until=EXCLUDED.fresh_until,
 default_age_seconds=EXCLUDED.default_age_seconds,max_age_seconds=EXCLUDED.max_age_seconds,renewal_notice_seconds=EXCLUDED.renewal_notice_seconds;

-- name: ClampPolicyGrantDeadlines :exec
UPDATE access_grant SET policy_not_after=requested_at+make_interval(secs=>sqlc.arg(max_age_seconds)::integer),
 expires_at=CASE WHEN decision='approved' THEN requested_at+make_interval(secs=>sqlc.arg(max_age_seconds)::integer) ELSE NULL END
WHERE root_id=sqlc.arg(root_id)::uuid AND kind='policy' AND (decision IS NULL OR decision='approved')
 AND policy_not_after>requested_at+make_interval(secs=>sqlc.arg(max_age_seconds)::integer);
