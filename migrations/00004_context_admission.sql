-- +goose Up
-- Protected workload-to-allocation mappings and bounded initial admission only.
-- No row here authorizes execution, publication, key unwrap or native download.
CREATE TABLE context_storage_binding (
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 cluster_id uuid NOT NULL, namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_uid text NOT NULL CHECK(octet_length(workload_uid) BETWEEN 1 AND 64),
 allocation_id uuid NOT NULL UNIQUE REFERENCES custody_allocation(id),
 source_uid text NOT NULL CHECK(octet_length(source_uid) BETWEEN 1 AND 64),
 source_generation bigint NOT NULL CHECK(source_generation BETWEEN 1 AND 2147483647),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 observed_at timestamptz NOT NULL, fresh_until timestamptz NOT NULL,
 PRIMARY KEY(root_id,cluster_id,namespace_uid,workload_uid),
 CHECK(fresh_until>observed_at AND fresh_until<=observed_at+interval '30 seconds')
);
CREATE TABLE context_capture (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 request_key bytea NOT NULL CHECK(octet_length(request_key)=32),
 submission_digest bytea NOT NULL CHECK(octet_length(submission_digest)=32),
 scope_digest bytea NOT NULL CHECK(octet_length(scope_digest)=32),
 scope_json bytea NOT NULL CHECK(octet_length(scope_json) BETWEEN 1 AND 65536),
 expectation_json bytea NOT NULL CHECK(octet_length(expectation_json) BETWEEN 1 AND 65536),
 pod_pin_json bytea NOT NULL CHECK(octet_length(pod_pin_json) BETWEEN 1 AND 4096),
 attempt_id uuid NOT NULL UNIQUE REFERENCES custody_attempt(id),
 permission_epoch uuid NOT NULL, permission_sequence bigint NOT NULL,
 identity_policy_uid text NOT NULL CHECK(octet_length(identity_policy_uid) BETWEEN 1 AND 64),
 identity_policy_generation bigint NOT NULL CHECK(identity_policy_generation BETWEEN 1 AND 2147483647),
 identity_policy_digest bytea NOT NULL CHECK(octet_length(identity_policy_digest)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), deadline timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'accepted_pending_audit' CHECK(state IN ('accepted_pending_audit')),
 UNIQUE(root_id,request_key), CHECK(deadline>created_at)
);
-- The immutable accepted record is also the pending intent source. It cannot be
-- acknowledged as object audit merely because the SQL transaction committed.
-- Finite history cleanup and the durable intent/dispatch coordinator follow.
