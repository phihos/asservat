-- +goose Up
-- Storage facets only: these tables confer no acquisition or disclosure rights.
CREATE TABLE custody_pool (
 id uuid PRIMARY KEY, store_id uuid NOT NULL UNIQUE,
 revision bigint NOT NULL CHECK (revision > 0), valid_until timestamptz NOT NULL,
 paused boolean NOT NULL DEFAULT false,
 byte_limit bigint NOT NULL CHECK (byte_limit >= 0), object_limit bigint NOT NULL CHECK (object_limit >= 0),
 allocated_bytes bigint NOT NULL DEFAULT 0 CHECK (allocated_bytes >= 0 AND allocated_bytes <= byte_limit),
 allocated_objects bigint NOT NULL DEFAULT 0 CHECK (allocated_objects >= 0 AND allocated_objects <= object_limit)
);
CREATE TABLE custody_allocation (
 id uuid PRIMARY KEY, pool_id uuid NOT NULL REFERENCES custody_pool(id),
 scope_id uuid NOT NULL, service_class text NOT NULL CHECK (service_class IN ('context','evidence')),
 revision bigint NOT NULL CHECK (revision > 0), valid_until timestamptz NOT NULL,
 paused boolean NOT NULL DEFAULT false,
 byte_limit bigint NOT NULL CHECK (byte_limit >= 0), object_limit bigint NOT NULL CHECK (object_limit >= 0),
 charged_bytes bigint NOT NULL DEFAULT 0 CHECK (charged_bytes >= 0 AND charged_bytes <= byte_limit),
 charged_objects bigint NOT NULL DEFAULT 0 CHECK (charged_objects >= 0 AND charged_objects <= object_limit),
 UNIQUE (pool_id, scope_id, service_class)
);
CREATE TABLE custody_attempt (
 id uuid PRIMARY KEY, cluster_id uuid NOT NULL, artifact_id uuid NOT NULL UNIQUE,
 allocation_id uuid NOT NULL REFERENCES custody_allocation(id),
 request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
 pool_revision bigint NOT NULL, allocation_revision bigint NOT NULL,
 native_limit bigint NOT NULL CHECK (native_limit BETWEEN 0 AND 8388608),
 reserved_bytes bigint NOT NULL CHECK (reserved_bytes > 0),
 anchor_at timestamptz NOT NULL, write_until timestamptz NOT NULL, expires_at timestamptz NOT NULL, delete_by timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','stored_unpublished','deleting','deleted')),
 copies_digest bytea CHECK (octet_length(copies_digest)=32),
 deletion_fence bigint NOT NULL DEFAULT 0 CHECK (deletion_fence >= 0),
 lease_until timestamptz, deleted_at timestamptz,
 CHECK (anchor_at < write_until AND write_until <= expires_at AND expires_at < delete_by),
 CHECK ((state = 'deleted') = (deleted_at IS NOT NULL))
);
CREATE INDEX custody_due ON custody_attempt(expires_at,id) WHERE state <> 'deleted';
CREATE INDEX custody_overdue ON custody_attempt(allocation_id,delete_by) WHERE state <> 'deleted';
CREATE TABLE custody_copy (
 attempt_id uuid NOT NULL REFERENCES custody_attempt(id),
 role smallint NOT NULL CHECK (role BETWEEN 0 AND 3),
 byte_limit bigint NOT NULL CHECK (byte_limit > 0),
 ciphertext_bytes bigint CHECK (ciphertext_bytes > 0 AND ciphertext_bytes <= byte_limit),
 ciphertext_sha256 bytea CHECK (octet_length(ciphertext_sha256)=32),
 etag text CHECK (octet_length(etag) BETWEEN 1 AND 1024),
 version_id text CHECK (octet_length(version_id) BETWEEN 1 AND 1024),
 PRIMARY KEY(attempt_id,role),
 CHECK ((ciphertext_bytes IS NULL) = (ciphertext_sha256 IS NULL)),
 CHECK ((ciphertext_bytes IS NULL) = (etag IS NULL))
);
-- This is a minimized transactional outbox, NOT an acknowledged object audit.
CREATE TABLE custody_event (
 attempt_id uuid NOT NULL REFERENCES custody_attempt(id),
 phase text NOT NULL CHECK (phase IN ('registered','stored','deleted')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(attempt_id,phase)
);

-- No down migration: dropping live charges/tombstones is not a rollback.
