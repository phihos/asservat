-- +goose Up
-- Accepted configuration only. Kubernetes remains the authoring authority.
CREATE TABLE permission_stream (
 id uuid PRIMARY KEY, epoch uuid NOT NULL, sequence bigint NOT NULL DEFAULT 0 CHECK(sequence>=0),
 trust_digest bytea NOT NULL CHECK(octet_length(trust_digest)=32),
 projection_digest bytea CHECK(octet_length(projection_digest)=32),
 lease_until timestamptz NOT NULL,
 observed_at timestamptz, fresh_until timestamptz,
 suspended boolean NOT NULL DEFAULT true,
 CHECK ((observed_at IS NULL)=(fresh_until IS NULL)),
 CHECK (fresh_until IS NULL OR (fresh_until>observed_at AND fresh_until<=observed_at+interval '5 seconds'))
);
CREATE TABLE permission_basis (
 stream_id uuid NOT NULL REFERENCES permission_stream(id), basis_key text NOT NULL CHECK(octet_length(basis_key) BETWEEN 1 AND 256),
 uid text NOT NULL CHECK(octet_length(uid) BETWEEN 1 AND 64),
 kind text NOT NULL CHECK(kind IN ('AccessBinding','PermissionSource')),
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 2147483647), resource_version text NOT NULL CHECK(octet_length(resource_version) BETWEEN 1 AND 128),
 observation_version text NOT NULL CHECK(octet_length(observation_version)<=128),
 spec_digest bytea NOT NULL CHECK(octet_length(spec_digest)=32), scope_digest bytea NOT NULL CHECK(octet_length(scope_digest)=32),
 cluster_id uuid NOT NULL, namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_uids text[] NOT NULL CHECK(cardinality(workload_uids)<=64),
 effect text NOT NULL CHECK(effect IN ('Allow','Deny')), not_after timestamptz,
 seen_sequence bigint NOT NULL CHECK(seen_sequence>0),
 PRIMARY KEY(stream_id,basis_key)
);
CREATE TABLE permission_assignment (
 id uuid PRIMARY KEY, stream_id uuid NOT NULL, basis_key text NOT NULL,
 subject_kind text NOT NULL CHECK(subject_kind IN ('User','Group','Workload')),
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048), subject_id text NOT NULL CHECK(octet_length(subject_id) BETWEEN 1 AND 256),
 role text NOT NULL CHECK(role IN ('workload-maintainer','evidence-reader','evidence-owner','action-approver')),
 basis_digest bytea NOT NULL CHECK(octet_length(basis_digest)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), retired_at timestamptz,
 activation_audit_id uuid NOT NULL,
 retirement_audit_id uuid,
 CHECK ((retired_at IS NULL)=(retirement_audit_id IS NULL)),
 FOREIGN KEY(stream_id,basis_key) REFERENCES permission_basis(stream_id,basis_key)
);
CREATE UNIQUE INDEX permission_current_assignment ON permission_assignment(stream_id,basis_key,subject_kind,issuer,subject_id,role) WHERE retired_at IS NULL;
CREATE INDEX permission_scope ON permission_basis(cluster_id,namespace_uid,stream_id);
CREATE TABLE permission_acceptance (
 request_id uuid PRIMARY KEY, stream_id uuid NOT NULL REFERENCES permission_stream(id), epoch uuid NOT NULL,
 sequence bigint NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 audit_id uuid NOT NULL, assignments integer NOT NULL, retired integer NOT NULL,
 UNIQUE(stream_id,epoch,sequence)
);
-- Scope changes are audit-gated; denial and retirement are immediate.
CREATE TABLE authority_audit (
 id uuid PRIMARY KEY, stream_id uuid NOT NULL REFERENCES permission_stream(id), epoch uuid NOT NULL,
 sequence bigint NOT NULL, event_kind text NOT NULL CHECK(event_kind IN ('permission-reset','permission-change','permission-suspend')),
 event_digest bytea NOT NULL CHECK(octet_length(event_digest)=32), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 record jsonb NOT NULL CHECK(octet_length(record::text)<=12582912),
 acknowledged_at timestamptz,
 object_key text, object_version text, object_etag text, object_bytes bigint, object_sha256 bytea,
 CHECK ((acknowledged_at IS NULL)=(object_key IS NULL)),
 CHECK ((acknowledged_at IS NULL)=(object_version IS NULL)),
 CHECK ((acknowledged_at IS NULL)=(object_etag IS NULL)),
 CHECK ((acknowledged_at IS NULL)=(object_bytes IS NULL)),
 CHECK ((acknowledged_at IS NULL)=(object_sha256 IS NULL)),
 CHECK (object_key IS NULL OR octet_length(object_key) BETWEEN 1 AND 256),
 CHECK (object_version IS NULL OR octet_length(object_version)<=1024),
 CHECK (object_etag IS NULL OR octet_length(object_etag) BETWEEN 1 AND 256),
 CHECK (object_sha256 IS NULL OR octet_length(object_sha256)=32),
 CHECK (object_bytes IS NULL OR object_bytes BETWEEN 1 AND 16777216)
);
CREATE INDEX authority_audit_pending ON authority_audit(created_at,id) WHERE acknowledged_at IS NULL;
ALTER TABLE permission_assignment ADD CONSTRAINT permission_activation_audit
 FOREIGN KEY(activation_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE permission_assignment ADD CONSTRAINT permission_retirement_audit
 FOREIGN KEY(retirement_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE permission_acceptance ADD CONSTRAINT permission_acceptance_audit
 FOREIGN KEY(audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
-- No destructive down: retired assignment IDs and acknowledged audits are needed
-- to prevent historical audiences from being resurrected after configuration loss.
