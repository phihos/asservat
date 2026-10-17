-- +goose Up
-- Runtime enrollment projection, not a second configuration API. Producers
-- must complete current bootstrap, audit and certificate issuance before they
-- may activate these rows. No enrollment writer is enabled by this migration.
CREATE TABLE fleet_trust (
 installation_id uuid PRIMARY KEY,
 issuer_epoch uuid NOT NULL,
 source_uid text NOT NULL CHECK(octet_length(source_uid) BETWEEN 1 AND 64),
 source_generation bigint NOT NULL CHECK(source_generation BETWEEN 1 AND 2147483647),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 suspended boolean NOT NULL DEFAULT true,
 recovery_blocked boolean NOT NULL DEFAULT true,
 observed_at timestamptz NOT NULL,
 fresh_until timestamptz NOT NULL,
 CHECK(fresh_until>observed_at AND fresh_until<=observed_at+interval '30 seconds')
);
CREATE TABLE fleet_peer (
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 peer_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 issuer_epoch uuid NOT NULL,
 role text NOT NULL CHECK(role='connector'),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
 enabled boolean NOT NULL DEFAULT false,
 not_after timestamptz NOT NULL,
 -- Exact verified enrollment audit receipt; absence always denies. The future
 -- enrollment/audit transaction owns publication of this receipt and enabled.
 audit_id uuid,
 audit_object_key text CHECK(octet_length(audit_object_key) BETWEEN 1 AND 1024),
 audit_object_version text CHECK(octet_length(audit_object_version) BETWEEN 1 AND 1024),
 audit_object_sha256 bytea CHECK(octet_length(audit_object_sha256)=32),
 CHECK((audit_id IS NULL)=(audit_object_key IS NULL)),
 CHECK((audit_id IS NULL)=(audit_object_version IS NULL)),
 CHECK((audit_id IS NULL)=(audit_object_sha256 IS NULL)),
 CHECK(NOT enabled OR audit_id IS NOT NULL),
 PRIMARY KEY(installation_id,peer_id)
);
CREATE TABLE fleet_peer_certificate (
 installation_id uuid NOT NULL,
 peer_id uuid NOT NULL,
 slot smallint NOT NULL CHECK(slot IN (0,1)),
 certificate_sha256 bytea NOT NULL CHECK(octet_length(certificate_sha256)=32),
 not_before timestamptz NOT NULL,
 not_after timestamptz NOT NULL,
 CHECK(not_after>not_before AND not_after<=not_before+interval '1 hour'),
 PRIMARY KEY(installation_id,peer_id,slot),
 UNIQUE(installation_id,certificate_sha256),
 FOREIGN KEY(installation_id,peer_id) REFERENCES fleet_peer(installation_id,peer_id)
);
-- No destructive down: enrollment/certificate history requires reviewed
-- retirement. This schema only supplies current two-slot registration reads.
