-- +goose Up
-- Accepted Kubernetes configuration, never a second authoring surface.
ALTER TABLE permission_basis ADD COLUMN automation_json jsonb;
ALTER TABLE permission_basis ADD COLUMN automation_audit_id uuid REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE permission_basis ADD CONSTRAINT automation_envelope_complete CHECK (
 (automation_json IS NULL)=(automation_audit_id IS NULL) AND
 (automation_json IS NULL OR (kind='AccessBinding' AND effect='Allow' AND jsonb_typeof(automation_json)='object' AND octet_length(automation_json::text)<=4096))
);
-- Existing rows do not gain automation. A protected current acceptance must
-- retain the envelope and independently acknowledge its immutable audit.
UPDATE permission_stream SET suspended=true, observed_at=NULL, fresh_until=NULL;

-- Policy intent remains Kubernetes-authored; these are protected observations
-- and immutable accepted authority facts, never recipes or personal credentials.
CREATE TABLE policy_source (
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 policy_uid text NOT NULL CHECK (octet_length(policy_uid) BETWEEN 1 AND 64),
 installation_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK (octet_length(namespace_uid) BETWEEN 1 AND 64),
 name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 253),
 generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 2147483647),
 spec_digest bytea NOT NULL CHECK (octet_length(spec_digest)=32),
 resource_version text NOT NULL CHECK (octet_length(resource_version) BETWEEN 1 AND 128),
 observed_at timestamptz NOT NULL,
 fresh_until timestamptz NOT NULL,
 deleted boolean NOT NULL,
 suspended boolean NOT NULL,
 collection_digest bytea NOT NULL CHECK (octet_length(collection_digest)=32),
 intent_version bigint NOT NULL DEFAULT 1 CHECK (intent_version>0),
 active_id uuid,
 creator_json jsonb CHECK (creator_json IS NULL OR (jsonb_typeof(creator_json)='object' AND octet_length(creator_json::text)<=8192)),
 PRIMARY KEY(root_id,policy_uid),
 CHECK (fresh_until>observed_at AND fresh_until<=observed_at+interval '5 seconds')
);
CREATE TABLE policy_acceptance (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL,
 policy_uid text NOT NULL,
 generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 2147483647),
 nonce uuid NOT NULL,
 scope_digest bytea NOT NULL CHECK (octet_length(scope_digest)=32),
 request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
 record_digest bytea NOT NULL CHECK (octet_length(record_digest)=32),
 record jsonb NOT NULL CHECK (jsonb_typeof(record)='object' AND octet_length(record::text)<=65536),
 accepted_at timestamptz NOT NULL,
 acknowledged_at timestamptz,
 receipt_json jsonb,
 FOREIGN KEY(root_id,policy_uid) REFERENCES policy_source(root_id,policy_uid),
 UNIQUE(root_id,nonce),
 UNIQUE(root_id,policy_uid,scope_digest),
 CHECK ((acknowledged_at IS NULL)=(receipt_json IS NULL)),
 CHECK (receipt_json IS NULL OR (jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=4096))
);
ALTER TABLE policy_source ADD CONSTRAINT policy_active_record FOREIGN KEY(active_id) REFERENCES policy_acceptance(id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX policy_acceptance_pending ON policy_acceptance(root_id,accepted_at,id) WHERE acknowledged_at IS NULL;
-- No destructive down: tombstones/nonces must outlive the signed submissions;
-- accepting the same generation again must never reset its scope or budgets.
