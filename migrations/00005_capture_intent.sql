-- +goose Up
-- Receipt of an independently verified encrypted intent; no execution permit.
ALTER TABLE context_capture DROP CONSTRAINT context_capture_state_check;
ALTER TABLE context_capture ADD CONSTRAINT context_capture_state_check CHECK(state IN ('accepted_pending_audit','intent_audited'));
ALTER TABLE context_capture ADD COLUMN intent_acknowledged_at timestamptz;
ALTER TABLE context_capture ADD COLUMN intent_digest bytea;
ALTER TABLE context_capture ADD COLUMN intent_object_key text;
ALTER TABLE context_capture ADD COLUMN intent_object_version text;
ALTER TABLE context_capture ADD COLUMN intent_object_etag text;
ALTER TABLE context_capture ADD COLUMN intent_object_bytes bigint;
ALTER TABLE context_capture ADD COLUMN intent_object_sha256 bytea;
ALTER TABLE context_capture ADD CONSTRAINT context_intent_receipt_complete CHECK (
 (intent_acknowledged_at IS NULL)=(state='accepted_pending_audit') AND
 (intent_acknowledged_at IS NULL)=(intent_digest IS NULL) AND
 (intent_acknowledged_at IS NULL)=(intent_object_key IS NULL) AND
 (intent_acknowledged_at IS NULL)=(intent_object_version IS NULL) AND
 (intent_acknowledged_at IS NULL)=(intent_object_etag IS NULL) AND
 (intent_acknowledged_at IS NULL)=(intent_object_bytes IS NULL) AND
 (intent_acknowledged_at IS NULL)=(intent_object_sha256 IS NULL) AND
 (intent_digest IS NULL OR octet_length(intent_digest)=32) AND
 (intent_object_key IS NULL OR octet_length(intent_object_key) BETWEEN 1 AND 256) AND
 (intent_object_version IS NULL OR octet_length(intent_object_version)<=1024) AND
 (intent_object_etag IS NULL OR octet_length(intent_object_etag) BETWEEN 1 AND 256) AND
 (intent_object_bytes IS NULL OR intent_object_bytes BETWEEN 1 AND 131072) AND
 (intent_object_sha256 IS NULL OR octet_length(intent_object_sha256)=32)
);
CREATE INDEX context_intent_pending ON context_capture(root_id,created_at,id) WHERE state='accepted_pending_audit';
