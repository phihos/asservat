-- +goose Up
-- Minimized download control/accounting. No native hash, filename or body.
CREATE TABLE download_allocation (
 id uuid PRIMARY KEY, root_id uuid NOT NULL REFERENCES permission_stream(id),
 cluster_id uuid NOT NULL, namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_uid text NOT NULL CHECK(octet_length(workload_uid) BETWEEN 1 AND 64),
 output_limit bigint NOT NULL CHECK(output_limit BETWEEN 1 AND 17592186044416),
 read_limit bigint NOT NULL CHECK(read_limit BETWEEN 1 AND 70368744177664),
 session_limit bigint NOT NULL CHECK(session_limit BETWEEN 1 AND 100000),
 reserved_output bigint NOT NULL DEFAULT 0 CHECK(reserved_output>=0 AND reserved_output<=output_limit),
 reserved_read bigint NOT NULL DEFAULT 0 CHECK(reserved_read>=0 AND reserved_read<=read_limit),
 reserved_sessions bigint NOT NULL DEFAULT 0 CHECK(reserved_sessions>=0 AND reserved_sessions<=session_limit),
 valid_until timestamptz NOT NULL,
 UNIQUE(id,root_id)
);
CREATE TABLE artifact_download (
 id uuid PRIMARY KEY, root_id uuid NOT NULL, allocation_id uuid NOT NULL,
 FOREIGN KEY(allocation_id,root_id) REFERENCES download_allocation(id,root_id),
 artifact_id uuid NOT NULL REFERENCES context_catalog(artifact_id),
 -- principal key excludes client; actor key includes it. These are control identities.
 principal_key bytea NOT NULL CHECK(octet_length(principal_key)=32),
 actor_key bytea NOT NULL CHECK(octet_length(actor_key)=32),
 idempotency_digest bytea NOT NULL CHECK(octet_length(idempotency_digest)=32),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 scope_json jsonb NOT NULL CHECK(jsonb_typeof(scope_json)='object' AND octet_length(scope_json::text)<=8192),
 state text NOT NULL DEFAULT 'Preparing' CHECK(state IN ('Preparing','Ready','Streaming','Interrupted','Completed','Cancelled','Expired','Denied','Failed')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), deadline timestamptz NOT NULL,
 output_limit bigint NOT NULL CHECK(output_limit BETWEEN 1 AND 17592186044416),
 read_limit bigint NOT NULL CHECK(read_limit BETWEEN 1 AND 70368744177664),
 request_limit bigint NOT NULL CHECK(request_limit BETWEEN 1 AND 1024),
 charged_output bigint NOT NULL DEFAULT 0 CHECK(charged_output>=0 AND charged_output<=output_limit),
 charged_read bigint NOT NULL DEFAULT 0 CHECK(charged_read>=0 AND charged_read<=read_limit),
 requests bigint NOT NULL DEFAULT 0 CHECK(requests>=0 AND requests<=request_limit),
 emitted_bytes bigint NOT NULL DEFAULT 0 CHECK(emitted_bytes>=0 AND emitted_bytes<=charged_output),
 generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),
 active_batch uuid,
 CHECK(deadline>created_at AND deadline<=created_at+interval '8 hours'),
 UNIQUE(root_id,actor_key,idempotency_digest), UNIQUE(id,root_id)
);
CREATE INDEX download_principal_streams ON artifact_download(root_id,principal_key,state);
CREATE TABLE download_batch (
 id uuid PRIMARY KEY, session_id uuid NOT NULL REFERENCES artifact_download(id),
 generation bigint NOT NULL CHECK(generation>0),
 intent_json jsonb NOT NULL CHECK(jsonb_typeof(intent_json)='object' AND octet_length(intent_json::text)<=16384),
 lease_until timestamptz NOT NULL,
 audit_acknowledged_at timestamptz, audit_receipt_json jsonb,
 outcome_json jsonb, outcome_acknowledged_at timestamptz, outcome_receipt_json jsonb,
 CHECK((audit_acknowledged_at IS NULL)=(audit_receipt_json IS NULL)),
 CHECK(audit_receipt_json IS NULL OR (jsonb_typeof(audit_receipt_json)='object' AND octet_length(audit_receipt_json::text)<=4096)),
 CHECK(outcome_json IS NULL OR (jsonb_typeof(outcome_json)='object' AND octet_length(outcome_json::text)<=24576)),
 CHECK((outcome_acknowledged_at IS NULL)=(outcome_receipt_json IS NULL)),
 CHECK(outcome_acknowledged_at IS NULL OR outcome_json IS NOT NULL),
 CHECK(outcome_receipt_json IS NULL OR (jsonb_typeof(outcome_receipt_json)='object' AND octet_length(outcome_receipt_json::text)<=4096)),
 UNIQUE(session_id,generation)
);
ALTER TABLE artifact_download ADD CONSTRAINT download_active_batch FOREIGN KEY(active_batch) REFERENCES download_batch(id);
CREATE INDEX download_active_leases ON download_batch(lease_until) WHERE outcome_json IS NULL;
-- +goose StatementBegin
CREATE FUNCTION protect_download_allocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['reserved_output','reserved_read','reserved_sessions']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['reserved_output','reserved_read','reserved_sessions']) OR NEW.reserved_output<OLD.reserved_output OR NEW.reserved_read<OLD.reserved_read OR NEW.reserved_sessions<OLD.reserved_sessions THEN
  RAISE EXCEPTION 'immutable download allocation; reservations cannot be refunded' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER download_allocation_immutable BEFORE UPDATE ON download_allocation FOR EACH ROW EXECUTE FUNCTION protect_download_allocation();
-- +goose StatementBegin
CREATE FUNCTION protect_download_session() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['state','charged_output','charged_read','requests','emitted_bytes','generation','active_batch']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','charged_output','charged_read','requests','emitted_bytes','generation','active_batch']) OR NEW.charged_output<OLD.charged_output OR NEW.charged_read<OLD.charged_read OR NEW.requests<OLD.requests OR NEW.emitted_bytes<OLD.emitted_bytes OR NEW.generation<OLD.generation THEN
  RAISE EXCEPTION 'immutable download session or decreasing spend' USING ERRCODE='23514';
 END IF;
 IF OLD.state IN ('Completed','Cancelled','Expired','Denied','Failed') AND NEW.state<>OLD.state THEN
  RAISE EXCEPTION 'terminal download session' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER download_session_immutable BEFORE UPDATE ON artifact_download FOR EACH ROW EXECUTE FUNCTION protect_download_session();
-- +goose StatementBegin
CREATE FUNCTION protect_download_batch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.session_id,NEW.generation,NEW.intent_json,NEW.lease_until) IS DISTINCT FROM ROW(OLD.id,OLD.session_id,OLD.generation,OLD.intent_json,OLD.lease_until) OR
 (OLD.audit_acknowledged_at IS NOT NULL AND ROW(NEW.audit_acknowledged_at,NEW.audit_receipt_json) IS DISTINCT FROM ROW(OLD.audit_acknowledged_at,OLD.audit_receipt_json)) OR
 (OLD.outcome_json IS NOT NULL AND NEW.outcome_json IS DISTINCT FROM OLD.outcome_json) OR
 (OLD.outcome_acknowledged_at IS NOT NULL AND ROW(NEW.outcome_acknowledged_at,NEW.outcome_receipt_json) IS DISTINCT FROM ROW(OLD.outcome_acknowledged_at,OLD.outcome_receipt_json)) THEN
  RAISE EXCEPTION 'immutable download batch or receipt' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER download_batch_immutable BEFORE UPDATE ON download_batch FOR EACH ROW EXECUTE FUNCTION protect_download_batch();
