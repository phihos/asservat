-- +goose Up
-- Durable ordered configuration obligations. This migration intentionally has
-- no source-ready mutation: audit acknowledgement alone is never catch-up.
CREATE TABLE retention_source (
 root_id uuid NOT NULL REFERENCES permission_stream(id), cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 hub boolean NOT NULL, protection_digest bytea NOT NULL CHECK(octet_length(protection_digest)=32),
 epoch uuid NOT NULL, sequence bigint NOT NULL DEFAULT 0 CHECK(sequence BETWEEN 0 AND 2147483647),
 lease_until timestamptz NOT NULL, suspended boolean NOT NULL DEFAULT true,
 recovery_blocked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(root_id,cluster_id,namespace_uid)
);
CREATE TABLE retention_checkpoint (
 id uuid PRIMARY KEY, root_id uuid NOT NULL, cluster_id uuid NOT NULL, namespace_uid text NOT NULL,
 epoch uuid NOT NULL, sequence bigint NOT NULL CHECK(sequence BETWEEN 1 AND 2147483647),
 transition_digest bytea NOT NULL CHECK(octet_length(transition_digest)=32),
 transition_json jsonb NOT NULL CHECK(octet_length(transition_json::text)<=12582912),
 record_digest bytea NOT NULL CHECK(octet_length(record_digest)=32),
 record_json jsonb NOT NULL CHECK(octet_length(record_json::text)<=393216),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 audit_acknowledged_at timestamptz, audit_receipt jsonb CHECK(octet_length(audit_receipt::text)<=4096),
 CHECK ((audit_acknowledged_at IS NULL)=(audit_receipt IS NULL)),
 FOREIGN KEY(root_id,cluster_id,namespace_uid) REFERENCES retention_source(root_id,cluster_id,namespace_uid),
 UNIQUE(root_id,cluster_id,namespace_uid,sequence)
);
CREATE TABLE retention_source_epoch (
 root_id uuid NOT NULL, cluster_id uuid NOT NULL, namespace_uid text NOT NULL, epoch uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(root_id,cluster_id,namespace_uid,epoch),
 FOREIGN KEY(root_id,cluster_id,namespace_uid) REFERENCES retention_source(root_id,cluster_id,namespace_uid)
);
CREATE INDEX retention_checkpoint_pending ON retention_checkpoint(root_id,created_at,id) WHERE audit_acknowledged_at IS NULL;
-- +goose StatementBegin
CREATE FUNCTION retention_checkpoint_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.root_id,NEW.cluster_id,NEW.namespace_uid,NEW.epoch,NEW.sequence,NEW.transition_digest,NEW.transition_json,NEW.record_digest,NEW.record_json,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.cluster_id,OLD.namespace_uid,OLD.epoch,OLD.sequence,OLD.transition_digest,OLD.transition_json,OLD.record_digest,OLD.record_json,OLD.created_at)
 OR (OLD.audit_acknowledged_at IS NOT NULL AND ROW(NEW.audit_acknowledged_at,NEW.audit_receipt) IS DISTINCT FROM ROW(OLD.audit_acknowledged_at,OLD.audit_receipt)) THEN
 RAISE EXCEPTION 'retention checkpoint is immutable';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER retention_checkpoint_immutable BEFORE UPDATE ON retention_checkpoint FOR EACH ROW EXECUTE FUNCTION retention_checkpoint_immutable();
-- +goose StatementBegin
CREATE FUNCTION retention_source_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.root_id,NEW.cluster_id,NEW.namespace_uid,NEW.hub,NEW.protection_digest) IS DISTINCT FROM ROW(OLD.root_id,OLD.cluster_id,OLD.namespace_uid,OLD.hub,OLD.protection_digest)
 OR NEW.sequence<OLD.sequence OR NEW.sequence>OLD.sequence+1 THEN
 RAISE EXCEPTION 'retention source identity or sequence changed';
 END IF;
 IF NEW.sequence<>OLD.sequence AND NOT EXISTS(SELECT 1 FROM retention_checkpoint c WHERE c.root_id=NEW.root_id AND c.cluster_id=NEW.cluster_id AND c.namespace_uid=NEW.namespace_uid AND c.sequence=NEW.sequence AND c.epoch=NEW.epoch) THEN
 RAISE EXCEPTION 'retention source lacks exact checkpoint';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER retention_source_monotonic BEFORE UPDATE ON retention_source FOR EACH ROW EXECUTE FUNCTION retention_source_monotonic();
-- No destructive down: prior shortening obligations must survive restart.
