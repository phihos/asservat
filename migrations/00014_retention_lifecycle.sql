-- +goose Up
-- Original custody dates are cryptographic provenance. These columns are a
-- separate monotonic overlay and never authorize acquisition or disclosure.
ALTER TABLE custody_attempt ADD COLUMN effective_expires_at timestamptz;
ALTER TABLE custody_attempt ADD COLUMN effective_delete_by timestamptz;
ALTER TABLE custody_attempt ADD COLUMN retention_sequence bigint NOT NULL DEFAULT 0 CHECK(retention_sequence>=0);
UPDATE custody_attempt SET effective_expires_at=expires_at,effective_delete_by=delete_by;
ALTER TABLE custody_attempt ALTER COLUMN effective_expires_at SET NOT NULL;
ALTER TABLE custody_attempt ALTER COLUMN effective_delete_by SET NOT NULL;
ALTER TABLE custody_attempt ADD CONSTRAINT custody_retention_bounds CHECK(anchor_at<effective_expires_at AND effective_expires_at<effective_delete_by AND effective_expires_at<=expires_at AND effective_delete_by<=delete_by);
CREATE INDEX custody_effective_due ON custody_attempt(effective_expires_at,id) WHERE state<>'deleted';
CREATE INDEX custody_effective_overdue ON custody_attempt(allocation_id,effective_delete_by) WHERE state<>'deleted';

CREATE TABLE retention_decision (
 id uuid PRIMARY KEY,root_id uuid NOT NULL REFERENCES permission_stream(id),
 attempt_id uuid NOT NULL REFERENCES custody_attempt(id),sequence bigint NOT NULL CHECK(sequence>0),
 previous_expires_at timestamptz NOT NULL,previous_delete_by timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,delete_by timestamptz NOT NULL,
 decision_digest bytea NOT NULL CHECK(octet_length(decision_digest)=32),
 decision_json bytea NOT NULL CHECK(octet_length(decision_json) BETWEEN 1 AND 32768),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 audit_acknowledged_at timestamptz,audit_receipt_json bytea CHECK(octet_length(audit_receipt_json) BETWEEN 1 AND 4096),
 UNIQUE(attempt_id,sequence),
 CHECK(expires_at<delete_by AND expires_at<=previous_expires_at AND delete_by<=previous_delete_by AND (expires_at<previous_expires_at OR delete_by<previous_delete_by)),
 CHECK((audit_acknowledged_at IS NULL)=(audit_receipt_json IS NULL))
);
CREATE INDEX retention_pending_audit ON retention_decision(root_id,recorded_at,id) WHERE audit_acknowledged_at IS NULL;
-- +goose StatementBegin
CREATE FUNCTION protect_custody_retention() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.retention_sequence<>0 OR (NEW.effective_expires_at IS NOT NULL AND NEW.effective_expires_at<>NEW.expires_at) OR (NEW.effective_delete_by IS NOT NULL AND NEW.effective_delete_by<>NEW.delete_by) THEN RAISE EXCEPTION 'initial retention must match registration'; END IF;
  NEW.effective_expires_at:=NEW.expires_at;NEW.effective_delete_by:=NEW.delete_by;RETURN NEW;
 END IF;
 IF (NEW.id,NEW.cluster_id,NEW.artifact_id,NEW.allocation_id,NEW.request_digest,NEW.pool_revision,NEW.allocation_revision,NEW.native_limit,NEW.reserved_bytes,NEW.anchor_at,NEW.write_until,NEW.expires_at,NEW.delete_by) IS DISTINCT FROM
 (OLD.id,OLD.cluster_id,OLD.artifact_id,OLD.allocation_id,OLD.request_digest,OLD.pool_revision,OLD.allocation_revision,OLD.native_limit,OLD.reserved_bytes,OLD.anchor_at,OLD.write_until,OLD.expires_at,OLD.delete_by) THEN RAISE EXCEPTION 'immutable custody registration'; END IF;
 IF (NEW.retention_sequence,NEW.effective_expires_at,NEW.effective_delete_by) IS DISTINCT FROM (OLD.retention_sequence,OLD.effective_expires_at,OLD.effective_delete_by) THEN
  IF NEW.retention_sequence<>OLD.retention_sequence+1 OR NEW.effective_expires_at>OLD.effective_expires_at OR NEW.effective_delete_by>OLD.effective_delete_by OR NOT EXISTS(SELECT 1 FROM retention_decision d WHERE d.attempt_id=OLD.id AND d.sequence=NEW.retention_sequence AND d.previous_expires_at=OLD.effective_expires_at AND d.previous_delete_by=OLD.effective_delete_by AND d.expires_at=NEW.effective_expires_at AND d.delete_by=NEW.effective_delete_by) THEN RAISE EXCEPTION 'retention decision mismatch'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER custody_retention_immutable BEFORE INSERT OR UPDATE ON custody_attempt FOR EACH ROW EXECUTE FUNCTION protect_custody_retention();
CREATE FUNCTION protect_retention_decision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.id,NEW.root_id,NEW.attempt_id,NEW.sequence,NEW.previous_expires_at,NEW.previous_delete_by,NEW.expires_at,NEW.delete_by,NEW.decision_digest,NEW.decision_json,NEW.recorded_at) IS DISTINCT FROM
 (OLD.id,OLD.root_id,OLD.attempt_id,OLD.sequence,OLD.previous_expires_at,OLD.previous_delete_by,OLD.expires_at,OLD.delete_by,OLD.decision_digest,OLD.decision_json,OLD.recorded_at) OR
 (OLD.audit_acknowledged_at IS NOT NULL AND (NEW.audit_acknowledged_at,NEW.audit_receipt_json) IS DISTINCT FROM (OLD.audit_acknowledged_at,OLD.audit_receipt_json)) THEN RAISE EXCEPTION 'immutable retention journal';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER retention_decision_immutable BEFORE UPDATE ON retention_decision FOR EACH ROW EXECUTE FUNCTION protect_retention_decision();
-- +goose StatementEnd
-- No down migration may restore older access dates or drop outstanding cleanup.
