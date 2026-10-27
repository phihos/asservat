-- +goose Up
-- ADR-255: encrypted parameter snapshots are private control data, not catalog
-- evidence. Payloads, selectors, filter literals and keysets never enter SQL.
CREATE TABLE capture_history_quota (
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 selector_key bytea NOT NULL CHECK(octet_length(selector_key)=32),
 used integer NOT NULL DEFAULT 0 CHECK(used>=0),
 PRIMARY KEY(root_id,selector_key)
);
CREATE TABLE capture_history_parameter (
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 capture_id uuid PRIMARY KEY REFERENCES context_capture(id),
 attempt_id uuid NOT NULL UNIQUE REFERENCES custody_attempt(id),
 selector_key bytea NOT NULL CHECK(octet_length(selector_key)=32),
 settings_key bytea NOT NULL CHECK(octet_length(settings_key)=32),
 mac_version text NOT NULL CHECK(octet_length(mac_version) BETWEEN 1 AND 64),
 expectation_json bytea NOT NULL CHECK(octet_length(expectation_json) BETWEEN 1 AND 8192),
 retention_json bytea NOT NULL CHECK(octet_length(retention_json) BETWEEN 1 AND 16384),
 summary_expires_at timestamptz NOT NULL,
 visible boolean NOT NULL DEFAULT true,
 state text NOT NULL DEFAULT 'reserved' CHECK(state IN('reserved','write_claimed','available','deleting','deleted')),
 write_id uuid, write_digest bytea CHECK(write_digest IS NULL OR octet_length(write_digest)=32),
 write_started_at timestamptz, write_until timestamptz, write_executor_epoch uuid,
 purge_completion_json bytea CHECK(purge_completion_json IS NULL OR octet_length(purge_completion_json) BETWEEN 1 AND 8192),
 delete_id uuid, delete_executor_epoch uuid, delete_started_at timestamptz, delete_until timestamptz, delete_fence bigint,
 writer_completion_json bytea CHECK(writer_completion_json IS NULL OR octet_length(writer_completion_json) BETWEEN 1 AND 8192),
 copies_digest bytea CHECK(copies_digest IS NULL OR octet_length(copies_digest)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(summary_expires_at>created_at AND summary_expires_at<=created_at+interval '3650 days'),
 CHECK((write_id IS NULL)=(write_digest IS NULL)),
 CHECK((write_id IS NULL)=(write_started_at IS NULL)),
 CHECK((write_id IS NULL)=(write_until IS NULL)),
 CHECK(write_until IS NULL OR (write_until>write_started_at AND write_until<=write_started_at+interval '30 seconds')),
 CHECK(state<>'available' OR (writer_completion_json IS NOT NULL AND copies_digest IS NOT NULL)),
 CHECK(state NOT IN('deleting','deleted') OR (write_id IS NULL OR writer_completion_json IS NOT NULL))
);
CREATE INDEX capture_history_parameter_selector ON capture_history_parameter(root_id,selector_key,created_at DESC,capture_id DESC) WHERE visible;
CREATE INDEX capture_history_parameter_retirement ON capture_history_parameter(root_id,summary_expires_at,capture_id);
-- Active-only indexes avoid scanning every retained available snapshot at idle.
CREATE INDEX capture_history_parameter_hidden ON capture_history_parameter(root_id,capture_id) WHERE NOT visible AND state IN('reserved','available','deleting');
CREATE INDEX capture_history_parameter_reserved ON capture_history_parameter(root_id,capture_id) INCLUDE(attempt_id) WHERE state='reserved';

-- Independently expiring lineage is not a foreign key or an access grant.
ALTER TABLE context_capture ADD COLUMN history_parameters_required boolean NOT NULL DEFAULT false;
ALTER TABLE context_capture ALTER COLUMN history_parameters_required SET DEFAULT true;
ALTER TABLE context_capture ADD COLUMN repeated_from_capture_id uuid;
ALTER TABLE context_capture ADD COLUMN repeated_from_expires_at timestamptz;
ALTER TABLE context_capture ADD CONSTRAINT context_capture_repeat_lineage CHECK((repeated_from_capture_id IS NULL)=(repeated_from_expires_at IS NULL));
CREATE OR REPLACE VIEW capture_operation_intents WITH(security_barrier=true) AS
SELECT c.* FROM public.context_capture c WHERE c.intent_operation_id=c.id AND public.capture_audit_role_ok(c.root_id,'reader');

-- +goose StatementBegin
CREATE FUNCTION guard_capture_history_parameter() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c public.context_capture;e jsonb;a public.custody_attempt;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=OLD.attempt_id;
  IF a.state<>'deleted' OR clock_timestamp()<OLD.summary_expires_at THEN RAISE EXCEPTION 'retained history obligation' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.root_id,NEW.capture_id,NEW.attempt_id,NEW.selector_key,NEW.settings_key,NEW.mac_version,NEW.expectation_json,NEW.retention_json,NEW.summary_expires_at,NEW.created_at)
   IS DISTINCT FROM ROW(OLD.root_id,OLD.capture_id,OLD.attempt_id,OLD.selector_key,OLD.settings_key,OLD.mac_version,OLD.expectation_json,OLD.retention_json,OLD.summary_expires_at,OLD.created_at) OR (NOT OLD.visible AND NEW.visible) OR
   (OLD.write_id IS NOT NULL AND ROW(NEW.write_id,NEW.write_digest,NEW.write_started_at,NEW.write_until,NEW.write_executor_epoch) IS DISTINCT FROM ROW(OLD.write_id,OLD.write_digest,OLD.write_started_at,OLD.write_until,OLD.write_executor_epoch)) OR
   (OLD.writer_completion_json IS NOT NULL AND ROW(NEW.writer_completion_json,NEW.copies_digest) IS DISTINCT FROM ROW(OLD.writer_completion_json,OLD.copies_digest)) THEN
    RAISE EXCEPTION 'immutable history parameters' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT c FROM public.context_capture WHERE id=NEW.capture_id;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 e:=convert_from(NEW.expectation_json,'UTF8')::jsonb;
 IF NEW.root_id<>c.root_id OR (e->>'RootID')::uuid<>c.root_id OR (e->>'CaptureID')::uuid<>c.id OR
   (e#>>'{Registration,Location,AttemptID}')::uuid<>a.id OR (e#>>'{Registration,Location,ArtifactID}')::uuid<>a.artifact_id OR
   (e#>>'{Registration,Location,ClusterID}')::uuid<>a.cluster_id OR (e#>>'{Registration,AllocationID}')::uuid<>a.allocation_id OR a.native_limit<>131072 OR
   public.connector_digest(e->'OriginalExecutionDigest')<>c.scope_digest OR
   (e#>>'{Registration,StoreID}')::uuid<>(SELECT p.store_id FROM public.custody_pool p JOIN public.custody_allocation x ON x.pool_id=p.id WHERE x.id=a.allocation_id) OR
   (e#>>'{Registration,PoolRevision}')::bigint<>a.pool_revision OR (e#>>'{Registration,AllocationRevision}')::bigint<>a.allocation_revision OR
   (e#>>'{Registration,AnchorAt}')::timestamptz<>a.anchor_at OR (e#>>'{Registration,WriteUntil}')::timestamptz<>a.write_until OR
   (e#>>'{Registration,ExpiresAt}')::timestamptz<>a.expires_at OR (e#>>'{Registration,DeleteBy}')::timestamptz<>a.delete_by OR
   a.allocation_id<>(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,AllocationID}')::uuid OR
   a.cluster_id<>c.history_cluster_id OR NEW.summary_expires_at>c.created_at+interval '3650 days' THEN
  RAISE EXCEPTION 'history parameter scope changed' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_history_custody_settlement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE h public.capture_history_parameter;
BEGIN
 SELECT * INTO h FROM public.capture_history_parameter WHERE attempt_id=OLD.id;
 IF NOT FOUND THEN RETURN NEW;END IF;
 -- Ordinary evidence cleanup must not certify absence under v1/ while these
 -- objects live under history/v1/. Only typed physical purge can settle them.
 IF NEW.state='deleting' AND (h.state<>'deleting' OR h.delete_fence IS DISTINCT FROM NEW.deletion_fence OR h.delete_until IS DISTINCT FROM NEW.lease_until) THEN
  RAISE EXCEPTION 'history deletion claim not bound' USING ERRCODE='23514';END IF;
 IF NEW.state='deleted' AND OLD.state<>'deleted' AND (h.state<>'deleting' OR h.purge_completion_json IS NULL) THEN
  RAISE EXCEPTION 'history physical purge not acknowledged' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_capture_repeat_lineage() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' AND ROW(NEW.repeated_from_capture_id,NEW.repeated_from_expires_at) IS DISTINCT FROM ROW(OLD.repeated_from_capture_id,OLD.repeated_from_expires_at) THEN
  RAISE EXCEPTION 'immutable repeat lineage' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' AND NEW.repeated_from_capture_id IS NOT NULL THEN
  IF NEW.repeated_from_capture_id=NEW.id OR clock_timestamp()>=NEW.repeated_from_expires_at THEN RAISE EXCEPTION 'invalid repeat lineage' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_capture_history_parameter(),guard_capture_repeat_lineage(),guard_history_custody_settlement() FROM PUBLIC;
CREATE TRIGGER capture_history_parameter_guard BEFORE INSERT OR UPDATE OR DELETE ON capture_history_parameter FOR EACH ROW EXECUTE FUNCTION guard_capture_history_parameter();
CREATE TRIGGER capture_repeat_lineage_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_capture_repeat_lineage();
-- No destructive rollback: independent ciphertext/deletion obligations remain.

CREATE TRIGGER history_custody_settlement_guard BEFORE UPDATE ON custody_attempt FOR EACH ROW EXECUTE FUNCTION guard_history_custody_settlement();
