-- +goose Up
CREATE TABLE hub_owner_configuration (
 installation_id uuid NOT NULL REFERENCES fleet_trust(installation_id),
 cluster_id uuid NOT NULL,
 source_uid uuid NOT NULL,
 generation bigint NOT NULL DEFAULT 0 CHECK(generation BETWEEN 0 AND 2147483647),
 observed_at timestamptz NOT NULL,
 fresh_until timestamptz NOT NULL CHECK(fresh_until<=observed_at+interval '5 seconds'),
 PRIMARY KEY(installation_id,cluster_id),
 UNIQUE(installation_id,cluster_id,source_uid)
);
CREATE TABLE hub_owner_configuration_revision (
 installation_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 source_uid uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 2147483647),
 snapshot_json bytea NOT NULL CHECK(octet_length(snapshot_json) BETWEEN 1 AND 65536),
 audit_receipt_json bytea CHECK(octet_length(audit_receipt_json) BETWEEN 1 AND 8192),
 PRIMARY KEY(installation_id,cluster_id,source_uid,generation),
 FOREIGN KEY(installation_id,cluster_id,source_uid) REFERENCES hub_owner_configuration(installation_id,cluster_id,source_uid)
);
-- +goose StatementBegin
CREATE FUNCTION guard_owner_configuration_head() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.observed_at>clock_timestamp() THEN
  RAISE EXCEPTION 'owner configuration observation cannot be in the future';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.generation<>0 OR NEW.fresh_until>NEW.observed_at THEN
   RAISE EXCEPTION 'owner configuration starts unavailable';
  END IF;
 ELSE
  IF ROW(NEW.installation_id,NEW.cluster_id,NEW.source_uid) IS DISTINCT FROM ROW(OLD.installation_id,OLD.cluster_id,OLD.source_uid)
  OR NEW.generation<OLD.generation OR NEW.observed_at<OLD.observed_at
  OR (NEW.observed_at=OLD.observed_at AND NEW.fresh_until>OLD.fresh_until) THEN
   RAISE EXCEPTION 'owner configuration identity, revision and original deadline cannot roll back or renew';
  END IF;
  IF NEW.generation>OLD.generation AND NOT EXISTS (
   SELECT FROM hub_owner_configuration_revision WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id AND source_uid=NEW.source_uid AND generation=NEW.generation
  ) THEN
   RAISE EXCEPTION 'owner configuration revision must be recorded first';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER owner_configuration_head_guard BEFORE INSERT OR UPDATE ON hub_owner_configuration FOR EACH ROW EXECUTE FUNCTION guard_owner_configuration_head();
-- +goose StatementBegin
CREATE FUNCTION guard_owner_configuration_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM 1 FROM hub_owner_configuration WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id AND source_uid=NEW.source_uid FOR UPDATE;
  IF NOT FOUND OR NEW.audit_receipt_json IS NOT NULL OR (
   SELECT count(*) FROM hub_owner_configuration_revision WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id AND source_uid=NEW.source_uid
  )>=1024 THEN
   RAISE EXCEPTION 'owner configuration revision capacity or initial state invalid';
  END IF;
 ELSE
  IF ROW(NEW.installation_id,NEW.cluster_id,NEW.source_uid,NEW.generation,NEW.snapshot_json)
  IS DISTINCT FROM ROW(OLD.installation_id,OLD.cluster_id,OLD.source_uid,OLD.generation,OLD.snapshot_json)
  OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json) THEN
   RAISE EXCEPTION 'owner configuration revision and audit are immutable';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER owner_configuration_revision_guard BEFORE INSERT OR UPDATE ON hub_owner_configuration_revision FOR EACH ROW EXECUTE FUNCTION guard_owner_configuration_revision();
-- No destructive down: source pins and rollback/failure history cannot be reset.
