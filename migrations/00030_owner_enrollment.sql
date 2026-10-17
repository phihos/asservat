-- +goose Up
CREATE TABLE hub_owner_enrollment (
 id uuid PRIMARY KEY,
 installation_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 issuer_epoch uuid NOT NULL,
 pod_uid uuid NOT NULL,
 process_epoch uuid NOT NULL,
 usage text NOT NULL CHECK(usage IN ('server','client')),
 enrollment_json bytea NOT NULL CHECK(octet_length(enrollment_json) BETWEEN 1 AND 16384),
 audit_receipt_json bytea CHECK(octet_length(audit_receipt_json) BETWEEN 1 AND 8192),
 created_at timestamptz NOT NULL,
 hold_until timestamptz NOT NULL,
 highest_epoch bigint NOT NULL DEFAULT -1 CHECK(highest_epoch>=-1),
 retired_at timestamptz,
 UNIQUE(installation_id,cluster_id,issuer_epoch,pod_uid,process_epoch,usage),
 FOREIGN KEY(installation_id,cluster_id) REFERENCES hub_owner_configuration(installation_id,cluster_id),
 CHECK(hold_until>created_at)
);
CREATE TABLE hub_owner_certificate (
 id uuid PRIMARY KEY,
 enrollment_id uuid NOT NULL REFERENCES hub_owner_enrollment(id),
 epoch bigint NOT NULL CHECK(epoch>=0),
 ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 2),
 not_after timestamptz NOT NULL,
 attempt_json bytea NOT NULL CHECK(octet_length(attempt_json) BETWEEN 1 AND 65536),
 certificate_json bytea CHECK(octet_length(certificate_json) BETWEEN 1 AND 65536),
 certificate_sha256 bytea UNIQUE CHECK(octet_length(certificate_sha256)=32),
 audit_receipt_json bytea CHECK(octet_length(audit_receipt_json) BETWEEN 1 AND 8192),
 activated_at timestamptz,
 CHECK((certificate_json IS NULL)=(certificate_sha256 IS NULL)),
 CHECK(audit_receipt_json IS NULL OR certificate_json IS NOT NULL),
 CHECK(activated_at IS NULL OR audit_receipt_json IS NOT NULL),
 UNIQUE(enrollment_id,epoch,ordinal)
);
-- +goose StatementBegin
CREATE FUNCTION guard_owner_enrollment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF clock_timestamp()<OLD.hold_until THEN
   RAISE EXCEPTION 'owner registration still holds possible live certificates';
  END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  PERFORM 1 FROM hub_owner_configuration WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id FOR UPDATE;
  IF NOT FOUND OR NEW.audit_receipt_json IS NOT NULL OR NEW.retired_at IS NOT NULL OR NEW.highest_epoch<>-1
  OR NEW.created_at>clock_timestamp() OR NEW.created_at<clock_timestamp()-interval '5 seconds'
  OR NEW.hold_until<>to_timestamp((floor((extract(epoch FROM NEW.created_at)+60)/1200)+1)*1200)+interval '1 minute'
  OR (SELECT count(*) FROM hub_owner_enrollment WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id)>=1024
  OR (SELECT count(*) FROM hub_owner_enrollment WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id AND pod_uid=NEW.pod_uid)>=32 THEN
   RAISE EXCEPTION 'owner registration capacity or initial state invalid';
  END IF;
 ELSE
  IF ROW(NEW.id,NEW.installation_id,NEW.cluster_id,NEW.issuer_epoch,NEW.pod_uid,NEW.process_epoch,NEW.usage,NEW.enrollment_json,NEW.created_at)
  IS DISTINCT FROM ROW(OLD.id,OLD.installation_id,OLD.cluster_id,OLD.issuer_epoch,OLD.pod_uid,OLD.process_epoch,OLD.usage,OLD.enrollment_json,OLD.created_at)
  OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json)
  OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at)
  OR NEW.highest_epoch<OLD.highest_epoch OR NEW.hold_until<OLD.hold_until
  OR (NEW.hold_until>OLD.hold_until AND (OLD.retired_at IS NOT NULL OR NEW.hold_until>clock_timestamp()+interval '22 minutes')) THEN
   RAISE EXCEPTION 'owner identity, audit, retirement and consumed periods are immutable';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER owner_enrollment_guard BEFORE INSERT OR UPDATE OR DELETE ON hub_owner_enrollment FOR EACH ROW EXECUTE FUNCTION guard_owner_enrollment();
-- +goose StatementBegin
CREATE FUNCTION guard_owner_certificate() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent hub_owner_enrollment;
BEGIN
 IF TG_OP='DELETE' THEN
  IF clock_timestamp()<OLD.not_after+interval '1 minute' THEN
   RAISE EXCEPTION 'owner signing spend cannot be refunded before expiry';
  END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO parent FROM hub_owner_enrollment WHERE id=NEW.enrollment_id FOR UPDATE;
  IF NOT FOUND OR parent.retired_at IS NOT NULL OR parent.audit_receipt_json IS NULL
  OR NEW.epoch<parent.highest_epoch OR NEW.epoch<>floor((extract(epoch FROM clock_timestamp())+60)/1200)
  OR NEW.not_after<>to_timestamp((NEW.epoch+1)*1200)
  OR NEW.ordinal<>(SELECT count(*)+1 FROM hub_owner_certificate WHERE enrollment_id=NEW.enrollment_id AND epoch=NEW.epoch)
  OR NEW.certificate_json IS NOT NULL OR NEW.audit_receipt_json IS NOT NULL OR NEW.activated_at IS NOT NULL THEN
   RAISE EXCEPTION 'owner signing attempt must be current, audited and next bounded ordinal';
  END IF;
  UPDATE hub_owner_enrollment SET highest_epoch=NEW.epoch,hold_until=greatest(hold_until,NEW.not_after+interval '1 minute') WHERE id=NEW.enrollment_id;
 ELSE
  IF ROW(NEW.id,NEW.enrollment_id,NEW.epoch,NEW.ordinal,NEW.not_after,NEW.attempt_json)
  IS DISTINCT FROM ROW(OLD.id,OLD.enrollment_id,OLD.epoch,OLD.ordinal,OLD.not_after,OLD.attempt_json)
  OR (OLD.certificate_json IS NOT NULL AND ROW(NEW.certificate_json,NEW.certificate_sha256) IS DISTINCT FROM ROW(OLD.certificate_json,OLD.certificate_sha256))
  OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json)
  OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
   RAISE EXCEPTION 'owner certificate attempt and results are immutable';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER owner_certificate_guard BEFORE INSERT OR UPDATE OR DELETE ON hub_owner_certificate FOR EACH ROW EXECUTE FUNCTION guard_owner_certificate();
-- No destructive down: possible live leaves and spent attempts must survive.
