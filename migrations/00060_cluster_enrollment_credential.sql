-- +goose Up
-- ADR-168: per-profile rotating cluster enrollment keys. Only public keys are
-- stored. Possession admits that exact profile's connector process enrollment
-- or renewal; it is not evidence, workload, fleet or administrator authority.
-- No runtime role is granted here; the protected installer provisions purposes.
CREATE TABLE cluster_enrollment_lineage (
 lineage_id uuid PRIMARY KEY,
 root_id uuid NOT NULL, peer_id uuid NOT NULL,
 installation_id uuid NOT NULL, cluster_id uuid NOT NULL,
 validity_seconds bigint NOT NULL CHECK (validity_seconds BETWEEN 3600 AND 2592000),
 rotation_seconds bigint NOT NULL CHECK (rotation_seconds >= 60 AND 3*rotation_seconds <= validity_seconds),
 current_generation bigint NOT NULL CHECK (current_generation >= 1),
 fenced text CHECK (fenced IN ('fork','revoked')), fenced_at timestamptz,
 created_at timestamptz NOT NULL, retired_at timestamptz,
 CHECK ((fenced IS NULL) = (fenced_at IS NULL)),
 FOREIGN KEY (root_id, peer_id) REFERENCES connector_identity_profile(root_id, peer_id)
);
-- Reenrollment retires the previous lineage; its history stays readable.
CREATE UNIQUE INDEX cluster_enrollment_lineage_current ON cluster_enrollment_lineage(root_id, peer_id) WHERE retired_at IS NULL;
CREATE TABLE cluster_enrollment_credential (
 lineage_id uuid NOT NULL REFERENCES cluster_enrollment_lineage(lineage_id),
 generation bigint NOT NULL CHECK (generation >= 1),
 public_key bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
 issued_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL CHECK (valid_until > issued_at AND valid_until <= issued_at + interval '30 days'),
 superseded_at timestamptz,
 successor_digest bytea CHECK (successor_digest IS NULL OR octet_length(successor_digest) = 32),
 first_used_at timestamptz,
 CHECK ((superseded_at IS NULL) = (successor_digest IS NULL)),
 PRIMARY KEY (lineage_id, generation)
);
-- +goose StatementBegin
CREATE FUNCTION guard_cluster_enrollment() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'cluster enrollment history is append-only' USING ERRCODE='23514'; END IF;
 IF TG_OP = 'INSERT' THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME = 'cluster_enrollment_lineage' THEN
  IF ROW(NEW.lineage_id,NEW.root_id,NEW.peer_id,NEW.installation_id,NEW.cluster_id,NEW.validity_seconds,NEW.rotation_seconds,NEW.created_at) IS DISTINCT FROM ROW(OLD.lineage_id,OLD.root_id,OLD.peer_id,OLD.installation_id,OLD.cluster_id,OLD.validity_seconds,OLD.rotation_seconds,OLD.created_at)
   OR NEW.current_generation NOT IN (OLD.current_generation, OLD.current_generation+1)
   OR NEW.current_generation <> OLD.current_generation AND (OLD.fenced IS NOT NULL OR OLD.retired_at IS NOT NULL)
   OR OLD.fenced IS NOT NULL AND ROW(NEW.fenced,NEW.fenced_at) IS DISTINCT FROM ROW(OLD.fenced,OLD.fenced_at)
   OR OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
   RAISE EXCEPTION 'cluster enrollment lineage transition unavailable' USING ERRCODE='23514';
  END IF;
 ELSE
  IF ROW(NEW.lineage_id,NEW.generation,NEW.public_key,NEW.issued_at,NEW.valid_until) IS DISTINCT FROM ROW(OLD.lineage_id,OLD.generation,OLD.public_key,OLD.issued_at,OLD.valid_until)
   OR OLD.superseded_at IS NOT NULL AND ROW(NEW.superseded_at,NEW.successor_digest) IS DISTINCT FROM ROW(OLD.superseded_at,OLD.successor_digest)
   OR OLD.first_used_at IS NOT NULL AND NEW.first_used_at IS DISTINCT FROM OLD.first_used_at THEN
   RAISE EXCEPTION 'cluster enrollment credential transition unavailable' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER cluster_enrollment_lineage_guard BEFORE UPDATE OR DELETE ON cluster_enrollment_lineage FOR EACH ROW EXECUTE FUNCTION guard_cluster_enrollment();
CREATE TRIGGER cluster_enrollment_credential_guard BEFORE UPDATE OR DELETE ON cluster_enrollment_credential FOR EACH ROW EXECUTE FUNCTION guard_cluster_enrollment();
