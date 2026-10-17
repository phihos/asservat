-- +goose Up
-- ADR-166: bounded shared streaming custody journal; not acquisition authority.
-- Existing registration digests, reservations and the four final roles are
-- unchanged. Attempts above one 8 MiB frame require their journal row.
ALTER TABLE custody_attempt DROP CONSTRAINT custody_attempt_native_limit_check;
ALTER TABLE custody_attempt ADD CONSTRAINT custody_attempt_native_limit_check CHECK (native_limit BETWEEN 0 AND 134217728);
CREATE TABLE custody_stream (
 attempt_id uuid PRIMARY KEY REFERENCES custody_attempt(id),
 writer_epoch uuid NOT NULL,
 plan_digest bytea NOT NULL CHECK (octet_length(plan_digest) = 32),
 temporary_bytes bigint NOT NULL CHECK (temporary_bytes BETWEEN 1 AND 136314880),
 temporary_objects bigint NOT NULL CHECK (temporary_objects BETWEEN 2 AND 18),
 state jsonb NOT NULL CHECK (jsonb_typeof(state) = 'object' AND octet_length(state::text) <= 16384),
 revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
 released_at timestamptz
);
-- +goose StatementBegin
CREATE FUNCTION require_custody_stream() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.native_limit > 8388608 AND NOT EXISTS (SELECT 1 FROM public.custody_stream WHERE attempt_id = NEW.id) THEN
  RAISE EXCEPTION 'streaming attempt requires its journal' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
CREATE FUNCTION guard_custody_stream() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'streaming journal is retained with its attempt' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.attempt_id,NEW.writer_epoch,NEW.plan_digest,NEW.temporary_bytes,NEW.temporary_objects) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.writer_epoch,OLD.plan_digest,OLD.temporary_bytes,OLD.temporary_objects)
  OR NEW.revision <> OLD.revision + 1
  OR OLD.released_at IS NOT NULL
  OR (NEW.state->>'CreateSpent')::boolean IS DISTINCT FROM true AND (OLD.state->>'CreateSpent')::boolean = true
  OR (NEW.state->>'CompleteSpent')::boolean IS DISTINCT FROM true AND (OLD.state->>'CompleteSpent')::boolean = true THEN
  RAISE EXCEPTION 'streaming journal transition unavailable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER custody_attempt_stream_required AFTER INSERT ON custody_attempt DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_custody_stream();
CREATE TRIGGER custody_stream_guard BEFORE UPDATE OR DELETE ON custody_stream FOR EACH ROW EXECUTE FUNCTION guard_custody_stream();
