-- +goose Up
-- ADR-176: attempt-scoped artifact key wrap authority. One row per prepared
-- API context execution; each of the three keyset roles (data, index,
-- manifest) is spent at most once, by the executor process's own activated
-- connector client leaf. Spending is irreversible and never refunded.
CREATE TABLE context_key_wrap (
 attempt_id uuid PRIMARY KEY REFERENCES context_execution(attempt_id),
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 certificate_sha256 bytea NOT NULL CHECK(octet_length(certificate_sha256)=32),
 used_roles smallint NOT NULL CHECK(used_roles BETWEEN 1 AND 7),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- +goose StatementBegin
CREATE FUNCTION guard_context_key_wrap() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'context key wrap spend cannot be deleted' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.attempt_id,NEW.root_id,NEW.certificate_sha256,NEW.created_at) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.root_id,OLD.certificate_sha256,OLD.created_at)
  OR (NEW.used_roles & OLD.used_roles)<>OLD.used_roles THEN
  RAISE EXCEPTION 'context key wrap spend is append-only' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER guard_context_key_wrap BEFORE UPDATE OR DELETE ON context_key_wrap FOR EACH ROW EXECUTE FUNCTION guard_context_key_wrap();

-- +goose Down
DROP TABLE context_key_wrap;
DROP FUNCTION guard_context_key_wrap();
