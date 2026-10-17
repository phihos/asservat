-- +goose Up
-- ADR-181: verification unwrap authority for the publisher. One row per
-- stored API context attempt; the counter only grows, by one per unwrap, and
-- is bounded at three keyset roles times four verification attempts. Spending
-- is never refunded and the row is never deleted.
CREATE TABLE context_key_unwrap (
 attempt_id uuid PRIMARY KEY REFERENCES context_execution(attempt_id),
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 last_certificate_sha256 bytea NOT NULL CHECK(octet_length(last_certificate_sha256)=32),
 unwraps smallint NOT NULL CHECK(unwraps BETWEEN 1 AND 12),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- +goose StatementBegin
CREATE FUNCTION guard_context_key_unwrap() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'context key unwrap spend cannot be deleted' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.attempt_id,NEW.root_id,NEW.created_at) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.root_id,OLD.created_at)
  OR NEW.unwraps<>OLD.unwraps+1 THEN
  RAISE EXCEPTION 'context key unwrap spend only increments' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER guard_context_key_unwrap BEFORE UPDATE OR DELETE ON context_key_unwrap FOR EACH ROW EXECUTE FUNCTION guard_context_key_unwrap();

-- +goose Down
DROP TABLE context_key_unwrap;
DROP FUNCTION guard_context_key_unwrap();
