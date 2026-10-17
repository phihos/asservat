-- +goose Up
-- Passive, private review blueprints only. No observation, runtime proof,
-- credential, evidence or plaintext user reason belongs in this table.
CREATE TABLE context_preview (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL REFERENCES permission_stream(id),
 capture_id uuid NOT NULL UNIQUE,
 attempt_id uuid NOT NULL UNIQUE,
 actor_key bytea NOT NULL CHECK(octet_length(actor_key)=32),
 principal_key bytea NOT NULL CHECK(octet_length(principal_key)=32),
 blueprint_json bytea NOT NULL CHECK(octet_length(blueprint_json) BETWEEN 1 AND 131072),
 blueprint_sha256 bytea NOT NULL CHECK(octet_length(blueprint_sha256)=32),
 created_at timestamptz NOT NULL,
 deadline timestamptz NOT NULL,
 CHECK(isfinite(created_at) AND isfinite(deadline)),
 CHECK(created_at>='2020-01-01 00:00:00+00' AND deadline<'10000-01-01 00:00:00+00'),
 CHECK(deadline>created_at AND deadline<=created_at+interval '5 minutes'),
 CHECK(id<>capture_id AND id<>attempt_id AND capture_id<>attempt_id)
);
CREATE INDEX context_preview_expiry ON context_preview(root_id,deadline,id);
CREATE INDEX context_preview_principal ON context_preview(root_id,principal_key,deadline);

-- Even a cleanup credential cannot evict a live review or rewrite its original
-- identities/deadline. Expiry cleanup never touches captures or custody charges.
-- +goose StatementBegin
CREATE FUNCTION context_preview_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  RAISE EXCEPTION 'context preview is immutable' USING ERRCODE='23514';
 END IF;
 IF OLD.deadline>clock_timestamp() THEN
  RAISE EXCEPTION 'context preview is not expired' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER context_preview_immutable BEFORE UPDATE OR DELETE ON context_preview
 FOR EACH ROW EXECUTE FUNCTION context_preview_immutable();
