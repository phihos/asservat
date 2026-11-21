-- Applied at every hub start; every statement must be repeatable.

CREATE TABLE IF NOT EXISTS clusters (
  name         text PRIMARY KEY,
  token_sha256 bytea NOT NULL UNIQUE,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS captures (
  id          uuid PRIMARY KEY,
  requester   text NOT NULL,
  cluster     text NOT NULL,
  request     jsonb NOT NULL,
  sensitive   boolean NOT NULL,
  state       text NOT NULL,
  message     text NOT NULL DEFAULT '',
  approver    text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS captures_created ON captures (created_at DESC);
CREATE INDEX IF NOT EXISTS captures_expires ON captures (expires_at);

CREATE TABLE IF NOT EXISTS tasks (
  capture_id uuid NOT NULL REFERENCES captures ON DELETE CASCADE,
  pod        text NOT NULL,
  node       text NOT NULL,
  state      text NOT NULL,
  message    text NOT NULL DEFAULT '',
  PRIMARY KEY (capture_id, pod)
);

CREATE TABLE IF NOT EXISTS artifacts (
  capture_id  uuid NOT NULL REFERENCES captures ON DELETE CASCADE,
  name        text NOT NULL,
  size        bigint NOT NULL,
  sha256      text NOT NULL,
  blob        text NOT NULL,
  wrapped_key bytea NOT NULL,
  PRIMARY KEY (capture_id, name)
);

-- A watch creates a capture when a container of its workload crashes, with
-- the identity of the user who created it.
CREATE TABLE IF NOT EXISTS watches (
  id         uuid PRIMARY KEY,
  requester  text NOT NULL,
  groups     jsonb NOT NULL,
  cluster    text NOT NULL,
  request    jsonb NOT NULL,
  selector   text NOT NULL,
  remaining  integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- The audit log outlives the captures it describes.
CREATE TABLE IF NOT EXISTS audit (
  id         bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  actor      text NOT NULL,
  action     text NOT NULL,
  capture_id uuid,
  detail     jsonb
);
CREATE INDEX IF NOT EXISTS audit_at ON audit (at DESC);
