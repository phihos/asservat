-- Applied at every hub start; every statement must be repeatable.

-- Clusters are configuration, not state: the table of an earlier version goes.
DROP TABLE IF EXISTS clusters;

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
-- A capture's number, counted up: what people call it by.
ALTER TABLE captures ADD COLUMN IF NOT EXISTS number bigserial;
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

ALTER TABLE captures ADD COLUMN IF NOT EXISTS stopped_at timestamptz;

-- The progress of each recording of the task, as the agent reports it.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS recordings jsonb NOT NULL DEFAULT '[]';

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
ALTER TABLE watches ADD COLUMN IF NOT EXISTS sensitive boolean NOT NULL DEFAULT false;
ALTER TABLE watches ADD COLUMN IF NOT EXISTS approver text NOT NULL DEFAULT '';
-- What the watch waits for; a watch from before conditions waits for a crash.
ALTER TABLE watches ADD COLUMN IF NOT EXISTS condition jsonb NOT NULL DEFAULT '{"kind":"crash"}';
-- How far the watch's running recordings reach back; 0: its time frame.
ALTER TABLE watches ADD COLUMN IF NOT EXISTS before_seconds integer NOT NULL DEFAULT 0;
-- The firings of alerts that an alert watch has recorded: Alertmanager repeats them.
ALTER TABLE watches ADD COLUMN IF NOT EXISTS fired jsonb NOT NULL DEFAULT '[]';

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
