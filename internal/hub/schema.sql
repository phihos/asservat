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

-- Whether a capture still has an open task is asked at every report of a
-- pod: this finds one without reading the tasks that have ended.
CREATE INDEX IF NOT EXISTS tasks_open ON tasks (capture_id) WHERE state IN ('Queued','Running');

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
-- Packed: a core that is mostly holes, stored as its data and their places.
-- Its size and checksum are those of the file as it is downloaded.
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS packed boolean NOT NULL DEFAULT false;
-- Stored: what a packed file takes of the store; of the others, their size.
-- A packed file from before this column has none and counts by its size
-- until its retention ends: nothing in the database tells what it takes.
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS stored bigint;
-- Shared: also there for everyone who may capture in its namespace.
ALTER TABLE captures ADD COLUMN IF NOT EXISTS shared boolean NOT NULL DEFAULT false;

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
-- Who has approved so far, where a request needs more than one approval;
-- approver names them all once the last has approved.
ALTER TABLE watches ADD COLUMN IF NOT EXISTS approvals text[] NOT NULL DEFAULT '{}';
ALTER TABLE captures ADD COLUMN IF NOT EXISTS approvals text[] NOT NULL DEFAULT '{}';
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
