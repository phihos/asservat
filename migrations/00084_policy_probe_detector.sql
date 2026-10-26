-- +goose Up
-- ADR-230: probe-failure triggers. Additive: an older binary neither reads
-- nor writes these columns (its rows take the 'exit' default), and it
-- rejects a probe DebugPolicy at compile time, so the ADR-227 compatibility
-- floor stays at 81.

-- A watermark's detector: a restart count (exit) or the newest probe failure
-- second (probe). A row of another detector than the policy's current one is
-- a new baseline, so a changed detector never compares a count with a time.
-- armed is the probe level's re-arm state (always true for exit).
ALTER TABLE policy_pod_watermark
 ADD COLUMN detector text NOT NULL DEFAULT 'exit' CHECK (detector IN ('exit','probe')),
 ADD COLUMN armed boolean NOT NULL DEFAULT true;

-- An occurrence's detector. A probe occurrence's restarts column holds the
-- newest failure second (unix time, at least 2001-09-09), which the region
-- caps far above any restart count, so the existing
-- UNIQUE(root_id,policy_uid,pod_uid,restarts) stays a per-detector key.
ALTER TABLE policy_occurrence
 ADD COLUMN detector text NOT NULL DEFAULT 'exit' CHECK (detector IN ('exit','probe')),
 ADD CONSTRAINT policy_occurrence_probe_second CHECK (detector<>'probe' OR restarts>=1000000000);
-- No destructive Down: occurrences and watermarks survive.
