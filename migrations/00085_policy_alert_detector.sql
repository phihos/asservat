-- +goose Up
-- ADR-231: alert triggers. Additive: an older binary treats an 'alert'
-- watermark as another detector's (a new baseline) and rejects an alert
-- DebugPolicy at compile time, so the ADR-227 compatibility floor stays at 81.

-- An alert watermark holds the newest matching alert's startsAt second and
-- the level's re-arm state, as a probe watermark does.
ALTER TABLE policy_pod_watermark
 DROP CONSTRAINT policy_pod_watermark_detector_check,
 ADD CONSTRAINT policy_pod_watermark_detector_check CHECK (detector IN ('exit','probe','alert'));

-- An alert occurrence's restarts column holds that startsAt second (unix
-- time, at least 2001-09-09), like a probe occurrence's failure second.
ALTER TABLE policy_occurrence
 DROP CONSTRAINT policy_occurrence_detector_check,
 ADD CONSTRAINT policy_occurrence_detector_check CHECK (detector IN ('exit','probe','alert')),
 DROP CONSTRAINT policy_occurrence_probe_second,
 ADD CONSTRAINT policy_occurrence_probe_second CHECK (detector NOT IN ('probe','alert') OR restarts>=1000000000);
-- No destructive Down: occurrences and watermarks survive.
