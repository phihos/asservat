-- +goose Up
-- ADR-241: log and resource triggers. Additive: an older binary treats a
-- 'log' or 'resource' watermark as another detector's (a new baseline),
-- rejects such a DebugPolicy at compile time and never writes the new
-- suppression reason, so the ADR-227 compatibility floor stays at 81.

-- A log watermark holds the newest matching record second and a resource
-- watermark the newest sample second at which its condition held, with the
-- level's re-arm state, as probe and alert watermarks do.
ALTER TABLE policy_pod_watermark
 DROP CONSTRAINT policy_pod_watermark_detector_check,
 ADD CONSTRAINT policy_pod_watermark_detector_check CHECK (detector IN ('exit','probe','alert','log','resource'));

-- Their occurrences' restarts column holds that second (unix time, at least
-- 2001-09-09), like probe and alert occurrences.
ALTER TABLE policy_occurrence
 DROP CONSTRAINT policy_occurrence_detector_check,
 ADD CONSTRAINT policy_occurrence_detector_check CHECK (detector IN ('exit','probe','alert','log','resource')),
 DROP CONSTRAINT policy_occurrence_probe_second,
 ADD CONSTRAINT policy_occurrence_probe_second CHECK (detector NOT IN ('probe','alert','log','resource') OR restarts>=1000000000);

-- overlong: a log poll of a Pod whose window held a record longer than the
-- detector's maxRecordBytes, dropped instead of evaluated (REQ-TRG-001). A
-- content-free saturating count like every other reason.
ALTER TABLE policy_suppression
 DROP CONSTRAINT policy_suppression_reason_check,
 ADD CONSTRAINT policy_suppression_reason_check CHECK (reason IN ('cooldown','budget','coalesced','capacity','authority','unavailable','overlong'));
-- No destructive Down: occurrences, watermarks and suppression counts survive.
