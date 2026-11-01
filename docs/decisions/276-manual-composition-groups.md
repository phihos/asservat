# ADR-276 — A manual packet + syscall composition is a reviewed group

Date: 2026-11-01. Status: proposed (agent decision); slice B3 part 2.
Requirements: REQ-CPR-003, SC-CPR-003 (compositions are a DebugCapture
authoring form), specs/capture-assessment.md, ADR-266, ADR-275.

## Context

A capture is one attempt and one artifact (UNIQUE constraints). Manual
packet recordings (ADR-248) and manual syscall recordings (#115) each work
alone; a manual composition mixing them is refused (`RecorderEvidenceType`).
Policies already record both (ADR-275). The ADR-266 recording save group
provides one header with 2–16 child captures in one transaction, but nearly
all of its checks are policy/snapshot-shaped (policy executor, source
reservations, `recording-save/v1` scope, snapshot T0, NOT NULL policy
columns in 00109).

## Decision

1. Each child is byte-identical to today's single manual recording: the
   composition is split per action into per-component sub-compositions and
   compiled with `CompileRecorder`/`RecordingFor` unchanged, so expectation,
   node work, the 00115 processing trigger and hub recompilation stay as they
   are. A component with more than one action is refused for now.
2. A new parent scope document `recorder-group/v1` names executor, target,
   Pod, timing marker and per child `{captureID, actionID, kind,
   evidenceType, scopeDigest}`. One review/grant covers the parent digest;
   the review aggregates child summaries.
3. A new preview kind `compositionGroup` (separate from the save `Group`)
   with per-child IDs, retention review, scope digest and assessment; the
   executor is the human.
4. Migration 00116: `preview_kind` and the save-group header gain the kind;
   `policy_uid`/`acceptance_id` become nullable tied to the kind; member,
   scope-equality and audit-matcher checks become kind-aware (child scope
   bound via the parent's child digest; child count from the header);
   `context_preview_read_until` admits the kind's grant; the group history
   guard refuses this kind; Down refuses populated rows.
5. Request: one approval gate on the parent; resolve both recorders; one
   atomic admission of all children; serial start per child under the human
   identity. Cancellation is refused for this kind; no parent history entry
   in v1 (an explicit gap).

## Qualification

Unit/SQL tests (custody shards) and a native `manual-mixed` focus: packet
and syscall finite recordings at once on one Pod (shared frozen budget and
capture-busy handling on the node).

## Complexity gate

Benefit: one review and case for a mixed manual capture (spec). Cost: one
migration touching audit/grant matching (riskiest), a new admission path,
~L effort. Policies already cover the automated mixed case, so this is
scheduled after the main installed-qualification flakes are fixed.

## Implementation notes (2026-11-01)

Done on `feature/s04-manual-mixed`: `SplitComposition`, `CompileRecorderGroup`
(`recorder-group/v1`), `CompositionGroupPreview` on `ContextPreview`, and
migration 00116 (custody shards 1–4 pass with it applied).

Remaining, in order:

1. Admission (`internal/adapters/postgres/capture.go`). The single path
   (`group == nil`) locks its own stored preview and grant via
   `readReviewedContext`; the save-group path (`contextAdmissionGroupOptions`)
   takes a policy reservation. A composition child needs a third branch:
   recovery/stream from the group transaction, `reviewed` = the locked parent
   preview with the child's own target/scope substituted, the parent grant
   locked once (by parent preview ID, parent capture ID and parent scope
   digest, `lock_approved_context_grant`), no policy reservation, and
   `group_id`/`group_ordinal` from the child index (not `Snapshot.Group`).
   `InsertRecordingSaveGroup` gains `group_kind` and nullable policy columns.
2. `recordingGroupAccepted` / progress / history readers become kind-aware
   (`Operation` collect, PodUID set, no `Snapshot.T0`), and composition
   groups write no parent history entry.
3. Application: `previewCompositionGroup` (split, compile each child, compile
   the parent, one assessment and approval), `requestCompositionGroup` (one
   approval gate, resolve both recorders, `AdmitRecordingCompositionGroup`,
   serial `StartContext` per child under the human identity).
4. Presentation: allow `collect` groups in progress actions; MCP/browser
   schemas already carry `actions[]`.
5. Tests: unit, custody shards, native `manual-mixed` (packet + syscall
   finite recordings at once on one Pod).
