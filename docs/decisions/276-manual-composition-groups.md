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

Implemented on `feature/s04-manual-mixed`:

- Planning: `SplitComposition`, `CompileRecorderGroup` (`recorder-group/v1`,
  carrying the children's shared `timing` marker so the parent grant passes
  `lock_approved_context_grant`, plus merged `profileComposition`/`lifecycle`
  for display), `ReadRecorderGroupScope`, `RecorderGroupDisplay` and
  `RecorderGroupSummary` (one review over all child actions).
- SQL (migration 00116): kind-aware header, member, history and audit checks;
  `AdmitRecordingCompositionGroup` inserts the header and admits every child
  in one transaction (children created at the header's `accepted_at`, no
  policy reservation, parent grant locked per child). Replay, resolution,
  progress (`collect`, one Pod) and capture-intent readers are kind-aware;
  cancellation of a composition group is refused (finite children).
- Application: `previewCompositionGroup` (one eligibility/storage
  observation, per-child retention by evidence type, per-child compile,
  assessment and processing coverage), `requestCompositionGroup` (one
  approval gate, both node recorders resolved for the same Pod, one atomic
  admission) and serial `StartContext` per child under the human identity.
- Tests: unit (planning, domain progress, presentation), custody
  `recording-composition-group` and the native `continuation-manual-mixed`
  focus.

Known v1 limits: a component with several actions is refused; each child
keeps the composition's `maxTotalBytes` as its own cap (the per-capture
8 MiB recording limit still applies), and no parent history entry is
written, so repeating needs a new preview.
