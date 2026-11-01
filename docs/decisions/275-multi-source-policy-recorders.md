# ADR-275 — One policy arms one source per composed recorder

Date: 2026-11-01. Status: accepted (agent decision); native qualification
continuation-ongoing-mixed run 41333094076 passed. Implementation is slice
B2 in docs/research/capture-profile-catalogs-plan.md.
Requirements: REQ-CPR-003 (specs/capture-profiles.md), SC-CPR-003,
specs/action-lifecycle.md.

## Context

Slice B1 expands an N-component composition into one alias/ID map and one
aggregate budget, but a policy still carries one
`PolicyRecorderConfiguration` (`PolicyTrigger.Recorder`), so a policy can arm
only one packet or one syscall source. Ongoing sources are already
independent below the policy: the node keys them by `SourceID`, and the SQL
source slot is unique on `(root_id, policy_uid, action_id, pod_uid)`
(migration 00105). One capture remains one attempt and one artifact (three
UNIQUE constraints and the verification key), so a save of several sources
is already modelled as an ADR-266 recording save group.

## Decision

1. A policy recorder becomes a list: `PolicyTrigger.Recorder` keeps the
   first action and a new `MoreRecorders` holds the others, each a complete
   single-action `PolicyRecorderConfiguration` sharing the policy's authored
   composition, scope digest and aggregate budget. `omitempty` keeps every
   existing policy's scope digest unchanged; no migration rewrites stored
   policies.
2. Arming, renewal and stop iterate the recorders. Each recorder is its own
   source per Pod under the existing per-action slot, observation budget and
   retention (resolved per evidence type, as today per action).
3. Incident snapshots and Save create one child capture per (Pod, recorder)
   in one save group, so every artifact keeps its own attempt, manifest and
   download, and the group shares one review, scope and case.
4. Incidents (step 3). An occurrence stays one execution and keeps its one
   `capture_id`/`reserved_capture_id` (migrations 00082, 00102) for the
   first recorder. A new child table `policy_occurrence_capture`
   (occurrence, action ID, unique capture ID, reserved bytes) holds the
   further recorders' captures, each idempotent on a key derived from the
   occurrence ID and action ID. Every child reservation is charged to the
   same acceptance output pool as the first capture, so the authored
   `MaxBytes` bounds the whole incident; the execution is spent once. A
   refused child does not refuse the occurrence: its outcome is recorded
   per child, and the first recorder's outcome remains the occurrence's.
   Qualified with `make custody-integration` (concurrent reservation, pool
   exhaustion between children, replay).
5. B1's conflict rule stands: at most one packet and one syscall recorder per
   policy, so the only mixed pair is packet + syscall.

## Gate before enabling

A native test runs a packet and a syscall source on the same Pod at the same
time; nothing qualifies that coexistence today. Until it passes, the public
runtime schema keeps one component.

## Complexity gate

1. Spec requirement (first release, SC-CPR-003). 3. Typical: incident
   investigation wants traffic and syscalls together. 5. No new privilege;
   the same node sources. 6. No new failure state; a refused source is the
   existing per-source refusal. 7. No configuration. 9. Cost is the sum of
   the two existing sources, already bounded by the node budget and
   `MaxActiveSources`. 11. Smaller alternative (two policies on one workload)
   splits review and the case, which REQ-CPR-003 rules out.
