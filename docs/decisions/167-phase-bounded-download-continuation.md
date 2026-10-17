# ADR-167 — Phase-bounded context download continuation

Date: 2026-10-14. Status: accepted; component and fixture-native qualification pass; installed qualification pending.
Requirements: REQ-DLD-001–004; existing download/continuation scenarios and
TASK-07 / TASK-11 retain traceability ownership.

## Problem and evidence

One explicit `prepare_artifact_download` request owns one current identity whose
original interval ends at most five seconds after construction
([current request identity](../architecture/current-request-identity.md)).
The console repeats an acknowledged `continue_preparation` reply with the same
key every two seconds ([public context download](../architecture/public-context-download.md)).
The worker paces every next native connection by one second after NoCommand or
Joined ([ADR-121](121-native-worker-startup.md)).

The regional journey runs in `test/results/public-context-journey-native-14` … `-28`
show that one continuation request tried to host three bounded phases at once:

1. **Enrollment.** Native14 recovered the original continuation outcome. Its
   enrollment was refused 5.6 ms after the continuation started, before the
   continuation could register. The fixture's once-only owner-claim notification
   had been consumed by the *first* preparation's own registration (fence 1).
   That was a fixture defect; the waiter now arms explicitly and accepts only the
   next fence. Native15 then reproduced native12's PostgreSQL 53300 under the
   fixture's 16-connection pools. The journey now uses the installed
   one-connection profile instead; no server limit changed. With these fixes,
   native21–23 showed the hub's one-second arrival window closing a registration
   while the worker's enrollment exchange was in flight. Closing the route
   cancelled that exchange after CSR processing and before activation.
2. **Native preparation.** Native16/17 completed enrollment, then started the
   native exchange with about 1.4 s of the original bound left. The exchange
   ended Uncertain at the bound.
3. **Ready view.** Native20 completed the prepare conversation in the next
   continuation (origin lease 3.7 s remaining, Joined). The same request's Ready
   view then needed a second Observe conversation one paced second later, which
   started with 0.62 s left and failed; the request ended as `identity.ErrDenied`.

Stretching the five-second identity, renewing it from polling, or retrying an
uncertain conversation would violate existing invariants. None is selected.

## Decision

- **An enrollment produced while this request's own registration is open ends
  the request as Preparing** (`continue_preparation: true`). Native preparation
  belongs to the next deliberate continuation with its own current identity.
  An enrollment already present when the request began keeps its previous path
  unchanged, including the short-peer renewal behavior.
- **A registration with an enrollment exchange in flight is not closed at the
  one-second arrival window.** `WorkerOwnerRegistration.Delivering` reports the
  exact route's busy delivery. The request keeps that registration until the
  exchange ends or the original bound expires. It never extends that bound or
  reopens a closed route.
- **The acknowledged preparation hands its exact verified facts to the same
  process's metadata cache once.** `prepareChecked` calls its existing private
  retention point only after acknowledged finish and commit. The continuation
  hands those facts off only when they equal the metadata `PrepareCurrent`
  returned. The first metadata load for exactly the same session, preparation
  (batch and generation) and scope then consumes them instead of a second worker
  Observe. A handoff is single-use and bounded by the existing sixteen slots and
  the facts' original read cutoff. It never substitutes for a different
  preparation or scope, and it is cleared on close. It carries no authority:
  every current identity, permission, retention, path and transition check in
  `prepared()` and in the coordinator still runs.

## Consequences

A cold download now normally takes three acknowledged explicit requests:
dispatch, enrollment, then native preparation with the Ready view. Each request
stays inside its original five-second bound. This adds at most one two-second
console interval compared with the old shape, which could not finish in time.
Workers that arrive outside every one-second window are still retried by the
worker supervisor's bounded backoff; that availability interaction is unchanged
and unqualified.

Same-process handoff is not a cross-replica cache. Another hub replica still
observes the worker. An Observe after a restart is unchanged.

`context_native_content_test` previously asserted that prepare plus one Observe
cost four native transitions. Its expectations are now two transitions after
preparation and four after one GET. That real-service suite has not been rerun
since this change.

## Verification

Component regressions fail before and pass after each production change:
`TestContextRuntimeNewEnrollmentDefersPreparationToNextContinuation`,
`TestContextRuntimeKeepsRegistrationDuringInFlightEnrollment` and
`TestContextNativeMetadataHandoffExactSingleUse`. The whole
`internal/application/evidence` race suite, vet, Go architecture and spec checks pass.

Native30 then exposed a regression in the first version of this decision. SQL
showed the new enrollment as soon as activation committed, and the request closed
its registration while the certificate was still being delivered. A new
enrollment therefore ends the request only after `Delivering()` is false
(`TestContextRuntimeNewEnrollmentWaitsForDeliveryToEnd`).

Native qualification of the fixture journey: native36 and native37 pass end to
end (capture, publication, case, three-request download, native bytes, Stop and
revocation). The changed content/resume/interrupted modes and the complete
41-mode download-worker family pass against real PostgreSQL/S3. Earlier native
failures remain recorded in the progress tracker: publication 53300 under the
fixture's 45 ordinary slots, the stale pre-migration-47 Stop composition, and
runs under heavy unrelated host load. This is fixture qualification with
synthetic authority inputs, not installed-workflow or sustained-availability
qualification.
