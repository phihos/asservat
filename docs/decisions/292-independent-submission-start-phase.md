# ADR-292 — Bound admission and start as separate request phases

Date: 2026-11-03. Status: implemented under the maintainer's delegated
simplification mandate; local regressions pass, installed rerun pending.
Requirements: REQ-EXE-001, S-05.

## Observed problem

Installed manual-profile run
[41592791975](https://github.com/phihos/asservat/actions/runs/41592791975)
at `78afa6ec` reached approved submission, but a storage observation wait and
admission consumed roughly three seconds. The start later had less than half
a second left and returned `AcquisitionNotStarted`. The outer request already
allowed fifteen seconds; the single-start phase nevertheless used five seconds
from request ingress, including the completed admission phase. Recovery also
had a separate approved-profile scope defect; this deadline change does not
repair that defect or establish a successful installed workflow.

## Decision

After consuming current admission metadata, the single-start phase (intent
lookup plus start) receives at most five seconds from its handoff. Admission
keeps its own five-second limit. Both remain inside the original fifteen-second
public request and any earlier caller or identity bound. The start additionally
retains the accepted capture deadline and `WriteUntil`; recording snapshots
retain their original `StartBy`. Fresh start authority, original observation
expiry and effect checks remain mandatory. No admission observation is renewed
or reused as start authority, no attempt is retried and no quota is refunded.

History still follows the start under ADR-272 and uses only the remaining
original request window. A phase budget is a ceiling, not a completion promise.
The existing exact read-only metadata refresh supplies an accepted reply when
the earlier response observation expired during a successful start.

## Cost and validation

This changes one existing deadline anchor: zero new API calls, watches,
credentials, configuration, workers or fallback states. It can use more of the
already authorized request window without extending it. The previous anchor
was an implementation choice, not a maintainer requirement. Independent bounded
phases already exist in grouped submissions and capture preview composition.

A regression with real submission/identity composition and explicit synthetic
SQL/start ports fails before the fix: three seconds of admission followed by
three seconds of start preparation is denied. It passes afterward and verifies
that expired caller, identity, accepted-capture and five-second phase bounds,
cancellation and fresh start denial all still prevent an effect. Focused
submission, group and history race tests pass in 3.420 seconds. The full capture
application race suite also passes in 16.583 seconds; vet, specification and
architecture gates pass. Native rerun
and complete installed workflow qualification remain required.
