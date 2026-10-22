# ADR-218 — Consume download preflight observations at their phase

Date: 2026-10-23. Status: accepted under the maintainer's implementation and
simplification instruction; implemented; qualification in progress.
Requirements: REQ-DLD-003, REQ-CAP-003; S-02.

## Observed problem

Download preparation used the remaining lifetime of a passive runtime-readiness
observation as the deadline for every subsequent effect. It likewise retained
the transfer plan's freshness deadline after session reservation had completed.
Both observations may inherit an older, still-valid worker-configuration interval.
Current SQL configuration and authorization are independently checked at worker
reservation and launch, and the Kubernetes Job driver checks configuration again.

A composed coordinator/runtime/dispatcher regression crosses a 200-millisecond
preflight interval during 400 milliseconds of simulated audit work. Readiness,
configuration-readiness and plan variants all acknowledge the synthetic audit but
refuse before claiming a worker, although the original authorization remains live. This is
controlled component evidence, not a measured provider delay. Native55 also ends
with an audited, unclaimed worker; the available native diagnostics do not prove
that this coupling caused that run's failure.

The separately qualified real PostgreSQL/S3 path with compiled installed roles
reaches the first Job boundary in about 185 milliseconds under one original
authority observation. It does not include the upstream preflight observations.
See [implementation progress](../implementation-progress.md) for exact results.

## Decision

Consume passive runtime readiness when checking it. An unavailable or already
expired observation still prevents preparation. Its expiry after that check does
not shorten the whole operation or confer permission for a later effect.

Consume plan freshness through session reservation, including its acknowledged
return. Reservation receives the earlier of the original operation cutoff and
the plan's freshness cutoff. Expiry, cancellation or an unknown/error reply
prevents continuation; any committed reservation retains its original accounting.
After acknowledged reservation, discard only that consumed freshness bound.
Accepted byte/request limits, allocation/access expiry and `HardUntil` remain
fixed in the original session.

Retain the original caller/token, request-owned five-second authority, recovery,
retention, source, attachment and session bounds. Worker reservation/launch and
evidence effects retain current SQL permission, recovery, configuration, retention
and accounting checks; Job
creation retains its current configuration and exact profile checks. No check
renews an old observation, retries an uncertain effect or selects another target.
This refines the existing context-download coordinator and ADR-167's phase-bound
continuation, and complements ADR-214's removal of repeated authorization. It
changes no public schema, SQL row or grant scope.

## Complexity and qualification

Added credentials, privileges, configuration, timers, retries, background tasks
and durable states: zero. Two consumed preflight deadlines stop constraining
unrelated later phases. No timeout is enlarged and no extra source request is
added. The existing non-authorizing readiness contract and transactional effect
checks supply the needed boundaries; this is not a new caching mechanism.

Keep regressions for expired readiness, expiry/cancellation during reservation,
caller/identity/authority/session expiry, cancellation after audit and unchanged
single reservation/audit/claim behavior. Run the affected race and design gates
and the installed investigation. Component success alone does not qualify native
download, sustained availability or the complete lifecycle.
