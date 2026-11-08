# ADR-314: A preview that finds cold storage tries once more within its request window

Status: accepted (agent decision, 2026-11-08). Refines
[ADR-213](213-storage-readiness-at-consumption.md) and
[ADR-200](200-on-demand-capacity-refresh.md); the request-side counterpart is
[ADR-277](277-storage-refreshing-refusal.md).

## Context

A workload's stored storage binding is fresh for 30 seconds after its own
observation (migrations 00072/00073). The hub-worker keeps it fresh only while
a refresh demand is active (60 s after the last demand) or when its discovery
pass reaches the workload; a regional pass takes much longer than 30 s. A
preview issued after more than a minute without one, or the first preview after
a hub restart, therefore finds an expired binding, demands a refresh and polls.

The preview's current-observation phase is five seconds (identity, recovery,
target, eligibility, capability, retention; recovery is SQL fenced at five
seconds). Its storage readiness ends 750 ms before that phase. A demanded
regional refresh took 2.3–4.5 s on CI (guarded read through the connector), so
the refresh often landed a few hundred milliseconds after readiness ended and
the preview was refused `facts/storage/expired/readiness-tail`, although its
operation request window (`CapturePreviewRequestWindow`, 15 s) still had about
ten seconds. Installed `continuation-manual-logs` failed this way in runs
42460732876, 42455366262, 42456491656, 42457527896 and 42459705978; in
42460732876 the refresh landed 0.97 s after the refusal.

## Decision

When a capture preview attempt (`Preview`, `PreviewRepeat`,
`PreviewComposition`, `PreviewCompositionRepeat`) ends at exactly that stage,
and the caller's context still has at least two seconds, the preview runs one
more complete attempt. The second attempt reads identity, recovery, target,
eligibility, capability, retention and storage again, each under its own
original bound; it reuses nothing from the first attempt, which persisted
nothing. The caller's deadline, the 15 s request window, the 30 s binding
lifetime, the five-second observation phase and the one-second storage margin
are unchanged. Every other refusal, including a failed demand and a missing
refresh port, is returned as before.

Two seconds is a scheduling choice: a warm installed preview measured 0.6 s,
plus the 750 ms response reserve.

## Alternatives considered

- Widening the readiness or binding window: the preview's own facts are five
  second observations (recovery is SQL fenced), so a longer storage wait would
  outlive them; the cold refresh would still not fit.
- Keeping every enrolled binding warm: one guarded regional read per workload
  every ~25 s, growing with the workload count, to serve an occasional
  preview.
- Returning a retryable code and letting clients retry (ADR-277 for requests):
  every client would need the loop; the server already has the time.

## Complexity gate

1. Frequent: about one in three installed manual-logs runs, and the first
   preview after every hub restart. 2. Not a reopened risk. 3. All deployments
   with regional or idle workloads. 4. Bounded retry of an idempotent read is
   the common pattern. 5. No privileges. 6. One added path (the retry), no new
   state. 7. No configuration. 8. None. 9. At most one extra set of fact reads,
   only for a cold binding. 10. Revert removes it. 11. Smaller alternatives
   above do not meet the observed timing.
