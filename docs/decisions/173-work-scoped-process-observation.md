# ADR-173 — Work-scoped regional process observation

Date: 2026-10-14. Status: accepted; implemented; the connector executor's local start passes natively.
Requirements: REQ-EXE-002, S-02 regional context start; TASK-03 / TASK-11.

## Context

Under [ADR-171](171-hub-run-context-execution.md), one API context execution
reads the executor process proof many times. The hub runner reads it three
times through the `read-process` operation: its first check, before
PrepareStart and before ConsumeStart. The connector-Deployment start preparer
(`ConnectorAPIStartPreparer`) re-reads it in every start check: twice in
PrepareStart and up to three times in ReadyStart. Each read beyond the cached
proof is a complete current recheck: namespace, account, a SelfSubjectReview,
both guard policies and bindings, the settings ConfigMap, the
Deployment/ReplicaSet/Pod chain and every approved input, about 13 API calls.
The cold proof itself costs about 71.

Every start step must finish within the process observation's original
five-second interval. Kubernetes clients stay at 20 QPS/burst 20.
[Native runs](../../test/results/connector-api-timing-4/result.json) measured
about 1 ms per round trip, so elapsed time is limiter wait. A cold proof took
2.8 s; ReadyStart's three rechecks took 2.15 s more and were denied 47 ms before
the bound. Raising limits or dropping the start checks were both rejected.

## Decision

1. One verified work owns one complete process observation. The regional
   session (`contextstart.regionalSession`) keeps the first successful
   `read-process` result. Later `read-process` operations for the same work
   return it unchanged, with the original CheckedAt and ValidUntil, while it is
   within that original interval. After expiry, a new complete read replaces
   it. Nothing renews or extends an observation, and no observation outlives
   or crosses a work.
2. Start checks may use that observation instead of reading the process again
   (`executionapp.ObservedAPIStartPreparation`). The connector preparer
   requires it to be its own process's observation (exact binding, including
   the process epoch), still valid, and matching the start binding. It is never
   accepted from the hub: the hub only ever receives copies.
3. Everything else stays current on every call. That covers the capacity
   account's SelfSubjectReview, the capacity ServiceAccount, the start guard
   policy and binding, and the CapacityReservation CAS itself under both
   admission guards. The hub's identity, permission, recovery, retention and
   capability checks are unchanged.

## Consequences

Within one work, a change to the executor's Deployment, inputs or settings
that no admission check rejects can stay unobserved until that observation's
original deadline, at most five seconds after it began. This is the same
bounded freshness as the transport lease in
[ADR-163](163-original-work-transport-observation-lease.md); no instantaneous
revocation is claimed. Kubernetes still enforces both guards on every start
write, and the next work makes a complete read.

The start sequence then costs one process proof plus about four API calls per
start check and the CAS writes.

## Implementation

- `executionapp.ObservedAPIStartPreparation`: `PrepareObservedStart` and
  `ReadyObservedStart`.
- `kube.ConnectorAPIStartPreparer` implements it; `check` takes an optional
  observation and otherwise reads the process as before. The bare-Pod
  preparer's checks never read the process and are unchanged.
- `contextstart.regionalSession`: `readProcess` and `observed`.
  `TestRegionalSessionReusesOneProcessObservationPerWork` covers one read for
  three operations, use of the observed start variant, non-renewal after
  expiry, and refusal for another process epoch.

The native test's timed phase follows a work's real order: a cold complete
process read, then observed Prepare and Ready, then Consume, all within that
read's original interval. The test also gates on an admitted dry-run CREATE
before timing. It creates the CRD itself, and the first CREATEs after that were
refused for about two seconds ([runs 1–3](../../test/results/connector-api-timing-3/result.json)).
The chart installs the CRD long before any start.

## Native result

[Run 6](../../test/results/connector-api-timing-6/result.json) passes all of
`TestConnectorAPIProcessWithRealKubernetes` (exit 0, empty cleanup, unchanged
sources). This is the first native pass of the connector-Deployment local
start. Within one observation's original 5.0 s interval:

| Phase | Elapsed | API calls |
| --- | --- | --- |
| Cold complete process read | 1.80 s | 71 |
| Observed PrepareStart (with CREATE) | 0.30 s | 9 |
| Observed ReadyStart (with Ready /status) | 0.45 s | 14 |
| ConsumeStart (StartCommitted /status) | 16 ms | 3 |
| Whole sequence | 2.57 s | |

Runs 4 and 5 are retained failures. Run 4 ran ReadyStart's per-call rechecks
and was denied 47 ms before the bound. Run 5 had a test-side binding with
non-canonical times. The accepted connector source, CA/registry and
preparation grant are explicit fixture inputs; no SQL preparation, hub runner
or product binary ran.
