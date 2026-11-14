# ADR-223 — Lost regional completion replies end Indeterminate

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

Date: 2026-10-24. Status: implemented; real SQL and installed completion-loss recovery qualified.
Related: [ADR-104](104-regional-api-context-execution.md),
[ADR-105](105-durable-context-progress.md),
[ADR-205](205-installed-context-deletion.md).

## Problem

In the regional API path (ADR-171), the region captures and stores the context
artifact, then returns the acquisition instant, copy receipts and writer
completion to the hub over the open exchange. When that exchange breaks after
the region committed its copies, the hub cannot record `stored`. SQL keeps the
durable `started` phase. Retry correctly returns `AlreadyStarted` and never
collects again, but progress then reports Running/AcquisitionStarted with no end.

Migration 00034 already provides `deadline_observed_at` and the bounded
`ObserveOverdueContextCaptures` facet, which turns any unpublished capture whose
original deadline elapsed into Indeterminate/DeadlineOutcomeUnconfirmed. No
installed process called it, so that end state was never reached.

The S-02 exit item 6 asks that a reconnect import committed results without
repeating collection.

## Decision

1. Do not import a committed regional artifact whose completion reply is lost.
   Collection is never repeated. After the original deadline, the capture ends
   Indeterminate/DeadlineOutcomeUnconfirmed. Its storage charge is retained and
   released only by the normal context deletion lifecycle (ADR-205).
2. The hub-worker context deletion sweep calls the deadline observer on every
   30-second pass, before and independently of deletion preparation: pages of
   at most 16 captures while pages are full, at most 8 pages per pass, each page
   bounded to five seconds. A failed page is logged once per change and retried
   on the next pass.
3. The observer uses the existing `context-cleanup` login. Its role plan adds
   exactly the fixture `context_deadline_runtime` grants: SELECT on
   `context_capture` and `context_catalog` and UPDATE of
   `context_capture.deadline_observed_at`. No new login, credential, pool,
   migration or configuration is added. The fixed trigger keeps the timestamp
   SQL-assigned, once-only and no earlier than the original deadline.
4. A `prepared` execution row (preparation recorded, no start recorded) reports
   Pending/DispatchUnconfirmed explicitly; an unknown execution phase is
   unavailable rather than falling through.

## Complexity gate

1. Frequency/harm: the window is the reply of one finished regional operation,
   milliseconds to seconds; the harm is a stuck status and a held charge until
   deletion, not lost or repeated evidence. Observed in analysis, not in an
   installed run.
2. Accepted risk: unknown starts already stay spent (ADR-104); this keeps
   that rule.
3. Typical deployments: the observer helps every installation with a
   publisher; the import would help only the lost-reply path.
4. Precedent: a Kubernetes Job past `activeDeadlineSeconds` gets a
   DeadlineExceeded condition instead of waiting indefinitely for its Pods.
5. Privileges: one column update and two table reads on an existing hub-worker
   login. Importing would need hub-side unwrap/verification authority for a
   regional artifact the hub did not observe completing.
6. States: none added; DeadlineOutcomeUnconfirmed already exists. Import would
   add at least two (import pending, import failed).
7. Configuration: none.
8. External dependencies: none.
9. Cost: at most one indexed UPDATE per 30 s in the common case (partial index
   on unobserved rows).
10. Upgrade/rollback: the role layout digest changes; as with ADR-205, only
    fresh installations take the new layout.
11. Smaller fix: this is the smaller fix; documenting the limitation replaces
    the import.

## Consequences

S-02 exit item 6 is satisfied for duplicate and reconnected starts (one effect,
`AlreadyStarted`), not by importing results whose reply was lost. Those end
Indeterminate after their deadline. Unit tests cover the runner, the progress
projection and the sweep.

Installed run 42630012490
qualifies the recovery state through the real storage, execution, replay,
progress and deadline-observer path. A scoped trigger rejected only the hub's
`started → stored` transition after all four regional ciphertext objects
committed; execution stayed `started` and custody `reserved`. Replay named the
original capture without another execution or custody attempt, and the original
deadline produced stable `Indeterminate/DeadlineOutcomeUnconfirmed`. This is a
deterministic completion-loss fixture, not a measurement of TCP packet-loss
timing. The separate pre-start KMS failure also reached the same terminal state
with zero executions.

The targeted real-PostgreSQL observer run
also passed: both the original deadline role and the installed `context-cleanup`
role produced one durable transition under concurrency, public progress changed
to the expected indeterminate reason, and repeated/reverse mutations were denied
without refunding the charge. Its environment report records unchanged sources
and no cleanup failures. A broader custody run had unrelated publication,
profile and download rollback-check failures; it is not claimed as a full-suite
pass and those checks were not changed by this qualification slice.
