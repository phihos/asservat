# ADR-223 — Lost regional completion replies end Indeterminate

Date: 2026-10-24. Status: implemented; real SQL and installed qualification pending.
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
projection and the sweep. The real-SQL observer grants under the installed role
plan are not yet qualified.
