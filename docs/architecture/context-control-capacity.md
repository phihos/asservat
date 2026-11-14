# Context control capacity

Capture metadata (capture rows, preview-independent idempotency records and
their audit rows) is hub SQL state. To keep one workload from exhausting it for
others (REQ-CAP-006), each workload's capacity account carries a limit on
retained capture records ([ADR-108](../decisions/108-backed-context-control-capacity.md),
mechanism per [ADR-330](../decisions/330-event-driven-system-design.md) D7).
Evidence bytes and objects keep their separate C-07 counters
([capacity production](capacity-production.md)).

## Rules

- The limit comes from the workload's `EvidenceBudgetPolicy`. The pool row
  holds the installation-wide total so per-workload limits cannot exceed what
  the hub SQL budget covers.
- Admission increments the workload's record counter in the admission
  transaction with a conditional update. It locks that workload's account row
  only, plus the pool row when burst use applies.
- Deleting a capture's metadata (retention expiry, workload removal) decrements
  the counter in the deleting transaction. The counter is a count of live rows,
  not a prepaid allowance.
- Lowering a limit below current use blocks new admissions for that workload
  and reports over-limit; it deletes nothing.
- An admission whose commit outcome is unknown is resolved by looking up its
  idempotency key. If it did not commit, nothing was charged.

The preview reports a full account before the user submits. The preview
reserves nothing; another request can take the last slot before submission.

## Approved queries

Approved reads use the separate [query capacity](context-query-capacity.md),
not capture-control records.
