# ADR-108: back context control records per workload

- Status: Accepted for the initial bounded context component; native qualification pending.
- Date: 2026-10-11
- Owners: C-07 capacity, C-09 captures, C-15 privacy, C-21 SQL adapters
- Related: REQ-CAP-004/005, REQ-DB-002–004; U13 in the user-task review;
  ADR-107 request resolution; migration 00037

## Decision

Replace the installation-wide lifetime count of 1,024 context captures with
explicit protected control-metadata backing. A root pool reserves independent
full-record and retained-disposition slots for each existing immutable workload
storage allocation. The exact `context_storage_binding` selects the account;
a capture request cannot supply a cheaper account or change its workload.
There is no shared burst in this component. One workload cannot borrow another
workload's backing, even when their evidence uses the same object store.

Every first acceptance reserves one slot in both dimensions, in the same SQL
transaction as custody registration and the immutable capture. Source-managed
counters and a deferred capture-to-charge constraint enforce the accounting at
the database boundary. Capture execution roles cannot lower counters, alter backing, omit the
charge or remove history. Exact accepted replay runs before
new-capacity checks and never spends another slot.

Protected C07 configuration uses monotonic revision/CAS updates against the
same root and allocation. Renewal preserves all retained charges. A pool cannot
shrink below total backing; an account cannot shrink below retained charges.
Only its unused backing is adjustable, preserving every other account. Root
and account suspension are independent and never release either charge. New
configuration carries one original at-most-five-second observation through all
blocking work; exact historical replay cannot renew expiry or rewind revision.
This is neither a new public permission API nor a production configuration-source
accepter. Source protection,
reconciliation and installation provisioning still need composition. Fixture
administrator configuration is not that implementation.

## Existing data and finite retirement

Migration37 adopts every historical capture, including pending, failed, unknown
and deleted records. The legacy accounts/pools start unconfigured with all
original charges reserved. Explicit protected configuration must cover these
costs before admitting new captures. It cannot erase or reset them. Historical
capture IDs, request/preview identities, scope, execution and custody rows remain
unchanged, preserving accepted lookup and the migration36 closure protocol.

This slice does **not** claim to close U13. It fixes cross-workload exhaustion
and removes the unrelated installation lifetime cap. A workload can still fill
its own allocation while retirement is pending. A concrete read-only C15 query
reports retained custody/audit/execution/download/retention dependencies, but
those facts never grant deletion, capacity release or a spend refund. Missing
execution history is unresolved. Every retained download row is a dependency,
including a terminal session; its reserved disclosure spend is not refunded.

A future bounded retirement transaction must require qualified writer
quiescence and deletion inventory, independently acknowledged cleanup/restore
checkpoints, settled audit/leaf dependencies, and a finite metadata/replay policy.
It must retain non-reopenable replay identity before compacting execution/capture
records, preserve unknown spend, and include live/WAL/backup privacy deadlines.
No such producer is fabricated here. No DELETE, compaction, release or tombstone
purge function is introduced. An expired deadline or `deleted`/`captureFailed`
label alone is never a cleanup proof.

## Limits and consequences

Slots bound logical context record sets, not exact PostgreSQL heap, index, WAL
or backup bytes. Variable download/lifecycle records retain their independent
bounds. Operators need physical headroom for privacy processing. Optional
capture-history views do not use this admission budget. Reserving retained slots
before collection avoids a future compaction that cannot safely retain replay
identity, while leaving the exact finite retirement format to its own decision.

The current storage observation checks that the selected account and pool are
configured, current and have both slots available before preview; this is an
observation, not a reservation. Admission still locks and rechecks them. The
original shortest configuration deadline survives all blocking work. Accepted
request recovery remains independent of present acquisition readiness.

## Validation scope

Targeted Go/race and sqlc generation results are recorded in the staged handoff.
Native fixture sources cover shared-root workload isolation, independent full
and replay exhaustion, concurrent original-key replay, deferred omission,
immutable role boundaries, legacy migration adoption and descriptive-deletion
non-release. They must run against PostgreSQL under the parent's frozen-source
qualification before this is described as native-qualified. This decision does
not enable collection, public installation, or a completed S-01/S-02 release.
