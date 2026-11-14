# Capacity production

C-07 turns the hub's `capacity` Helm values
([capacity.schema.json](../../specs/contracts/capacity.schema.json)) into per-workload SQL capacity accounts
([REQ-CAP-004 through REQ-CAP-006](../../specs/capacity.md)). C-01 supplies the
accepted resources; C-20 owns the adapters. Mechanisms follow
[ADR-330](../decisions/330-event-driven-system-design.md).

## Inputs

- A-HWORK reads the `capacity` values from its configuration; a
  `helm upgrade` that changes them is a reconcile event. Invalid values fail
  the chart's schema check.
- Namespaces and workloads of enrolled clusters come from the
  [cluster state push](cluster-observations.md). Candidate discovery is a query
  over that SQL projection, not a Kubernetes LIST.

## Reconciliation

The capacity reconciler runs in A-HWORK and reacts to events: a `capacity` values
change, a pushed workload or namespace change, or a workload deletion. For each
affected workload it:

1. creates or updates the workload's capacity account and storage binding in
   one SQL transaction that locks only that workload's account row and, when
   burst limits apply, the pool row;
2. reports `CapacityNotAllocated` on the workload when its allocation does not fit.

The storage binding is SQL state maintained by these events. Admission reads it
under ordinary row checks; it has no freshness interval, readiness wait or
refresh demand. A workload whose binding is missing is reported
`CapacityNotAllocated` at preview.

Changing a value never creates a second account or detaches retained
charges. Workload deletion or name reuse keeps the account until its retained
evidence is deleted or moved to a backed residual account (REQ-CAP-006).

## Accounting

Each workload account holds byte and object counters for live evidence and a
count of retained capture metadata rows, derived from the workload's storage
share ([context control capacity](context-control-capacity.md)).
Admission charges them with a conditional update (`WHERE used + n <= limit`);
deleting evidence or metadata releases the charge. An effect whose outcome is
unknown is resolved by its idempotency key and its charge is released when the
outcome is known (D7).

Pool rows hold the pool's protected total and shared burst counters. Parent
envelopes subtract unused protected allocations of their children before
granting burst (REQ-CAP-004). Storm protection uses per-workload token-bucket
rate limits from the `capacity` values (maintainer decision, ADR-335 D8; defaults
derive from cluster size).

## Packet evidence funding

An authored packet reserve funds
`records = min(context bytes / 1544192, context objects / 4)` records,
`min(context bytes, records * 9928704)` evidence bytes and `records * 4`
objects ([ADR-257](../decisions/257-approved-recording-funding.md)). 1,544,192
and 9,928,704 bytes are per-record footprint estimates derived from the
artifact format (internal estimates, ADR-335 D2); the byte and object budgets
bound the record count. The packet output of one record or save is the
capture's configured duration × its configured ring/segment size, bounded by
the workload's storage share; there is no fixed output cap.

## Saved settings of accepted captures

Saving the authored settings of an already accepted capture
([ADR-301](../decisions/301-accepted-history-metadata-capacity.md)) charges
metadata against the capture's existing workload account in the history
transaction. It is not a new collection admission and needs no live workload.

## Queries and downloads

Approved queries and downloads use the [query capacity](context-query-capacity.md)
limits. They do not consume collection admission and are not gated by live
workload capacity.
