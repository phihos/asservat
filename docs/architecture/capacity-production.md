# Capacity production

C-07 turns the administrator's `EvidenceStoragePool` and `EvidenceBudgetPolicy`
resources into per-workload SQL capacity accounts
([REQ-CAP-004 through REQ-CAP-006](../../specs/capacity.md)). C-01 supplies the
accepted resources; C-20 owns the adapters. Mechanisms follow
[ADR-330](../decisions/330-event-driven-system-design.md).

## Inputs

- A-HWORK watches the pool and budget-policy resources with a shared informer.
  An accepted resource stays valid until the watch replaces or deletes it;
  validation errors are written to the resource's status conditions with
  `observedGeneration`.
- Namespaces and workloads of enrolled clusters come from the
  [cluster state push](cluster-observations.md). Candidate discovery is a query
  over that SQL projection, not a Kubernetes LIST.
- Kubernetes RBAC protects the resources; the hub does not re-verify admission
  policies, UIDs or installer receipts.

## Reconciliation

The capacity reconciler runs in A-HWORK and reacts to events: a pool or policy
change, a pushed workload or namespace change, or a workload deletion. For each
affected workload it:

1. selects exactly one matching budget policy (`CapacityNotAllocated` when none
   matches, `AmbiguousBudgetProfile` when several match);
2. creates or updates the workload's capacity account and storage binding in
   one SQL transaction that locks only that workload's account row and, when
   burst limits apply, the pool row;
3. writes the outcome to the policy's status conditions.

The storage binding is SQL state maintained by these events. Admission reads it
under ordinary row checks; it has no freshness interval, readiness wait or
refresh demand. A workload whose binding is missing is reported
`CapacityNotAllocated` at preview.

Changing a selector never creates a second account or detaches retained
charges. Workload deletion or name reuse keeps the account until its retained
evidence is deleted or moved to a backed residual account (REQ-CAP-006).

## Accounting

Each workload account holds byte and object counters for live evidence and a
count of retained capture metadata rows ([context control capacity](context-control-capacity.md)).
Admission charges them with a conditional update (`WHERE used + n <= limit`);
deleting evidence or metadata releases the charge. An effect whose outcome is
unknown is resolved by its idempotency key and its charge is released when the
outcome is known (D7).

Pool rows hold the pool's protected total and shared burst counters. Parent
envelopes subtract unused protected allocations of their children before
granting burst (REQ-CAP-004). Storm protection uses per-workload token-bucket
rate limits from the budget policy.

## Packet evidence funding

An authored packet reserve funds
`records = min(context bytes / 1544192, context objects / 4, 512)` records,
`min(context bytes, records * 9928704)` evidence bytes and `records * 4`
objects ([ADR-257](../decisions/257-approved-recording-funding.md)). This covers
the 8 MiB packet output cap.

## Saved settings of accepted captures

Saving the authored settings of an already accepted capture
([ADR-301](../decisions/301-accepted-history-metadata-capacity.md)) charges
metadata against the capture's existing workload account in the history
transaction. It is not a new collection admission and needs no live workload.

## Queries and downloads

Approved queries and downloads use the [query capacity](context-query-capacity.md)
limits. They do not consume collection admission and are not gated by live
workload capacity.
