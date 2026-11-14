# Retention

C-01 owns the policy source (observation and acceptance), C-15 owns effective
evidence deadlines and their application to existing artifacts, C-21 supplies
the Kubernetes and SQL adapters and C-24 the policy and deadline types. This
implements REQ-PRV-001–004, REQ-DB-002/004/005 and the retention parts of
REQ-DLD-004 under [ADR-055](../decisions/055-retained-evidence-cutoffs.md) and
[ADR-330](../decisions/330-event-driven-system-design.md) D1, D5, D6 and D12.

## Policy source

`EvidenceRetentionPolicy` is a namespaced CRD. The hub source is the hub
control namespace; a cluster may add one local source in its connector
namespace. Both namespaces are administrator-only
([ADR-328](../decisions/328-administrator-only-namespaces.md)), so Kubernetes
RBAC decides who writes policies. The CRD schema and CEL rules validate shape
only: bounded selectors, named rule-list identity and a deletion budget that
leaves positive usable time. `status.observedGeneration` and conditions report
what the hub has applied; status is informational and never authority.

Which sources apply to a cluster (the hub source, plus the cluster's local
source or none) is a column of the cluster's SQL registration, set from Helm
values at installation. Requests never select sources, and a missing local
decision never falls back to a hub-only intersection.

The hub runs one shared informer on the hub source; each connector runs one on
its local source and pushes changes over its hub connection
([connector connection](regional-context-start.md)). The informer lists once,
then watches. Its cache stays valid while the watch is established and is
replaced or invalidated only by watch events; it does not expire with time. A
watch failure marks the source unavailable until the relist completes. The
resume cursor stays in memory; after a restart the controller relists.
Bookmarks are not persisted.

The policy controller runs under client-go `leaderelection` on a Lease. Its SQL
writes are idempotent upserts keyed by policy UID and `metadata.generation`, so
a replaced leader repeats nothing and needs no epoch fence.

Each accepted spec change (a new generation, a creation or a deletion) is one
SQL policy-revision row plus one append-only audit row in the same
transaction. Status-only and bookmark events write nothing. The hub source must
contain exactly one empty-scope baseline; without it new collection stops and
existing deadlines stay bound.

## Matching

Matching follows [the privacy specification](../../specs/privacy.md): selector
dimensions are ANDed, cluster IDs and rules ORed, all matching policies apply
and the shortest maximum wins. Local policies only tighten the hub baseline. At
most 64 applicable policy references are allowed per artifact; overflow fails
planning and is never truncated.

Selectors match against the namespace and workload labels the connector
delivers. At admission, the artifact row stores the target identity, the
selector-relevant namespace and workload labels, the applicable policy UIDs and
generations, and the resulting deadlines. Later policy changes match against
these stored labels, so a newly selected label selector can always be evaluated
for existing evidence and later label edits cannot lengthen retention.

## Stored deadlines

Each artifact row keeps its original registration dates and stores the
effective read cutoff (`effective_expires_at`), the effective deletion deadline
(`effective_delete_by`) and a `retention_sequence`. Insert initializes the
effective dates from the registration. SQL triggers reject rewritten
registration dates, increased effective dates and skipped sequence numbers.
Effective dates are monotonic: they only shorten and never extend past the
original dates.

A larger cleanup budget is reserved inside the already-bound deletion deadline;
a relaxed maximum never moves that deadline outward. If the budget consumes the
whole lifetime, the read cutoff becomes the acquisition anchor and cleanup is
due at once, with the original hard deadline unchanged.

## Applying a policy change

When a policy event is accepted, C-15 computes the restrictive effect and
applies it with set-based statements:

```sql
UPDATE custody_attempt
SET effective_expires_at = LEAST(effective_expires_at, $read_cutoff_expr),
    effective_delete_by  = LEAST(effective_delete_by,  $delete_expr),
    retention_sequence   = retention_sequence + 1
WHERE <stored-label and class/type match>
  AND (effective_expires_at > $read_cutoff_expr OR effective_delete_by > $delete_expr)
LIMIT <batch>;   -- via a keyed subselect, repeated until no row changes
```

Each batch writes one append-only `retention_decision` row with the policy
revision, the number of rows changed and the earliest new dates, in the same
transaction. No per-artifact signed or encrypted journal exists. A longer
maximum, a new default or a deleted override changes no row; deleting the
only baseline stops new collection and shortens nothing. Unchanged or relaxed
policy creates no decision.

## Effects

Capture admission resolves the current policy set from the informer cache and
stores the result on the new row. Every later effect (verification,
publication, catalog visibility, download reservation, deletion claim) compares
database `now()` with the row's stored effective dates inside its own
transaction. No retention proof, topology read or source-readiness check runs
inside effect transactions.

A started download continues under its original authorization
([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md)) and
ends at the stored read cutoff it was admitted with. A shortening that lands
during the stream reaches it as a `LISTEN/NOTIFY` event on the session and ends
it at the new cutoff.

Deletion becomes claimable at the effective read cutoff and is due at the
effective deletion deadline. The deletion claim carries both the original and
the effective dates. A shortening never releases storage by itself; the charge
is released when deletion completes.
