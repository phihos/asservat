# Permission observation and acceptance

Scope: C-01 owns observation and acceptance, C-03 evaluates current
projections, C-20 carries the wire DTOs, C-21 implements the Kubernetes and
SQL adapters and C-24 holds the values. Parts of REQ-PER-001 to REQ-PER-008,
REQ-DB-001 and TASK-07. Kubernetes is the only permission authoring surface;
the hub stores an accepted projection and evaluates it per operation. Design
rules: [ADR-329](../decisions/329-accessbindings-in-application-namespaces.md)
and [ADR-330](../decisions/330-event-driven-system-design.md) D1, D5, D6, D11,
[ADR-335](../decisions/335-usable-by-default.md) D4, D14.

## Sources

| Source | Where it lives | Who writes it |
| --- | --- | --- |
| AccessBinding | The application namespace it grants access to, in the workload's cluster | Anyone ordinary namespace RBAC lets write AccessBindings there |
| AccessBinding with `spec.automation` (ADR-059) | The application namespace it grants access to | Namespace writers who also hold `bind` on `accessroles.asservat.io` named `automation` |
| ClusterAccessBinding | Cluster-scoped, in a workload cluster (that cluster) or the hub cluster (named clusters or all) | Principals with cluster-scoped write access and `bind` on the roles |
| PermissionSource (`namespaceMetadata`, `workloadMetadata`, `kubernetesExec`, `kubernetesAccessReview`) | Hub control namespace | Asservat administrators only (ADR-328) |
| `identity.administrators` | Helm values | The chart operator |

A binding's scope is its own namespace, optionally narrowed to workloads
named by kind and name; it names no cluster or namespace UID. Subjects are
users by username and groups by name; `issuer` defaults to the installation's
issuer. A ClusterAccessBinding's scope is its cluster's namespaces matching its
optional `namespaceSelector`, and in the hub cluster the clusters it names.
A Helm-rendered
ValidatingAdmissionPolicy requires `bind` on `accessroles.asservat.io` for
each role a binding adds or changes, and `bind` on `automation` for an added
or changed `spec.automation`; the chart never aggregates `automation` into
`admin` unless `permissions.aggregateAutomation` is set
([REQ-PER-001](../../specs/permissions.md)). The chart ships one bindable
ClusterRole per role (`asservat-bind-<role>`).

The generated structural CRDs and their reviewed CEL rules validate shape
only (`make permission-crd-check`). Who may write a resource is decided by
Kubernetes RBAC and the `bind` admission policy above; there is no
delegation envelope, dry-run probe, bootstrap review object or namespace UID pin.
Objects that exist before the hub first starts, for example synced by GitOps
before the chart, are accepted on first observation like any later object.
Namespace labels that `namespaceMetadata` sources read are protected by the
Helm-installed admission policies of ADR-247; Asservat does not prove those
policies at runtime. Status fields, field managers and annotations never
confer authority.

## Observation

Each region's connector runs client-go shared informers for AccessBindings and
ClusterAccessBindings in its cluster and for the namespace labels and workload metadata that accepted
PermissionSources select (only the selected keys are kept; values are
SHA-256 digests). The hub-worker runs informers for PermissionSources in
the hub control namespace and for ClusterAccessBindings in the hub cluster.
An informer LISTs once and then
WATCHes; it relists only after a watch restart or `410 Gone`. Its cache stays
valid while the informer is synced and becomes unavailable only when the
watch is lost and the relist has not completed.

The connector pushes changes over its hub connection
([regional-context-start.md](regional-context-start.md)). After a reconnect
it sends a digest of its current projection and resends the full projection
only on mismatch. Per-object payloads keep the object UID, resourceVersion,
generation, deletion state and the SHA-256 of the RFC 8785 canonical spec;
free-text reasons count toward the digest but are not stored.

Fail-closed bounds (no silent truncation): 1,024 bindings per namespace,
1,024 ClusterAccessBindings and 1,024 sources per cluster, 64 KiB per spec, at
most 32 selected label keys per source, 65,536 namespaces carrying a selected
key per cluster, 256 rows for one Pod. Delivery and storage are paged, so the
number of namespaces and bindings per cluster is otherwise bounded only by
memory. An overflow rejects only the offending namespace's bindings (or the
offending source) with a narrowing diagnostic, never by dropping an owner or a
deny, and never the rest of the cluster. A malformed object is reported as invalid; valid objects of the
same kind stay usable. A terminating deny stays effective until it is gone.

## Acceptance

`PermissionStore` applies each pushed or watched change in one SQL
transaction: an idempotent upsert keyed by (cluster, object UID) that is
ignored when the stored resourceVersion is already current, plus one
append-only audit row naming the object, its spec digest and the resulting
basis changes ([operation-audit.md](operation-audit.md)). Denies, removals
and new allows take effect at commit and notify hub processes with
`LISTEN/NOTIFY` in the same transaction. One hub-worker replica runs the
acceptance controllers, elected with client-go `leaderelection` on a Lease;
idempotent upserts make a duplicate delivery after a leader change
harmless, so no SQL controller epoch is needed. The controller writes each
object's `status.observedGeneration` and `Ready` condition after its
generation is accepted (REQ-PER-002); application-namespace bindings get
their status from the connector once the hub acknowledges the push.

A PermissionSource spanning namespaces records one basis per namespace or
workload and keeps the source UID as provenance. A source whose inputs are
unavailable (watch lost, connector disconnected) keeps its rows and grants
nothing until the informer is synced again. The deny set is fed by the same
watch events and pushes and stays valid until replaced; when it is
unavailable, allow evaluation for that cluster fails closed. No interval
renews or expires it.

## Evaluation

C-03 evaluates the current accepted bindings and sources per operation.
Evidence audiences and share managers are recorded at capture or share time
as identity-provider group names and subject identifiers, never as
assignment IDs. An ordinary read requires a recorded audience member (or an
EvidenceShare) who also holds a current matching allow and no deny. A new
owner team therefore sees only evidence captured after it was granted;
older evidence needs an explicit share or ownership decision (REQ-PER-008).
A relist, a harmless binding edit or an A → B → A change neither revokes nor
reissues access: the current bindings decide. Share management passes to an
administrator only when the managing group no longer exists. The
authorization result is reused for at most `identity.AuthorityRecheckInterval`
within the operation's original deadline (ADR-311).

Explicit bindings match namespace and optional workload kind/name; the
workload UID current at evaluation is recorded as provenance, and an optional
`uid` pin must equal it. Namespace sources match exact selector values and
exclusions; value maps keep several owner teams and never split
comma-separated group names; `groupName` mode takes the value (with the
configured prefix) as one group name. `workloadMetadata`
sources match one workload per basis.

## Decision-time sources (pod exec inheritance)

`kubernetesExec` and `kubernetesAccessReview` sources carry no subjects. For
an operation on a Pod, C-03 asks the target cluster's connector whether the
principal holds the configured Kubernetes permission (for exec,
`create pods/exec`) on that Pod. The connector caches an allowed review per
(principal, groups, attributes) for at most `identity.AuthorityRecheckInterval`
(30 s, ADR-311); denials are not cached; a miss runs a SubjectAccessReview.
This is the only time-bounded permission cache. An allow adds a `Reviewed` user allow for that principal and Pod to the
current evaluation only; nothing is stored per decision. At capture time the
connector also reviews each of the principal's current groups alone (at most
256, batched) to record the groups that hold the same right as audience
(REQ-PER-008). A source mapped to another role (`evidence-owner`,
`action-approver`) contributes that role the same way. The operation that
used the decision records it in its own audit row.

## Automation envelopes

An automation-bearing AccessBinding in an application namespace carries the
typed envelope of ADR-059 ([policy-automation.md](policy-automation.md)). The
envelope is part of the accepted basis and of the audit row; editing it
changes the basis immediately for later policy evaluations.
