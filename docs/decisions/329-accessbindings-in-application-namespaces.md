# ADR-329 — AccessBindings in application namespaces

Date: 2026-11-13. Status: accepted (maintainer decision); implemented
2026-11-14 for the hub cluster and for workload clusters joined with
`mode: cluster` (see Implementation and decision (c), revised 2026-11-14 to
watch-driven delivery without expiry). Supersedes the hub-control-namespace storage of
AccessBindings in `specs/permissions.md`, the delegated-writer envelope of
ADR-189/ADR-237 and the permission guard.

## Decision

AccessBindings live in the application namespace they grant access to, in the
workload's own cluster, like Kubernetes RoleBindings. Teams that may write
AccessBindings in their namespace (ordinary Kubernetes RBAC, typically the
same people who manage that namespace's RoleBindings) manage Asservat access
for it. The Asservat namespaces stay administrator-only (ADR-328).

Consequences:

- A binding's scope is its own namespace; it no longer names a cluster or a
  namespace UID. The hub learns bindings through each region's connector,
  which observes AccessBindings in its cluster and delivers them with the
  existing permission observation.
- The delegation envelope and the permission admission guard go. Kubernetes
  RBAC decides who may write in a namespace. Cluster-wide or multi-namespace
  grants use PermissionSources, which stay administrator-managed.
- Automation-bearing bindings and escalation are decided below.

## Decision (a): automation-bearing bindings

Namespace RBAC also governs `spec.automation`, with one extra right: the
writer needs `bind` on the virtual resource `accessroles.asservat.io` named
`automation` in that namespace. The chart ships a non-aggregated ClusterRole
granting it, which an administrator binds per namespace. This keeps ADR-059's
rule that ordinary delegated writers cannot create automation envelopes,
without a second observation path for hub-namespace bindings whose scope is
not their own namespace. It reuses the check of decision (b) and adds no
runtime state.

## Decision (b): escalation

External evidence (2026-11-14):

- Kubernetes RBAC refuses a RoleBinding unless the writer holds the role's
  permissions or the `bind` verb on it
  ([RBAC docs](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping)).
  CertificateSigningRequest approval uses the same pattern on a virtual
  resource: `approve` on `signers` named after the signer
  ([CSR docs](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)).
- cert-manager's approval webhook checks `approve` on the virtual resource
  `signers.cert-manager.io` named after the issuer
  ([source](https://github.com/cert-manager/cert-manager/blob/master/internal/webhook/admission/certificaterequest/approval/certificaterequest_approval.go));
  approver-policy checks `use` on a policy name with a SubjectAccessReview.
- Rancher's webhook refuses ProjectRoleTemplateBindings and
  ClusterRoleTemplateBindings with more rights than the writer holds and
  skips that check for writers with `bind` on the role
  ([rancher/webhook docs](https://github.com/rancher/webhook/blob/main/docs.md)).
- Capsule's tenant owners cannot edit the Tenant that defines their extra
  RoleBindings ([permissions](https://projectcapsule.dev/docs/tenants/permissions/)).
  Argo CD limits apps-in-any-namespace by the administrator-managed AppProject
  `sourceNamespaces`, with no per-writer check
  ([docs](https://argo-cd.readthedocs.io/en/stable/operator-manual/app-any-namespace/)).
  Kyverno and Crossplane define no such check for their resources.

Comparable systems do prevent it, and the common form is a `bind`-style verb
on a named virtual resource checked against the requesting user. Asservat
uses that form natively: a Helm-rendered ValidatingAdmissionPolicy (GA since
Kubernetes 1.30; the chart requires 1.35) whose CEL `authorizer` requires
`bind` on `accessroles.asservat.io/<role>` in the binding's namespace for each
role, on CREATE and UPDATE. Asservat roles are not Kubernetes permissions, so
the "holds the role" alternative of RBAC does not apply. DELETE is not
checked, as for RoleBindings; the namespace controller must remove a deleted
namespace's bindings. The chart aggregates write access and `bind` on the four
roles into `admin`, read access into `view`, `edit` and `admin`.

This is platform admission, not a guard proof: the hub does not verify the
policy, and an administrator who removes it accepts that namespace writers
grant any role there. It adds no runtime component, request or state.

## Implementation

- CRD: `spec.scope` is gone; optional `spec.workloads` narrows the binding.
  The scope is the observing cluster, `metadata.namespace` and that
  namespace's UID.
- The hub-worker LISTs and watches AccessBindings in every namespace of the
  hub cluster (ClusterRole `get/list/watch accessbindings`). It reads a
  new binding's namespace once for all bindings in that namespace in a LIST,
  then remembers the placement for its UID. A binding whose namespace is
  gone, lacks timestamps or was created after the binding (a later
  incarnation) grants and denies nothing; it does not stop the stream.
  PermissionSources stay in the release namespace.
- The bind check covers roles and automation that a CREATE or UPDATE adds
  or changes; metadata-only updates (finalizers, labels) pass, as for
  RoleBindings, whose roleRef is immutable.
- Any namespace writer can store a binding the embedded schema refuses; it
  is kept as an invalid entry that grants and denies nothing instead of
  stopping the whole stream. Administrators can use Kubernetes
  `count/accessbindings.asservat.io` ResourceQuotas in individual namespaces.
- Removed: the delegation envelope (`identity.permissionDelegations`,
  hub-worker `delegations`, hub-api `permissionDelegations`), the permission
  admission policy builder and the delegated previewers. The permission
  impact preview is for fleet operators; an AccessBinding change names its
  `clusterID` and `namespace`.
- Workload clusters joined with `mode: cluster`: see decision (c).

## Decision (c): workload clusters joined with `mode: cluster`

Date: 2026-11-14. The first implementation read AccessBindings in the hub
cluster only, so bindings in a joined workload cluster granted nothing, a
regression against the earlier `scope.clusterID` bindings stored in the hub.

Each `mode: cluster` connector delivers its cluster's complete AccessBinding
LIST to the hub over the existing connector lifecycle channel (ADR-169), as a
new purpose `access-bindings`, whenever it changes (maintainer correction
2026-11-14: no polling where an event source exists):

- The connector watches both binding collections. A change triggers a
  paginated LIST through the same reader as the hub. The connector skips
  bindings from an earlier namespace incarnation and enforces its 8 MiB wire
  budget as each page arrives. Bursts coalesce to at most one observation per
  second. Failed reads or deliveries retry after five seconds.
- Before its first LIST, the authenticated connector reads its cluster's
  delivery revision from the hub. Each acknowledged transfer returns the
  revision for the next LIST. The connector submits against the revision it
  held before that source read. Another
  publication or confirmation makes a delayed submission retry from a new LIST.
  The hub compares digests so an unchanged set only needs a confirmation.
  Kubernetes pagination holds no federation slot or database connection.
  An idle watch needs no hub requests.
  Both binding kinds share the documented wire budget in
  [the permission contract](../../specs/permissions.md).
- The connector presents its cluster credential on that channel (ADR-168,
  exporter-bound signature, checked under the SQL lineage lock). The
  federation asks for the delivery only after that check and stores it under
  the lineage's cluster ID. The payload names no cluster; a delivery for the
  hub cluster is refused (the hub-worker observes it directly). The chart
  grants `get/list/watch accessbindings` to the connector's ClusterRole in
  `mode: cluster` only.
- The federation validates every spec with the same embedded schema: a
  schema-invalid spec becomes an inert entry. A stored Deny with an
  unrepresentable subject makes its scope unavailable as specified in
  [permission management](../../specs/permissions.md).
- It is stored in `remote_access_binding_delivery` (migration 00162), one row
  per cluster; an older delivery never replaces a newer one. A trigger
  (migration 00163) notifies `asservat_remote_bindings` in the writing
  transaction.
- The hub-worker's permission reconciler LISTENs on that channel on its own
  connection and rereads the rows on a notification, when the connection is
  (re)established and at the start of each epoch; it no longer reads them on
  its one-second tick. It adds each cluster's bindings to the same accepted
  batch as the hub cluster's, scoped to that cluster. The last delivered set
  stays in effect, allows included, until a newer delivery replaces it:
  connector liveness is a health signal, not authority; every new remote
  action needs the connector anyway, and expiring allows broke stored-evidence
  reads during connector outages. A cluster reporting an incomplete or oversized
  observation becomes unavailable until its next complete delivery.
- The escalation ValidatingAdmissionPolicy and the aggregated ClusterRoles
  render in every mode.

Precedent: Open Cluster Management's klusterlet keeps the managed cluster's
key and reports status into the hub's per-cluster namespace under its own
identity ([architecture](https://open-cluster-management.io/docs/concepts/architecture/));
Karmada's pull-mode `karmada-agent` reports its cluster's status to the
control plane ([cluster registration](https://karmada.io/docs/userguide/clustermanager/cluster-registration/)).
Both attribute an agent's report to the cluster its credential names, as here.

Rejected: the ADR-247 cluster-observation channel (per-exchange SQL
registration reads, four fresh proofs, owner routing), because this
attribution needs only the existing cluster credential check; and a
hub-initiated pull, because connectors are outbound-only.

Complexity gate:

1. Problem: every AccessBinding in a joined workload cluster grants nothing
   (deterministic, all `mode: cluster` users), a regression.
2. Not accepted as a limitation; the maintainer asked for parity.
3. Typical deployments with more than one cluster.
4. OCM and Karmada agents report per-cluster state under their own identity
   (above).
5. Privilege: `list/watch accessbindings,clusteraccessbindings` on the workload-cluster
   connector; the federation's existing `cluster-credential` login gets
   SELECT/INSERT/UPDATE on one table, the hub-worker's `permission-accept`
   login SELECT. No new credential, endpoint, listener or exposure.
6. Degraded states: one, an unreachable connector (its last delivered set
   stays in effect until it delivers again). A connected reporter unable to send
   a complete set names that condition in the same authenticated exchange.
   The projection records just the unavailable cluster IDs beside its existing
   revision. Fresh decisions for those clusters fail until a complete delivery
   is accepted. This requires no additional credential, decision-time SQL
   round trip or background reconciliation.
7. No configuration.
8. Depends on the connector reaching the federation, which every
   `mode: cluster` function already needs.
9. Per cluster: one watch per binding kind on the member's API server; one
   LIST and one lifecycle conversation per change (at most one per second,
   bounded by 8 MiB; typical deliveries are kilobytes), plus one digest
   comparison per connector start; one upsert and one notification per
   delivered change; the hub-worker holds one LISTEN connection and reads
   rows only on a notification. Linear in clusters.
10. Upgrade adds a table; downgrade drops it; without deliveries remote
    bindings grant nothing, as before.
11. Smaller alternatives (documenting the gap, PermissionSources only) leave
    the regression in place.

Known limits: a remote change reaches the hub within about a second of the
watch event while the connector is connected; a binding removed during a
connector outage keeps granting until the next delivery, and a deny created
during an outage applies only after it (connector liveness is not authority). Decision-time review sources (`kubernetesExec`) of that
cluster are not gated on the delivery.
