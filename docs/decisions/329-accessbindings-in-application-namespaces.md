# ADR-329 — AccessBindings in application namespaces

Date: 2026-11-13. Status: accepted (maintainer decision); implemented
2026-11-14 for the hub cluster and for workload clusters joined with
`mode: cluster` (see Implementation and decision (c)). Supersedes the hub-control-namespace storage of
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
  binding's namespace once per binding UID. A binding whose namespace is
  gone, lacks timestamps or was created after the binding (a later
  incarnation) grants and denies nothing; it does not stop the stream.
  PermissionSources stay in the release namespace.
- The bind check covers roles and automation that a CREATE or UPDATE adds
  or changes; metadata-only updates (finalizers, labels) pass, as for
  RoleBindings, whose roleRef is immutable.
- Any namespace writer can store a binding the embedded schema refuses; it
  is kept as an invalid entry that grants and denies nothing instead of
  stopping the whole stream. The shared bounds (1,024 bindings, 4,096 rows,
  8 MiB) are a cluster-wide limitation; `count/accessbindings.asservat.io`
  ResourceQuotas bound a namespace.
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
LIST to the hub every 10 seconds over the existing connector lifecycle
channel (ADR-169), as a new purpose `access-bindings`:

- The connector already presents its cluster credential on that channel
  (ADR-168, exporter-bound signature, checked under the SQL lineage lock).
  The federation asks for the delivery only after that check and stores it
  under the lineage's cluster ID. The payload names no cluster; a delivery
  for the hub cluster is refused (the hub-worker observes it directly).
- The connector uses the hub cluster's LIST code: paginated, 1,024 objects,
  8 MiB, each binding's namespace UID read once and a younger namespace
  refused. The chart grants `get/list/watch accessbindings` to the
  connector's ClusterRole in `mode: cluster` only.
- The federation validates every spec with the same embedded schema: a
  refused spec becomes an invalid entry that grants and denies nothing. A
  delivery over 1,024 bindings or 4,096 subject-role rows is refused.
- The delivery is observed no later than the hub's own presentation check
  (`CheckedAt`, database clock), so connector clock skew cannot lengthen it.
  It is stored in `remote_access_binding_delivery` (migration 00161), one row
  per cluster; an older delivery never replaces a newer one.
- The hub-worker's permission reconciler reads the rows every second (a
  digest query; bindings are decoded only when they change) and adds each
  cluster's bindings to the same accepted batch as the hub cluster's,
  scoped to that cluster. Allows grant only within the ADR-311 window
  (`identity.Check(observedAt, identity.Recheck)`, 30 s); denies stay until a
  later delivery removes them, so a connector outage never lifts a deny. A
  cluster whose bindings do not fit the stream's remaining 1,024 bases and
  4,096 rows contributes nothing rather than a partial set.
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
5. Privilege: `get/list/watch accessbindings` on the workload-cluster
   connector; the federation's existing `cluster-credential` login gets
   SELECT/INSERT/UPDATE on one table, the hub-worker's `permission-accept`
   login SELECT. No new credential, endpoint, listener or exposure.
6. Degraded states: one, a stale delivery (its allows lapse, its denies
   stay); an over-budget cluster grants nothing.
7. No configuration.
8. Depends on the connector reaching the federation, which every
   `mode: cluster` function already needs.
9. Per cluster: one LIST and one lifecycle conversation per 10 s (bounded by
   8 MiB; typical deliveries are kilobytes), one upsert; the hub-worker runs
   one digest query per second and decodes only changed rows. Linear in
   clusters; one federation conversation slot for at most the LIST duration.
10. Upgrade adds a table; downgrade drops it; without deliveries remote
    bindings grant nothing, as before.
11. Smaller alternatives (documenting the gap, PermissionSources only) leave
    the regression in place.

Known limits: a remote allow change reaches the hub within about 11 s (one
delivery interval plus one reconciler tick) and lapses 30 s after the last
delivery; a deny created during a connector outage applies only after the
next delivery. Decision-time review sources (`kubernetesExec`) of that
cluster are not gated on the delivery.
