# ADR-329 — AccessBindings in application namespaces

Date: 2026-11-13. Status: accepted (maintainer decision); implemented
2026-11-14 for the hub cluster (see Implementation). Supersedes the hub-control-namespace storage of
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
  binding's namespace once per binding UID and refuses a namespace created
  after the binding (a later incarnation). PermissionSources stay in the
  release namespace.
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
- Pending: workload clusters joined with `mode: cluster`. Their connectors do
  not yet serve the cluster-observation channel (the namespace and workload
  journals of ADR-247 are equally uncomposed), so AccessBindings there grant
  nothing; PermissionSources (for example `kubernetesExec`) cover them until
  the connector delivers its cluster's bindings with that channel.
