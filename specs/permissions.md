# Permission management and automatic inheritance

This specification defines application permissions inside one organization; there is no tenant model. Read with [authorization](authorization.md), [targets](targets.md), [ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md), [ADR-335](../docs/decisions/335-usable-by-default.md) D4/D14 and the [research](../docs/research/permission-automation.md).

Permission state reaches the evaluator through events ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1): the hub watches its own cluster with informers, and each remote connector watches its cluster and pushes changes. The hub keeps each cluster's last delivered set until the connector replaces it. Nothing here expires because time passed.

## REQ-PER-001 — Canonical permission configuration

Administrators (`identity.administrators`, [REQ-AUT-001](authorization.md#req-aut-001--identity-and-ordinary-access)) need no binding; everyone else receives access only through three resources. They configure ongoing access; expiring `AccessGrant` approvals are separate.

An `AccessBinding` lives in the application namespace it grants, in the workload's cluster, like a RoleBinding ([ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md)). It assigns users (by username), groups (by name) or workload identities fixed roles over its namespace, optionally narrowed by `spec.workloads` to Deployments/StatefulSets by kind and name. A workload entry matches whatever workload currently has that name; the matched UID is provenance, and an optional `uid` pins one instance. `effect: Deny` subtracts the named roles' operations. Wildcard subjects are not supported.

A `ClusterAccessBinding` is the cluster-scoped equivalent, like a ClusterRoleBinding: in a workload cluster it grants roles in every namespace matching its optional `namespaceSelector`; in the hub cluster it may name `spec.clusters` (or `*`) to grant a role across the fleet, and may grant `privacy-operator`.

A `PermissionSource` is an administrator-managed derivation rule for one cluster in the hub control namespace: `namespaceMetadata`, `workloadMetadata`, `kubernetesExec` or `kubernetesAccessReview`. Effective decisions are computed, never stored as grants per Pod or member. Existing objects take effect when first observed.

Kubernetes RBAC decides who writes AccessBindings; the Asservat namespaces are administrator-only ([ADR-328](../docs/decisions/328-administrator-only-namespaces.md)). A Helm-rendered ValidatingAdmissionPolicy requires, on CREATE and UPDATE of an AccessBinding or ClusterAccessBinding, `bind` on the virtual resource `accessroles.asservat.io` named after each added or changed role (and `automation` for a changed `spec.automation`), as Kubernetes does for RoleBindings ([RBAC escalation prevention](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping)). The chart ships one `asservat-bind-<role>` ClusterRole per role plus `asservat-bind-automation`, and aggregates binding write access into the namespace `admin` ClusterRole and read access into `view`, `edit` and `admin`; `permissions.aggregateAutomation` also aggregates `asservat-bind-automation` into `admin`. DELETE is not checked. Denies override all allows, including shares. Optional `CollectionCeiling` rules restrict collection further; without them every namespace outside the chart's excluded system namespaces is collectable.

| Role | Operations granted within scope |
| --- | --- |
| `evidence-reader` | Discover permitted cases and read metadata/extracts; no collection, sharing or raw access |
| `workload-maintainer` | Reader and owner operations; manage collection policies; collect approved ordinary evidence; request intrusive capture and raw-query grants |
| `evidence-owner` | Reader operations; create and manage shares and capture/policy sharing instructions (REQ-SHR-008); raw sharing still needs review. For teams that own evidence without collecting it |
| `action-approver` | Review intrusive capture, raw-query, raw-sharing and policy-grant requests in scope; no evidence reading and no self-approval |
| `privacy-operator` | Installation-wide privacy workflows ([REQ-PRV-006](privacy.md#req-prv-006--rights-requests-and-restricted-processing)); granted only by a hub-cluster ClusterAccessBinding; administrators hold it implicitly |

A role is never an active intrusive or raw-query grant. `workload-maintainer` makes a caller eligible to request raw access; raw operations still need a grant, an approved raw share or the equivalent Kubernetes right ([REQ-AUT-002](authorization.md#req-aut-002--authorization-composition)). Users cannot relabel a sensitive action as ordinary.

### SC-PER-001

Given a provisioning identity with `admin` in the payments namespace, when it creates a binding there naming group `/payments` and workload `Deployment/api`, then the binding grants once the cluster's bindings reach the hub, and still grants after `api` is deleted and recreated. A binding in payroll, a role it lacks `bind` for, an automation envelope without `bind` on `automation`, or a PermissionSource change is refused by Kubernetes RBAC or admission for kubectl, GitOps and other API clients. A deny removes the matching operation even if another source permits it. One hub-cluster ClusterAccessBinding granting group `/sre` `action-approver` in every cluster lets that group approve in every namespace of every joined cluster.

## REQ-PER-002 — Kubernetes administration and effective access explanation

The Kubernetes API is the only permission-configuration interface, with its authentication, RBAC, admission, list/watch, server-side apply and resourceVersion conflicts. There is no second permission HTTP API, OAuth scope or change journal; Kubernetes audit attributes changes. The CRDs publish structural schemas, `kubectl explain` descriptions and printer columns (TASK-07).

Status uses `observedGeneration` and conditions (`Ready`, `Rejected`, `UnsafeSource`); `Ready=True` means the hub has applied that generation.

`explain_access` (MCP and browser, [ADR-234](../docs/decisions/234-access-explanation.md)) explains the caller's own access to a named cluster, namespace and workload for `capture`, `read` or `download`. It resolves the same whole-pod target as `preview_capture` and returns the decision, the unmet condition (`NoMatchingAllow`, `ExplicitDeny`, `ClientScopeMissing`, `ClusterNotObserved`, `IdentityUnavailable`, `ServiceUnavailable`), the roles that permit the operation and the caller's own contributing allows or deny. Without a matching binding or source, and for an unknown workload, the reply is uniformly `Deny`/`NoMatchingAllow`.

`preview_access_change` (browser only, administrators, [ADR-237](../docs/decisions/237-permission-impact-preview.md)) evaluates proposed AccessBinding, ClusterAccessBinding or PermissionSource creates, updates or deletes against the current permission snapshot with the real evaluator. Per affected namespace it evaluates every named workload plus one cell for all others, for each subject whose access changes, and returns paged before/after rows naming targets, subject, operation, decisions and deciding objects. Cells of clusters whose state has not reached the hub are `Indeterminate`; a proposed metadata source asks the connector for current key values; a review source is `Indeterminate` (`DecisionTimeSource`). Admission is not simulated. Namespace teams use `kubectl --dry-run=server` and `explain_access`.

### SC-PER-002

Given two clients replacing one resourceVersion, when both write, then one succeeds and the other receives Conflict. Dry-run starts nothing; a persisted binding reports `Ready` only for the generation the hub applied. A developer without hub Kubernetes access can explain their own access without discovering another team's inventory.

### SC-PER-009

Given a maintainer whose group holds `evidence-reader` on a workload, when they call `explain_access` for `read`, then the result is `Allow` naming that binding; for `capture` it is `Deny` with `ClientScopeMissing` or `NoMatchingAllow` and the required role `workload-maintainer`. When a deny naming their group is added, `read` is `Deny`/`ExplicitDeny` naming that deny. A user with no matching binding receives the same `Deny`/`NoMatchingAllow` reply as for a workload that does not exist.

### SC-PER-010

Given an administrator and a namespace where group team-a holds `workload-maintainer` through a namespace-wide binding, when they preview deleting that binding, then every workload cell without another binding for team-a shows `Allow` → `Deny` for capture, read and download, and a workload that another binding still covers shows no change. A proposed deny naming team-a shows `Allow` → `Deny`/`ExplicitDeny`. A cell of a cluster whose state has not reached the hub, and a proposed PermissionSource of a disconnected cluster, are `Indeterminate`, never `Allow`; a proposed source mapping an owner value present on a namespace shows `Deny` → `Allow` for that team in each mapped namespace without the source being applied. Larger results are paged through `next_cursor`; a caller who is not an administrator receives `AdministratorRequired` before any permission data is read; MCP does not offer the operation.

## REQ-PER-003 — Namespace metadata inheritance

A `namespaceMetadata` source reads a configured label or annotation key on namespaces matching its selector and exclusions, and resolves the value into groups of the installation's issuer through an explicit value-to-group map or `groupName` mode (the value, with an optional prefix, is the group name). Values never select roles, issuers, actions or administrator authority. Missing, malformed or ambiguous values grant nothing. Namespaces created by a provisioner inherit permissions as soon as their metadata reaches the hub, including future workloads.

Each source names a protection mode:

- `administratorManaged`: the administrator states that only trusted administrators or provisioners write namespaces and the relevant metadata.
- `admissionEnforced`: the Helm-rendered namespace label ValidatingAdmissionPolicy stops non-administrators from creating namespaces with, or changing, the source's selector and mapping keys. Labels only; an annotation key is `SourceUnsupported`.

The hub-worker and each connector watch namespaces with informers and push changed key values (as SHA-256 digests). A source grants nothing until its cluster's namespace metadata has reached the hub.

### SC-PER-003

Given an enabled source reading an administrator-managed ownership label, when the provisioner creates a namespace for the payments group, then members gain only the configured role there once the namespace event reaches the hub. A developer changing unrelated workload labels gains nothing. With `admissionEnforced`, an unauthorized edit or removal of the ownership key is refused by admission.

## REQ-PER-004 — Exec-based and generic Kubernetes inheritance

`kubernetesExec` maps verified exec authorization to `workload-maintainer` on the whole selected Pod. The target cluster's connector submits a SubjectAccessReview for the human:

```yaml
resourceAttributes:
  group: ""
  version: v1
  resource: pods
  subresource: exec
  verb: create
  namespace: payments
  name: payments-api-7d9f-example
```

`identityMappingRef` names a connector identity mapping (`cluster.identityMappings`): Kubernetes user = `usernamePrefix` + the username claim (or subject, matching the cluster's `--oidc-username-claim`), groups = `groupsPrefix` + each current group plus `system:authenticated`. Clients cannot supply Kubernetes identities; an ambiguous mapping denies. No impersonation is used. The connector gets `create subjectaccessreviews` only when mappings are configured.

Only `allowed: true` without `denied` allows; errors and no opinion deny. `get`-only exec, `nodes/proxy`, port-forward and Pod read rights are not equivalent. The administrator states that exec is whole-pod in this cluster (`admissionParity.mode: noAdditionalRestrictions`); container-confined exec is `UnsafeSource`. Manual intrusive collection still needs its one approval. The same review is the equivalent Kubernetes right of [REQ-AUT-002](authorization.md#req-aut-002--authorization-composition).

`kubernetesAccessReview` maps one configured check to any role: `create debugcaptures` in the namespace, or `get`/`patch`/`update` on the exact Deployment/StatefulSet (for example `update deployments` → `action-approver`). Eligibility is never inferred from a role name or SelfSubjectRulesReview.

Review sources are evaluated per decision for the resolved Pod: before preview, request, `explain_access` and each read of evidence collected under the source. The connector caches allowed results per (principal, groups, attributes) for at most `identity.AuthorityRecheckInterval` (30 s, [ADR-311](../docs/decisions/311-operation-authority-recheck.md)); denials are not cached and listings batch reviews. Policy executors and workload principals are never reviewed. Decisions are recorded in the operation's audit row.

Every resolved Pod is evaluated separately. An automatic policy is re-evaluated for each replacement Pod under its executor. Source eligibility never waives intrusive approvals and never grants node access or permission administration.

### SC-PER-004

Given a user who can `create pods/exec` only for Pod A, when a selector resolves A and B, then B is never observed or collected. A false or erroring review, a spoofed group, a `get`-only grant or a container-confined exec restriction cannot authorize A. A permitted live dump still waits for its approval. An approved automatic policy rechecks each replacement replica under its executor. A teammate in a recorded group who also holds exec on the workload reads the capture.

## REQ-PER-005 — Workload ownership and integration adapters

`workloadMetadata` applies the same mapping to Deployment/StatefulSet metadata in shared namespaces. It requires `admissionEnforced` (the chart renders the workload label ValidatingAdmissionPolicy when workload keys are configured) and a non-empty `workloadSelector`. Connectors watch matching workloads and push key values. Pods are never matched by labels: the workload is derived through the Pod's validated controller chain.

GitOps, Terraform, provisioners and service catalogs MAY manage AccessBindings through the Kubernetes API within their RBAC. Catalog ownership, CODEOWNERS, field managers and arbitrary labels are not permission evidence. No external catalog, policy engine or SCIM service is required.

### SC-PER-005

Given two applications owned by different teams in one namespace, when protected workload ownership is resolved, then permissions apply only to the matching workload and its validated Pods. Editing a Pod label, copying an ownerReference or supplying a catalog owner string cannot expand scope. An integration cannot write bindings into another team's namespace.

## REQ-PER-006 — Freshness, composition and explainability

An operation requires an eligible identity, a current allow, no deny, local ceilings and all grant/share conditions. Independent allows are unioned; no failure falls back to a broader role.

The evaluator reads one snapshot: the hub cluster's informer caches and each remote cluster's last delivered state. It stays valid until an event replaces it. State that is not yet available (during a hub relist, or before a connector's first delivery) grants nothing and fails closed for that cluster. An operation reuses its snapshot for at most 30 s ([ADR-311](../docs/decisions/311-operation-authority-recheck.md)).

Collection admits each source start once under one snapshot, bounded by every hard end (policy grant, binding `notAfter`, observation grant, local ceiling). When authority is removed the hub pushes a stop; a disconnected connector's source runs to its admitted hard end and gets the stop on reconnect.

An artifact records its complete audience (REQ-PER-008). The audit row records the deciding bindings or sources with their generations.

### SC-PER-006

Given a running ongoing recorder admitted under team-a's binding, when the binding is deleted, then the hub pushes a stop and the recorder ends; new admissions are refused as soon as the deletion reaches the hub. If the connector is disconnected, the recorder runs to its admitted hard end unless the stop arrives first on reconnect. A reconnect does not extend a source past its admitted hard ends.

Given a cached review allow, when the user's exec right is removed, then reads refuse within at most 30 s. A review outage denies that source; an independent explicit binding still works. A remote cluster that has never delivered its bindings grants nothing.

## REQ-PER-007 — Submission and policy execution identity

Accepted executions live in SQL; CRD status is a projection. A controller never executes a user-editable object with its own privileges. Browser and MCP submissions take identity from validated credentials. A DebugCapture or DebugPolicy written through Kubernetes is authorized by RBAC on its resource in the workload's namespace, as for a CronJob; Kubernetes audit attributes the writer. Policy execution identity and acceptance follow [team policy automation](policy-automation.md). Human tokens are never execution credentials.

### SC-PER-007

Given a developer who can create DebugCapture objects, when they set a forged requester or name a powerful service account, then no collection starts. A valid admission dry-run starts nothing. A GitOps edit of a DebugPolicy is attributed to the controller's identity, runs only within its envelope and needs review again when its intrusive execution scope changes. After a team policy's author leaves, that person cannot manage or read through former membership, while the team policy remains eligible. A deleted envelope, a sponsoring group without a current allow, a deny or a forged executor blocks execution. A namespace writer without `bind` on `automation` cannot add, change or remove an envelope.

## REQ-PER-008 — Ownership changes and retained evidence

Changing ownership grants access to future evidence, not to existing evidence. Each artifact records its audience at collection, in the manifest's `accessProvenance` and in SQL: namespace and workload with UIDs and every `(issuer, group name or subject, role)` entry with the deciding binding or source. Member lists are never stored. Derived extracts inherit the parent audience; combining artifacts requires access to all parents.

An ordinary read is allowed when the caller belongs to a recorded audience group (or is the recorded subject), that entry currently holds a reading role on the workload and no deny applies; otherwise a share is needed. A new team therefore gets no access to older evidence, and a returning team sees its own earlier evidence again. Evaluation is level-based on the current snapshot ([controller pattern](https://kubernetes.io/docs/concepts/architecture/controller/)).

For a review source the audience is the capturing principal plus those of the principal's groups for which a group-only SubjectAccessReview allows at capture time. Later reads require a current review of the reader for the recorded Pod; a deleted Pod is reviewed by its recorded name only while no same-name Pod with another UID exists.

An administrator can take ownership of selected retained evidence and share it with a new team; this is audited and creates no raw grant. A recreated namespace inherits no prior evidence.

### SC-PER-008

Given a namespace reassigned from payments to payroll, when payroll collects new evidence, then payroll is recorded as its audience. Older payments cores stay inaccessible to payroll until an explicit share or ownership decision. Removing payments' current allow also ends payments' ordinary access. A newly created namespace with the same name inherits no old audience.

Artifact readers may download the approved artifacts they may inspect. Raw downloads need a covering grant, an approved raw share or the equivalent Kubernetes right under [REQ-DLD-002](artifact-downloads.md). A download or extract share cannot reveal a hidden raw parent or companion.
