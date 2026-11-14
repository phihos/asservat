# Permission management and automatic inheritance

This specification defines application permissions inside one organization. It introduces no tenant model. Read with [authorization](authorization.md), [targets](targets.md), [ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md), [ADR-330](../docs/decisions/330-event-driven-system-design.md), [ADR-335](../docs/decisions/335-usable-by-default.md) D4/D14 and the [research](../docs/research/permission-automation.md).

Permission state reaches the evaluator through events ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1): the hub watches its own cluster with informers, and each remote cluster's connector watches its cluster and pushes changes over its hub connection. The hub keeps the last delivered set of each cluster until the connector replaces it. Nothing in this specification expires because time passed.

## REQ-PER-001 — Canonical permission configuration

These resources configure ongoing application access; they do not replace expiring `AccessGrant` execution approvals. Administrators (`identity.administrators`, [REQ-AUT-001](authorization.md#req-aut-001--identity-and-ordinary-access)) need no binding; everyone else receives access only through the three resources below.

An `AccessBinding` lives in the application namespace it grants, in the workload's own cluster, like a RoleBinding ([ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md)). It assigns users (by username), groups (by name, as the provider emits them) or workload identities one or more fixed roles over its own namespace, optionally narrowed by `spec.workloads` to Deployments/StatefulSets named by kind and name. A subject's `issuer` defaults to the installation's issuer. A workload entry matches whatever workload currently has that name, so a recreated Deployment keeps its access; the hub records the UID it matched as provenance, and an optional `uid` pins one instance. `effect: Deny` subtracts the named roles' operations. `reason` is optional. Wildcard subjects are not supported.

A `ClusterAccessBinding` is the cluster-scoped equivalent, like a ClusterRoleBinding. In a workload cluster it grants its subjects roles in every namespace of that cluster matching its optional `namespaceSelector`. In the hub cluster it may additionally name `spec.clusters` (cluster names, or `*` for every joined cluster), which lets one object grant a central SRE or approver group a role across the fleet. Only principals with cluster-scoped write access create one; the same `bind` admission applies. A ClusterAccessBinding in the hub cluster may also grant the installation role `privacy-operator`.

A `PermissionSource` is one administrator-managed derivation rule for one cluster, stored in the hub control namespace: `namespaceMetadata`, `workloadMetadata`, `kubernetesExec` or `kubernetesAccessReview`. It fixes selectors, role, identity mapping, protection mode and limits. Metadata sources resolve groups; review sources evaluate the current authenticated principal. Effective decisions and provenance are computed, never user-writable grants or one object per Pod or member. Existing bindings and sources take effect when the hub first observes them, including objects that predate the installation.

Ordinary Kubernetes RBAC decides who writes AccessBindings in a namespace; the Asservat namespaces stay administrator-only ([ADR-328](../docs/decisions/328-administrator-only-namespaces.md)). A Helm-rendered ValidatingAdmissionPolicy uses the CEL `authorizer` to require, on CREATE and UPDATE of an AccessBinding or ClusterAccessBinding, `bind` on the virtual resource `accessroles.asservat.io` named after each role the binding adds or changes, in the binding's namespace (cluster-wide for a ClusterAccessBinding), and `bind` on `automation` for an added or changed `spec.automation`. This is the Kubernetes RoleBinding `bind` pattern ([RBAC escalation prevention](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping)). The chart ships one ClusterRole per role (`asservat-bind-<role>`, plus `asservat-bind-automation`) that administrators bind with `kubectl create rolebinding`; it aggregates AccessBinding write access and the four role ClusterRoles into the namespace `admin` ClusterRole and read access into `view`, `edit` and `admin`. `asservat-bind-automation` is aggregated into `admin` only when `permissions.aggregateAutomation` is set. DELETE is not checked, as for RoleBindings. The hub does not verify the policy at runtime; an administrator who removes it accepts that namespace writers grant any role there. No role below permits editing permission configuration. GitOps does not bypass admission. Denies override explicit and derived allows, including shares. Optional local `CollectionCeiling` rules further restrict collection; without them every namespace outside the chart's excluded system namespaces is collectable.

| Role | Operations granted within scope |
| --- | --- |
| `evidence-reader` | Discover permitted cases and read metadata/extracts; no collection, sharing or raw access |
| `workload-maintainer` | Reader and owner operations; manage collection policies; observe triggers/rings and collect approved ordinary evidence; request intrusive capture and raw-query grants |
| `evidence-owner` | Reader operations; manage shares and sharing instructions personally or as an owner team under REQ-SHR-008; share existing evidence or attach bounded capture/policy sharing instructions; raw sharing still requires review. For teams that own evidence without collecting it |
| `action-approver` | Review intrusive capture, raw-query, raw-sharing and policy-grant requests in scope; no automatic evidence reading and no self-approval of manual requests |
| `privacy-operator` | Installation-wide: privacy workflows of [REQ-PRV-006](privacy.md#req-prv-006--rights-requests-and-restricted-processing); granted only by a hub-cluster ClusterAccessBinding; administrators hold it implicitly |

A role never constitutes an active intrusive or raw-query grant. `workload-maintainer` provides baseline raw-query eligibility for permitted evidence, but raw operations still require a grant or the equivalent Kubernetes right ([REQ-AUT-002](authorization.md#req-aut-002--authorization-composition)) and the OAuth scope. Other readers can request such a grant; approval cannot invent missing raw eligibility. Raw shares can supply that eligibility under the composition rules. Ordinary collection is intersected with recipe classification and local ceilings; users cannot relabel a sensitive action as ordinary.

### SC-PER-001

Given a provisioning identity with `admin` in the payments namespace, when it creates a binding there naming group `/payments` and workload `Deployment/api`, then the binding grants once the cluster's bindings reach the hub, and still grants after `api` is deleted and recreated. A binding in payroll, a role it lacks `bind` for, an automation envelope without `bind` on `automation`, or a PermissionSource change is refused by Kubernetes RBAC or admission for kubectl, GitOps and other API clients. A deny removes the matching operation even if another source permits it. One hub-cluster ClusterAccessBinding granting group `/sre` `action-approver` in every cluster lets that group approve in every namespace of every joined cluster.

## REQ-PER-002 — Kubernetes administration and effective access explanation

The Kubernetes API is the only permission-configuration CRUD interface. Namespace teams and provisioning identities manage `accessbindings.asservat.io` in their namespaces; cluster administrators manage `clusteraccessbindings.asservat.io`; Asservat administrators manage `permissionsources.asservat.io` in the hub control namespace. Use Kubernetes authentication, RBAC, admission, list/watch, server-side apply and resourceVersion concurrency; there is no second permission HTTP API or permission-specific OAuth scope.

Non-apply replacements carry the last resourceVersion; a stale replacement returns Conflict (409). Server-side apply reports field-ownership conflicts; never force ownership automatically. `kubectl diff` and `apply --server-side --dry-run=server` validate schema and admission only. Publish structural schemas, `kubectl explain` descriptions, printer columns and RBAC examples (TASK-07).

Status uses the `/status` subresource with `observedGeneration` and conditions (`Ready`, `Rejected`, `UnsafeSource`) with bounded reasons. `Ready=True` refers to `observedGeneration` and means the hub has applied that generation. GitOps health checks compare generation as well as condition. A successful API write is not yet permission activation. Kubernetes audit attributes configuration changes; Asservat does not keep a second change journal.

The browser/query service offers read-only effective-access explanation and a bounded configuration impact preview through the real evaluator. These are queries, not a configuration store. They return `Allow`, `Deny` or `Indeterminate`, contributing bindings/sources with their generation, target names and unmet conditions such as `GrantRequired`. Check authorization before revealing candidate targets; never enumerate group members or evidence. User and group pickers search only the known-principals table (REQ-AUT-001).

`explain_access` (MCP and browser, [ADR-234](../docs/decisions/234-access-explanation.md)) explains the caller's own access. Input is a cluster, namespace and workload by name and one operation: `capture`, `read` or `download`. The service resolves the same whole-pod target as `preview_capture` and runs the ordinary evaluator. The reply names the decision, the unmet condition (`NoMatchingAllow`, `ExplicitDeny`, `ClientScopeMissing` with the scope, `ClusterNotObserved`, `IdentityUnavailable`, `AudienceOverflow`, `ServiceUnavailable`), the roles that permit the operation, the target names and the caller's own contributing allows or matching deny (binding or source, role, subject kind, generation). Details are returned only when at least one binding or source matches the caller; otherwise, and for an unresolvable workload, the reply is uniformly `Deny`/`NoMatchingAllow` without targets. Retained audiences, shares and grants are not explained.

`preview_access_change` (browser only, [ADR-237](../docs/decisions/237-permission-impact-preview.md)) is for administrators, checked before any proposal is decoded. Namespace teams validate their own changes with `kubectl --dry-run=server` and `explain_access`. Input is 1–16 AccessBinding, ClusterAccessBinding or PermissionSource create (spec), update (name and spec) or delete (name) changes; an AccessBinding change names the cluster and namespace it lives in. Specs pass the same schema checks as observed objects. For each affected namespace the service takes one snapshot of the current permission state for every workload named by a current or proposed binding plus one cell for all other workloads (at most 1,000 cells, which bounds the synchronous preview request: each cell is one evaluation per subject), applies the changes and evaluates each subject whose grants change before and after, alone and with every client scope. Rows name targets, subject, operation, both decisions, unmet conditions and the deciding objects (proposed rows marked). Results are paged within 256 KiB through `next_cursor`, bound to the snapshot revision. Cells of clusters whose state has not reached the hub are `Indeterminate`. A proposed metadata source is evaluated in the same call: the hub asks the cluster's connector for the proposed keys' current values on the selected namespaces or workloads, so the source need not be applied first. A disconnected cluster gives `Indeterminate` (`MetadataNotObserved`). A review source grants per principal at request time and is `Indeterminate` (`DecisionTimeSource`). Admission is not simulated.

### SC-PER-002

Given two clients replacing one resourceVersion, when both write, then one succeeds and the other receives Conflict. Dry-run starts nothing; a persisted binding reports `Ready` only for the generation the hub applied. A developer without hub Kubernetes access can explain their own access without discovering another team's inventory.

### SC-PER-009

Given a maintainer whose group holds `evidence-reader` on a workload, when they call `explain_access` for `read`, then the result is `Allow` naming that binding; for `capture` it is `Deny` with `ClientScopeMissing` or `NoMatchingAllow` and the required role `workload-maintainer`. When a deny naming their group is added, `read` is `Deny`/`ExplicitDeny` naming that deny. A user with no matching binding receives the same `Deny`/`NoMatchingAllow` reply as for a workload that does not exist.

### SC-PER-010

Given an administrator and a namespace where group team-a holds `workload-maintainer` through a namespace-wide binding, when they preview deleting that binding, then every workload cell without another binding for team-a shows `Allow` → `Deny` for capture, read and download, and a workload that another binding still covers shows no change. A proposed deny naming team-a shows `Allow` → `Deny`/`ExplicitDeny`. A cell of a cluster whose state has not reached the hub, and a proposed PermissionSource of a disconnected cluster, are `Indeterminate`, never `Allow`; a proposed source mapping an owner value present on a namespace shows `Deny` → `Allow` for that team in each mapped namespace without the source being applied. More than 16 changes or 1,000 cells are refused; larger results are paged within 256 KiB; a caller who is not an administrator receives `AdministratorRequired` before any permission data is read; MCP does not offer the operation.

## REQ-PER-003 — Namespace metadata inheritance

An enabled `namespaceMetadata` source reads a configured label or annotation key; existing organization metadata need not be renamed. It matches a bounded namespace selector and exclusions and resolves the value into groups of the installation's issuer, either through an explicit value-to-group map or in `groupName` mode, which takes the value as a group name (with an optional configured prefix, since label values cannot contain `/`). Values never select roles, issuers, actions, URLs, KMS profiles or administrator authority. Missing, malformed, ambiguous or oversized values grant nothing. One value is one group; several owner groups use the explicit map.

Namespaces created by the provisioning workflow inherit permissions as soon as their metadata reaches the hub; there is no per-namespace click. A namespace-wide source includes future workloads in that namespace; shared namespaces should use workload metadata or explicit bindings.

Each source names a protection mode:

- `administratorManaged`: the administrator who writes the source states that namespace creation, deletion and the relevant metadata are written only by trusted administrators or provisioners. The source itself is that statement.
- `admissionEnforced`: the Helm-rendered namespace label ValidatingAdmissionPolicy protects the source's selector and mapping keys: non-administrator writers cannot create a namespace carrying them or change their presence or values. It covers labels only; a source mapping an annotation key under this mode is `SourceUnsupported`. The hub does not verify the policy at runtime ([ADR-328](../docs/decisions/328-administrator-only-namespaces.md)); its presence is the operator's responsibility, as for any admission-dependent controller.

The hub-worker watches the hub cluster's namespaces; each remote connector watches its cluster's namespaces with an informer and pushes the observed key values (as SHA-256 digests) when they change, resending only on a digest mismatch after reconnect. The hub derives one whole-namespace allow per granted namespace. A source of a cluster whose namespace metadata has never reached the hub grants nothing; afterwards the last delivered values stand until replaced. Bounds: 32 observed keys per source, 65,536 namespaces with an observed key per cluster, optional `maxNamespaces` per source.

### SC-PER-003

Given an enabled source reading an administrator-managed ownership label, when the provisioner creates a namespace for the payments group, then members gain only the configured role there once the namespace event reaches the hub. A developer changing unrelated workload labels gains nothing. With `admissionEnforced`, an unauthorized edit or removal of the ownership key is refused by admission.

## REQ-PER-004 — Exec-based and generic Kubernetes inheritance

`kubernetesExec` is an explicit per-cluster option that maps verified exec authorization to `workload-maintainer` eligibility for the whole selected Pod. The target cluster's connector submits an `authorization.k8s.io/v1` SubjectAccessReview with these attributes:

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

The connector submits the review; its subject is the actual human, never the connector. `identityMappingRef` names a record of the connector's configuration (`cluster.identityMappings`): Kubernetes user = `usernamePrefix` + the verified username claim (or the OIDC subject, as configured to match the cluster's `--oidc-username-claim`), groups = `groupsPrefix` + each current group name (plus `system:authenticated`), optional uid. Clients cannot submit Kubernetes usernames or groups; an ambiguous mapping denies; there is no email or display-name fallback. No impersonation and no command execution are needed. The connector account receives `create subjectaccessreviews` only when identity mappings are configured.

Only `allowed: true` without `denied` or an evaluation error allows. Timeouts, no opinion and missing review authority deny. `get`-only exec grants, `nodes/proxy`, port-forward and Pod read rights are not equivalent. Kubernetes does not express container or argv in this review. Before enabling the source, the administrator states that exec is whole-pod in this cluster and that no additional exec admission/JIT restriction applies (`admissionParity.mode: noAdditionalRestrictions`); container-confined exec is `UnsafeSource`. Asservat has no container permissions. The review does not prove that a container can run a shell, has ptrace rights or exposes pprof; exec inheritance authorizes Asservat's bounded diagnostics, and manual intrusive collection still needs its one approval and local ceilings. The same review, run for raw reads and downloads, is the equivalent Kubernetes right of [REQ-AUT-002](authorization.md#req-aut-002--authorization-composition).

`kubernetesAccessReview` maps one configured check to any role: `create debugcaptures` in the namespace, or `get`/`patch`/`update` on the exact Deployment/StatefulSet, mapped for example to `evidence-reader`, `evidence-owner` or `action-approver` (`update deployments`). The operator accepts that semantic mapping deliberately. Never infer eligibility from a role name or SelfSubjectRulesReview.

Before a capture preview or request, before `explain_access` and before each read of evidence collected under a review source, hub-api asks the connector to review the human for the resolved Pod (namespace, selector, exclusions and Pod checked). The connector caches an allowed result per (principal, groups, attributes) for at most `identity.AuthorityRecheckInterval` (30 s, [ADR-311](../docs/decisions/311-operation-authority-recheck.md)); denials are not cached. Listings batch their reviews. The result becomes an allow for that principal on that Pod only; explicit denies still win. Policy executors and workload principals are never reviewed. Decisions are recorded in the operation's audit row; there is no persistent per-decision assignment. At most 16 review sources per cluster, because each enabled review source adds one SubjectAccessReview to every decision in that cluster.

Every resolved Pod is evaluated separately; permission on one replica is not permission on another. An automatic policy is bound to its recorded executor and re-evaluated for each replacement Pod. Source eligibility never waives live-dump, profiling, custom-command, sensitive-file or payload grants and never grants node access, peer memory or permission administration.

### SC-PER-004

Given a user who can `create pods/exec` only for Pod A, when a selector resolves A and B, then B is never observed or collected. A false or erroring review, a spoofed group, a `get`-only grant or a container-confined exec restriction cannot authorize A. A permitted live dump still waits for its approval. An approved automatic policy rechecks each replacement replica under its executor. A teammate in a recorded group who also holds exec on the workload reads the capture.

## REQ-PER-005 — Workload ownership and integration adapters

`workloadMetadata` applies the same fixed-role, issuer and value-mapping semantics to Deployment/StatefulSet metadata in shared namespaces. It requires `admissionEnforced` protection: the Helm-rendered workload label ValidatingAdmissionPolicy over Deployment and StatefulSet CREATE/UPDATE forbids non-administrator writers to create a workload carrying the protected keys or to change their presence or values. The chart renders it when the operator configures workload keys; without it workload sources grant nothing. A source needs a non-empty `workloadSelector`; its scope is that selector and `excludedNamespaces` (`namespaceSelector` is `SourceUnsupported`).

The connector (the hub-worker for the hub cluster) watches matching workloads' metadata with an informer and pushes key values when they change; the hub derives one allow per granted workload in its namespace. Pods are never matched by labels: target resolution derives the workload through its validated controller chain and matches it; a Pod whose chain cannot be validated is unavailable for that source.

GitOps, Terraform, namespace provisioners and approved service-catalog integrations MAY manage AccessBindings through the Kubernetes API within the namespaces and roles their RBAC permits. Catalog display ownership, CODEOWNERS, field-manager names, creator annotations and arbitrary GitOps labels are not permission evidence. No catalog, policy engine, cloud IAM or SCIM service is a hard dependency.

### SC-PER-005

Given two applications owned by different teams in one namespace, when protected workload ownership is resolved, then permissions apply only to the matching workload and its validated Pods. Editing a Pod label, copying an ownerReference or supplying a catalog owner string cannot expand scope. An integration cannot write bindings into another team's namespace.

## REQ-PER-006 — Freshness, composition and explainability

An effective operation requires an eligible identity, a current allow, no explicit deny, local target/action ceilings and all grant/share conditions. Independent allows are unioned. No source failure falls back to a broader role. A source grants only within its configured cluster and selectors.

The evaluator reads one permission snapshot: the hub cluster's informer caches and the last delivered state of every remote cluster. The snapshot stays valid until an event replaces it; it does not expire with time ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1). The hub cluster's state is unavailable only while its watch relists; a remote cluster's state is unavailable only until its connector first delivers it. Unavailable state grants nothing and, because deny state is then unknown, fails closed for that cluster. Each operation takes one snapshot and reuses it for at most `identity.AuthorityRecheckInterval` (30 s), never past an original hard end ([ADR-311](../docs/decisions/311-operation-authority-recheck.md)). Group membership is the caller's current access token ([authorization](authorization.md)).

Collection admits each source start once, under one snapshot, bounded by every hard end that applies: policy grant expiry, binding `notAfter`, action/observation grant and local ceiling. The started source runs to those bounds. When a binding, source or deny removes the authority, or a policy is deactivated, the hub pushes a stop over the connector connection. While its connector is disconnected a started source runs to its admitted hard end; a pending stop is delivered on reconnect. Started downloads follow [ADR-312](../docs/decisions/312-started-downloads-run-to-original-bounds.md).

An artifact records its complete audience; an owner is never omitted. Its size is bounded by the bindings and sources that exist. Approver-only assignments are not audience entries. The operation's audit row records the deciding bindings or sources with their generations, the principal mapping, targets and reason; never bearer tokens. The API explains why access exists and what a source removal would remove.

### SC-PER-006

Given a running ongoing recorder admitted under team-a's binding, when the binding is deleted, then the hub pushes a stop and the recorder ends; new admissions are refused as soon as the deletion reaches the hub. If the connector is disconnected, the recorder runs to its admitted hard end unless the stop arrives first on reconnect. A reconnect does not extend a source past its admitted hard ends.

Given a cached review allow, when the user's exec right is removed, then reads refuse within at most 30 s. A review outage denies that source; an independent explicit binding still works. A remote cluster that has never delivered its bindings grants nothing.

## REQ-PER-007 — Submission and policy execution identity

Accepted executions live in SQL; CRD status is a projection with `observedGeneration`. A controller never executes a user-editable object merely with its own privileges. Each accepted capture records its authenticated submitter; each accepted policy generation records the policy, its namespace and its authorized execution identity.

HTTP and MCP submissions derive identity from validated credentials. A DebugPolicy lives in the application namespace of the workload it targets ([team policy automation](policy-automation.md)). Writing it through Kubernetes (kubectl or GitOps) is authorized by RBAC on `debugpolicies.asservat.io` in that namespace, as CronJob or Flux treat writers; the actual writer is attributed by Kubernetes audit and `managedFields`. The hub accepts each generation that fits a current `spec.automation` envelope in that namespace, with no separate activation step; commit authorship never becomes the actor. Admission dry-run produces no execution and no durable side effect. A spec change advances the generation and is accepted again; replaced objects and copied status cannot reuse an acceptance; re-applying an unchanged generation changes nothing.

Execution re-evaluates the accepted scope, the current envelope, sponsoring groups, denies, grants and budgets at each source admission. It never reuses a human token as an execution credential. A retry with the same idempotency key returns the original acceptance without changing expiry or resetting budgets.

Recurring team policies use the installation-local policy execution identity and the `AccessBinding.spec.automation` envelope under [team policy automation](policy-automation.md). Logout, token expiry or departure of the author does not revoke team execution. Current human authority is checked at approval, management, live viewing and disclosure. Human-only exec inheritance supplies no automation envelope. Changing executor or envelope requires acceptance and, for intrusive actions, applicable review. Approvers cannot approve outside their scope.

### SC-PER-007

Given a developer who can create DebugCapture objects, when they set a forged requester or name a powerful service account, then no collection starts. A valid admission dry-run starts nothing. A GitOps edit of a DebugPolicy is attributed to the controller's identity, runs only within its envelope and needs review again when its intrusive execution scope changes. After a team policy's author leaves, that person cannot manage or read through former membership, while the team policy remains eligible. A deleted envelope, a sponsoring group without a current allow, a deny or a forged executor blocks execution. A namespace writer without `bind` on `automation` cannot add, change or remove an envelope.

## REQ-PER-008 — Ownership changes and retained evidence

Changing ownership grants access to future evidence; it does not expose existing evidence to a different team. Each artifact records its audience at collection in the encrypted manifest's `accessProvenance` and in SQL: the namespace and workload with their UIDs and every entry `(issuer, group name or subject, role)` with the deciding binding or source and its generation. Group membership lists are never stored. Derived extracts inherit the parent audience; combining artifacts requires authorization to all parents.

An ordinary read is allowed when the caller belongs to a recorded audience group (or is the recorded subject), that group or subject currently holds a reading role on the artifact's workload through any current allow, and no deny applies; otherwise an explicit EvidenceShare is needed. A new team never appears in an old audience, so it gets no access to older evidence. If ownership returns to an earlier team, that team sees its own earlier evidence again. An administrator-created binding does not add an audience to existing artifacts. Denies and expiry always apply. Evaluation is level-based on the current snapshot ([controller pattern](https://kubernetes.io/docs/concepts/architecture/controller/)); there is no assignment-ID history.

For a review source the audience is the capturing principal plus those of the principal's current groups for which a group-only SubjectAccessReview of the same attributes allows at capture time. A member of such a group, or the principal, may read while the source is enabled and a current review of that reader for the recorded Pod attributes allows. A deleted Pod is reviewed by its recorded name only while the namespace UID is unchanged and no same-name Pod with another UID exists; otherwise use a share. A review never authorizes historical artifacts for a user who gained exec rights later outside a recorded group.

An administrator can take ownership of selected retained evidence and share it with the new team under the sharing rules. This is audited and does not create a raw-query grant. The UI shows which older artifacts need that decision. A recreated namespace inherits no prior evidence. Evidence deletion does not depend on namespace deletion.

### SC-PER-008

Given a namespace reassigned from payments to payroll, when payroll collects new evidence, then payroll is recorded as its audience. Older payments cores stay inaccessible to payroll until an explicit share or ownership decision. Removing payments' current allow also ends payments' ordinary access. A newly created namespace with the same name inherits no old audience.

Artifact readers may download the approved artifacts they may inspect; there is no lead-only download role. Raw downloads still need raw eligibility and a covering grant or the equivalent Kubernetes right under [REQ-DLD-002](artifact-downloads.md). A download or extract share cannot reveal a hidden raw parent or companion.
