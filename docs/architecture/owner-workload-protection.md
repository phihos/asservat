# Private hub workload protection

[ADR-080](../decisions/080-private-hub-workload-protection.md) implements a prerequisite of owner enrollment under REQ-FED-001 and REQ-DEP-003. C-24 owns the pure `OwnerWorkloadAdministration` value, C-01 owns its installation configuration semantics, and C-21 owns native admission generation and `OwnerWorkloadProtection`. The subsequent [C-04 enrollment proof](owner-enrollment-proof.md) requires this protection alongside accepted configuration and current token/workload observations; recovery and durable activation remain separate. It cannot treat this component's digest as process or certificate authority.

## Scope and controller profile

The installation plan fixes the policy/binding name, exact namespace name/UID, probe Deployment name/UID and finite independent Kubernetes administrator users/groups. These values are not selected by the Pod, ConfigMap contents, public caller or evidence owner. Constructors copy administrator, configuration-probe and scheduling-Lease slices. Changes require requalification and cannot change a live guard through caller-owned memory.

The policy covers all namespaced resources and subresources, all API versions, and CREATE/UPDATE/DELETE/CONNECT in the exact namespace. `failurePolicy: Fail` and a Deny binding are mandatory. Matching is independent of attacker-controlled labels and object contents. This protects alternate workloads, future CRDs, service account token requests, Secrets, RBAC, exec/attach/portforward, ephemeral containers and control leases; blocking only the hub Deployment would leave indirect credential theft possible. Ordinary events remain writable subject to existing RBAC. [ADR-092](../decisions/092-independent-source-admission-probes.md) additionally permits only installer-listed same-namespace ServiceAccounts to dry-run UPDATE their exact named ConfigMaps, with no subresource. This lets independently pinned source policies return their own enforcement denial. At most eight distinct pairs are allowed; every real ConfigMap update and all other ConfigMap request scopes retain namespace protection. Source protection must still be independently present and enforcing.

[ADR-093](../decisions/093-bounded-hub-scheduling-permission.md) additionally permits an exact listed same-namespace account to UPDATE a named `coordination.k8s.io` Lease without subresources. There are at most four distinct account/Lease pairs; this is not a blanket Lease exception. Creation, deletion, other identities/objects/resources and credential operations remain guarded. The runtime retains exact namespace/Lease UID, CAS and record-bound checks; the Lease schedules work but supplies no authority. The actual RBAC role grants only get/update on that name. Installer-owned `schedulingLeases` is required in the private deployment projection, with `[]` allowing none.

Exact `kube-system` service-account usernames are allowed for specific built-in controller duties: workload reconciliation, autoscaling, endpoint updates, service-account creation, quota status and deletion cleanup. The shared `system:kube-controller-manager` identity may perform the union of these duties. Kubernetes documents [shared versus per-controller credentials](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#roles-for-built-in-controllers). These are explicit controller names, never a wildcard service-account group. None receives an exec/attach/portforward, token-request or RBAC-writing exception. Kubernetes RBAC continues to restrict what each principal can do.

`system:kube-scheduler` may create Pod bindings and update Pod status. A node username with the `system:nodes` group may update Pod status and create service-account token requests; Kubernetes node authorization remains mandatory. Node/API/controller compromise is not addressed by this policy. Secret reads are not admission operations, so the installer must independently ensure that developers and unrelated workloads cannot read the hub's credentials. Legacy service-account token creation is not an allowed controller duty.

The namespace is private to the protected hub workload and its installation control resources. Acquisition Jobs, user namespaces and other application controllers requiring write access belong in separate configured namespaces. There is no new per-investigation administrator work. The eventual Helm installation must manage the policy, pins, roles and topology and report unsupported controller profiles before enabling the service.

## Current enforcement proof

`OwnerWorkloadProtection.Current` uses distinct bounded observer/probe clients pinned to the same API cluster and namespace UID. Its original five-second interval covers all network calls. It:

1. Checks current namespace identity and deletion state.
2. Reads the exact policy UID/generation/spec/type-check status and binding UID/resourceVersion/spec, using the existing admission verifier.
3. Uses SelfSubjectReview to reject administrator and controller probes, then SelfSubjectAccessReview to establish that ordinary RBAC allows this exact named Deployment update.
4. Reads the current apps/v1 Deployment with the independently pinned UID and re-submits it unchanged, with `dryRun=All`, strict validation and no automatic retries.
5. Requires a bounded structured denial naming the exact expected policy, binding and denial text for the apps/deployments resource. Other authorization or admission failures are insufficient.
6. Rechecks policy/binding and namespace, rejects changes/expiry, then returns only a scoped digest and the original deadline.

There is no saved synthetic probe object and no persistent mutation even when the policy is missing. The runtime probe needs update RBAC only for the named Deployment; the observer needs only GET on that Deployment, namespace and the exact policy/binding. Neither requires Secret reads or general workload writes. The integration attack client deliberately has additional mutation rights for negative tests; those are not runtime probe requirements.

Controller status updates may advance the Deployment resource version between
GET and dry-run UPDATE, returning HTTP 409 before admission is evaluated. Only
an exact structured Conflict for the pinned Deployment permits another fresh
GET and unchanged dry-run, at most three attempts within the same original
five-second interval. Every read rechecks object identity. An unrelated denial,
accepted write, replaced object or expired interval remains unavailable; retries
never search for a preferred admission-policy response. The native regression
advances resourceVersion deterministically between the read and probe.

Kubernetes [does not type-check wildcard resource schemas](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#type-checking). Most policy branches read common request fields. [ADR-095](../decisions/095-hub-workload-garbage-collection.md) additionally reads guarded old/new specs and labels/annotations for the exact garbage collector's metadata maintenance on Deployments/ReplicaSets/Pods, plus assigned-node identity/deletion/terminal status for final kubelet Pod removal. Native kind-specific positive and negative tests must qualify those branches; they are not schema-type-checked by wildcard matching. Empty native type-check status is an additional prerequisite, not a substitute for actual admission tests.

Normalize optional `request.resource.group` and `request.subResource` through `has(...)`-guarded variables before comparing them. The [AdmissionRequest wire type](https://github.com/kubernetes/api/blob/v0.36.3/admission/v1/types.go) omits an empty subresource, and core resources may omit their empty API group. A CEL evaluation error must not be mistaken for an intentional denial: native tests require the exact static denial message and separately exercise a permitted controller request and actual replacement.

## Bootstrap boundary and qualification

Current protection cannot prove that a Pod was created while protection was continuously active. Install protection before credentials/workload launch in a clean private namespace. An existing namespace requires separately qualified migration/recovery; matching references or a currently passing dry-run cannot bless preexisting processes. The subsequent [ADR-081 proof](owner-enrollment-proof.md) verifies live Pod/account/controller identities, the dedicated token and CSR independently of Ready endpoints. Trusted clean installation and durable key/process enrollment remain pending; this guard is not wired as a production enrollment shortcut.

Unit fixtures exercise exact denial, administrator/controller rejection, RBAC denial, missing/mutated policy/binding, type warnings, foreign Deployment, namespace replacement during the proof, expiry, changed policy during I/O, wrong resource/cause and unexpectedly accepted dry-runs. The owned Kubernetes fixture additionally tests actual attack rejection, unchanged Deployment resource versions, administrator access, observer RBAC and real controller replacement of a Restricted Pod after admission is active. Removing the binding must invalidate the guard, and a subsequent unchanged dry-run must succeed as the negative control. Results and remaining gaps are recorded in [implementation progress](../implementation-progress.md).

This qualifies the tested reference controller path only. StatefulSet/PVC lifecycle, autoscaling, finalizers outside the ADR-095 reference Deployment chain, managed-provider controller identity variants and clean installation bootstrap need their own measured acceptance before claiming support. A successful reference deployment is not evidence for those untested branches or the full public download workflow.

ADR-095 preserves normal foreground deletion through exact garbage-collector metadata maintenance and the assigned kubelet's final removal of an already-deleting terminal Pod. No worker/developer workload-write permission is added. Garbage-collector workload specs, labels and annotations must remain unchanged; credential/configuration writes remain denied. A shared controller-manager identity retains its existing controller union and cannot claim the isolation of dedicated controller accounts. Actual source-matched results remain in implementation progress.
