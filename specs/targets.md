# Workload targeting

## REQ-TGT-001 — Stable workload selection

A policy MUST select exactly one namespace-local workload reference or pod label selector. Workload references name a Deployment or StatefulSet by kind and name (`apiVersion` is derived from the kind); direct Pod references are supported for ad hoc captures. The target namespace is the object's own namespace. The controller resolves owner UIDs and follows Deployment → ReplicaSet → Pod ownership. By default a target follows its name ([ADR-335](../docs/decisions/335-usable-by-default.md) D4): a workload deleted and recreated under the same name in the same namespace, for example by an Argo CD replace or a blue/green recreate, stays the target, and the new UID is recorded in status and in each occurrence's provenance. `adoption: pinUID` opts into binding the UID seen at acceptance; a replacement under that setting reports `TargetReplaced`. Rolling updates keep the target either way; an intrusive grant decides whether image digests are constrained.

Omitted target fields default to `maxPods: 1` (the maintainer's independent per-incident collection cap; the user may raise it), `selection: triggeringPod` for policies and `oldestReady` for manual captures, and `adoption: followName`.

The pod is the smallest public configuration, authorization and collection unit (ADR-028). There are no container selectors, container permissions or container filters. Include all available regular, sidecar, init and ephemeral container sources belonging to an authorized pod; unavailable terminated sources produce explicit gaps. Runtime container/process identities remain internal attribution and anti-reuse data. `target.maxPods` limits collection per occurrence, not observation. Policies observe all authorized replicas under separate administrator sensor limits. StatefulSet ordinal filters deliberately narrow the pod set and are shown in preview. A collection label selector never grants namespace access. Separately configured, protected namespace/workload metadata may establish ownership through [permission sources](permissions.md).

### SC-TGT-001

Given a policy targeting Deployment `checkout` (UID A), when a ReplicaSet rolls to a new image under A, then selected replacement pods are armed according to the image policy. When `checkout` is deleted and recreated with UID B, then the policy follows B without an edit, status reports the new UID and B's occurrences record UID B. With `adoption: pinUID`, B is not collected and the policy reports `TargetReplaced`.

## REQ-TGT-002 — Execution identity

Each action MUST bind the internal cluster ID, node UID/boot ID, pod UID, full runtime container ID, restart count, host PID and process start time where applicable. Check this identity locally on the node immediately before opening a namespace, file, socket or debugger; authorization is the operation's single decision under REQ-EXE-002 and is not repeated per attach. A mismatch MUST produce `TargetGone` or `TargetChanged`, not silently retarget a restarted process.

### SC-TGT-002

Given a capture resolved PID 420 in container X, when X restarts and PID 420 is reused, then no command, dump or file read runs against the replacement and the occurrence retains the original target.

## REQ-TGT-003 — Cluster and namespace scope

Targets MUST belong to an enrolled cluster and lie within the requesting principal or policy identity's allowed workload scope. Every namespace outside the system namespaces (`kube-*`, the Asservat release namespace, and collector, KMS, identity and secret-management namespaces) is collectable by default; there is no namespace opt-in ([ADR-335](../docs/decisions/335-usable-by-default.md) D1). An optional `CollectionCeiling` or the namespace label `asservat.io/evidence: disabled` narrows or excludes a namespace; deny rules override allows and policy grants. Enabling collection for an excluded system namespace requires a cluster-administrator CollectionCeiling. Evidence sharing does not authorize new collection. Permission derivation, submission identity and automatic-policy execution identity follow [permission management](permissions.md).

### SC-TGT-003

Given a broad selector and an opted-out namespace or workload outside the requesting identity's allowed scope, when a policy resolves targets, then no observation or collection begins there and diagnostics reveal no unauthorized pod inventory.

## REQ-TGT-004 — Peer selection for network actions

Peer filters MUST support IP/CIDR, ports/protocols, authorized pod selectors and Pod/Service/Deployment/StatefulSet references with explicit namespaces, plus checked pcap expressions under [packet requirements](packets.md). Resolve pod selectors to pod UID/IP sets, supporting IPv4/IPv6 and EndpointSlice context. Record resolution time and every effective filter generation. The capture target and traffic peer are distinct; permission to collect one workload does not imply permission to collect the peer's logs or memory.

Expanded requests choose frozen or follow explicitly; UI network presets default to follow with a visible preview. Frozen sets pin membership at arming but still remove known deleted/reassigned unsafe IPs, never authorize their replacement. An explicitly enabled follow mode updates the set from the connector's EndpointSlice and Pod informers: each membership change produces a new filter generation that the connector pushes to the node collector (no resolution polling). New members MUST be within the enrolled cluster and the authorized namespace/workload scope, and the peer set must fit the compiled filter's 4,096-instruction bound (`BPF_MAXINSNS`); generations follow EndpointSlice events, with no separate change-rate cap. IP reuse and NAT mean peer identity is best-effort observation, not cryptographic attribution. Service VIP, backend IP and observed tuple are separate fields.

### SC-TGT-004

Given a peer selector `app=database`, when database pods rotate IPs during a frozen capture, then no replacement is adopted, known unsafe/deleted addresses are removed and the manifest records the gap. In follow mode, new generations are recorded with activation times and no unauthorized namespace is added.

## REQ-TGT-005 — Observation coverage and incident selection

A policy observes every authorized matching pod (no field selects this) through the connector's shared Pod informer, including unready/crashing replicas, within administrator workload/node/cluster sensor ceilings. An optional observation.maxPods may only narrow those ceilings; there is no separate per-policy pod cap beyond the administrator ceilings. No per-replica approval or user-entered container choice. Attach new replicas under the same workload UID after current pod authorization; do not equate an attached collector with fresh observations.

On overflow, keep the already armed eligible set stable, fill vacancies in creation-time/UID order and report `CoverageLimited` with observed/eligible counts and authorized skipped pod references. Do not silently rotate sampling or call the workload fully monitored. Permission-denied pods are never observed; only authorized inventory is exposed. Ring/parser memory is reserved separately for each armed pod; adding a ring can reduce that action's coverage without stopping cheap log/resource observation.

Collection defaults to `target.maxPods: 1`, `selection: triggeringPod`. Resolve the actual contributing pod even if unready; never substitute an oldest healthy replica. Workload-scoped expressions must retain contributing pod identities; collect at most maxPods contributors ordered by latest contributing observation then UID. Signals without a pod (schedule/rollout/external aggregate) require an explicit deterministic collection selection; a triggeringPod-only plan reports `NoIncidentPod`. A manual preview pins concrete pods including health/restart state. Pod loss produces gaps, not capture of a replacement.

### SC-TGT-005

Given 20 authorized replicas, when replica 17 logs an error and becomes unready, then it is observed and selected for the one-pod capture. A sensor ceiling of 10 is visible as limited coverage; a collection cap of one does not reduce observation to one. Scaling up does not multiply dump rate or grant budgets.

## REQ-TGT-006 — Pod scope and internal identity

Authorization for a pod covers its declared containers as one debugging unit; workload/namespace rules resolve to those pod UIDs. Asservat does not implement isolation between teams sharing one pod. A cluster whose inherited exec policy permits only some containers cannot map that permission to whole-pod maintainership; mark that inheritance source unavailable unless a separate explicit whole-pod assignment authorizes it. Do not introduce container ACL adapters to work around this choice.

Logs and file reads fan out internally to available container sources, with provenance for each; process snapshots enumerate only processes proven to belong to the pod's runtime cgroups. Network actions attach once to the pod network namespace and include sidecar/loopback traffic. The sandbox infrastructure process is not an application dump target. hostNetwork/hostPID pods do not confer node authority: deny actions lacking qualified pod attribution, preserving available safe actions.

All internal fanout shares action/recipe/pod/workload byte, time, process-count and concurrency reservations. maxBytes is the aggregate per action per selected pod, recipe.maxTotalBytes is the aggregate recipe per pod, and capture admission reserves their product with selected pods plus storage overhead/derivatives. Individual process-affecting starts each consume an execution; 4 processes are not one grant start. These aggregate per-pod reservations bound the cost of fanout, so there is no separate container or process count: containers are bounded by the Pod object and processes by the pod cgroup's `pids.max`. Context uses fair slices of the pod's reservation. Preview shows actual fanout/cost without requiring container configuration.

### SC-TGT-006

Given a pod with app, sidecar and ephemeral debugger, when ordinary context is collected, then available sources are attributed within one pod budget and network capture attaches once. A container-restricted exec grant cannot authorize the whole pod. PID 1 in a shared process namespace is never assumed to be the application's main process.

Observation pod counts apply to ongoing packet/syscall sources as well as detectors, subject to separately reserved per-action sensor capacity. Incident target.maxPods applies to saved windows and onTrigger actions. [Lifecycle readiness](action-lifecycle.md) distinguishes a fresh detector, an armed recorder and enough achieved history on each pod. A healthy replica's ring cannot substitute for an unrecorded failing replica.
