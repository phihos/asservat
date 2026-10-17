# Workload targeting

## REQ-TGT-001 — Stable workload selection

A policy MUST select exactly one namespace-local workload reference or pod label selector. Workload references support `apps/v1` Deployment and StatefulSet in the first release; direct Pod references are supported for ad hoc captures. The controller MUST resolve owner UIDs, follow Deployment → ReplicaSet → Pod ownership, and refuse same-name workload replacement unless the policy explicitly adopts a new UID after authorization review. A policy can follow ordinary rolling updates under the same workload UID; its grant decides whether image digests are constrained.

The pod is the smallest public configuration, authorization and collection unit (ADR-028). There are no container selectors, container permissions or container filters. Include all available regular, sidecar, init and ephemeral container sources belonging to an authorized pod; unavailable terminated sources produce explicit gaps. Runtime container/process identities remain internal attribution and anti-reuse data. `target.maxPods` limits collection per occurrence, not observation. Policies observe all authorized replicas under separate administrator sensor limits. StatefulSet ordinal filters deliberately narrow the pod set and are shown in preview. A collection label selector never grants namespace access. Separately configured, protected namespace/workload metadata may establish ownership through [permission sources](permissions.md).

### SC-TGT-001

Given a policy pinned to Deployment UID A, when a ReplicaSet rolls to a new image under A, then selected replacement pods are armed according to the image policy. When Deployment A is deleted and its name reused with UID B, then B is not collected and the policy reports `TargetReplaced`.

## REQ-TGT-002 — Execution identity

Each action MUST bind cluster UUID, node UID/boot ID, pod UID, full runtime container ID, restart count, host PID and process start time where applicable. Revalidate before opening a namespace, file, socket or debugger. A mismatch MUST produce `TargetGone` or `TargetChanged`, not silently retarget a restarted process.

### SC-TGT-002

Given a capture resolved PID 420 in container X, when X restarts and PID 420 is reused, then no command, dump or file read runs against the replacement and the occurrence retains the original target.

## REQ-TGT-003 — Cluster and namespace scope

Targets MUST belong to an enrolled cluster and an administrator-enabled namespace within the requesting principal or policy identity's allowed workload scope. Deny rules override opt-in and policy grants. Collector, KMS, identity and secret-management namespaces are excluded by default. Enabling collection for a sensitive namespace requires a cluster-administrator policy change. Evidence sharing does not authorize new collection. Permission derivation, submission identity and automatic-policy execution identity follow [permission management](permissions.md).

### SC-TGT-003

Given a broad selector and an opted-out namespace or workload outside the requesting identity's allowed scope, when a policy resolves targets, then no observation or collection begins there and diagnostics reveal no unauthorized pod inventory.

## REQ-TGT-004 — Peer selection for network actions

Peer filters MUST support IP/CIDR, ports/protocols, authorized pod selectors and Pod/Service/Deployment/StatefulSet references with explicit namespaces, plus checked pcap expressions under [packet requirements](packets.md). Resolve pod selectors to pod UID/IP sets, supporting IPv4/IPv6 and EndpointSlice context. Record resolution time and every effective filter generation. The capture target and traffic peer are distinct; permission to collect one workload does not imply permission to collect the peer's logs or memory.

Expanded requests choose frozen or follow explicitly; UI network presets default to follow with a visible preview. Frozen sets pin membership at arming but still remove known deleted/reassigned unsafe IPs, never authorize their replacement. An explicitly enabled follow mode may update the set during a capture, but MUST revalidate enrolled cluster and namespace/workload scope and bound changes. IP reuse and NAT mean peer identity is best-effort observation, not cryptographic attribution. Service VIP, backend IP and observed tuple are separate fields.

### SC-TGT-004

Given a peer selector `app=database`, when database pods rotate IPs during a frozen capture, then no replacement is adopted, known unsafe/deleted addresses are removed and the manifest records the gap. In follow mode, new generations are recorded with activation times and no unauthorized namespace is added.

## REQ-TGT-005 — Observation coverage and incident selection

An expanded policy MUST declare `observation.mode: allAuthorized`; presets resolve that automatically. Watch every authorized matching pod, including unready/crashing replicas, within administrator workload/node/cluster sensor ceilings. An optional observation.maxPods may only narrow those ceilings; the initial portable ceiling is 1,000 pods per policy, intersected with the qualified installation envelope. No per-replica approval or user-entered container choice. Attach new replicas under the same workload UID after current pod authorization; do not equate an attached collector with fresh observations.

On overflow, keep the already armed eligible set stable, fill vacancies in creation-time/UID order and report `CoverageLimited` with observed/eligible counts and authorized skipped pod references. Do not silently rotate sampling or call the workload fully monitored. Permission-denied pods are never observed; only authorized inventory is exposed. Ring/parser memory is reserved separately for each armed pod; adding a ring can reduce that action's coverage without stopping cheap log/resource observation.

Collection defaults to `target.maxPods: 1`, `selection: triggeringPod`. Resolve the actual contributing pod even if unready; never substitute an oldest healthy replica. Workload-scoped expressions must retain contributing pod identities; collect at most maxPods contributors ordered by latest contributing observation then UID. Signals without a pod (schedule/rollout/external aggregate) require an explicit deterministic collection selection; a triggeringPod-only plan reports `NoIncidentPod`. A manual preview pins concrete pods including health/restart state. Pod loss produces gaps, not capture of a replacement.

### SC-TGT-005

Given 20 authorized replicas, when replica 17 logs an error and becomes unready, then it is observed and selected for the one-pod capture. A sensor ceiling of 10 is visible as limited coverage; a collection cap of one does not reduce observation to one. Scaling up does not multiply dump rate or grant budgets.

## REQ-TGT-006 — Pod scope and internal identity

Authorization for a pod covers its declared containers as one debugging unit; workload/namespace rules resolve to those pod UIDs. Asservat does not implement isolation between teams sharing one pod. A cluster whose inherited exec policy permits only some containers cannot map that permission to whole-pod maintainership; mark that inheritance source unavailable unless a separate explicit whole-pod assignment authorizes it. Do not introduce container ACL adapters to work around this choice.

Logs and file reads fan out internally to available container sources, with provenance for each; process snapshots enumerate only processes proven to belong to the pod's runtime cgroups. Network actions attach once to the pod network namespace and include sidecar/loopback traffic. The sandbox infrastructure process is not an application dump target. hostNetwork/hostPID pods do not confer node authority: deny actions lacking qualified pod attribution, preserving available safe actions.

All internal fanout shares action/recipe/pod/workload byte, time, process-count and concurrency reservations. maxBytes is the aggregate per action per selected pod, recipe.maxTotalBytes is the aggregate recipe per pod, and capture admission reserves their product with selected pods plus storage overhead/derivatives. Individual process-affecting starts each consume an execution; 4 processes are not one grant start. Bound runtime members to 64 container instances and 256 processes per pod initially, with administrator narrowing and explicit gaps. Use fair bounded slices for context; no unbounded per-container multiplication. Preview shows actual fanout/cost without requiring container configuration.

### SC-TGT-006

Given a pod with app, sidecar and ephemeral debugger, when ordinary context is collected, then available sources are attributed within one pod budget and network capture attaches once. A container-restricted exec grant cannot authorize the whole pod. PID 1 in a shared process namespace is never assumed to be the application's main process.

Observation pod counts apply to ongoing packet/syscall sources as well as detectors, subject to separately reserved per-action sensor capacity. Incident target.maxPods applies to saved windows and onTrigger actions. [Lifecycle readiness](action-lifecycle.md) distinguishes a fresh detector, an armed recorder and enough achieved history on each pod. A healthy replica's ring cannot substitute for an unrecorded failing replica.
