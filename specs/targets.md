# Workload targeting

## REQ-TGT-001 — Stable workload selection

A policy selects exactly one namespace-local workload reference or pod label selector. Workload references name a Deployment or StatefulSet by kind and name; ad hoc captures may also name a Pod. The target namespace is the object's own namespace. The controller follows Deployment → ReplicaSet → Pod ownership. A target follows its name ([ADR-335](../docs/decisions/335-usable-by-default.md) D4): a workload deleted and recreated under the same name, for example by an Argo CD replace, stays the target, and the new UID is recorded in status and provenance. `adoption: pinUID` binds the UID seen at acceptance instead; a replacement then reports `TargetReplaced`. Rolling updates keep the target either way; an intrusive grant decides whether image digests are constrained.

Defaults: `maxPods: 1` (the maintainer's per-incident collection cap; the user may raise it), `selection: triggeringPod` for policies and `oldestReady` for manual captures, `adoption: followName`.

The pod is the smallest configuration, authorization and collection unit (ADR-028). There are no container selectors, permissions or filters. All regular, sidecar, init and ephemeral container sources of an authorized pod are included; unavailable terminated sources are explicit gaps. Container and process identities are internal attribution only. StatefulSet ordinal filters narrow the pod set and are shown in preview. A collection label selector never grants namespace access.

### SC-TGT-001

Given a policy targeting Deployment `checkout` (UID A), when a ReplicaSet rolls to a new image under A, then selected replacement pods are armed according to the image policy. When `checkout` is deleted and recreated with UID B, then the policy follows B without an edit, status reports the new UID and B's occurrences record UID B. With `adoption: pinUID`, B is not collected and the policy reports `TargetReplaced`.

## REQ-TGT-002 — Execution identity

Each action binds cluster, node UID/boot ID, pod UID, runtime container ID, restart count, host PID and process start time where applicable. The node checks this identity immediately before opening a namespace, file, socket or debugger; authorization is the operation's single decision (REQ-EXE-002) and is not repeated per attach. A mismatch yields `TargetGone` or `TargetChanged`, never a silent retarget.

### SC-TGT-002

Given a capture resolved PID 420 in container X, when X restarts and PID 420 is reused, then no command, dump or file read runs against the replacement and the occurrence retains the original target.

## REQ-TGT-003 — Cluster and namespace scope

Targets belong to a registered cluster and lie within the requester's or policy identity's allowed workload scope. Every namespace except the system namespaces (`kube-*`, the Asservat release namespace, and collector, KMS, identity and secret-management namespaces) is collectable by default ([ADR-335](../docs/decisions/335-usable-by-default.md) D1). A `CollectionCeiling` or the namespace label `asservat.io/evidence: disabled` narrows or excludes a namespace; denies override allows and policy grants. Collecting in a system namespace needs a cluster-administrator CollectionCeiling. Sharing evidence does not authorize collection. Permissions follow [permission management](permissions.md).

### SC-TGT-003

Given a broad selector and an opted-out namespace or workload outside the requesting identity's allowed scope, when a policy resolves targets, then no observation or collection begins there and diagnostics reveal no unauthorized pod inventory.

## REQ-TGT-004 — Peer selection for network actions

Network actions select peers by IP/CIDR, ports/protocols, pod selectors and Pod/Service/Deployment/StatefulSet references, resolved by the connector's informers with `frozen` or `follow` membership ([REQ-NET-002](packets.md#req-net-002--kubernetes-peers-and-continuous-updates)). New members stay within the registered cluster and the authorized scope. The capture target and the traffic peer are distinct: collecting one workload grants nothing on its peers.

### SC-TGT-004

Given a peer selector `app=database`, when database pods rotate IPs during a frozen capture, then no replacement is adopted, deleted addresses are removed and the manifest records the gap. In follow mode, new generations are recorded with activation times and no unauthorized namespace is added.

## REQ-TGT-005 — Observation coverage and incident selection

A policy observes every authorized matching pod through the connector's Pod informer, including unready and crashing replicas, within administrator workload/node/cluster sensor ceilings; `observation.maxPods` may only narrow them. No per-replica approval. New replicas of the same workload attach after their pod is authorized.

On overflow, keep the armed set stable, fill vacancies in creation-time/UID order and report `CoverageLimited` with observed/eligible counts. Never rotate sampling silently or call the workload fully monitored. Ring/parser memory is reserved per armed pod; adding a ring can reduce that action's coverage without stopping cheap log/resource observation.

Collection uses the actual contributing pod even when unready, never an oldest healthy replica. Workload-scoped detectors keep contributing pod identities and collect at most `maxPods` of them, latest contribution first. Signals without a pod (schedule, rollout, external aggregate) need an explicit selection; a triggeringPod-only plan reports `NoIncidentPod`. A manual preview pins concrete pods. Pod loss is a gap, never capture of a replacement.

### SC-TGT-005

Given 20 authorized replicas, when replica 17 logs an error and becomes unready, then it is observed and selected for the one-pod capture. A sensor ceiling of 10 is visible as limited coverage; a collection cap of one does not reduce observation to one. Scaling up does not multiply dump rate or grant budgets.

## REQ-TGT-006 — Pod scope and internal identity

Authorization for a pod covers its containers as one debugging unit. Asservat does not isolate teams sharing one pod. An inherited exec policy that permits only some containers cannot authorize the whole pod; that source is unavailable unless a separate whole-pod assignment exists.

Logs and file reads fan out to the pod's container sources with per-source provenance; process snapshots enumerate only processes proven to belong to the pod's cgroups. Network actions attach once to the pod network namespace. The sandbox process is never a dump target. hostNetwork/hostPID pods confer no node authority; actions without qualified pod attribution are denied.

Fanout shares the action's per-pod byte, time and concurrency reservations: `maxBytes` per action per selected pod, `recipe.maxTotalBytes` per recipe per pod. Containers are bounded by the Pod object and processes by `pids.max`, so there is no separate container or process count. Each process-affecting start counts as one execution. Preview shows the actual fanout and cost.

### SC-TGT-006

Given a pod with app, sidecar and ephemeral debugger, when ordinary context is collected, then available sources are attributed within one pod budget and network capture attaches once. A container-restricted exec grant cannot authorize the whole pod. PID 1 in a shared process namespace is never assumed to be the application's main process.

Observation pod counts apply to ongoing packet/syscall recorders as well as detectors; `maxPods` applies to saved windows and onTrigger actions. [Lifecycle readiness](action-lifecycle.md) distinguishes a fresh detector, an armed recorder and achieved history per pod; a healthy replica's ring never substitutes for an unrecorded failing one.
