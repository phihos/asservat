# Named workload target resolution

Initial C-05 observation adapter for the C-09 context preview path, under
REQ-EXE-001/002, TASK-02/03 and S-01/S-02. This is private target observation,
not public inventory, eligibility, capture admission or an execution permit.

`targets.WorkloadRequest` accepts the existing public `target_ref` fields:
cluster UUID, namespace name, kind (`Deployment`, `StatefulSet`, `Pod`) and
name. The caller supplies no namespace/workload/pod UID, node facts, endpoint
or credential. Bootstrap constructs `PodTargets` with an independently
selected enrolled-cluster `PermissionClient`; another cluster ID is rejected
before API I/O. No container selector or permission scope is introduced.

## Selecting one pod for the initial context profile

`ResolveWorkload` observes the actual namespace and named workload. For a
Deployment or StatefulSet it compiles that object's Kubernetes label selector,
requests a bounded Pod LIST and requires a complete result with at most 256
items. Empty/invalid selectors, continuation, excess items, inconsistent
remaining counts, duplicate identities and incorrectly filtered results do
not produce a selection. This path retains the existing 2 MiB per-response
transport bound and does not request a stale Kubernetes resource version.

The initial `builtin-pod-status-v1` profile captures one pod. The original
node-collector class considers scheduled nonterminating candidates; the
[API reader class](api-context-execution.md) also supports unscheduled pods.
For its class's eligible candidates, the resolver checks names in lexical order and
selects the first whose actual current controller chain belongs to the named
workload. Labels only narrow candidate enumeration; they do not establish
ownership. A Deployment requires Pod → ReplicaSet → Deployment identities;
a StatefulSet requires the direct StatefulSet controller. A foreign owner
with identical labels does not qualify. Unreadable or changed owner objects
fail rather than being treated as an absent foreign owner.

Readiness and running phase are not selection requirements: status collection
must remain useful for unhealthy pods. A failed pod can therefore be selected.
The preview uses `lexicalEligiblePod` (or `explicitPod` for a direct reference),
must explicitly identify the selected pod and say that
the recipe collects one pod. It must not imply diagnosis of every replica or
choose a different pod at request acceptance. Workloads exceeding this bounded
preview ceiling require an explicit Pod reference until the separate inventory
workflow is implemented; this ceiling does not change the specified all-replica
monitoring default.

A direct Pod reference resolves its supported real workload root. An owned
Deployment/StatefulSet pod retains that workload's UID for permissions,
retention and quotas; it cannot manufacture a separate Pod workload allocation.
An unowned Pod uses its own UID. Other controller families are explicitly
unsupported by this initial resolver. Naming a Pod does not list siblings or
choose a replacement.

## Independent pins and deadlines

The selected name and observed identities feed the existing `ResolvePod`
implementation. It independently rechecks the exact namespace, pod and owner
chain. The node class also pins scheduled node UID and node boot ID; the API
class carries no invented node/runtime provenance. Its result is the existing
`PodResolution`, without workload labels, annotations, container names,
configuration or other raw API content. The entire operation retains the
original at-most-five-second observation interval and earlier caller deadline;
the later `ResolvePod` call cannot renew the first namespace/workload reads.
Cancellation, clock rollback and expiry fail after blocking work.

The coordinator authenticates the current caller and checks current ordinary
eligibility for the exact resolved target before disclosing preview metadata.
It must preserve the resulting `targets.Request` and canonical preview scope.
Request acceptance refreshes that exact request using `ResolvePod`, then
compares the approved scope. A replaced pod/root/node or changed boot identity
cannot become an implicit alternative or extend a prior approval. No value
returned here is a permission or recovery proof.

## Qualification and composition

The focused real-TLS fake-API race suite passes in
`test/results/workload-targets-unit.log`: domain 1.005 seconds and Kubernetes
adapter 3.028 seconds, including existing pinned-Pod regressions. New cases
cover real-owner selection despite spoofed matching labels, StatefulSet and
owned/unowned Pod roots, bounded complete lists, duplicates, selector errors,
RBAC denial, replacement, node reboot, original-deadline expiry and canceled
I/O. The initial test run rejected client-go's legitimate `timeout=5s` query
parameter; the fixture now explicitly checks it together with the selector and
limit. No production restriction was relaxed.

Native component results and any pending class-specific qualification are
recorded in [implementation progress](../implementation-progress.md). These fixtures do not establish
production reader credentials, namespace ownership protection, accepted
permission projections, public workflows, discovery permissions or authority
to execute a collection. The adapter needs read-only namespace/workload/
ReplicaSet/Pod GET permissions and namespace-scoped Pod LIST; only the node
class additionally requires Node GET. Adding those
permissions to runtime installation remains separate from this implementation.
