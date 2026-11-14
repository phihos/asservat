# Workload target resolution

C-05 target resolution for the C-09 preview and request paths, under
REQ-TGT-001/002/003/006, REQ-EXE-001/002, TASK-02/03/05 and S-01/S-02. It
observes targets; it is not inventory permission, eligibility, admission or an
execution permit.

## Source of state

Each connector runs shared informers (LIST once, then WATCH) for Namespaces,
Pods, ReplicaSets, Deployments, StatefulSets and, for the node-collector class,
Nodes. Resolution reads these caches; it issues no per-request API GET or LIST.
A cache stays valid while its informer is synced. After a watch failure the
cache is unavailable until the relist completes, and resolution returns
`Unavailable` rather than a stale or partial answer. The hub sends a resolution
request as a stream on the [connector connection](regional-context-start.md)
and receives the typed result on the same stream.

The connector's ServiceAccount needs get/list/watch on those resources (Nodes
only for the node class). These are read permissions; they grant no user
authority to enumerate a namespace.

## Request

`targets.WorkloadRequest` accepts the public `target_ref` fields: cluster UUID,
namespace name, kind (`Deployment`, `StatefulSet`, `Pod`) and name. The caller
supplies no UID, node fact, endpoint or credential. A request for a cluster
other than the connection's cluster is rejected. Scope is the whole Pod; there
is no container selector.

## Ownership

Labels narrow candidates; they never establish ownership. A Deployment target
requires the Pod → ReplicaSet → Deployment controller chain with matching
names, API versions and UIDs; a StatefulSet requires the direct StatefulSet
controller. A foreign owner with identical labels does not qualify.

A direct Pod reference resolves its actual supported workload root. An owned
Deployment/StatefulSet Pod keeps that workload's UID for permissions,
retention and quotas. An unowned Pod uses its own UID, and a Pod that gains a
controller after pinning no longer matches an unowned pin. Other controller
families are unsupported and return a closed unsupported result.

## Selection for the single-Pod context profile

`builtin-pod-status-v1` captures one Pod. Among eligible candidates of the
named workload (scheduled and nonterminating for the node class; any phase for
the [API reader class](api-context-execution.md)), the resolver selects the
first by lexical name whose controller chain belongs to the workload.
Readiness and phase are not requirements: status collection stays useful for
unhealthy Pods. The preview names the selected Pod (`lexicalEligiblePod`, or
`explicitPod` for a direct reference) and states that the recipe collects one
Pod. This does not change the all-replica monitoring default of other
recipes.

An unscheduled Pod returns `ErrUnscheduled` for the node class; the API class
supports it without a node identity.

## Recording inventory root identity

`ResolveWorkloadIdentity` returns the current namespace and Deployment or
StatefulSet UIDs without selecting a Pod, so retained recordings remain
discoverable for a workload with no live replicas. A deleted object is not
replaced with fabricated identity. Current workload eligibility precedes
source lookup, and each original Pod still needs current eligibility before a
row is returned.

## Result and pinning

The result contains the exact input reference, namespace/workload/Pod UIDs,
the immediate controller UID, the node name and UID for the node class, and
resource versions. It contains no labels, annotations, container names,
environment values or other raw API content.

Request acceptance resolves the same target again and compares it with the
approved scope; a replaced Pod, workload root or node is never substituted and
cannot extend an approval. The executing collector or API reader verifies the
Pod UID once when the effect starts. No value returned here is a permission.

For an approved packet request, `resolve-packet-recorder` returns the exact Pod
resolution together with recorder availability from the node collectors'
current status, in one response. Availability is an observation, not
authority. Preview keeps its separate workload selection because it also
produces plans for unavailable or unsupported recorders.
