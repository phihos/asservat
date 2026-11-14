# Regional Kubernetes API context

This C-06/C-11/C-14/C-21 segment implements the execution class of
[ADR-104](../decisions/104-regional-api-context-execution.md) under
REQ-EXE-002, REQ-EVD-001–003 and the S-02 context workflow. It lets the fixed
Pod status snapshot inspect a Pod that has not been scheduled. Execution is
described in [the API context runner](api-context-runner.md).

## Exact class and target

`artifact.ContextExecutionClass` has two values. The empty value is the node
class and stays omitted in historical JSON. `kubernetesAPI` is explicit and
server-selected; it is not a user choice or inferred from missing node fields.

The class is carried by `targets.PodResolution`,
`planning.ContextCapability`, `capture.ContextPreview` and
`artifact.ContextExpectation`. The compiler requires target and capability to
agree. API targets and previews forbid `Pin.NodeName`; API targets and
expectations forbid node UID/boot. A class change is a reviewed-scope change.

The resolver works on the connector's pushed workload and Pod state (ADR-330
D1). A named Deployment/StatefulSet selects the lexically first
non-terminating Pod it owns. An explicitly selected Pod normalizes to its
actual workload owner. API selection includes unscheduled Pods and never reads
Nodes. Deletion, replacement or owner change yields no substitute target.
Workload eligibility precedes target disclosure.

## Scope, manifest and collection

API `collection-scope/v1` pod bindings include `executionClass: kubernetesAPI`
and `podUID`, without node or boot fields. The schema limits this class to the
single-Pod `builtin-pod-status-v1` profile. Historical node bindings keep their
canonical bytes.

The connector reads the pinned Pod through its namespace/Pod read permission
and checks namespace, Pod and owner identity. `scheduled` is an observed
condition; the projection exposes no node name, workload configuration,
labels, annotations, addresses, environment or free-text messages. Responses
are capped at 2 MiB, which covers the 1.5 MiB etcd object limit plus JSON
overhead; the projection is a subset of that response and needs no separate
ceiling.

The accepted expectation requires metadata, `pod-status` and the 2 MiB
response bound. The encrypted manifest includes `target.executionClass:
kubernetesAPI`; the canonical schema forbids node/boot claims and restricts
kind, format, action and size. Removing the class cannot produce a valid node
manifest, and adding node facts cannot turn an API artifact into node evidence.
Encryption framing, AAD, the wrap-only producer, retention and native reads
are shared with the node class.

## Authorization

The hub authorizes the start once (ADR-311): accepted work, caller, ordinary
permission, retention and storage are checked in the SQL transaction that
records the execution row. The decision is reused for at most
`identity.AuthorityRecheckInterval` and never past the request deadline. SQL
effect checks at commit remain. The hub writes the execution row with its ordinary
SQL credential ([ADR-222](../decisions/222-hub-process-sql-credentials.md)).
