# ADR-104 — Regional Kubernetes API context execution

Status: implementation decision under the maintainer's continuation
authorization. Qualification and enabled runtime scope remain recorded in
[implementation progress](../implementation-progress.md).

A Pod's API status is useful before scheduling, including an investigation of a
Pod that never starts. Requiring a node UID, boot ID, privileged collector or
node enrollment for this fixed API projection prevents that ordinary use case
and adds deployment work without supplying authority for the actual API read.
Node identity remains necessary for mechanisms that execute on a workload node.

Introduce one explicit `kubernetesAPI` execution class for
`builtin-pod-status-v1`, selected by protected capability and regional service
composition. Its target binds the exact namespace, workload owner chain and Pod
UID. It requires no scheduled node and cannot contain a node UID, boot ID or node
execution pin. The resolver and collector use read-only Kubernetes credentials;
neither needs Nodes, Pod exec, logs or Secret access. The status projection and
4096-byte ceiling do not expand. A Pod becoming scheduled is observed status,
not a change in acquisition authority.

Preserve the historical node class as the omitted class value. Its canonical
scope, expected-facts JSON and encrypted manifest rendering remain unchanged,
and its node/boot validation remains mandatory. There is no missing-node
fallback. Explicit class participates in API collection scope, capability,
passive preview, accepted expectation and manifest verification. A class change
requires a new preview; uploaded evidence cannot choose its own class.

Reuse existing capture admission, reservations, encrypted intent audit,
single-use key preparation, local start consumption, custody verification,
outcome audit, publication and native downloads. Do not introduce another
approval service, evidence format or public acquisition endpoint. Regional API
execution still requires a protected execution identity distinct from the
capacity allocator, current permissions/retention/recovery and conservative
handling of unknown starts. It cannot borrow the node collector's identity or
weaken the node `runAction` validator to accept missing provenance.

The first implementation segment covers API resolution, planning, expected
facts, bounded collection and encrypted verification. A native fixture exercises
an actual unscheduled Deployment using a service account explicitly denied
Nodes and exec; synthetic authority inputs remain documented fixture inputs.
Production regional start/publication composition and installation remain
separate, required work. See [the class contract](../architecture/api-context-execution.md).
