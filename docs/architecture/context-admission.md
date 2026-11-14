# Context planning and admission

C-03/06/07/09/15/21/24 under I-09, TASK-02/03/05/07/11 and S-01/S-02. Implements
part of REQ-EXE-001/002, REQ-PRV-001–003, REQ-CAP-004/005 and REQ-EVD-001–003.
Mechanisms follow [ADR-330](../decisions/330-event-driven-system-design.md).

## Plan

`planning.CompileContext` compiles one pinned Pod into `builtin-pod-status-v1`:
one required on-trigger pod-status action, five seconds of collection,
4096 native bytes. It requires the exact projection definition and the
capability reported for the target cluster ([context capability](context-capability.md)).
General snapshot recipes and unknown projections cannot use it.

Canonical `collection-scope/v1` binds capture, actor/client, workload, exact Pod
UID, execution class, original deadline, recipe, collector image, projection and
ceiling digests. The node class binds the node and requires a scheduled Pod;
the [Kubernetes API class](api-context-execution.md) permits unscheduled Pods
and has no node authority. Requested retention and `effectiveRetention` bind
each action's purpose, class/type, maximum, deletion budget and every applied
policy UID/generation/digest. Reason, sharing, result access, grant handle and
idempotency key are separate submission fields. Compilation runs no
acquisition. The original request deadline is at most five minutes away; the
dependency limit is 64 and overflow fails with a consolidation diagnostic.

## Retention intersection

The C-15 resolver takes the complete policy set matching the exact target plus
exactly one installation baseline. All maxima apply, defaults use the shortest
default, and deletion reserves the largest required budget inside the shortest
maximum. Incompatible purposes, a combined budget leaving no usable interval,
duplicate policy/rule identities and excessive inputs fail.

Unknown classification receives potential-personal-data restrictions; stricter
classes also match broader personal-data rules; generic `other` output matches
every type-specific cap. Every matched policy reference is kept. Derived
evidence inherits the earliest parent anchor and cutoffs; an expired parent
prevents new usable output. Tightening cannot lengthen or resurrect evidence.
The resulting deletion deadline is stored on the capture row
([ADR-330](../decisions/330-event-driven-system-design.md) D12).

## Atomic admission

`AdmitContext` is one SQL transaction that:

1. locks the workload's capacity account and storage binding (and the pool row
   only when burst use applies), then the capture row for the idempotency key;
2. checks current SQL permissions, denies and the complete default audience
   against the operation's authorization decision (one decision per operation,
   [ADR-311](../decisions/311-operation-authority-recheck.md));
3. checks storage ownership, the workload's byte/object/record limits
   ([control capacity](context-control-capacity.md)) and the processing
   coverage of [processing admission](processing-admission.md);
4. inserts the capture with its stored retention deadlines, its expected
   manifest facts and one append-only audit row.

No remote I/O occurs inside the transaction. Failure rolls back everything,
including the audit row; there is no pending-audit state.

The idempotency key is scoped to actor and client. A retry with the same key and
the same submission digest returns the stored capture without recollection, new
charges, audience change or deadline renewal. The same key with a different
digest conflicts. An unknown commit outcome is resolved by looking the key up.

SQL stores minimized control metadata, not native evidence, workload
configuration, bearer tokens or evidence keys.

## After admission

The accepted capture is dispatched to its cluster over the connector connection
([regional context start](regional-context-start.md)). The dispatcher resumes
accepted, unstarted captures from SQL after a restart. Collection, verification,
publication and download are separate steps with their own authorization.
