# Local durable start journal

C-07/C-11/C-20/C-21/C-24 under I-02, TASK-03/05 and S-01/S-02; partial REQ-FED-002, REQ-CAP-002/005 and REQ-ARC-003/004 implementation. This is a narrow local journal, not a node execution listener or a complete distributed permit service.

The first `CapacityReservation` profile, `onTriggerStart/v1`, stores one immutable prepaid effect. Operation/capture/action/attempt, cluster/issuer epoch, pod/node/boot/collector epoch, scope/authority/budget/audit digests, native-byte limit and original start interval are required. The interval is at most 60 seconds. No evidence, reason, command, tokens or keys enter this record. Record name is derived from the immutable attempt; the reference resolver also pins its original Kubernetes object UID. Work IDs, delivery fences and reconnects cannot choose another effect identity.

The capacity writer creates the object only after all required reservations are durably held, then makes it Ready. The execution role may only change Ready to StartCommitted through the status subresource. A resourceVersion compare-and-swap consumes the start before any effect. The adapter never creates, recreates, resets, refunds or deletes a reservation. Initial cleanup intentionally has no implementation or permission; finite record quotas and proven-spend retirement must precede production readiness.

`ConsumeStart` checks original authority freshness before and after blocking API work, reads the fixed control namespace UID and exact record, verifies every immutable binding and issues a single non-retrying status PUT. Only receipt of the successful update while authority remains valid returns `MayStart`. A duplicate or restarted reader returns the existing disposition without this allowance. A lost reply requires `LookupStart`; lookup after the original deadline is useful for reconciliation but never authorizes execution. Expiry after the successful write leaves the record consumed. A crash between consumption and the effect may lose evidence; it cannot justify a second unproven start.

The structural CRD enforces bounds, immutable spec and forward-only consumption. A separately installed native admission policy separates capacity and execution users even if ordinary resource RBAC is broadened. It rejects deletion, parent owner references, metadata/spec updates and a consumer trying to create or mark Ready. Installation-policy protection and narrow production credentials still require qualification. Administrator control of admission itself remains a trust boundary, as for the permission guards.

Native CEL matches the namespace name; it does not independently attest namespace UID. An attempted UID expression was rejected by the actual Kubernetes server because that metadata field is absent from its CEL namespace type (`test/results/local-start-namespace-cel-unavailable.log`). The journal and protected configuration readers therefore retain their independent API namespace-UID check on every read. The real namespace-replacement test exercises that authoritative boundary. A policy object's presence or a successful dry run cannot substitute for it.

`StartCommitted` means only that the right was consumed. It does not prove a process began, a capture succeeded, evidence committed or a writer stopped. The receiver must still authenticate enrollment, resolve current signed references, enforce the protected local ceiling, recheck the target, hold local process exclusion, and check the returned deadline immediately before the effect. No HTTP handler can accept an arbitrary `execution.Request` as authority. Duplicate response delivery, old collector processes and partition exclusion require the node-side gate; this adapter alone does not establish them.

## Verification

Actual TLS component tests race twelve callers, reconstruct the adapter, lose a committed PUT reply, expire authority during GET/PUT and substitute UID, namespace, boot, collector, audit, byte limit, generation, deletion state and owner references. A case-insensitive JSON field regression was reproduced before the exact-key check was added. The fixed component suite passes under the race detector (`test/results/local-start-unit.log`).

The owned real Kubernetes fixture passed with exit 0, exercising the structural CRD, admission policy, separate users, Ready initialization, competing CAS, restart and denial of reset/mutation/deletion. The permission observation/reconciliation checks also passed. Source hashes were unchanged and all owned resources were removed. Results are in `test/results/local-start-integration-check.log`, `test/results/permission-admission.log` and the permission environment report. Go/import architecture, SQL generation, specification and architecture gates subsequently passed in `test/results/local-start-gates.log`. This is journal/admission evidence, not distributed node exclusion or full execution qualification.


ADR-106 adds the separate private `apiContextStart/v1` profile for the fixed
regional API snapshot. Target node/boot fields are absent; executor Pod/account
and process identity are mandatory. Each policy now matches its own control
namespace so independent node/API journals can coexist. This does not replace
the journal's exact namespace UID check. The API preparation, result and current
qualification boundary are in [regional API execution](api-context-runner.md).
