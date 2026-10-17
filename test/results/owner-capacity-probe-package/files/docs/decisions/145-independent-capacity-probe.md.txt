# ADR-145 — Independent capacity admission probe

Status: selected under continued implementation authorization. Requirements:
REQ-DEP-003, REQ-FED-001, REQ-CAP-001. Component and native results remain in
[implementation progress](../implementation-progress.md).

The installed configuration worker must prove that the capacity administrator
policy rejects its two dry-run CREATE requests. The private namespace policy
otherwise rejects the same requests, which can mask the required independent
capacity-policy denial. RBAC permission alone cannot prove either policy.

Extend the original private workload plan with optional `capacityProbe`, holding
one exact same-namespace ServiceAccount name and UID. The namespace policy permits
only explicitly true dry-run CREATE of the main `asservat.io/v1alpha1`
EvidenceStoragePool and EvidenceBudgetPolicy resources by that exact account.
The independently pinned capacity policy must still reject the request. Real
CREATE, UPDATE, DELETE, status, other versions, resources and actors retain the
namespace denial. No generic dry-run exception or source-writing authority is
introduced. Normal RBAC remains separately required.

A fresh installed owner layout derives the account from original resource receipt
1 before creating workload policy/binding 17/18. It also adds the fixed
`asservat-<compact-installation>-processing-source` ConfigMap to the existing
named dry-run UPDATE probes. Worker activation, owner deployment, configuration
role production and their native readers retain the complete original plan.
Worker-only and legacy omissions remain distinct. Existing claims cannot be
rewritten or adopted as this new original plan; none of these inputs activate a
source, recover a database or enable public collection.

The native regression first establishes the old namespace-only blocker, then
proves the new exact nonpersistent branch before installing the independent
capacity guard. Persistent and differently scoped requests must receive the
namespace policy's structured denial. The actual CapacityGuard must then verify
both capacity resource probes with both guards installed and reject missing
capacity protection. Its disposable permissive CRDs qualify policy composition,
not the eventual production CRD schema or installed worker execution.
