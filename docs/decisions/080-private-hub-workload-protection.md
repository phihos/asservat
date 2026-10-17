# ADR-080 — Protect the private hub workload namespace

Status: accepted for component implementation; production installation and owner enrollment composition remain pending. Refines ADR-076–079 under REQ-FED-001 and REQ-DEP-003.

## Problem and decision

A Pod-bound token and matching Pod → ReplicaSet → Deployment references are insufficient if another namespace writer can create Pods with the hub account, forge owner references, inject a process or mint its credentials. Kubernetes documents the authority implicit in [workload creation](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation). Protect the dedicated private hub namespace before installing credentials/workloads; observed application namespaces retain their existing permissions and Restricted Pod Security.

Use a native fail-closed ValidatingAdmissionPolicy plus Deny binding, with independently pinned namespace UID, administrator roster and policy/binding identities. Restrict all namespaced create/update/delete/connect operations. Permit installation administrators and bounded operations by exact reference Kubernetes controller identities. Ordinary RBAC remains required and controls reads. Event writes are the sole resource exception; they carry no workload, credential or permission authority. No custom webhook dependency or developer approval is introduced.

Prove current enforcement with a separate non-administrator, non-controller identity that has ordinary RBAC for the exact Deployment update. Re-submit the existing Deployment unchanged with `dryRun=All` and require the exact policy/binding denial. Re-read policy/binding and namespace around the proof, retaining an original five-second deadline. An arbitrary Forbidden error, changed binding, type warning or successful dry-run is not protection.

## Limits and consequences

The [private contract](../architecture/owner-workload-protection.md) defines the controller profile, scope and qualification. This is current enforcement, not proof of historical integrity or owner enrollment. Installation must establish a clean protected namespace, least-privilege Secret access and independently trusted workload identity before accepting tokens. Applying this policy after compromise does not repair it. A compromised node/controller, cluster administrator or actor with credential-read/impersonation authority remains outside this boundary.

Do not reuse this namespace for user workloads or acquisition Jobs whose application controllers need write access. The installer must arrange separate scopes. Unsupported controller identities/operations fail closed until separately qualified; do not solve an installation failure by granting all service accounts or all authenticated users access. Native integration covers the reference controller path and attack denials; it does not certify every controller branch or managed Kubernetes distribution.

No SQL migration, public permission API, evidence format, user-facing approval, dependency or application data collection changes. Pod/token/CSR proof, durable owner enrollment/signing/audit/activation and protected installer bootstrap remain subsequent composition.
