# ADR-093 — Bounded scheduling permission inside the private hub namespace

Date: 2026-10-11. Status: selected under continuing implementation authorization. Requirements: REQ-DEP-003/005, REQ-FED-001, REQ-DB-005; part of TASK-02/07/11 and S-01/S-02.

## Problem

ADR-091's scheduling adapter has only get/update access to one installation-created, UID-pinned Lease. However, ADR-080's namespace-wide workload admission policy rejects every non-administrator Lease update. The separate configuration-worker and owner fixtures did not exercise this combination. Source probes were fixed in ADR-092; persistent scheduling updates require a different, explicitly bounded rule. Granting the worker installation-administrator status or excluding all Leases would be inappropriate.

## Decision

Add a required private `schedulingLeases` array to the owner deployment projection and a corresponding workload administration value. It contains at most four unique `{lease, serviceAccount}` pairs, each an exact Kubernetes name within the already pinned private namespace. An explicit empty array grants no exceptions. The installer owns this input alongside the existing source-probe list; developers do not configure it and no per-investigation approval is added.

For a listed pair, the namespace admission policy permits only UPDATE on the `coordination.k8s.io` `leases` main resource by that exact ServiceAccount username. This includes real updates used by leader election. No CREATE, DELETE, subresource, other actor/resource/object, token request, workload mutation, Secret or configuration write is exempted. Ordinary RBAC remains mandatory and gives the actual worker only get/update on the named Lease plus its already scoped namespace read. Separate source/audit/identity roles remain unchanged.

[Kubernetes Leases](https://kubernetes.io/docs/concepts/architecture/leases/) support component scheduling, and [named RBAC resources](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources) can bound get/update to that object. The installer creates it first. The runtime still pins namespace and Lease UID, uses resourceVersion CAS, rejects excessive/coordinated-election records and never creates or adopts a replacement. The admission exception describes the permitted object operation; it does not attest a Lease's content or grant authority to observe, accept configuration, recover a database, issue credentials or collect evidence. An actor able to corrupt its own scheduling Lease can deny scheduling service; it cannot turn that Lease into those independent authorities.

Use only common request fields in the wildcard namespace policy, preserving the existing qualified CEL approach. The ordinary API enforces object identity/validation, while the existing scheduling adapter enforces original UID and record bounds. Do not treat wildcard-policy type checking as Lease schema verification. Retain the exact list in expected policy and protection digest, defensively copy it, and require restart/requalification on changes. The private pre-release v1 projection gains a required field; no deployed public API or database migration is involved.

## Qualification

First extend the native configuration-worker fixture to install both source policies and the real namespace policy, and reproduce the blocked scheduling UPDATE with the actual non-administrator token. Then verify automatic protected reconciliation with the exception, denial to a different actor, actual-role denial of create/delete/unrelated resources, and namespace denial of those operations even with broader fixture-only attack RBAC. Retain original Lease loss, no recreation, source removal, blocked initial recovery and audit checks.

The context harness supports an explicitly recorded `--run` pattern for this regression; its default remains the full suite. A zero Go exit with no passing selected test is rejected. Filtered runs do not qualify the complete suite. Actual terminal outcomes, source hashes and cleanup belong in [implementation progress](../implementation-progress.md).

This closes scheduling/policy composition. Installer-generated workloads/projections, native in-Pod operation, initial/recovery activation and the complete investigation platform remain separate unfinished work.
