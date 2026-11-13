# ADR-329 — AccessBindings in application namespaces

Date: 2026-11-13. Status: accepted (maintainer decision); specification and
implementation pending. Supersedes the hub-control-namespace storage of
AccessBindings in `specs/permissions.md`, the delegated-writer envelope of
ADR-189/ADR-237 and the permission guard.

## Decision

AccessBindings live in the application namespace they grant access to, in the
workload's own cluster, like Kubernetes RoleBindings. Teams that may write
AccessBindings in their namespace (ordinary Kubernetes RBAC, typically the
same people who manage that namespace's RoleBindings) manage Asservat access
for it. The Asservat namespaces stay administrator-only (ADR-328).

Consequences:

- A binding's scope is its own namespace; it no longer names a cluster or a
  namespace UID. The hub learns bindings through each region's connector,
  which observes AccessBindings in its cluster and delivers them with the
  existing permission observation.
- The delegation envelope and the permission admission guard go. Kubernetes
  RBAC decides who may write in a namespace. Cluster-wide or multi-namespace
  grants use PermissionSources, which stay administrator-managed.
- Automation-bearing bindings (`spec.automation`, ADR-059) and their
  envelope need a separate decision: either they stay administrator-only in
  the hub, or namespace RBAC also governs them.
- Escalation: Kubernetes does not apply RoleBinding `escalate`/`bind`
  protection to custom resources. Whether Asservat limits which roles a
  namespace writer may assign is a security measure that needs external
  evidence under the evidence rule before it is added.

The permissions specification, the CRD scope, the connector observation and
the hub evaluator change together in one implementation slice.
