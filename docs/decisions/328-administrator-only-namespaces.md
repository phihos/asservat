# ADR-328 — Administrator-only Asservat namespaces

Date: 2026-11-13. Status: accepted (maintainer decision). Supersedes the
namespace-writer, forged-workload and tampered-configuration threat
assumptions of earlier ADRs, which now reference this record.

## Decision

Operators keep every non-Asservat-administrator completely out of the
Asservat namespaces (hub, bootstrap, connector, download-worker). Kubernetes
RBAC and Pod Security `restricted` enforce that, as for any other
application. Inside this boundary everything is trusted:

- anyone who can create or modify objects in an Asservat namespace,
- any cluster administrator,
- the objects in those namespaces (ConfigMaps, Secrets, Pods, Deployments,
  ServiceAccounts, owner references).

Asservat therefore does not verify its own installation at runtime:
no admission policies pinned to object UIDs, no dry-run denial or access-review
probes, no installer journals, witnesses or launch receipts, no
re-verification that its own objects are unchanged. Components read
configuration from mounted ConfigMaps and Secrets and authenticate callers
with TokenReview and TLS.

## What remains in scope

Users and workloads outside the Asservat namespaces: per-operation checks of
the current human or workload identity, permissions, retention and sharing;
encrypted evidence and audit; SQL effect fences; key material confined to the
key service; peer authentication between clusters over mutual TLS. Writers in
application namespaces are outside Asservat: where permission sources derive
grants from their labels, Helm-installed admission policies protect those
labels (ADR-247), with no runtime proof of the policies.

## External evidence

- Kubernetes RBAC good practices: restrict who can write workloads, Secrets
  and ConfigMaps in a namespace, because those writers can act as any
  service account there:
  https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- Kubernetes multi-tenancy: the namespace is the unit of isolation, with
  RBAC, Pod Security and network policy per namespace:
  https://kubernetes.io/docs/concepts/security/multi-tenancy/
- Comparable operators run in a dedicated namespace and trust its contents
  (cert-manager, Vault, Argo CD installation guides); none verifies its own
  objects at runtime. See docs/reviews/security-evidence-2026-11-13.md.

## Implementation status

The superseded notes describe the target state. The code still contains the
mechanisms until the Helm-native installation and guard removal land
(docs/reviews/helm-native-install-plan.md, TASK-11).

## Evidence rule

Every security measure must be backed by external research describing its
benefit (standards, vendor guidance, incident reports, comparable projects).
Measures without such evidence are removed. Agent-authored ADRs are not
evidence.

## Consequences

Earlier ADRs that rely on the superseded assumptions carry a
"Superseded in part by ADR-328" note naming what no longer applies. The
mechanisms they describe are removed by the Helm-native installation plan
(`docs/reviews/helm-native-install-plan.md`).
