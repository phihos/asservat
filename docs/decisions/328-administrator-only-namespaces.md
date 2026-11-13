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
key service; peer authentication between clusters over mutual TLS.

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
