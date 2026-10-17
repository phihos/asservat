# ADR-101 — Protect installation staging before workload identities exist

Status: accepted engineering refinement of ADR-099/100. Native qualification
and remaining provisioning work are tracked in [progress](../implementation-progress.md).

## Decision

Install a temporary, administrator-only namespace admission policy before
creating the fresh setup namespace. Its inert plan needs a namespace name, not
an invented namespace UID or future Pod/account identity. After creation, bind
observations to the actual retained namespace UID and exact policy/binding pins.
Use a separate harmless public ConfigMap and non-administrator probe to prove
enforcement before creating future installer identities, workloads or provider
credentials. Bootstrap probe credentials have only the explicit diagnostic
purpose; they do not establish collection, SQL or key-service authority.

The staging policy denies all non-administrative namespaced mutations and
connections, including Pod/Secret creation and TokenRequest. Its only exception
is a dry-run UPDATE of the separately named public startup-input ConfigMap.
That exception allows the final workload guard's independent denial to remain
visible while both policies are installed. The staging policy's own probe uses
a different ConfigMap, where it must deny even a dry-run UPDATE. No persisted
write, Secret operation, workload launch or general dry-run bypass is added.

Keep the original installer Pod gated through setup. Install and independently
qualify final namespace/source/witness protection before retiring the temporary
binding; retain exact object UIDs/resource versions and original deadlines.
Only then can the supervisor remove the original Pod's scheduling gate.
An interrupted handover cannot adopt another namespace, Pod, policy or binding.
The temporary guard is not a permanent runtime policy and grants no ability to
clear database recovery.

Kubernetes [admission controls](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
govern mutations and connections, not GET/LIST/WATCH. Scoped RBAC, protected
policy administration and Secret storage remain mandatory. NamespaceLifecycle
also rejects operations against a nonexistent namespace; a successfully created
policy therefore is not itself proof of namespace enforcement. Use the current
native denial after namespace creation and preserve explicit historical setup
state. A present-day guard observation alone cannot prove clean provisioning.

## Implementation boundary

C-01 owns the private domain plan; C-21 provides an inert policy/binding builder,
create-only namespace producer, exact read-only resumption and current
guarded-namespace reader. Ordered creates reauthenticate the administrator,
retain acknowledged pins and stop on unknown replies without replay/adoption.
No new public API, database field, executable, dependency or Helm runtime switch
is added. The owned fixture invokes these producers and probes actual admission;
the durable bootstrap journal, complete resource inventory, provider orchestration and guarded handover
are still required. Multi-API-server propagation and supported-cluster coverage
remain qualification work; a single owned Kubernetes control plane is not proof
of instantaneous fleet-wide admission or revocation.
