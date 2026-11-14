# Cluster state push

The hub needs current namespaces, workloads, Pods, EndpointSlices,
AccessBindings and permission sources of every enrolled cluster (REQ-FED-001,
REQ-CAP-004). The connector (A-CONN) watches them and pushes changes; the hub
never reads a remote API server per operation. Implements
[ADR-330](../decisions/330-event-driven-system-design.md) D1/D2.

## Connector side

- The connector runs shared informers (LIST once, then WATCH) for namespaces,
  for workloads, Pods and EndpointSlices in opted-in namespaces, and for
  AccessBindings and the permission sources of [ADR-329](../decisions/329-accessbindings-in-application-namespaces.md).
- An informer cache stays valid until the watch replaces or invalidates it. A
  watch failure marks that resource type unavailable until the relist
  completes; the connector reports the unavailable type to the hub.
- On each change the connector sends a minimized delta (cluster ID, kind, UID,
  namespace, name, `resourceVersion`, the fields the hub uses, or a delete) on
  the cluster-state stream of its one hub connection. Pod specs, environment,
  Secrets and status fields the hub does not use are not sent.
- Deltas are coalesced per object: a burst of updates to one object sends its
  latest state.

## Hub side

- The hub replica holding the connection upserts each delta into a SQL
  projection keyed by `(cluster, kind, uid)` in stream order; one stream
  carries a cluster's deltas, so they arrive in watch order. The stored
  `resourceVersion` is opaque and used only for the reconnect digest. A
  delete removes the row.
- The same transaction issues `NOTIFY` so hub processes that cache the
  projection (target resolution, capacity, permissions) update without
  polling.
- Projection rows carry no expiry. They stay valid until replaced, deleted or
  marked unavailable. Requests that need a resource type marked unavailable
  return `NotAvailable`; they do not wait or trigger a remote read.

## Reconnect

After a reconnect or a connector informer relist the connector sends, per
resource type, a digest over `(uid, resourceVersion)` of its cache. The hub
compares it with the projection. On a match nothing is sent; on a mismatch
the connector resends that type and the hub replaces the cluster's rows of
that type in one transaction. There is no periodic full resend.

## Cost

API-server load is one LIST per resource type per connector start plus watch
events. Hub cost is one SQL upsert per changed object. Neither depends on the
number of user operations. Precedent: Open Cluster Management status
feedback, Karmada work-status controller, Argo CD cluster cache.
