# ADR-202 — Public API exposure

Date: 2026-10-18. Status: accepted; implemented, unit-tested; native
qualification with the installed journey pending.
Requirements: S-02 (installed browser and MCP access); REQ-DEP-003.
Follows [ADR-194](194-promoted-owner-inputs.md) (promoted hub-api) and
[ADR-196](196-regional-cluster-join.md) decision 5 (the owner's native Service).

## Context

The promoted hub-api serves the console, `/mcp`, `/auth/*` and download routes
on its public port (9445), but only on the owner's in-cluster Service. Nothing
outside the cluster can reach it, so no browser or MCP client can use an
installed Asservat, and the installed journey cannot be qualified.

The public listener accepts direct TLS only: it terminates TLS with the
operator's certificate, requires the `Host` header to equal the configured
origin, and trusts no forwarded headers. A TLS-terminating gateway would need
its own qualified adapter.

## Decision

- An optional `Promotion.Exposure` (`serviceType` `NodePort` with an optional
  fixed node port, or `LoadBalancer`) makes the installer create the public
  API's own L4 Service, `asservat-<installation>-owner-public`, on port 9445,
  selecting the owner Deployment's Pods (step `public/exposure`, after the owner
  installation). A rerun accepts an unchanged Service and refuses a changed one.
- It is a separate Service, not a port on the native Service: the native
  Service's port set is pinned by ADR-196, and the public API's audience and
  exposure choice differ from the connectors'.
- Plain TCP only. An operator who fronts it with a load balancer or ingress must
  pass TLS through; TLS termination in front of the hub-api is not supported.
- Without `Exposure` nothing changes.

## Consequences

- Installed browsers and MCP clients can reach the hub-api at the operator's
  origin, which must resolve to the exposed address.
- The installed journey test uses a NodePort and connects with the origin's
  server name and `Host` header.
