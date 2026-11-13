# ADR-327 — Ingress and Gateway API exposure

Status: implemented and unit-tested; Ingress installed on the maintainer's
homelab (see Qualification); Gateway API installed qualification pending.

## Context

ADR-202 exposed the public API (console, MCP, `/auth/*`, downloads) only as a
NodePort or LoadBalancer Service, with TLS ending in the hub-api, so a browser
URL needed a non-standard port (`:31450`) and the operator's existing Ingress
controller or Gateway could not front it.

Maintainer decision (2026-11-13): support Ingress and Gateway API. Operators
must be able to let the proxy terminate TLS; encrypted or mutually
authenticated traffic between the proxy and Asservat is a recommendation, not
a requirement ("For my little homelab this totally overblown").

## Decision

`promotion.exposure` gains:

- `serviceType: ClusterIP`, for Services reached only through a route.
- `tls: pod | proxy` (default `pod`). `pod` keeps ADR-202: the hub-api
  terminates TLS with the operator's serving pair; a proxy may pass TLS
  through or re-encrypt to it. `proxy`: the operator's Ingress or Gateway
  terminates TLS for the `https` origin and forwards plain HTTP; the hub-api
  serves HTTP on its public port and needs no serving pair, so the
  `public-tls.*` material and the CLI's `--public-tls-*` flags become optional.
- `ingress` (`className`, `annotations`, optional `tlsSecretName`) or
  `httpRoute` (`parentRefs`, `annotations`), at most one. The installer creates
  a `networking.k8s.io/v1` Ingress or `gateway.networking.k8s.io/v1` HTTPRoute
  named like the public Service, for the origin's host and path `/`, in the
  protected hub namespace. Like the Service, a rerun accepts the unchanged
  route and refuses a changed one; controller-added annotations and API
  defaults that do not reroute are ignored.

A route requires an origin without an explicit port, because the hub-api
requires `Host` to equal the origin's host. Request checks that previously
required `r.TLS` now ask `edge.Secure`: TLS at the hub-api, or a listener
whose base context marks TLS at the proxy. Forwarded headers still confer
nothing, and no client address is read, so no trusted-proxy list is needed.

Only the installer runner and installation administrators can write in the
protected namespace, so cert-manager cannot place an Ingress certificate
there. Use the controller's default/wildcard certificate, an
administrator-managed `tlsSecretName`, or a Gateway (whose listener
certificate lives in its own namespace).

Federation, owner, owner-operation and key-service listeners are unchanged:
they authenticate peers with mutual TLS bound to the TLS session (ADR-193), so
a proxy may only pass them through. Browsers and humans never use them. The
bundled Keycloak keeps its NodePort Service in this change.

## Consequences

- With `tls: proxy`, anything that can reach the hub-api's Service inside the
  cluster talks plain HTTP to it. Recommended: restrict that Service with a
  NetworkPolicy to the proxy, or keep `tls: pod` and let the proxy re-encrypt.
- Session cookies keep `Secure` and the `__Host-` prefix: the browser still
  sees the `https` origin.
- Long native downloads go through the proxy; raise its idle/response
  timeouts and body/buffering limits as its documentation describes.

Complexity check: no new state, background task or fallback; two optional
objects created once by the existing exposure step; RBAC grows by `get/create`
on Ingresses and HTTPRoutes for the installer only.

## Qualification

- Unit: `internal/transport/edge` (TLS, marked proxy listener, forwarded
  header ignored), route create/rerun/change and input validation for both
  kinds, the public file shapes, ClusterIP exposure.
- Installed: see `docs/implementation-progress.md` for the homelab Ingress run.
