# ADR-085 — Private owner enrollment receiver

Follow-up: [ADR-087](087-live-owner-delivery.md) replaces the finite v1 reply with a live v2 response through downstream worker delivery; identity and original-deadline checks remain mandatory.

Date: 2026-10-10. Status: selected for implementation under the maintainer's continuing authorization. Requirements: REQ-FED-001, REQ-DEP-003, REQ-DLD-003, REQ-CAP-003; part of TASK-02 and S-01/S-02.

## Problem

The owner credential and locator components do not yet accept network requests. A TLS handshake alone cannot keep a retired owner authorized, and a wire locator cannot recreate the authenticated control request. Socket closure must accompany credential shutdown. Treating the first five-second peer observation as authority for the whole thirty-second enrollment would extend its lifetime; forcing all enrollment work into that observation would instead conflate identity admission with independently checked operation authority.

## Decision

Add the private HTTP/1.1 receiver and versioned [owner relay request](../../specs/contracts/owner-relay.schema.json). The request contains the existing bounded worker enrollment message and the exact shared locator. Its Authorization header carries only the dedicated Pod token; no personal credential, endpoint or authority is accepted. The reply reuses the worker enrollment response. A caller must still discover and authenticate the exact destination before transmitting the token; the outbound adapter is separate unfinished work.

Check actual client TLS and current local serving eligibility before reading the body. Bound that transfer by the earliest original peer/local observation. The receiving owner resolves the exact currently registered handle and performs existing independent human, Pod, locator, audit and signing checks under the original operation deadline. Recheck both identities before delivering the result, requiring unchanged caller registration/configuration/protection and limiting output to the new original observations plus every operation/owner/certificate deadline. No peer observation becomes an evidence permission. Keep owner cancellation live through the final flush.

Use a distinct C-04 local-server identity port; never fabricate a TLS handshake to authenticate oneself. C-21 verifies the owned server certificate under pinned and current roots; the application repeats registry/protection/Ready-route checks. Remote peers retain the actual TLS port. C-14 resolves the registration through the existing bounded router instead of adding another cache or durable locator table.

Use Go's established [HTTP server](https://pkg.go.dev/net/http#Server.Close), [TLS configuration](https://pkg.go.dev/crypto/tls#Config) and the already selected [netutil connection limiter](https://pkg.go.dev/golang.org/x/net/netutil#LimitListener). Pin TLS 1.3 and mutual certificate verification; disable session resumption and HTTP/2 for this finite control protocol. Limit accepted connections before TLS; keep TLS outermost so net/http observes actual peer state. Every connection ends within thirty-five seconds or its initially observed serving certificate's earlier expiry. Request deadline resets cannot extend that absolute limit. Cancellation closes listener, active sockets and request contexts; join request cleanup for at most five seconds and report failure if it does not finish. No evidence streaming or hijacking is supported on this receiver.

No new dependency version, SQL migration, public endpoint, approval or developer setting is added. Existing x/net becomes a direct import. Future optimization of pooling/protocols requires equivalent revocation, cancellation and resource qualification.

## Qualification

Tests exercise actual TLS, current-check phases, request and connection limits, stale ownership, cancellation, strict payload parsing and certificate response bounds. Native integration connects actual Kubernetes/OpenBao/SQL/S3 owner credentials to the receiver's admission checks; its inner operation deliberately returns unavailable. Separate SQL tests exercise exact live registration lookup and enrollment. These scopes are not a fully composed native forwarding workflow or production installation. Actual exits belong in [implementation progress](../implementation-progress.md).

Protected startup/token provisioning, outbound exact-owner forwarding, connector-local proof mediation, native transfer, public UI/MCP workflows and global admission/load qualification remain required.
