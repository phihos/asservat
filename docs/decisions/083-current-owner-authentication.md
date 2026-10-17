# ADR-083 — Current authentication of an enrolled hub peer

Date: 2026-10-10. Status: selected for implementation under the maintainer's continuing authorization. Requirements: REQ-FED-001, REQ-DEP-003, REQ-DLD-003; part of TASK-02 and S-01/S-02.

## Problem

An OpenBao-signed leaf and an active SQL enrollment do not establish that a connection may currently reach an authenticated request owner. A Pod may be unready or deleted, namespace protection may disappear, an administrator may remove roots, or an enrollment may be retired while a TLS connection remains open. Separate passing enrollment, discovery and TLS tests do not demonstrate their composition.

## Decision

Add a C-04 `OwnerAuthenticator` over typed current registry, route, workload-protection and actual-TLS ports. Use a single original five-second interval. Require the exact activated leaf/registration, accepted pool/source revision, Ready Pod/controller/account/service observation, independently qualified namespace protection and current explicit-root verification. Read registration/protection around routing, reject changes and retain all original deadlines. Return a finite `AuthenticatedOwner` identity value only; the request locator, live request/developer credentials, evidence authority and capacity remain separate.

C-21 owns an immutable bounded snapshot of an actual completed verified TLS 1.3 connection. It copies/reparses DER and revalidates both independently pinned and currently accepted roots on each use. Server connections additionally bind the exact expected owner and deterministic SNI. A current source change or expired certificate cannot survive through reuse of an earlier handshake. The adapter does not own a socket, authorize a callback, or promise cancellation of another component's I/O.

C-21's native workload guard additionally exposes its result bound to the exact observed hub cluster, namespace and Deployment. A constructor or certificate string cannot substitute for that current proof. No new SQL migration, public wire contract, user permission API or approval is introduced.

## Qualification and limits

Compose real protected Kubernetes Pod/token/CSR proof, accepted configuration, SQL enrollment/spend, purpose-scoped OpenBao signing, OpenBao-wrapped encrypted S3 audit and separate activation before readiness. Inject administrator suspension after signing and audit but before activation; resuming must reuse the stored leaf without re-signing. After readiness, authenticate the actual TLS peer; later root removal, retirement or Pod deletion must deny use of the same connection snapshot.

This is component integration: the fixture administrator supplies initial recovery/issuer bootstrap and short Pod-bound tokens; the test process owns the CSR/private keys and loopback TLS listener. The pause Pod is not a production hub executable. Protected installation, runtime owner credential transport/supervision, original-locator-bound forwarding, native transfer, local CA and the public workflow remain required. Actual results and cleanup belong in [implementation progress](../implementation-progress.md), not this decision.

The implementation uses Go's [verified TLS connection state](https://pkg.go.dev/crypto/tls#ConnectionState) and the existing online verification of [Kubernetes bound service-account tokens](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens). Those mechanisms provide different facts: actual key possession on a connection versus current Pod binding. Neither alone supplies Asservat's current registration or request authority.
