# ADR-076 — Exact hub owner discovery and TLS identity

> Superseded in part by ADR-328 (2026-11-13): verifying the Pod → ReplicaSet → Deployment chain, service account and pinned Service/Deployment identities against forged hub-namespace objects no longer applies. Discovery reads the named Service's EndpointSlices under RBAC; the TLS identity checks remain.

Date: 2026-10-10. Status: implementation refinement under the maintainer's continuation; full Go/race/import, owned Kubernetes/service and specification/design checks pass. Protected bootstrap, issuer activation and forwarding remain incomplete.

ADR-075 records which hub Pod/process owns an active request, but supplies no network address or proof of that identity. Resolve the Pod only through the hub cluster's Kubernetes API and the named internal Service. Do not accept callback URLs from workers or use a Service load balancer to select an arbitrary replica. This adds no broker, external discovery service, permission API or database table.

Use a dedicated selector-based ClusterIP Service, including headless Services, with one numeric `owner-control` TCP target port. Read bounded EndpointSlices, require the exact Pod UID and use its ready IPs. An observation's original maximum lifetime is five seconds. API loss, incomplete pagination, replacement or conflicting identity fails without a cached fallback.

[Kubernetes EndpointSlices](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/) expose owner references, controller labels and endpoint conditions; `publishNotReadyAddresses` can override readiness. Refuse that override for this private pool. These fields are routing observations, not certificates.

Require TLS 1.3 and separate server/client leaves, with explicit issuer roots, a finite one-hour certificate ceiling and one canonical installation/hub-cluster/issuer-epoch/Pod-UID/process-epoch URI. The server additionally carries an exact deterministic DNS SAN used for TLS verification when dialing the independently observed Pod IP. This name is not a DNS discovery mechanism. Standard [Go TLS](https://pkg.go.dev/crypto/tls) verification stays enabled, followed by current X.509/profile/expected-identity verification. Recheck on reused connections; old TLS verification is not current authority.

The new verifier establishes a signed identity only. It does not issue or activate a certificate, prove the caller's current membership in the owner pool, accept a locator as a capability, or confer human/evidence access. The future private forwarder must verify both endpoints before sending credentials, retain original cancellation/deadlines, and check the current exact SQL/local request fence at the receiver. Current connector-origin proof and ordinary enrollment authorization remain mandatory.

See [the contract](../architecture/hub-owner-discovery.md) and [verification progress](../implementation-progress.md). The synthetic TLS issuer and restricted pause-Pod fixture are test inputs, never production bootstrap.
