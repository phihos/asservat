# ADR-081 — Prove hub owner enrollment before readiness

Status: accepted for component implementation; durable owner registration, signing spend, activation and clean installation remain pending. Implements the proof prerequisite of ADR-079/080 under REQ-FED-001, REQ-DEP-003 and REQ-DLD-003.

## Decision

Use a dedicated Pod-bound service-account token audience, an identity-free signed CSR, the audited current owner configuration and independently qualified private namespace protection. Obtain the Pod name from online TokenReview and independently verify its exact account, namespace, Pod, ReplicaSet and Deployment identities. Initial proof accepts a scheduled Pending or Running Pod without requiring Ready or an EndpointSlice. Actual forwarding retains the existing Ready endpoint and exact TLS identity checks.

Kubernetes documents that [online TokenReview verifies bound-object claims](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#verifying-and-inspecting-private-claims), while offline JWT validation cannot prove current object existence. Its deletion grace also makes independent live deletion checks necessary for immediate rejection. The token proves possession of a Pod credential. It does not prove a unique process; the CSR proves key possession, and durable enrollment must subsequently bind the key, Pod, requested process epoch and leaf purpose with finite signing budgets.

Repeat token review and live membership reads around the observation, recheck current configuration/protection, and retain the earliest original deadline. Return only public scope/provenance and digests. No token, private key, Pod spec or credential-bearing provider error is persisted or returned by the proof adapter. This observes eligibility for enrollment; it does not sign, activate a peer or authorize evidence access.

## Consequences

The [owner enrollment contract](../architecture/owner-enrollment-proof.md) fixes the internal types, audience, proof lifetime and failure behavior. There is no public API, CRD, SQL migration, dependency or developer approval change. The existing worker TokenReview adapter shares the same bounded review decoder but keeps its separate audience and expected Pod-name check.

Clean installation and continuous protection before credential/workload launch remain mandatory under ADR-080. A current guard and matching controller references cannot repair historical compromise. Node/controller/API-server and administrator trust remain explicit. Production proof composition must use the audited SQL configuration reader, not a raw ConfigMap source or fixture configuration. Complete registration, encrypted enrollment audit, pre-I/O signing spend, certificate audit/activation, renewal and forwarding remain subsequent work.
