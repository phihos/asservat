# ADR-081 — Prove hub owner enrollment before readiness

> Superseded in part by ADR-328 (2026-11-13): the ReplicaSet/Deployment ownership checks and the namespace protection proof no longer apply. Online TokenReview with the dedicated audience and the identity-free CSR remain the enrollment proof.

Status: accepted for component implementation; durable owner registration, signing spend, activation and clean installation remain pending. Implements the proof prerequisite of ADR-079/080 under REQ-FED-001, REQ-DEP-003 and REQ-DLD-003.

## Decision

Use a dedicated Pod-bound service-account token audience, an identity-free signed CSR and the current owner configuration. Obtain the Pod name and account from online TokenReview. Initial proof accepts a scheduled Pending or Running Pod without requiring Ready or an EndpointSlice. Actual forwarding retains the existing Ready endpoint and exact TLS identity checks.

Kubernetes documents that [online TokenReview verifies bound-object claims](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#verifying-and-inspecting-private-claims), while offline JWT validation cannot prove current object existence. The token proves possession of a Pod credential. It does not prove a unique process; the CSR proves key possession, and durable enrollment must subsequently bind the key, Pod, requested process epoch and leaf purpose with finite signing budgets.

Recheck current configuration and retain the earliest original deadline. Return only public scope/provenance and digests. No token, private key, Pod spec or credential-bearing provider error is persisted or returned by the proof adapter. This observes eligibility for enrollment; it does not sign, activate a peer or authorize evidence access.

## Consequences

The [owner enrollment contract](../architecture/owner-enrollment-proof.md) fixes the internal types, audience, proof lifetime and failure behavior. There is no public API, CRD, SQL migration, dependency or developer approval change. The existing worker TokenReview adapter shares the same bounded review decoder but keeps its separate audience and expected Pod-name check.

Node/controller/API-server and administrator trust remain explicit (ADR-328). Complete registration, encrypted enrollment audit, pre-I/O signing spend, certificate audit/activation, renewal and forwarding remain subsequent work.
