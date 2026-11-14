# ADR-068 — Kubernetes-bound download worker proofs

> Superseded in part by ADR-328 (2026-11-13): reading the worker's namespace, ServiceAccount, Job and Pod to match UIDs, controller identity and spec digests against pinned dispatch facts no longer applies; objects in the download-worker namespace are trusted. Online TokenReview with the dedicated audience, binding to the acquisition certificate and minimized proof persistence remain.

Date: 2026-10-10. Status: implementation refinement of ADR-051/065/066. Proof production and consumption are implemented components; protected dispatch, peer issuance and runtime composition remain required.

A valid acquisition certificate identifies a peer but does not establish that it is the intended current worker for a download. Require a short-lived Kubernetes observation before the trusted coordinator creates the existing download key binding. This is an internal machine check, with no new developer approval or configuration task.

Use the worker cluster's TokenReview API with a dedicated installation audience and a finite Pod-bound ServiceAccount token. Match the returned account and Pod identities against the dispatch record. The dispatch record, not a successful token review alone, selects the download.

Kubernetes documents that offline token verification does not establish current bound-object validity. TokenReview verifies the bound claims. Node claims in a Pod-bound token are not node attestation. [Kubernetes ServiceAccount documentation](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/).

Bind each proof to the exact acquisition certificate whose peer ID is the Pod UID, download ID, installation and worker cluster. The evidence cluster can differ. Check the token within the original five-second interval. After successful TokenReview, read only the standard token lifetime claims to cap the proof at token expiry; reject unbounded tokens and lifetimes exceeding one hour. This does not introduce an offline JWT authority path.

Persist only the minimized identity/certificate/time proof and token digest in migration 24. Never retain the bearer token or full workload spec. SQL checks original proof freshness after locks and before completing key consumption. Retrying the same batch cannot replace its proof, extend its deadline or refill the three slots. Existing rows without a proof deny access; migration cannot fabricate authority for them.

The dispatcher records these facts when it creates the approved download-only Job, enroll its peer and deliver the token through authenticated control mediation. Those operations, production RBAC/audit configuration, issuer lifecycle, public transfer and installation remain unfinished. The component contract distinguishes these remaining responsibilities from proof validation.
