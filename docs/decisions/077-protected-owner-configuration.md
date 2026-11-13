# ADR-077 — Protected hub owner configuration

> Superseded in part by ADR-328 (2026-11-13): UID-pinned selection and the shared ConfigMap admission guard with its dry-run probe no longer apply. The `owner-pool.json` ConfigMap is Helm-rendered and read by name under RBAC; route composition remains.

Date: 2026-10-10. Status: implementation refinement under the maintainer's continuation; full Go/race/import, composed owned Kubernetes/service and specification/design checks pass. Credential issuance/activation and forwarding remain pending.

ADR-076's pinned constructor inputs cannot establish where the installation's owner pool and public issuer roots came from. Add a private `owner-pool.json` ConfigMap contract, read by name under RBAC and scoped to installation/cluster. The payload contains only public trust and routing configuration. Private issuer credentials remain outside that payload, so it cannot grant itself signing rights.

Plain RBAC protects the ConfigMap, as for other application configuration.

The source uses closed canonical JSON and bounded current public CA roots. Observation deadlines remain at most five seconds and cannot exceed any configured root's expiry. A suspended source can still be observed for operator diagnostics, but cannot produce a usable route.

Compose route resolution in C-04: read current configuration, resolve the exact owner endpoint under that pool, then read matching current configuration again. Reject changes in pool, revision/digest, roots or suspension. Preserve the first observation's deadline rather than renewing it with the second read. Bounded cached observations may be reused only while their original deadlines remain valid. No endpoint, key or configuration credential is selected from a worker callback.

This adds no SQL table, public permission API, external service or new user approval. It does not supply durable monotonic configuration acceptance, recovery authority, issuer bootstrap, certificate issuance/activation or forwarding. Those must compose with this observed configuration before any public credential or evidence path is enabled. See [the contract](../architecture/owner-configuration.md), [schema](../../specs/contracts/owner-configuration.schema.json) and [actual progress](../implementation-progress.md).
