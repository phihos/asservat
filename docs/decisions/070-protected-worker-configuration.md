# ADR-070 — Protected worker configuration and rollout fencing

> Superseded in part by ADR-328 (2026-11-13): the ConfigMap UID pin, admission-policy check and non-administrator dry-run probe no longer apply. The worker profile is a Helm-rendered ConfigMap read by name under RBAC. Revision tracking, rollout interruption and cleanup under historical identity remain.

Date: 2026-10-10. Status: implemented component refinement of ADR-069; scoped Kubernetes/SQL/S3 qualification passed, production runtime remains pending.

A constructor-supplied worker profile is insufficient authority to schedule or attest an acquisition worker. Resolve it from the administrator ConfigMap in the worker namespace, read by name under RBAC, with a closed `worker-profile.json` payload that names installation and cluster. Deletion or unavailable APIs deny observation.

Migration 26 persists monotonically accepted revisions and original observation deadlines. An independently credentialed audit role must acknowledge a matching encrypted immutable snapshot before use. A new staged revision immediately supersedes the previous head, even while its audit is pending; no fallback to an older audited revision. Refreshing the identical revision does not create another audit record or invoke encryption. Suspended settings deny work. Recovery blocking and source expiry remain independent fences.

Dispatch, binding and identity lookup check the current audited revision. The Kubernetes Job driver also requires the current configuration before creating or observing a worker. Historical accounting and proven cleanup remain possible after suspension or rollout: revoking authority must not prevent retirement. Existing immutable dispatch records cannot be rewritten to inherit a new image/configuration. An already issued worker proof keeps only its original deadline, capped by the configuration observation, so configuration changes have a bounded five-second exposure window rather than an instantaneous distributed revocation promise.

The initial rollout policy interrupts old-profile downloads: a changed revision requires a newly admitted worker after confirmed retirement. It cannot refill counters or extend the download/evidence deadline. Graceful concurrent profile draining is not implied. This conservative first implementation needs a visible interrupted/retry status in the eventual runtime, not manual developer configuration. The chart renders the profile; hand-written developer profile JSON is not a product workflow.

Configuration history is capped at 1024 immutable revisions per enrolled source; observations reuse the existing revision. Safe history cleanup and its backup obligations remain required. The actual acquisition executable/issuer, continuous runtime supervision and Helm composition remain unfinished. The transactional projection establishes these particular boundaries without claiming a deployed investigation platform.

See [worker configuration contract](../architecture/worker-configuration.md), [schema](../../specs/contracts/worker-configuration.schema.json) and [implementation progress](../implementation-progress.md) for actual tests and limits.
