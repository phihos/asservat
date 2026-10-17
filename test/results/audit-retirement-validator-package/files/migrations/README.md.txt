# Custody migrations and query bindings

`00001_custody.sql` is the initial storage-accounting facet described in [custody transactions](../docs/architecture/custody-transactions.md). It is not the complete hub schema. The current shared runtime adapter requires schema version 58; generated queries consume effective-retention columns and durable source checkpoints; runtime roles must not own schema objects or modify goose history. There is no destructive down migration that silently removes live charges or deletion records.

Use `make sql-tools` for pinned sqlc v1.31.1 and goose v3.28.0, with sufficient build space. `make sql-check` regenerates bindings in a private temporary directory and compares them with `internal/adapters/postgres/custodydb`. Intentional query/schema changes use the pinned `sqlc generate`, then review generated code and run the real PostgreSQL test.

`make custody-integration` applies the migration to a new, owned synthetic PostgreSQL container with a separate migration role, repeats `up` to check idempotence, and tests through a restricted runtime role. This fixture uses the goose CLI serially; it does **not** qualify concurrent production migrations. The production migration Job must use goose's PostgreSQL session locker, bounded migration/lock deadlines and a separate credential before runtime rollout. That Job/role composition and N/N-1 rollout are still pending.

Do not run the fixture's plaintext/private endpoint or synthetic role grants against an operator database. Production connections require endpoint-verified TLS, explicit primary/restore readiness and appropriate credential roles. The SQL outbox is not durable object audit. Full grant/configuration/lineage tables, metadata GC and backup/restore policy are subsequent migrations.

`00004_context_admission.sql` adds protected workload storage bindings and immutable pending-audit context admissions. It does not enable execution/publication. The context facet reserves four copy obligations and the accepted manifest scope in one transaction with current permission checks. See [context admission](../docs/architecture/context-admission.md).

`00005_capture_intent.sql` adds complete immutable encrypted-intent receipt fields and the non-executing `intent_audited` state. The capture-audit runtime role may update only those receipt/state columns, not accepted scope/deadlines, custody or permission content.

`00006_peer_identity.sql` adds blocked-by-default current fleet trust, disabled connector registrations and two bounded certificate slots. Its reader has SELECT-only credentials; it does not implement or authorize enrollment/issuance. See [peer identity](../docs/architecture/peer-identity.md).

`00007_enrollment_claim.sql` adds one-use, short-lived bootstrap claims bound to one CSR public key. The claim role cannot issue credentials or activate peers. [Claim contract and tests](../docs/architecture/enrollment-claims.md).

`00008_enrollment_audit.sql` adds write-once encrypted claim-audit receipts. `00009_certificate_issuance.sql` adds two bounded signing attempts, immutable public certificate results, encrypted certificate-audit receipts and atomic activation. These runtime facets consume an existing reviewed bootstrap; they do not supply its issuance producer. [Activation contract](../docs/architecture/enrollment-activation.md).

`00010_bootstrap_reservation.sql` adds immutable internal issuance reservations with actor/client idempotency and current serialized capacity checks. It creates no claimable token. See [bootstrap reservation](../docs/architecture/bootstrap-reservation.md).

`00011_bootstrap_issuance.sql` adds immutable credential digests, encrypted issuance-intent audit receipts and final claimable-token activation. The reserve, record, audit and activate roles have separate column/table grants. Provider credential storage alone creates no usable enrollment token. See [audited issuance](../docs/architecture/bootstrap-issuance.md).

`00012_context_publication.sql` adds immutable semantic-verification facts, encrypted verification-audit receipts and unique catalog associations. Narrow verification/audit/publish/read roles preserve the separation from generic ciphertext custody. See [context publication](../docs/architecture/context-publication.md); its external result/privacy gate and public delivery remain separate prerequisites.

`00013_download_sessions.sql` adds immutable per-workload transfer allocations, actor/client-idempotent sessions, prepaid generation-fenced batches and exact encrypted intent/outcome receipts. Read [download sessions](../docs/architecture/download-sessions.md) for authority, accounting and current qualification gaps. This is not an enabled public transfer route.

`00014_retention_lifecycle.sql` separates immutable original registration from monotonic effective cutoffs and appends exact lifecycle decisions with separately acknowledged signed/encrypted journal receipts. Existing attempts initialize from their original cutoffs. Runtime roles gain no deadline-extension or hold capability. [Contract and qualification](../docs/architecture/retention-lifecycle.md).

`00015_retention_sources.sql` persists pinned source identities, non-reusable controller epochs and immutable ordered policy checkpoints. Separate audit acknowledgement cannot mark a source Ready. Recovery blocking is not writable by source runtime roles. Read the [checkpoint contract](../docs/architecture/retention-checkpoints.md) for restart, review and catch-up boundaries.

`00016_closed_retained_interval.sql` permits an effective read cutoff equal to the acquisition anchor when a new cleanup budget consumes the old lifetime. Original registration remains strict and deadlines never extend. See [ADR-055](../docs/decisions/055-retained-evidence-cutoffs.md).

`00017_retention_catchup.sql` adds ordered, non-rewindable context catch-up pages and exact lifecycle-effect links. Bookmarks update a separate fenced resume cursor without scheduling evidence scans. The [catch-up contract](../docs/architecture/retention-catchup.md) describes the initial known-scope limit and remaining Ready barrier.

`00018_retention_observation.sql` separates finite complete-source observations from immutable policy history and bookmark progress. Availability is computed from fresh guard/LIST proof, the watch watermark, completed catch-up and exact audit receipts; there is no writable Ready flag. See [ADR-056](../docs/decisions/056-retention-watch-watermark.md).

`00019_policy_authority.sql` retains independently audited automation envelopes, bounded current policy-source observations, immutable accepted scopes, consumed submission nonces and separately acknowledged encrypted acceptance receipts. Current source/head and issuer-epoch checks prevent deletion, replacement, pause, stale observation or restore from silently reviving authority. Control edits retain scope; collection-intent edits advance a monotonic version. These facts are eligibility prerequisites, not execution permits or spending ledgers. See [team automation](../docs/architecture/policy-automation.md).

`00020_browser_sessions.sql` adds protected session roots/epochs, encrypted one-use login state, fixed-lifetime browser sessions, non-reusable refresh claims and bounded logout receipts. These operational credentials never confer policy or evidence authority. See [browser sessions](../docs/architecture/browser-sessions.md).

`00022_download_key_bindings.sql` adds private exact-batch/acquisition-certificate local-key bindings, original finite deadlines and a monotonically spent three-role mask. Coordinator insertion and key-service consumption use separate SQL credentials; current parent download, recovery and privacy fences still apply. It contains no keysets or artifact bytes. See [download key authority](../docs/architecture/download-key-authority.md).

`00023_local_key_configuration.sql` adds protected local key snapshots and immutable version fingerprints, with per-installation key-material uniqueness. No private root bytes enter SQL. Additive rotation and original source freshness are checked under recovery/scope locks; runtime cannot update/delete version history. See [local key lifecycle](../docs/architecture/local-key-lifecycle.md).

`00024_download_worker_proof.sql` binds original finite Kubernetes worker proofs to existing download key children. It stores minimized identities/digests, never bearer tokens; legacy NULL rows deny rather than receiving fabricated proofs. Runtime roles cannot replace proofs or renew deadlines. See [worker attestation](../docs/architecture/download-worker-attestation.md).

`00025_download_workers.sql` adds immutable dispatch/audit/launch/Job/Pod and termination/retirement transitions, separately counted unresolved workers and no expiry refund. See [worker lifecycle](../docs/architecture/download-worker-dispatch.md).

`00026_worker_configuration.sql` adds the current protected download-worker configuration head and immutable revision/audit history. Column-scoped observer, audit and reader credentials separate acceptance from use; monotonic triggers prohibit identity/revision rollback. Legacy worker records without a qualified configuration remain unavailable rather than receiving fabricated authority. See [worker configuration](../docs/architecture/worker-configuration.md).

`00027_worker_enrollment.sql` records immutable worker public-key enrollment, per-period signing attempts, public certificate/chain, independent encrypted audit acknowledgement and activation. No provider-call refund follows expiry; activation and signing/audit use disjoint roles. [Contract](../docs/architecture/worker-enrollment.md).

`00030_owner_enrollment.sql` adds immutable hub Pod/process/key registration, irreversible per-period signing spend, encrypted audit acknowledgements, separate activation/current registry and expiry-safe bounded pruning. [Contract](../docs/architecture/owner-registration.md).

`00058_audit_retirement_validator_scope.sql` preserves the original deferred
retirement predicates while allowing their two read-only trigger functions to
read shared lifecycle/history rows as the migration owner. Runtime capture
cleanup roles retain only their private filtered views and fixed effects; they
receive no shared-table or direct-validator execution grant. The fixed search
path and qualified relation names are retained. See [capture-intent lifecycle](../docs/architecture/capture-intent-lifecycle.md).
