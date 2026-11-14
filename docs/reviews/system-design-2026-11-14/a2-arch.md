# Spec design audit A2: docs/architecture `current-request-identity.md` … `native-reader-identity.md`

Worktree: `/home/phil/Projekte/asservat-specreview` (HEAD f9ccd35b). Read-only audit; no repository file changed.
Scope: 51 files. Twenty-one of them describe the removed installer, guard and journal design. They are listed as deletion candidates in §1 and were not audited further. The remaining 30 were read in full.

Severity counts (findings in §2): **high 9, medium 11, low 5**, plus **21 obsolete documents** to delete.

Abbreviations: "M-req" means a maintainer requirement cited from AGENTS.md. "Agent" means an agent-authored mechanism. Where an agent-added mechanism serves a maintainer capability, the finding names both.

---

## 1. Obsolete documents (delete or collapse)

The Helm-native install (#233/#234, `docs/reviews/helm-native-install-plan.md`) and ADR-328 remove the installer Pod, its continuation, UID-pinned admission guards, dry-run proofs, journals, the witness and temporary-credential retirement. `cmd/asservat/main.go` now has only `secrets, setup, download-worker, hub-api, hub-worker, hub-federation, connector, key-service, publisher, node`. None of the `initial-*`, `installer-*` commands remain. Each document below describes only those removed mechanisms:

| Document | What it describes | Action |
| --- | --- | --- |
| helm-bootstrap.md | ADR-137 five-command runner Pod, `installer-resume`, continuation container, legacy-Pod lookup | Delete; the replacement is `docs/installation/helm.md` plus secrets/setup Jobs |
| initial-activation-handover.md | ADR-129 initial-prepare→initial-install handover, marker guards | Delete |
| initial-activation-preparation.md | ADR-120 gated Pod, administrator/staging/continuity guards | Delete |
| initial-bootstrap-command.md | ADR-131 fixed bootstrap commands | Delete |
| initial-bootstrap-copy-closure.md | v3 setup-copy closure, tombstone marker | Delete |
| initial-bootstrap.md | ADR-131 trusted input producer, observation account | Delete |
| initial-final-inputs.md | `PrepareFinalInputs`, witness/fleet ConfigMaps + policy-binding pairs | Delete |
| initial-installation.md | ADR-098 first-installation activation coordinator, witness consumption | Delete. Keep one paragraph, wherever setup is documented, on how `setup` seeds the first recovery/incarnation row |
| initial-installer.md | ADR-099 `initial-install` executable | Delete |
| initial-namespace-staging.md | ADR-101 namespace staging policy/Deny binding | Delete |
| initial-preparation.md | ADR-102 create journal ConfigMap | Delete |
| initial-preparation-state.md | ADR-118 retained SQL material Secret pinned by UID | Delete |
| initial-preparer.md | ADR-117 `initial-prepare`, probe token | Delete |
| initial-private-probe.md | ADR-123 private probe issuance | Delete |
| initial-provider-provisioning.md | ADR-128 provider credential provisioning | Delete; the secrets Job replaces it |
| initial-schema.md | `initial-schema` command, plan/root, fifteen-minute limit | Delete. Keep a single line in the setup Job doc: goose migrations run in the setup Job (ADR-315 batched schema, if still applicable) |
| initial-sql-credentials.md | ADR-100 temporary SQL roles, retirement | Delete |
| initial-sql-provisioning.md | ADR-123 original SQL provisioning | Delete |
| installation-witness.md | ADR-097 one-use witness | Delete; the code in `internal/{application,domain}/fleet/installation_witness.go` and `internal/adapters/kubernetes/installation_witness.go` is also removable |
| installed-owner-identity.md | ADR-140/144 owner launch receipts, journal UID, workload guard, dry-run capacity probes (ADR-145) | Delete |
| installed-public-inputs.md | 2026-10-15 producer map for installer continuation inputs | Delete |

Consistent updates: AGENTS.md (the ADR-096…102 paragraphs, "Production installer provisioning … pending" and the ADR-080/088/090/092/093/094 owner-protection paragraphs all point at these documents); `docs/architecture/README.md` catalog; `specs/traceability.yaml` and the architecture checker inputs (`scripts/check-architecture.py`), if they list these files; `docs/decisions/README.md` status of ADR-097–102/117–145 (mark superseded by ADR-328 / helm-native plan).

**Partially obsolete documents.** These were audited below; their guard and pin text should be cut: download-environment.md:16, download-worker-dispatch.md:17-25, download-worker-attestation.md:9-21, fleet-administration.md:5-7, fleet-observation.md:29-40, hub-owner-discovery.md:7-15, identity-eligibility.md:34, local-key-lifecycle.md:7-9, local-start.md:11-13, native-owner-listener.md:9-20, custody-transactions.md:3 and 27.

---

## 2. Findings

### A2-01 (high): Per-64 MiB-window synchronous encrypted audit pairs and 5 s delivery leases on the download hot path

- **Files:** download-responses.md:7-9, 22-30, 57-98; download-sessions.md:15, 21; native-exchange.md:5, 47; native-owner-listener.md:42.
- **Current design:** Each 64 MiB window reserves SQL window rows and **two encrypted audit objects** (≤128 KiB each). Before any header or byte goes out, the window's intent object is written, independently read back and acknowledged. Delivery runs on ≤5 s leases. Each lease is renewed through an SQL renewal transition, and "the next window fully reattests" the worker. A 1 TiB download therefore needs 16,384 window transactions, 32,768 audit objects and up to 4 GiB of reserved audit capacity. The measured rate was 1.228 MiB/s with 70 current-check callbacks for one 8 MiB window. The document itself admits a "~0.4 MiB/s" ceiling.
- **Problem class:** Synchronous object-store audit on the hot path; per-window revalidation; chatty SQL; spend kept on uncertain outcomes.
- **Cost and scaling:** Throughput is far below what a Wireshark or core download needs. Object-store and SQL writes grow linearly with bytes. Each audit object is a create, a read-back and an acknowledgement.
- **Requirement status:** M-req: native download of all evidence with authenticated transfer, quotas and audit (ADR-044, AGENTS "native download for all gathered evidence"). M-req: ADR-312, where a started response runs to its original bounds with no rechecks. Windows, audit pairs, leases and per-window reattestation are agent-added (ADR-113/258/288).
- **Proposed replacement:**
  - Write one audit record at response start (intent) and one at end (outcome: bytes emitted, interrupted or completed). Write them through the SQL transactional outbox and publish the encrypted object asynchronously. The `custody_event` outbox already exists.
  - Track byte accounting with a single reservation for the selected range at start, then debit actual bytes at completion or interruption.
  - Bound the stream by ADR-312's original bounds only. Drop delivery leases and window reattestation.
  - Precedents: RFC 9110 Range/If-Range; S3 server access logs and CloudTrail data events, which are delivered asynchronously and never written before each GET; the transactional outbox pattern.
- **Other files to change:** download-sessions.md, native-exchange.md, native-owner-listener.md:42 (multi-interval conversations), download-stop-lifecycle.md (the Stop and window audit lifecycle disappears), specs/artifact-downloads.md, ADR-113/258/288, migration 00042 contract.

### A2-02 (high): Prepaid Stop lifecycle with signed certificates, purge leases and backup-horizon arithmetic

- **Files:** download-stop-lifecycle.md:1-166 (all).
- **Current design:**
  - Recording that a user pressed Stop on a download creates `download_stop_lifecycle` and `download_stop_history` rows.
  - Three proof modes (unused/unwritten/written) are tracked, with 2–32 finite purge leases of 5 s each and a once-only 30 s certificate claim.
  - A signed encrypted absence certificate is checked by an independent verifier with two fixed attempts.
  - Six frozen dates are derived from D−2H−3B−P and similar formulas, with twelve purpose-bound key operations per reservation and separate cleanup and acknowledgement roles.
- **Problem class:** Duplicated ledgers and receipts for one fact; spend kept on uncertain outcomes; bespoke protocol.
- **Cost and scaling:** Very large complexity for a cancellation record. Every download pre-reserves Stop backing, key operations and ciphertext slots. Lock-order rules (lines 150-166) couple it to `permission_stream`.
- **Requirement status:** Agent (ADR-124). The maintainer requires downloads to be cancellable and audited. Nothing in AGENTS.md asks for certificate-backed Stop retirement or backup-horizon proofs.
- **Proposed replacement:**
  - Stop becomes one SQL state transition on `artifact_download`, which the streaming handler observes through its context/LISTEN. Add one ordinary audit row in the same outbox.
  - Audit retention follows the common audit-retention policy and the normal deletion job.
  - For backups, document that expired rows age out with the backup rotation. The UK ICO's right-to-erasure guidance accepts backups being "put beyond use" until they are overwritten, with no per-record proofs.
- **Other files to change:** download-sessions.md, download-responses.md:40, custody-transactions.md:39 ("download-stop audit cleanup"), migration 47 contracts, specs/artifact-downloads.md, ADR-124.

### A2-03 (high): One Kubernetes Job per download, with full spec-digest pinning and deletion polling

- **Files:** download-worker-dispatch.md:7-37, 45-147; download-worker-attestation.md:9, 19; native-exchange.md:66.
- **Current design:**
  - Each download session dispatches a dedicated Job/Pod with a 30 s–8 h runtime.
  - Each dispatch reads PSA labels, the ServiceAccount, the immutable ConfigMap and the PriorityClass, and compares an RFC 8785 digest of the API-defaulted Job and Pod spec.
  - Capacity is held until a positive termination proof exists. Retirement polls up to 20×100 ms (42 requests).
  - Cleanup runs opportunistically inside user preparation and query requests (`ProjectionWorkerCleanup`).
  - Hard caps are 16 unresolved workers per installation and 2 per principal.
- **Problem class:** Design that cannot scale (per-request Jobs); self-verification of installer state; polling where watches exist; spend kept on uncertain outcomes.
- **Cost and scaling:**
  - Pod scheduling plus image pull adds seconds of latency to every download.
  - Downloads are capped at 16 concurrent per installation.
  - Spec-digest pinning breaks under any mutating webhook or sidecar injector (line 23 admits this).
  - Cleanup work is piggybacked onto user requests.
- **Requirement status:** M-req: native download from a separately scoped identity that can unwrap. Hub and collectors stay wrap-only (AGENTS ADR-044/065, "Key material only in the key service", hub cannot unwrap). The per-request Job, spec digests and retirement proofs are agent-added (ADR-069/073). ADR-328 removes the pin and self-verification checks.
- **Proposed replacement:**
  - Run a long-running `download-worker` Deployment in its Restricted namespace. Give it the download-read store credential and its own key-client identity, scale it with HPA, and have it receive work over the existing connector stream.
  - If per-download process isolation is kept, keep the Job but use `ttlSecondsAfterFinished`, a shared informer on Jobs (no GET/LIST loops), and the Job's `status.conditions` as termination evidence. Drop spec digests and PriorityClass/PSA re-reads.
  - Precedents: Loki/Tempo queriers, Argo CD repo-server, Velero node-agent (long-running workers fed by a queue); the Kubernetes TTL-after-finished controller.
- **Other files to change:** download-worker-attestation.md, native-exchange.md, native-owner-listener.md:12 and 20, download-key-authority.md, worker-configuration.md, worker-enrollment.md, worker-startup.md, `charts/asservat/templates/download-worker.yaml`, specs/artifact-downloads.md, ADR-069/070/073.

### A2-04 (high): Double TokenReview plus live Job/Pod spec checks on every key binding and response window

- **Files:** download-worker-attestation.md:17-31; download-responses.md:77-86; native-exchange.md:26; native-owner-listener.md:12, 20; download-key-authority.md:8, 20.
- **Current design:**
  - Within one 5 s interval the adapter runs TokenReview, exact GETs of namespace/SA/Job/Pod, a second TokenReview and a second set of GETs, then compares full spec digests.
  - The proof expires in 5 s. Key binding "still requires fresh five-second proof", and every new window "fully reattests".
  - The hub holds API tokens for up to 256 worker clusters/namespaces so it can run these reviews (native-owner-listener:12).
- **Problem class:** Requirements that defend against trusted actors; per-step revalidation; chatty API calls; cross-cluster credentials.
- **Cost and scaling:** About 10 API requests per proof, repeated per batch and per window, across every worker cluster. The hub keeps privileged TokenReview/read credentials in every worker cluster.
- **Requirement status:** Agent (ADR-068). ADR-328 (M-req): "authenticate callers with TokenReview and TLS"; namespace writers and forged Pods are trusted. The doc's own Kubernetes citation supports a single TokenReview.
- **Proposed replacement:**
  - Authenticate the worker once at enrollment with a single TokenReview against the dedicated audience, then issue its mTLS leaf.
  - After that, the mTLS certificate (lifetime ≤ token lifetime) identifies the worker. Drop the double reads, spec digests and per-window reattestation.
  - TokenReview runs in the worker's own cluster through the connector, so the hub needs no worker-cluster tokens.
  - Precedents: Vault/OpenBao Kubernetes auth (one TokenReview at login, then its own token); cert-manager csi-driver-spiffe (TokenReview once per issuance); the Kubernetes bound SA token docs.
- **Other files to change:** download-worker-dispatch.md:13, download-key-authority.md, native-exchange.md, native-owner-listener.md, download-responses.md:66-86, worker-enrollment.md, ADR-068.

### A2-05 (high): Installation-wide lock serialization (fleet trust row → permission root) on every effect

- **Files:** download-recovery.md:7, 21; download-worker-dispatch.md:7 ("The root/installation lock also serializes capacity admission across replicas"); download-key-authority.md:22; download-stop-lifecycle.md:111, 152-164; download-environment.md:20; local-key-lifecycle.md:21; enrollment-activation.md:7; enrollment-claims.md:11; custody-transactions.md:29.
- **Current design:** Every reserve, batch start, content permit, metadata permit, key binding/consume, dispatch, Stop cleanup and key-config acceptance locks the installation `fleet_current_trust` row and then the installation permission root (`permission_stream`) before its own rows.
- **Problem class:** Global locks and single-writer bottlenecks.
- **Cost and scaling:**
  - All download and capture effects in the installation serialize through one or two rows, so throughput is bounded by one transaction's lock hold time (5 s budgets, 1 s lock waits).
  - Fleet observer updates contend with this path. ADR-155/161 exist only to work around that contention (see A2-06).
- **Requirement status:** Agent (ADR-096 recovery fence, ADR-023 SQL authority). M-req (AGENTS, helm-native plan): "SQL effect fences" and "the recovery fence observed by hub-worker" remain. The fence is required; the serializing lock is not.
- **Proposed replacement:**
  - Read the recovery state with plain MVCC in the same transaction, or `FOR KEY SHARE` (which does not conflict with other readers or non-key updates). Compare its epoch/incarnation column in the effect's WHERE clause.
  - A recovery or restore transition takes `ACCESS EXCLUSIVE` or bumps the epoch, so later effects fail their CAS.
  - Replace the permission-root lock with a per-allocation conditional `UPDATE … SET used = used + n WHERE used + n <= limit RETURNING`.
  - Precedents: PostgreSQL explicit-locking docs (FOR KEY SHARE vs FOR UPDATE); optimistic concurrency/epoch fencing as in Kubernetes resourceVersion and etcd leases.
- **Other files to change:** download-sessions.md:19, download-responses.md, custody-transactions.md:29, native-owner-listener.md:18 (lock privileges), retention-effects.md and context-admission docs outside this range, ADR-096/155/161.

### A2-06 (high): Fleet trust kept "fresh" by a 5 s re-observation loop, with read failures suspending the installation

- **Files:** fleet-observation.md:5-7, 15-48; fleet-administration.md:7; download-recovery.md:3; local-key-lifecycle.md:13.
- **Current design:**
  - The `TrustObserver` re-reads the pinned fleet ConfigMap and writes an SQL observation whose freshness expires 5 s after read start. The recovery projection's source lease is 30 s.
  - A read or validation failure sets suspension, which blocks all effects.
  - Two tables (`fleet_trust`/`fleet_observation`), a materialized query, ADR-155's 55P03 lock-abort classification and equal-time replay rules exist to keep this loop from blocking itself.
- **Problem class:** Polling where watches exist; expiry-driven freshness windows; many degraded states.
- **Cost and scaling:**
  - The installation needs a write every few seconds just to stay usable.
  - Any API-server blip or slow SQL suspends every download, capture and key operation.
  - The machinery is complex (two ADRs and migration 00059 exist only to keep the observation fresh).
- **Requirement status:** Agent (ADR-091/155/161). Rule 1 (event-driven: cached state stays valid until replaced) and ADR-328 (trust mounted ConfigMaps) apply. M-req: recovery fence (database incarnation) stays.
- **Proposed replacement:**
  - Mount `fleet.json` (Helm-rendered) or watch it with a client-go informer. Persist a revision only when the content changes. Never expire it.
  - Last-known-good stays valid across API outages.
  - Keep only the database-incarnation fence: `setup` seeds the first incarnation, and restore changes it.
  - Delete `fleet_observation`, ADR-155's classification and the read-failure suspension.
  - Precedents: client-go SharedInformer; kubelet-projected ConfigMap updates; cert-manager and Argo CD reading configuration from watched ConfigMaps.
- **Other files to change:** download-recovery.md, fleet-administration.md, custody-transactions.md:3, configuration-reconciliation.md, ADR-091/155/161, migration 00059 contract.

### A2-07 (high): Exact-hub-process rendezvous with per-Pod/process PKI and EndpointSlice discovery

- **Files:** hub-owner-discovery.md:1-39; native-exchange.md:3, 24-28; native-owner-listener.md:3-20; download-responses.md:57-64.
- **Current design:**
  - A worker's bytes must reach the exact hub Pod/process that owns the browser request.
  - The routing uses SQL owner locators, a per-process SPIFFE-shaped identity (`…/pod/<podUID>/process/<processEpoch>`) with 1 h leaves and owner enrollment/registration/activation (ADR-079–088).
  - Each lookup does pinned Service/Deployment/SA/Pod/ReplicaSet reads plus a paginated EndpointSlice list, with resource-version re-reads (5 s bound, ≤1024 endpoints, 8 MiB).
  - A three-hop relay runs worker→connector→hub owner.
- **Problem class:** Bespoke PKI/enrollment and protocol; chatty API reads per request; self-verification of installer state.
- **Cost and scaling:**
  - API reads on every forwarded request.
  - A dedicated owner CA and registry, plus four SQL owner roles.
  - Hub scaling events invalidate routes.
  - The largest single block of agent machinery in this range.
- **Requirement status:** Agent (ADR-074–088, 122, 144). M-req: central multi-cluster management with connectors (ADR-016 "central multi-cluster management"), and native authenticated downloads.
- **Proposed replacement:**
  - The connector keeps one long-lived outbound HTTP/2 (or gRPC) reverse tunnel to the hub Service, opened from the cluster side.
  - Whichever hub replica serves the browser GET opens a stream through the tunnel to the worker, by worker ID. Replicas find the tunnel holder through PostgreSQL LISTEN/NOTIFY, or use a hub-federation Deployment that holds the tunnels.
  - Use one installation CA (cert-manager or the OpenBao PKI already present) for hub/connector/worker mTLS with ordinary DNS SANs. No per-process identities, no EndpointSlice discovery.
  - Precedents: Kubernetes apiserver-network-proxy (Konnectivity), OCM cluster-proxy, Rancher remotedialer, Teleport reverse tunnels.
- **Other files to change:** native-exchange.md, native-owner-listener.md, download-responses.md, worker-owner-locator.md, owner-*.md, worker-routing.md, worker-request-routing.md, interfaces.md:189-220 (I-13), ADR-074–090, chart Service with three ports.

### A2-08 (high): 5 s identity windows and repeated identity/permission re-resolution inside one operation contradict ADR-311

- **Files:** current-request-identity.md:16-52; download-authority.md:5-11, 17; download-environment.md:5; mcp-runtime.md:36-53, 73; native-reader-identity.md:32-46; identity-eligibility.md:21, 52; download-sessions.md:15-17; local-key-service.md:33, 55; native-exchange.md:5.
- **Current design:**
  - The default request interval is 5 s.
  - `ResolveIdentity` reads the identity again, and the docs require identity to be "checked again after blocking permission/evidence reads". The final download lease is ≤5 s from the initial check.
  - MCP rechecks identity before releasing every response.
  - The deny set must be "complete" and ≤5 s old, and environment and key permits are ≤5 s.
  - The evidence-read 20 s window exists because 5 s could not cover the audit plus SQL plus worker path.
- **Problem class:** Expiry-driven freshness windows; per-helper revalidation; chatty reads.
- **Cost and scaling:** Two or three identity resolutions per operation, each a SQL session read, a settings read and permission/deny observations. Installed runs lapsed mid-request (ADR-311 context: about 56 runs).
- **Requirement status:** M-req ADR-311 (maintainer, 2026-11-07): check once per operation and reuse for `AuthorityRecheckInterval` (30 s; 60 s for delivery policy). These docs were not updated.
- **Proposed replacement:**
  - Authenticate once at ingress. Evaluate eligibility and permissions once per operation, then reuse the snapshot until min(check+30 s, hard ends).
  - Remove "check again after blocking reads", the final pre-response identity re-read in MCP, the ≤5 s deny bound and the 5 s permit caps.
  - Precedents: ADR-311; the Kubernetes apiserver authenticates and authorizes once per request; RFC 6750 bearer validation per request.
- **Other files to change:** identity-eligibility.md, permission-observation.md (deny interval), download-environment.md, local-key-service.md, mcp-runtime.md, native-reader-identity.md, specs that state 5 s bounds (search `five-second` in specs/), AGENTS.md ADR-214/216 paragraphs.

### A2-09 (high): Publication re-reads and re-decrypts every uploaded frame

- **Files:** manifest-verification.md:23-30, 44; custody-transactions.md:19.
- **Current design:**
  - After upload, `ContextVerifier` reads back the envelope, manifest, index and **all data frames**, then authenticates and schema-checks them.
  - For recorder artifacts it reruns the PCAPNG/syscall streaming check, bounded by 30 s + 1 s per frame. The generic custodian also rereads all four ciphertext objects.
- **Problem class:** Duplicated work; O(size) synchronous read-back; publication latency grows with artifact size.
- **Cost and scaling:** Object-store egress and CPU double for every artifact. Publishing a multi-GiB PCAP waits minutes or more.
- **Requirement status:** M-req: encrypted managed storage, evidence provenance and verification. Full read-back is agent-added (ADR-048/244).
- **Proposed replacement:**
  - Have the writer compute the per-object SHA-256 while streaming. Send it as S3 `x-amz-checksum-sha256` so the store rejects corrupt uploads, then record it.
  - Verify the manifest and index (small) at publish time. Rely on the AEAD tag per frame at read time for data integrity.
  - Run the structural PCAPNG/syscall check in the producer before encryption.
  - Precedents: S3 additional checksums (`ChecksumAlgorithm=SHA256`); Tink streaming AEAD authenticates each segment on read; restic/borg verify at write and on scheduled `check`, not on every commit.
- **Other files to change:** custody-transactions.md, context-publication.md, artifact-format.md, ADR-048/244.

### A2-10 (medium): Single-use key slots (3-bit spent mask) and per-operation SQL authority in the key service

- **Files:** download-key-authority.md:7-24, 32; local-key-service.md:53-55, 63; native-exchange.md:41, 47.
- **Current design:**
  - Every preparation batch and every response window gets a `download_key_binding` row with three irreversible unwrap slots. Unwrap after a lost reply is refused.
  - The key service resolves authority through SQL per operation (a ≤5 s permit), then rechecks after resolution and again after crypto.
  - Preparation and content each spend three unwraps.
- **Problem class:** Exactly-once accounting where idempotency suffices; chatty SQL; per-step revalidation.
- **Cost and scaling:** Three key-service calls, three SQL transactions and one binding row per window. A lost reply forces a new paid batch.
- **Requirement status:** M-req: only the scoped download worker can unwrap, and hub/collectors are wrap-only (ADR-065, "Root/private keys belong only in the isolated key-service role"). Slots and the per-op SQL resolve are agent-added (ADR-066).
- **Proposed replacement:**
  - When the hub authorizes the download, it issues a short signed authorization (a JWS with artifact ID, worker cert digest and expiry, signed with the existing policy-signing purpose).
  - The key service verifies it locally and unwraps idempotently for that artifact until expiry. The worker caches the three DEKs for the response's lifetime.
  - Precedents: Kubernetes KMS v2 (DEK caching, few KMS calls); Vault transit with token policies (no per-call ledger); AWS KMS grants.
- **Other files to change:** download-worker-attestation.md (binding proof), native-exchange.md, local-key-service.md, local-key-lifecycle.md, migrations 00022/00024, ADR-066.

### A2-11 (medium): Local key configuration has an SQL acceptance ledger, 5 s observations and an SQL consult on every crypto call

- **Files:** local-key-lifecycle.md:7-25; local-keys.md:29.
- **Current design:**
  - The key configuration ConfigMap and its immutable Secret are pinned by UID and SHA-256 and read with namespace checks before and after.
  - An SQL `local_key_configuration`/`local_key_version` acceptance ledger is checked under the fleet recovery lock.
  - The backend reuses observations for only 5 s. Every operation runs a configuration/recovery guard before and after crypto that "still consults SQL for every guard call".
- **Problem class:** Self-verification of installer state; expiry-driven freshness; chatty SQL on the hot path.
- **Cost and scaling:** At least two SQL reads and periodic API reads per wrap, unwrap or sign. Key-service availability depends on SQL and the API server.
- **Requirement status:** M-req: purpose-separated static-key services (ADR-063). The pins, ledger and guards are agent-added (ADR-067). ADR-328: "configuration from mounted ConfigMaps and Secrets".
- **Proposed replacement:**
  - Mount the key Secret and reload on change (fsnotify or kubelet atomic symlink swap).
  - Tink keysets carry versioned keys, so rotation is additive by construction. Keep the anti-rollback rule as a validation in the Helm/secrets Job.
  - Drop the SQL ledger and the per-operation guard.
  - Precedents: OpenBao/Vault seal configuration from files; Prometheus/Alertmanager config reload; the Tink keyset rotation guide.
- **Other files to change:** local-key-service.md:55, local-keys.md, migration 23 contract, ADR-067.

### A2-12 (medium): Identity policy and deny sets are polled on expiry instead of watched; JWKS has no last-known-good

- **Files:** identity-eligibility.md:19-24, 32-34, 52.
- **Current design:**
  - The identity policy ConfigMap is pinned by UID. Snapshots last 30 s (max 60 s), and refresh is synchronous and coalesced.
  - The deny set must be complete and ≤5 s old.
  - The JWKS cache lasts 1 s–5 min, refreshes are serialized at 1/s, and expired keys are never used as a fallback.
- **Problem class:** Expiry-driven freshness; polling where watches exist; degraded states on IdP or API blips.
- **Cost and scaling:**
  - Every pod re-reads the ConfigMap each 30 s.
  - The 5 s deny bound forces near-continuous permission reads.
  - A JWKS outage longer than the cache lifetime rejects all users.
- **Requirement status:** Agent (ADR-049/214). Rule 1 and ADR-311 apply.
- **Proposed replacement:**
  - Use a client-go informer or mounted file for `identity.json`, valid until replaced.
  - Feed denies from the permission informer/projection change events.
  - For JWKS, use go-oidc's `RemoteKeySet` behaviour: cache, and refresh on unknown `kid` with a rate limit.
  - Precedents: Kubernetes RBAC authorizer (informer cache, no expiry); the go-oidc RemoteKeySet; Envoy jwt_authn remote JWKS with async refresh.
- **Other files to change:** current-request-identity.md, permission-observation.md, keycloak-profile.md:13, download-environment.md:7-14, ADR-049/214.

### A2-13 (medium): Download environment still described as guard-protected and expiring

- **Files:** download-environment.md:5-16, 20-32.
- **Current design:**
  - The ConfigMap source uses "native ConfigMap admission protection, independently pinned object/namespace/policy/binding identities, denied non-administrator probe, exact two reads and final guard".
  - The 60 s observation has a hard expiry ("refresh failures cannot reuse an expired observation"). The proof is ≤5 s, with three re-checks after blocking work.
  - Worker-enrollment and owner-claim SQL roles need processing-table reads because "those effects call the same current download fence".
- **Problem class:** Obsolete guard text; expiry-driven freshness; per-step revalidation.
- **Cost and scaling:** About four API reads per observation (ADR-311 context). Policy outages deny downloads.
- **Requirement status:** The guard text is obsolete under ADR-328. The 60 s figure is in M-req ADR-311, but as an authority reuse interval. Rule 1 forbids expiring the config cache itself.
- **Proposed replacement:** Mount or watch `download-environment.json`, keeping it valid until replaced. Apply the processing-restriction checks once per operation (ADR-311). Delete the guard sentence and the extra fence reads in the enrollment and owner roles.
- **Other files to change:** download-authority.md:9, download-recovery.md:5, ADR-127/214.

### A2-14 (medium): Bespoke connector enrollment with a two-attempt PKI budget, two encrypted audits and column-level role splits

- **Files:** enrollment-claims.md:5-31; enrollment-activation.md:7-25; fleet-administration.md:9-11.
- **Current design:**
  - A one-use bootstrap secret (≤5 min) is exchanged for a claim.
  - The flow then runs: encrypted claim audit (≤2 records per pass, 30 s budget), SQL "MaySign" attempt (≤2 ever, 5 s), signing, an encrypted issue audit with read-back, then separate activation.
  - Four SQL roles (claim/sign/audit/activate) are split by column privileges and triggers.
- **Problem class:** Bespoke enrollment/PKI layers; spend kept on uncertain outcomes; duplicated receipts.
- **Cost and scaling:**
  - Cluster onboarding fails permanently after two uncertain provider calls, so the administrator must issue a new slot.
  - The flow has many states and roles.
- **Requirement status:** M-req: central multi-cluster management with low-effort operator workflows. The mechanism is agent-added (ADR-052, migrations 00007–00011).
- **Proposed replacement:**
  - Use a bootstrap token in the connector Helm values or Secret. The connector POSTs a CSR, and the hub signs through OpenBao PKI or the local CA.
  - Make the request idempotent by public-key digest, which already exists, with unlimited retries until token expiry.
  - Write one audit row through the outbox and use one hub SQL role (ADR-222).
  - Precedents: kubeadm bootstrap tokens with kubelet TLS bootstrapping (CSR API); the OCM klusterlet registration (bootstrap kubeconfig → CSR → approval); Rancher cattle-cluster-agent registration tokens.
- **Other files to change:** bootstrap-issuance.md, connector-pki.md, peer-identity.md, fleet-administration.md, ADR-051/052.

### A2-15 (medium): Custody registration locks the pool row and keeps an unwired writer barrier and lease polling

- **Files:** custody-transactions.md:11-13, 27-41.
- **Current design:**
  - Registration locks pool → allocation → attempt.
  - Transactions have a 5 s total context, and the conservative full reservation is never refunded before physical cleanup.
  - Deletion claims a 30 s lease with a fence and requires `WriterBarrier.CloseAndWait`, which has "no production barrier implementation".
  - Automatic polling/backoff for deletion is "pending". Runtime pool construction re-checks role attributes (no superuser/createrole etc.).
- **Problem class:** Global lock (pool); an unimplementable barrier; future timer-driven polling; self-verification of installer state.
- **Cost and scaling:** All registrations on one pool serialize. Deletion cannot run in production without the barrier.
- **Requirement status:** M-req: storage-exhaustion protection and quotas (ADR-021), and verified deletion. The pool lock, barrier and constructor role checks are agent-added.
- **Proposed replacement:**
  - Use an atomic conditional `UPDATE allocation SET used=used+n WHERE used+n<=limit` with no pool row lock.
  - Fence writers by expiring their upload credential/deadline: the writer cannot finalize after its cutoff, and S3 multipart abort plus lifecycle rules handle stragglers.
  - Schedule deletion from a `due_at` index, woken by LISTEN/NOTIFY or a single timer to the next due date.
  - Drop the role-attribute self-checks (ADR-328).
  - Precedents: the S3 lifecycle `AbortIncompleteMultipartUpload` rule; River/Que-style PostgreSQL job queues with scheduled_at.
- **Other files to change:** download-stop-lifecycle.md (inventory reuse), retention-catchup/retention-lifecycle docs, ADR-021/023 consequences.

### A2-16 (medium): Download sessions have fixed installation-wide caps, per-batch encrypted intent audit and three SQL credentials

- **Files:** download-sessions.md:11-23, 37.
- **Current design:**
  - There are at most 16 simultaneous batches per installation permission root and 2 per principal, with preparation consuming slots.
  - Each batch's intent is encrypted, written and acknowledged before any metadata or content goes out, with a 5 s effect lease.
  - Separate configuration, runtime and audit SQL credentials are required.
- **Problem class:** Single-writer bottleneck/fixed global cap; synchronous audit on the hot path; credential splits.
- **Cost and scaling:** A team of more than 8 users downloading at once hits the cap. Every metadata view pays an object-store write and read-back.
- **Requirement status:** M-req: capture-storm and storage-exhaustion protection, and audit. The fixed 16/2 caps, synchronous per-batch audit and credential splits are agent-added. ADR-222 (in AGENTS) already consolidated hub SQL credentials.
- **Proposed replacement:** Make concurrency limits administrator-configurable through a token bucket per principal and per workload. Audit through the outbox (see A2-01). Use one hub SQL role per ADR-222.
- **Other files to change:** download-responses.md, download-worker-dispatch.md:29, ADR-054/113.

### A2-17 (medium): Worker idle polling, per-frame SQL rechecks and one TLS conversation per socket in the native exchange

- **Files:** native-exchange.md:5, 26, 66, 81; native-owner-listener.md:24-42.
- **Current design:**
  - Idle workers poll for work with ≥1 s backoff (up to 32,768 conversations), with the hub parking requests.
  - "Every frame … rechecks current registry/operation and caller authority" through a shared SQL read (`NativeRecheckInterval` 1 s), which contradicts lines 6-12 (ADR-312).
  - The listener allows one conversation per socket, one h2 stream, no session resumption and a 10 s socket deadline. A new conversation is set up per 64 MiB window (ADR-288, ≤60 s).
- **Problem class:** Polling where push exists; per-step revalidation; a TLS handshake per window.
- **Cost and scaling:** At least one SQL read per second per active stream, plus a handshake and attestation per window. The doc contradicts itself about rechecks.
- **Requirement status:** Agent (ADR-122/139/258/288). ADR-312 (M-req) removes post-start rechecks.
- **Proposed replacement:**
  - Use a long-lived multiplexed HTTP/2 connection per worker (see A2-07) and push work on it.
  - Check authority once at response start (ADR-312). Fence cancellation through LISTEN/NOTIFY on the Stop transition.
  - Precedents: gRPC bidirectional streams; Konnectivity.
- **Other files to change:** native-owner-listener.md, download-responses.md, native-download-retry.md:33-37.

### A2-18 (medium): Local start journal relies on an admission-policy guard and namespace UID reads, and has no cleanup

- **Files:** local-start.md:7-13, 24-38.
- **Current design:**
  - Each capture start writes a `CapacityReservation` custom resource. A native ValidatingAdmissionPolicy separates capacity and execution users and rejects deletion.
  - Every read re-checks the control namespace UID.
  - "Initial cleanup intentionally has no implementation or permission".
- **Problem class:** Requirements that defend against trusted actors; self-verification; unbounded object growth.
- **Cost and scaling:** One etcd object per start with no deletion, so etcd grows without bound with capture count.
- **Requirement status:** M-req: capture-storm protection and no repeated collection. The admission guard and UID reads are agent-added. ADR-328: no admission-policy proofs or UID pins.
- **Proposed replacement:**
  - Keep the CAS on status (Ready→StartCommitted) under ordinary RBAC.
  - Add an ownerReference/TTL cleanup after terminal state, or keep the journal in the connector's SQL/hub ledger.
  - Drop the policy and the UID checks.
  - Precedents: controller-runtime status CAS through resourceVersion; Kubernetes Job TTL / ownerReference GC; Argo Workflows `ttlStrategy`.
- **Other files to change:** interfaces.md:43-45, api-context-runner.md, ADR-106.

### A2-19 (medium): "Uncertain stays spent forever" accounting appears in every component

- **Files:** custody-transactions.md:31; download-sessions.md:11, 21; download-responses.md:7, 28; download-worker-dispatch.md:29, 37; download-key-authority.md:24; enrollment-activation.md:9; enrollment-claims.md:11; local-start.md:9; native-exchange.md:83, 89-91; download-environment.md:20 (16 decision attempts per rule for its whole history); download-stop-lifecycle.md:145.
- **Current design:** Lost replies, unknown COMMITs and uncertain provider calls permanently consume capacity, attempts or slots. The only remedy is a new paid admission, and fixed attempt counts (2, 3, 16) are never refilled.
- **Problem class:** Exactly-once or spent-on-uncertain accounting where idempotency keys suffice.
- **Cost and scaling:** Capacity leaks under normal network errors. Users must re-request, and cleanup reconcilers become mandatory.
- **Requirement status:** M-req: reserve capacity before acquisition and never repeat a collection (ADR-021, S-02 exit 6). Permanent spend on uncertainty is agent-added.
- **Proposed replacement:**
  - Key every effect by a client or operation idempotency key, and resolve an uncertain outcome by replaying the same key (the docs already do this for registrations).
  - Release the reservation when the operation reaches a known terminal state, or after its hard deadline once the writer's credential has expired.
  - Keep "no second collection" for intrusive starts only.
  - Precedents: Stripe idempotency keys; AWS client tokens; Kubernetes Job `backoffLimit` with deterministic names.
- **Other files to change:** All listed, plus specs/capacity.md.

### A2-20 (medium): Per-facet SQL credentials and column-level privileges contradict ADR-222

- **Files:** download-sessions.md:23; enrollment-activation.md:17; enrollment-claims.md:13, 29; download-key-authority.md:18; download-environment.md:18-20, 26-32; native-owner-listener.md:16-18, 52-57; download-responses.md:46.
- **Current design:** Separate configuration, runtime, audit, bind, read, claim, sign, activate and native-read roles exist, with column-limited `UPDATE(id)` lock privileges and SECURITY DEFINER grants. Installed runs failed on missing grants (native run 47; audit-role lock).
- **Problem class:** Configuration and complexity that does not pay for itself; failure-prone grants.
- **Cost and scaling:** Many roles and pools, which pressures the 32-connection cap, and repeated installed failures from missing grants.
- **Requirement status:** ADR-222 (AGENTS) already consolidates ordinary hub work into one compiled grant union. These docs predate it.
- **Proposed replacement:** One SQL role per process (hub-api, hub-worker, key-service, publisher), with table-level grants and ordinary triggers for immutability.
  - Precedents: GitLab, Harbor and Grafana each use one DB user per component.
- **Other files to change:** All listed, the migration grant files, the ADR-217/222 notes in AGENTS.md.

### A2-21 (low): Node status sent as a periodic full batch every 15 s

- **Files:** interfaces.md:35-37, 47-60.
- **Current design:** The I-01 long-poll waits up to 25 s, with heartbeat every 15 s and offline after 60 s. Node status is a 15 s batched status carrying source-set snapshots and cumulative accounting. The doc does not say what wakes a parked poll when SQL work becomes eligible.
- **Problem class:** Periodic full resend; unspecified wake source.
- **Cost and scaling:** O(nodes × sources) status payload every 15 s, even when nothing changed.
- **Requirement status:** Agent (ADR-246/263).
- **Proposed replacement:**
  - Send status deltas when state changes, and keep heartbeat as liveness only.
  - Specify that the hub wakes parked polls through PostgreSQL LISTEN/NOTIFY on outbox insert.
  - Precedents: kubelet node status update on change with a lease heartbeat (NodeLease KEP-589).
- **Other files to change:** node-collector.md, live-watch specs.

### A2-22 (low): native-reader-identity still specifies live-reader batch machinery that ADR-312 made unnecessary

- **Files:** native-reader-identity.md:19-104.
- **Current design:** `ReaderIdentity.BeginBatch` hands out fresh 5 s batches, with busy, shortening and terminal semantics. After ADR-312 it is used only until the response starts, and for raw grant-pool windows.
- **Problem class:** Leftover per-step revalidation; obsolete text.
- **Cost and scaling:** Code and documentation weight only.
- **Requirement status:** ADR-312 (M-req) removes post-start rechecks.
- **Proposed replacement:** Authenticate once at GET start with `CurrentIdentity`, and bound the response by session or token expiry. Delete the batch interface unless raw windows still need it. If they do, make the raw grant reservation a start-time reservation.
- **Other files to change:** download-responses.md:11-23, 50-53, native-exchange.md:24.

### A2-23 (low): Architecture docs carry long qualification and test-log narration

- **Files:** download-worker-dispatch.md:45-147 (half the file); fleet-observation.md:17, 50-69; download-environment.md:41-45; current-request-identity.md:61-94; helm/installed docs.
- **Current design:** Contracts are interleaved with run IDs, SHA-256 hashes of reports, timings and fixture caveats.
- **Problem class:** Specification bloat, which hides the actual contract.
- **Cost and scaling:** Reviewers and agents read thousands of lines that are not part of the contract.
- **Requirement status:** Agent.
- **Proposed replacement:** Keep only the contract in docs/architecture. Move qualification records to docs/implementation-progress.md or test/results, as AGENTS already directs.
- **Other files to change:** None beyond the docs themselves.

### A2-24 (low): Remaining documents still say "protected installer/bootstrap/issuer provisioning remains pending"

- **Files:** custody-transactions.md:3, 15; download-authority.md:9; download-recovery.md:9; download-key-authority.md:38; download-worker-attestation.md:37; download-worker-dispatch.md:43; enrollment-activation.md:25; fleet-administration.md:17; fleet-observation.md:13; hub-owner-discovery.md:37; local-key-lifecycle.md:31; local-key-service.md:73; native-exchange.md:28, 97; native-owner-listener.md:44.
- **Problem class:** Text from the removed installer era.
- **Proposed replacement:** Replace these with "rendered by the Helm chart; the secrets/setup Jobs create live external state" or delete the sentences. List the actual remaining gaps once in implementation-progress.

### A2-25 (low): Hub owner TLS profile hard-codes three named ports for one installer profile

- **Files:** hub-owner-discovery.md:9, 27.
- **Current design:** An "ADR144 observation-bootstrap profile" requires exactly `owner` 9443, `observation` 9444 and `public` 9445 on the Service and EndpointSlices, while the omitted profile keeps the one-port behaviour. A common SAN is allowed only for "explicitly opted fresh pools".
- **Problem class:** Profile forks tied to the installer era; configuration that exists only to tune its own machinery.
- **Proposed replacement:** Fold this into A2-07. Use ordinary Service DNS SANs and one profile.

---

## 3. Top cross-cutting recommendations

1. Update every 5 s window in this range to ADR-311/312 semantics: one check per operation, reused for 30 s or 60 s, and no rechecks after a download starts (A2-08, A2-13, A2-17, A2-22).
2. Replace observation loops with informers or mounted files, valid until replaced, and wake waiters with LISTEN/NOTIFY (A2-06, A2-12, A2-15, A2-21).
3. Move audit off the byte path into the existing SQL outbox with asynchronous encrypted publication (A2-01, A2-02, A2-16).
4. Replace the per-download Job, double TokenReview and exact-hub-process rendezvous with a long-running worker pool behind a connector reverse tunnel and one installation CA (A2-03, A2-04, A2-07).
5. Remove the installation-wide lock ordering and permanent spend on uncertain outcomes in favour of epoch CAS, conditional quota updates and idempotency keys (A2-05, A2-19).
6. Delete the 21 obsolete documents in §1, and cut the guard and pin sentences from the partially obsolete ones.
