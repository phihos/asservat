# A3 — Architecture docs audit: `node-collector.md` … `workload-target-resolution.md`

Scope: 45 files in `/home/phil/Projekte/asservat-specreview/docs/architecture/`
(node-collector, operation-audit*, owner-*, peer-identity, permission-*,
pod-resolution, policy-*, processing-admission, provider-installed-pair,
public-context-*, regional-context-start, research, retention-*, runtime,
runtime-profiles, validation.json, worker-*, workload-target-resolution).
All were read in full except `runtime-profiles.md`, where I read the authority and
endpoint sections plus a keyword sweep. Read-only audit; I edited no repository files.

Precedent shorthand used below. Each entry is a source cited in
`docs/reviews/security-evidence-2026-11-13.md` (SE#n = row n of that table) or a
well-known upstream mechanism:
- K8s informers/watch semantics: https://kubernetes.io/docs/reference/using-api/api-concepts/ (relist only after 410/watch restart)
- Node heartbeats vs status: KEP-589 Node Lease (kubelet renews a cheap Lease every 10 s and posts status only on change, or every 5 min)
- Webhook authz cache: 5 min allow / 30 s deny (SE source 1)
- Vault/Kubernetes audit: one fail-closed audit record, batch/log backends (SE source 4)
- Vault HA/etcd peer TLS/Teleport proxy peering: one shared CA, plain mTLS (SE source 5)
- Idempotency keys: IETF draft + AWS builders' library (SE source 3)
- Reverse tunnels: OCM klusterlet / Karmada agent / Rancher `remotedialer` / Teleport reverse tunnel (one long-lived multiplexed agent-initiated connection)
- cert-manager `Certificate` + CA `Issuer` for in-cluster mTLS

Severity counts: **High 23 · Medium 19 · Low 6** (48 findings). The end of the
file lists 23 docs to delete and 7 merge/rewrite groups.

---

## 1. Cluster: hub-replica "owner" PKI, enrollment, relay (obsolete)

### A3-01 (High) — Per-process hub-replica PKI with audited enrollment
- **Files:** owner-registration.md:7-36, owner-issuance.md:7-21, owner-credentials.md:7-27, owner-enrollment-proof.md:15-29, owner-startup.md:7-27
- **Current design:** each hub process generates server/client keys, proves itself with a dedicated-audience Pod token, live Pod/ReplicaSet/Deployment chain and admission-guard proof, then gets 20-minute OpenBao leaves. It also writes encrypted enrollment and certificate audit objects, spends two signing ordinals per UTC period that are never refunded, activates the certificate in SQL, enforces 1,024 registrations per pool and 32 per Pod, and runs a renewal supervisor with 8 retries per round.
- **Problem class:** bespoke PKI/enrollment layer; "spent on uncertain" accounting; synchronous encrypted audit; guards against namespace writers (ADR-328 says they are trusted).
- **Cost:** per replica: 2 KMS sign calls plus 4 S3 PUT/GET pairs plus ~6 SQL transactions every 20 min. Startup depends on OpenBao, S3 and SQL before the hub can become Ready. Two SQL tables, triggers and five owner SQL roles.
- **Requirement:** agent-added. SE#5 verdict REDUCE: "mTLS with one hub-only CA … remove enrollment proofs, registration, certificate audits, signing budgets, activation, readiness PKI loop, streaming relay".
- **Replacement:** a cert-manager `Certificate`, or a Helm-generated CA plus leaf Secret, mounted into the hub Deployment. Peers verify with `tls.Config{ClientCAs}` against that one hub CA. The certificate is reloaded on file change (fsnotify or kubelet projected-volume update). Precedents: Vault HA, etcd peer TLS.
- **Consistent changes:** delete migration-30 tables, ADR-079/081/082/084/088. Also `specs/contracts/owner-credentials`, `owner-identity-*`, `owner-provider-*` and `owner-bootstrap-selection` schemas, `catalog.yaml` (C-04 owner components), `hub-owner-discovery.md` and `native-owner-listener.md`.

### A3-02 (High) — Per-use peer re-authentication on every protected use, including reused connections
- **Files:** owner-authentication.md:7-17, owner-relay.md:15-17, owner-forwarding.md:15-27
- **Current design:** `AuthenticateOwner` runs 7 steps on every use: verify TLS, read the SQL registration, revalidate roots, read native workload protection (an admission dry-run probe), resolve the Ready route, re-read protection and registration, and revalidate TLS again. The forwarder repeats this before sending, after receiving and before the response.
- **Problem class:** per-step revalidation, chatty reads (≥3 SQL reads plus ≥2 K8s dry-runs plus 2 endpoint reads per hop).
- **Cost:** per forwarded request roughly 10–15 backend round trips on two peers. Availability is coupled to admission-policy probing.
- **Requirement:** agent-added. Violates ADR-311 (one check per operation) and SE#9g ("registry check at handshake/renewal or ≤30 s reuse").
- **Replacement:** standard mTLS handshake verification only. Pod identity comes from the certificate SAN. No registry.
- **Consistent changes:** owner-forwarding, owner-relay, native-owner-listener, regional-context-start (it uses `OwnerEnrollments.ReadContextStartOwners`).

### A3-03 (High) — Hub-to-hub owner relay for worker certificate enrollment (live-delivery protocol)
- **Files:** owner-relay.md:7-27, owner-forwarding.md:7-39, worker-owner-locator.md:15-35, worker-request-routing.md:15-40
- **Current design:**
  - A worker's CSR must reach the exact hub process that holds the live human request, through a SQL locator with fences.
  - The relay is an owner-relay/v2 chunked HTTP/1.1 stream that stays "open and silent" until the downstream write ends.
  - At most two dial attempts, no Service, exact Pod-IP dialing.
- **Problem class:** bespoke protocol; single-owner routing; human authority attached to a machine credential.
- **Cost:** sticky per-request ownership blocks HA. Failover loses the request. Locator rows and fences need cleanup.
- **Requirement:** agent-added. The docs themselves say ADR-221 supersedes it ("without a human certificate-owner registry/locator/relay", worker-*.md:3-11). The human authority already exists in SQL as the download session.
- **Replacement:** any replica authenticates the worker by TokenReview of its projected token, or by the worker's cert-manager certificate. It authorizes against the SQL download-session row the human created. Precedent: stateless Argo CD/Grafana replicas sharing PostgreSQL. If an owner is still needed, SE#5 allows "a SQL owner row" plus a Service/headless DNS route.
- **Consistent changes:** delete `specs/contracts/owner-relay.schema.json` and the migration-28 locator; update `worker-credential-channel.md:31` (ClientHello split on port 9443).

### A3-04 (High) — Namespace-wide admission guard with dry-run probes proving its own enforcement
- **Files:** owner-workload-protection.md:5-53, owner-configuration.md:9-13, owner-deployment.md:68-74, worker-configuration.md:9-13
- **Current design:**
  - A VAP denies every write in the hub namespace except explicit kube-system controller usernames and GC/kubelet special branches.
  - A probe identity re-submits the Deployment with `dryRun=All` to prove an exact denial. It is retried up to three times on 409.
  - Probe ConfigMap and Lease exceptions are listed in deployment input.
- **Problem class:** defends against trusted namespace writers and cluster admins. It is self-verification of installer state.
- **Cost:** a K8s write-path dry-run in every proof, fragile against managed-provider controller identities (doc :51). Blocks ordinary operations such as `kubectl rollout restart` by admins not listed.
- **Requirement:** agent-added. Removed by maintainer ADR-328 and the 2026-11-13 Helm-native decision ("Plain RBAC replaces UID-pinned admission guards and their proofs").
- **Replacement:** namespace RBAC plus Pod Security `restricted`. Nothing at runtime.
- **Consistent changes:** ADR-080/092/093/095, `configuration-reconciliation.md`, the probe lists in `owner-deployment.schema.json`, permission-acceptance.md:29-33, retention-observation.md:25-29.

### A3-05 (High) — Pinned owner-configuration ConfigMap with SQL acceptance, encrypted audit, watermarks, 1,024-revision history and S3 inventory
- **Files:** owner-configuration.md:5-127
- **Current design:**
  - An `owner-pool.json` ConfigMap is pinned by UID. It is read twice with guard rechecks, accepted into SQL heads/revisions, and audited by an encrypted object written before use. Negative watermarks, a historical S3 version inventory reader and "finite audit epochs" (ADR-156) are layered on top.
  - Routes re-read the configuration before and after endpoint discovery.
- **Problem class:** journals and receipts for a mounted config; audit before configuration use; expiry-driven 5 s freshness.
- **Cost:** large SQL/trigger surface and an S3 dependency on the route path.
- **Requirement:** agent-added. SE#9c REMOVE ("log the accepted revision and digest"). SE#4 removes "audit before configuration use".
- **Replacement:** Helm values rendered into a mounted ConfigMap. Reload on change (informer or file watch). Log revision and digest. CA bundle from cert-manager trust (`trust-manager` Bundle, or the CA Secret).
- **Consistent changes:** `owner-configuration.schema.json`, migration 29, ADR-077/078/156.

### A3-06 (High) — Owner deployment loader: 13 fixed credential files, 5 SQL users, per-request token reread, 1 s bundle polling
- **Files:** owner-deployment.md:3-76
- **Current design:**
  - `deployment.json` plus separate SQL credential files for enrollment, audit, activation, registry and routing (ADR-222 later merged some).
  - Kube observer and probe tokens, an owner Pod token, audit-wrap/unwrap tokens and server/client sign tokens.
  - "The loader watches the protected public worker bundle at one-second intervals … reopening the file" (:62).
- **Problem class:** per-purpose credentials in one process; polling a file where an event exists.
- **Cost:** connection budget (see A3-21). One file open and stat per second per replica. Operator burden.
- **Requirement:** agent-added. SE#2: one non-admin login per process.
- **Replacement:** one SQL login per Deployment, the standard in-cluster ServiceAccount, and fsnotify (or a ConfigMap informer) for reload.
- **Consistent changes:** `owner-deployment.schema.json`, `owner-worker-trust.schema.json`, public-context-composition.md:96-117.

### A3-07 (Medium) — Owner startup "launch receipt convergence" and journal-polling startup
- **Files:** owner-startup.md:85-112, 37-54
- **Current design:** the observation-mode loader polls the installer's original journal every 250 ms until the launch receipt appears, then re-proves guard, token, projection, Deployment and Pod.
- **Problem class:** installer-era obsolete text; polling; launch receipts are explicitly banned.
- **Requirement:** agent-added. Removed by ADR-328/Helm-native ("Do not add … journals or launch receipts").
- **Replacement:** delete. Helm hook Jobs finish before the Deployment rolls out, and readiness probes gate traffic.
- **Consistent changes:** ADR-144/164, `initial-bootstrap-passive-history.schema.json`.

### A3-08 (Medium) — `peer-identity.md`: per-request registry lookup and pinned `work-trust.json`
- **Files:** peer-identity.md:11-19
- **Current design:**
  - X.509 is re-verified on each request.
  - SQL registration is read per request, with authority capped at 5 s and a 30 s trust observation.
  - Work keys come from a pinned ConfigMap with up to 8 Ed25519 keys and a UID pin.
- **Problem class:** per-request reads on reused connections; UID pins.
- **Requirement:** 1 h certificates are acceptable (SE#9g KEEP). The per-request registry lookup is SE#9g REDUCE.
- **Replacement:** check the registry/revocation at handshake and renewal, or cache it ≤30 s. Drop the work-key ConfigMap if signed work is removed (A3-17).
- **Consistent changes:** enrollment-activation.md, enrollment-claims.md, node-collector.md.

---

## 2. Cluster: download workers (per-request Jobs, worker PKI)

### A3-09 (High) — One Kubernetes Job per download session with its own certificate enrollment
- **Files:** worker-enrollment.md:15-37, worker-credential-channel.md:13-39, worker-startup.md:13-104, worker-current-lifecycle.md:32-41
- **Current design:**
  - Each download dispatches a Job with a pinned PriorityClass and an immutable control ConfigMap whose digest is passed in the arguments.
  - The worker creates a P-256 key. The hub runs TokenReview plus two rounds of live checks, encrypted enrollment audit, a signing attempt that stays spent if uncertain, OpenBao sign, encrypted certificate audit and SQL activation.
  - Certificates last 20 minutes and are renewed for up to 24 periods.
  - Dispatch also writes an encrypted intent audit. Cleanup requires a persisted termination proof before deletion.
- **Problem class:** per-request Jobs; bespoke PKI; per-operation synchronous KMS/S3 audit; exactly-once accounting.
- **Cost:**
  - Latency: Job → Pod scheduling plus image pull plus enrollment add seconds to tens of seconds before the first byte.
  - Load: about 6–10 SQL transactions, 2 KMS signs plus 4–6 wraps, and 4+ S3 PUT/GET per download. Concurrency is bounded by Job/Pod churn.
  - Scaling: N downloads → N Pods per cluster.
- **Requirement:** maintainer requires native downloads, managed encryption, decryption kept out of the hub ("no hub raw unwrap") and audit. The Job-per-download form and worker PKI are agent-added.
- **Replacement:** a long-running regional "reader" Deployment, or the connector itself, holding the unwrap capability. Each download is a stream on the existing connector↔hub tunnel (A3-16). Worker identity is the Deployment's projected SA token (TokenReview, cached), or a cert-manager certificate from the one CA. Precedents: Loki/Tempo queriers and Pyroscope query-frontends serve reads from long-running Pods; Velero node-agent is a DaemonSet, not a per-request Pod.
- **Consistent changes:**
  - Delete or reduce: download-worker-dispatch.md, download-worker-attestation.md, download-sessions.md and download-stop-lifecycle.md.
  - Schemas to delete: `worker-control`, `worker-configuration`, `worker-enrollment`, `worker-store-credentials`.
  - Migrations 24–27.
  - Spec text: artifact-downloads spec wording on "scoped acquisition Job" (runtime.md:161).

### A3-10 (High) — Worker command channel polls the hub every second
- **Files:** worker-startup.md:86-93
- **Current design:** "Only an exact authenticated NoCommand or positively Joined result permits the next connection, with one-second backoff … 32,768 conversation ceiling". Each connection rereads the token and makes a new nonce.
- **Problem class:** polling where push exists; a new TLS handshake per poll.
- **Cost:** 1 TLS handshake plus TokenReview per second per worker.
- **Requirement:** agent-added.
- **Replacement:** one long-lived HTTP/2 or gRPC stream with server-pushed commands. Reconnect only on error, with exponential backoff. Precedent: kubelet↔API watch; OCM klusterlet.
- **Consistent changes:** download-worker-dispatch.md, native-owner-listener.md.

### A3-11 (High) — Protected worker configuration ConfigMap with guard, SQL revisions and encrypted audit
- **Files:** worker-configuration.md:5-29
- **Current design:** the `worker-profile.json` ConfigMap has its own VAP plus a dry-run probe. It is read twice. The observer stages SQL revisions with fresh-until timestamps, and an encrypted S3 snapshot must be acknowledged before dispatch. The dispatcher checks the profile before and after effects.
- **Problem class:** guard proofs; audit before configuration use; expiry-driven 5 s freshness.
- **Requirement:** agent-added. SE#9c REMOVE. Guards were removed by the maintainer decision.
- **Replacement:** Helm values mounted in the regional component and logged on load.
- **Consistent changes:** migration 26, ADR-070, `worker-configuration.schema.json`.

### A3-12 (Medium) — Worker trust catalog: 256 control documents, issuer roots selected per cluster
- **Files:** worker-routing.md:13-23
- **Current design:** the hub holds up to 256 per-cluster worker control documents keyed by ConfigMap digest and selects issuer roots by profile digest.
- **Problem class:** bespoke PKI multiplicity.
- **Replacement:** one hub CA for all internal mTLS (SE#5), or TokenReview against the worker cluster through the connector. The catalog goes away.
- **Consistent changes:** owner-forwarding.md, `owner-worker-trust.schema.json`.

### A3-13 (Medium) — Request-owned authority capped at 5 s
- **Files:** worker-current-lifecycle.md:9-17, 43-48
- **Current design:** one authority observation per operation, "capped at five seconds". Dispatch and enrollment retain it through audit, KMS and Job registration.
- **Problem class:** expiry-driven freshness shorter than the maintainer interval.
- **Cost:** slow KMS/S3 steps exceed 5 s and fail the operation.
- **Requirement:** ADR-311 sets the ceiling at 30 s (60 s for policy). 5 s is legacy.
- **Replacement:** `identity.AuthorityRecheckInterval` (30 s), never beyond the original deadline.
- **Consistent changes:** ADR-214/216 text, download-authority.md.

---

## 3. Cluster: operation audit (synchronous encrypted objects, deletion certificates)

### A3-14 (High) — Encrypted intent+outcome object pair per public operation, on the response path
- **Files:** operation-audit.md:29-35, 79-91, 115-123, 159-196
- **Current design:**
  - Every audited operation, including reads such as `list_diagnostics`, `get_case` and `get_capture`, follows this sequence:
    1. Reserve the intent in SQL.
    2. Claim it, Tink wrap, conditional S3 PUT, pinned GET, unwrap and verify.
    3. Acknowledge it through a separate SQL role.
    4. Repeat the same steps for the outcome.
  - The current identity is rechecked after each acknowledgement, and the response is withheld until both are acknowledged.
  - All audit stores share one semaphore of 1–16 slots. Each operation performs its own TLS setup with no credential cache.
  - Per-principal finite audit accounts are HMAC-keyed and split into normal and resolution lanes.
- **Problem class:** synchronous encrypted/object-store audit on the hot path; per-step revalidation; a global serialization bottleneck; prepaid accounting.
- **Cost:**
  - Each request: 2 wraps, 2 unwraps, 2 PUTs, 2 GETs, about 6 SQL transactions and 2 identity rechecks, adding tens to hundreds of ms.
  - The installation-wide audit concurrency cap of ≤16 limits whole-hub throughput.
  - Each operation pays a fresh TLS handshake to S3 and OpenBao.
- **Requirement:** maintainer requires audit ("preserve quotas/audit/managed encryption", AGENTS.md Authority section; creators are immutable audit actors). The object/encryption/pair form is agent-added. SE#4 REDUCE: "one synchronous fail-closed audit record per security-relevant operation, append-only table, optional SIEM/Object Lock export". It removes per-event envelope encryption, intent/outcome pairs and prepaid audit accounts.
- **Replacement:**
  - One INSERT into an append-only `audit_event` table, in the same transaction as the effect for mutations. Read operations need no audit or a single row at most.
  - Optional asynchronous export to SIEM or an Object Lock bucket, batched.
  - Precedents: Vault audit device (fail closed, HMAC'd fields); Kubernetes audit batch backend.
- **Consistent changes:**
  - Other audit docs: public-context-composition.md:9-16, public-context-download.md:16-19 and 53-66, policy-automation.md:25, permission-acceptance.md:19-23, retention-checkpoints.md:27, worker-*.
  - Spec and ADRs: `specs/` privacy/audit requirements, ADR-110/111.

### A3-15 (High) — Audit deletion certificates, H/B/P date algebra, cooling, prepaid verification and overdue fences
- **Files:** operation-audit-lifecycle.md:47-226, operation-audit-overdue.md:1-122
- **Current design:**
  - Six frozen dates per record, computed from D, H (backup/WAL history), B and P.
  - A two-inventory S3 purge, then a signed and encrypted deletion certificate with two prepaid verifier attempts.
  - A terminal key purge, then a finalizer that moves the charge to a "cooling" history table.
  - A pool policy pins row/index/TOAST and WAL footprints, with "21 + 3·MaxPurgeLeases" transitions per residual generation.
  - Overdue mode adds a fence, a `proof_window_missed` counter and producer/ack/cleanup/finalizer roles.
- **Problem class:** duplicated state machines; prepaid accounting; bespoke erasure proof; configuration that only tunes its own machinery.
- **Cost:** at least 2 more tables and 4 roles, about 25 SQL transitions per audit record lifetime, and extra S3 LIST/DELETE/PUT/GET per record.
- **Requirement:** agent-added. Retention of managed copies is maintainer intent (administrator-enforced maximum retention). Proving erasure per audit record through signed certificates is not. SE#4 removes deletion certificates. SE#6 removes "WAL/backup prepayment … charges released only after full inventory".
- **Replacement:** time-partitioned `audit_event` (native PostgreSQL range partitions, or pg_partman), dropping whole partitions past retention. Document that pgBackRest `repo-retention-full` must not exceed the audit retention window. Precedent: Sentry/Grafana retention jobs; Loki compactor retention.
- **Consistent changes:** download-stop-lifecycle.md, ADR-112/115/125, privacy spec REQ-PRV-004 text on backups (privacy.md:228).

### A3-16 (Medium) — Prepaid Stop row and Stop waits on audit
- **Files:** public-context-download.md:29-66, 89-96
- **Current design:**
  - A download INSERT must reserve a `download_stop` row against backing.
  - Stop writes an encrypted audit object: 30 s write window, 4 read retries, 16-record reconciliation sweep.
  - Stop is "Cancelled … pending/recorded/overdue audit".
- **Problem class:** prepaid accounting; synchronous audit on the urgent-revocation path.
- **Requirement:** Stop as urgent revocation is kept by SE#7. Audit-gated or prepaid Stop is agent-added (SE#4 "Stop waiting on audit" removed).
- **Replacement:** Stop is an UPDATE of the session row plus an audit row in the same transaction. Byte streams observe it via LISTEN/NOTIFY on the session channel.
- **Consistent changes:** download-stop-lifecycle.md.

---

## 4. Cluster: connector ↔ hub transport

### A3-17 (High) — Connector-originated "standby" conversations re-dialed every ≤30 s per hub process, plus hub-signed JWS work
- **Files:** regional-context-start.md:7-63
- **Current design:**
  - The connector opens one standby HTTP/2 POST to each discovered hub owner process: ≤16 owners, 64 standbys, a 30 s lifetime and a 30 s penalty after TLS refusal.
  - The hub attaches work to an idle standby and waits for the next registration if none is idle.
  - Work is a hub-signed Ed25519 JWS verified by the region through a separate trust ConfigMap with its own native enforcement proof.
  - A transport observation lease is re-checked on result send and receive.
- **Problem class:** polling-style reconnect churn; bespoke tunnel protocol; signed messages inside an already mutually authenticated channel; per-frame revalidation.
- **Cost:**
  - Per cluster: 16 owners × 1 reconnect per 30 s means continuous TLS handshakes plus peer proofs.
  - Latency: a request with no idle standby waits up to the deadline minus 2.5 s.
  - The standby budget caps the fleet at 64 per hub.
- **Requirement:** maintainer: "no mandatory broker", central multi-cluster management. Transport shape is agent-added.
- **Replacement:** one long-lived agent-initiated multiplexed connection per connector, using gRPC bidi or HTTP/2 with a Rancher `remotedialer`/OCM-style reverse tunnel. Any hub replica can hold it; the owner is recorded in a SQL row (SE#5). Each hub request becomes a new stream. Authentication is mTLS only. Drop JWS work, as for policy JWS (SE#9b). Precedents: OCM klusterlet, Karmada agent, Teleport reverse tunnel.
- **Consistent changes:**
  - Doc: research.md:15-22 (JWS signed control rationale).
  - Schemas: `history-work.schema.json`, `history-ciphertexts.schema.json`.
  - Docs that use the same standby pattern: node-collector.md, context-control-capacity.md, context-query-capacity.md.
  - ADRs: 135/163/171/211.

### A3-18 (High) — Connector API process "protection": per-operation full process proof (≈71 API calls cold)
- **Files:** regional-context-start.md:85-133, 145
- **Current design:**
  - `ConnectorAPIExecutionProtection` checks online TokenReview, SSR identity, the live Deployment/ReplicaSet/Pod chain and the guard policy/binding.
  - It compares the defaulted Deployment template field by field, pins the settings UIDs and resourceVersions, and enforces `dedicatedToAPI` whole-object approvals.
  - A cold proof takes 71 API calls. Earlier runs "exhausted PrepareStart or ReadyStart because every start check re-proved the whole process".
- **Problem class:** self-verification of installer state; defending against namespace writers; chatty reads.
- **Cost:** 2.57 s of a 5 s budget on a quiet cluster, and it does not scale with QPS limits.
- **Requirement:** agent-added. Removed by ADR-328 ("no runtime re-verification of installer-created objects").
- **Replacement:** nothing. The connector trusts its own mounted config and ServiceAccount; RBAC protects the namespace.
- **Consistent changes:** local-start.md, ADR-173, `installer-cluster` discovery check (:124-133, installer-era).

### A3-19 (High) — History ciphertext round-trips through signed JWS work to the region
- **Files:** regional-context-start.md:151-190
- **Current design:** capture-history *control metadata* is written as four encrypted objects through `asservat-history-work+jws`, with frames of up to 486,077 bytes and purge inventories.
- **Problem class:** application encryption of low-sensitivity metadata; bespoke protocol.
- **Requirement:** agent-added. SE#8 REDUCE: "plain rows under existing authorization", "remove envelopes for capture-history settings".
- **Replacement:** plain SQL rows in the hub, with PostgreSQL volume encryption and pgBackRest repository encryption.
- **Consistent changes:** `history-work`/`history-ciphertexts` schemas, the capture-history spec.

### A3-20 (Medium) — Strict closed decoders reject new fields; no rolling-upgrade skew
- **Files:** node-collector.md:304-309, regional-context-start.md:43-46, worker-startup.md:51-53
- **Current design:** "Nonzero new fields sent to an older node or connector decoder are rejected; no additive rolling compatibility". The same applies to `standbyUntil` and v1/v2 worker control.
- **Problem class:** cannot scale across a DaemonSet rolling update or hub/connector version skew.
- **Cost:** every protocol change needs lockstep upgrades across hub, connectors and 5,000 nodes. A DaemonSet `RollingUpdate` (default `maxUnavailable=1`) leaves mixed versions for minutes to hours.
- **Requirement:** contradicts runtime.md:139 (R-10 "rolling N/N-1 upgrades") and SE#9e ("documented N−1 skew").
- **Replacement:** additive-tolerant decoding (ignore unknown fields, as protobuf or JSON-with-version-negotiation do) plus a capability field in Hello. Precedent: Kubernetes version-skew policy.
- **Consistent changes:** all `specs/contracts/*` closed-schema policies for private wires.

---

## 5. Cluster: SQL credential sprawl

### A3-21 (High) — 79 public-runtime SQL credentials (44 in hub); 117 server connections; layout digests
- **Files:** public-context-composition.md:86-117, provider-installed-pair.md:23-38, processing-admission.md:9, 24-27, owner-deployment.md:3-11, 52
- **Current design:** each purpose has its own role and pool (capture-preview 46, capture-resolution 47, purpose15/40 …). An exact-count/layout-digest check rejects other layouts. The installer budgets 104 runtime plus 13 other connections.
- **Problem class:** in-process role splits; configuration that only tunes its own machinery.
- **Cost:** about 104 connections for one hub plus workers. A `max_connections` sizing burden. Every feature adds roles, grants and pools.
- **Requirement:** agent-added. SE#2 REDUCE: "one non-admin login per process, a separate migration owner … remove in-process role splits, `session_user` OID pins, layout digests, per-purpose pools". Precedent: GitLab, Harbor, Sentry, Grafana.
- **Replacement:** one login and pool per Deployment (hub-api, hub-worker, key-service), plus a migration owner used only by Helm hook Jobs.
- **Consistent changes:** AGENTS.md ADR-215/217/222 notes, `catalog.yaml`, all SQL role migrations, `research/installed-sql-budget.md`.

---

## 6. Cluster: permissions

### A3-22 (High) — One-second complete-LIST poll to renew deny completeness; 2 s watch sessions to renew freshness
- **Files:** permission-acceptance.md:13, 42-55; permission-observation.md:28-29, 47
- **Current design:**
  - A complete AccessBinding LIST runs every second to renew 5 s/30 s deny freshness.
  - The namespace watch session lasts 2 seconds, and "a clean end renews observation freshness".
  - If SQL is unavailable, authority expires within 5 s.
- **Problem class:** polling where watch exists; expiry merely to force refresh (rule 1).
- **Cost:**
  - One LIST per second per controller: at 1,024 bindings, ~8 MiB/s.
  - Namespace LISTs at 4,096 namespaces.
  - An API server restart or SQL hiccup cuts all access within seconds.
- **Requirement:** agent-added. The maintainer rule requires event-driven updates: "Cached state stays valid until replaced". ADR-311 allows a 30 s cap only for authorization reuse, not source polling.
- **Replacement:** a client-go shared informer per resource. Accept watch events into SQL. Relist only on 410/watch restart. The projection stays valid while the informer is synced; mark the stream unavailable only on watch loss beyond resync. Precedent: every Kubernetes controller (controller-runtime cache).
- **Consistent changes:** retention-checkpoints.md:47-51 (same pattern), ADR-056/200/242, `authorization.PermissionObservationInterval` text.

### A3-23 (High) — Encrypted authority-audit outbox gating new Allows
- **Files:** permission-acceptance.md:17-23, 59-63; policy-automation.md:17, 98-102
- **Current design:**
  - Each acceptance writes an outbox event that the publisher encrypts, PUTs, reads back, verifies and acknowledges, two events per batch.
  - New Allows require acknowledged receipts with non-null versions for the bootstrap, activation and epoch events.
  - Publication and download transactions repeat the receipt checks.
- **Problem class:** audit before use; per-event envelope encryption; duplicated receipts.
- **Cost:** new grants become usable only after KMS and S3 round trips. An S3 outage freezes every new permission.
- **Requirement:** agent-added. SE#4/SE#9c.
- **Replacement:** an audit row in the acceptance transaction, with optional async export.
- **Consistent changes:** policy-automation.md, download-authority.md.

### A3-24 (High) — Permission admission guard, dry-run probe and initial-review ConfigMap
- **Files:** permission-acceptance.md:25-41
- **Current design:**
  - A native VAP checks delegation envelopes.
  - A live guard reader with a SelfSubjectAccessReview-confirmed probe verifies a dry-run denial.
  - A bootstrap review ConfigMap (`reviewer`, `bindingsSHA256`, ≤1 h) is required for a non-empty baseline.
  - The namespace UID is pinned before and after reads.
- **Problem class:** guard proofs; installer review journals; defends against trusted namespace writers.
- **Requirement:** agent-added. ADR-328 applies. ADR-329 (maintainer) moves AccessBindings to application namespaces, "managed by ordinary namespace RBAC".
- **Replacement:** RBAC on AccessBinding in each application namespace, observed by the region's connector informer. CRD CEL validation only for shape, not delegation proofs.
- **Consistent changes:** permission-observation.md (control-namespace reader), policy-automation.md:7 (automation envelope admission), ADR-050/242/247.

### A3-25 (High) — ADR-247 reconciler re-reads remote namespace and workload journals every ≤10 s and renews guard proofs with <2 s left
- **Files:** permission-acceptance.md:72-80
- **Current design:** before each one-second refresh, the reconciler re-reads (at most every 10 s, concurrently, with a 3 s budget) the namespace and workload journals of joined clusters from their connectors. It also renews guard proofs and group directories that have less than 2 s left.
- **Problem class:** polling across clusters; expiry-driven refresh.
- **Cost:** O(clusters × selections) queries every 10 s, plus guard dry-runs.
- **Requirement:** agent-added.
- **Replacement:** connectors run informers and push deltas (with a sequence number) over the tunnel (A3-17). The hub resyncs a cluster only after reconnect or digest mismatch.
- **Consistent changes:** ADR-247, context-query-capacity.md.

### A3-26 (Medium) — A→B→A continuity: assignment retirement on any unverified intermediate change, keyed by assignment UUID
- **Files:** permission-acceptance.md:7-15; permission-observation.md:45
- **Current design:** an assignment is retired when the reconciler sees a generation jump, a removed subject or an unverified metadata change. It is retired even if the final state matches. Evidence audiences pin assignment UUIDs.
- **Problem class:** over-precise identity; restart- and compaction-induced access loss.
- **Cost:** a watch 410 after compaction retires assignments, which then require re-grant.
- **Requirement:** agent-added. SE#9d REDUCE: "stable team identity; admin transfer only when the team is gone".
- **Replacement:** key audiences and shares to stable (group/team ID, namespace) identities, and evaluate current bindings per request. Precedent: Kubernetes RBAC evaluation is stateless over current bindings.
- **Consistent changes:** authorization spec (audiences), sharing spec.

### A3-27 (Medium) — Decision-time access reviews persisted per Pod/principal, with outbox audit per decision change
- **Files:** permission-acceptance.md:82-86
- **Current design:** the connector runs a SAR per principal per Pod. `fresh_until` is ≤60 s and stored in SQL. Each decision change appends an encrypted audit outbox event. Read paths repeat the caller's recorded reviews.
- **Problem class:** chatty per-request reads; audit per cache entry.
- **Requirement:** pod-exec inheritance is maintainer ("configurable inheritance including pod exec rights"). Persistence and audit are agent-added.
- **Replacement:** an in-memory SAR decision cache in the connector (5 min allow / 30 s deny, like the K8s webhook authorizer). Audit only the operation that used it.
- **Consistent changes:** ADR-245, migration 00096.

### A3-28 (Medium) — Controller epochs and leases with a 31 s restart wait
- **Files:** permission-acceptance.md:7-9, 44-53; retention-checkpoints.md:15
- **Current design:** each SQL controller epoch has a 30 s lease. The restart grace is 1 s or 31 s.
- **Problem class:** a bespoke leader-election and fencing layer.
- **Replacement:** client-go `leaderelection` on a Lease. Idempotent SQL upserts keyed by object UID and resourceVersion, so no epoch fencing is needed.
- **Consistent changes:** configuration-reconciliation.md.

---

## 7. Cluster: retention

### A3-29 (High) — Retention source: LIST/guard observation every second, 5-observation window, 30 s stored freshness
- **Files:** retention-checkpoints.md:45-51; retention-observation.md:25
- **Current design:**
  - A follower takes a complete LIST plus a guard dry-run "at most one per second" to keep 30 s availability.
  - A bookmark cannot renew.
  - Readiness requires a fresh LIST, the watch watermark and every audit receipt.
- **Problem class:** polling where watch exists; expiry to force refresh.
- **Cost:** 1 LIST plus 1 dry-run write per second. Retention-dependent operations (capture, publication, download) fail within 30 s of any API-server or SQL blip.
- **Requirement:** administrator-enforced maximum retention is maintainer. The freshness machinery is agent-added.
- **Replacement:** an informer plus watch-applied changes. The source stays Ready while the informer is synced; resync only on watch restart.
- **Consistent changes:** ADR-056/200, retention-effects.md.

### A3-30 (High) — RetentionProof plus fresh topology read inside every effect transaction, including every download content batch permit
- **Files:** retention-effects.md:5-13
- **Current design:**
  - Before each effect transaction a fresh topology ConfigMap observation is taken.
  - Inside the transaction the code locks the sources and checks epoch, checkpoint, snapshot, live observation, catch-up and both audit acknowledgements.
  - This covers context admission, verification, publication, download reservation, batch start, metadata permit "and every content batch permit".
- **Problem class:** per-step revalidation; chatty reads; global serialization on the permission root lock.
- **Cost:** at least 1 K8s GET plus several locked SQL reads per content batch. Every transaction serializes on the permission-root row.
- **Requirement:** agent-added. ADR-312 (maintainer): started downloads run to their original bounds, including "effective retention cutoffs". That makes per-batch retention proofs redundant.
- **Replacement:** compute effective read and delete dates at admission and store them on the artifact row. That overlay already exists (retention-lifecycle.md:13). Policy changes update rows through the controller. Effects compare `now()` with the row's dates and need no proof or topology read. Byte streams end at the stored cutoff.
- **Consistent changes:** download-recovery.md, download-authority.md, AGENTS.md ADR-055 note.

### A3-31 (Medium) — Signed (detached JWS) plus encrypted lifecycle journal per retention shortening
- **Files:** retention-lifecycle.md:17, 23-27
- **Current design:** each shortening decision is JWS-signed with dedicated keys, envelope-encrypted, PUT, re-read, verified and then acknowledged.
- **Problem class:** application crypto on low-sensitivity metadata; duplicated journal.
- **Requirement:** agent-added. SE#8, and SE#9b (hub-signed, hub-verified).
- **Replacement:** an append-only SQL `retention_decision` row.
- **Consistent changes:** retention-catchup.md:15.

### A3-32 (Medium) — Catch-up job per checkpoint, 16 artifacts per page, oldest-first serialization
- **Files:** retention-catchup.md:5-11
- **Current design:**
  - Each policy checkpoint spawns a job that visits every context registration in pages of 16 under root/source locks.
  - Unknown historical selectors stop the page.
- **Problem class:** O(artifacts × policy changes) work; single-writer serialization.
- **Cost:** 100k artifacts means 6,250 transactions per policy edit, and later edits wait behind earlier ones.
- **Requirement:** shortening already-retained evidence is maintainer-consistent ("administrator-enforced maximum"). The paging mechanism is agent-added.
- **Replacement:** one set-based `UPDATE … SET effective_expires_at = LEAST(…) WHERE <selector match on stored labels>` per policy change, batched with `LIMIT`. Store the selector-relevant namespace and workload labels on the artifact row at capture, so historical selectors are always answerable. Precedent: Velero stores labels on Backup objects and applies TTL GC from stored fields.
- **Consistent changes:** retention-observation.md:9 (needs protected metadata observation), retention-lifecycle.md.

### A3-33 (Medium) — Immutable retention topology ConfigMap per cluster pinned by UID and content digest
- **Files:** retention-topology.md:5-13
- **Current design:** each target cluster has an immutable `topology.json` accepted by UID and digest pins. Changes require a "protected installation migration".
- **Problem class:** UID pins; installer-state verification.
- **Requirement:** agent-added. ADR-328 and the Helm-native decision apply.
- **Replacement:** the hub/local source set is a column on the SQL cluster registration, or Helm values.
- **Consistent changes:** `retention-topology.schema.json`, `examples/retention-topology.json`.

### A3-34 (Low) — Retention checkpoint per watch event including bookmarks, plus encrypted audit per checkpoint
- **Files:** retention-checkpoints.md:17, 25-27
- **Current design:** every watch event, including bookmarks, is persisted as a SQL checkpoint before the next, each with an encrypted acceptance audit object.
- **Replacement:** persist only spec changes (generation bumps) as SQL rows. Store the resume cursor in memory; on restart do LIST+WATCH, which is standard.

---

## 8. Cluster: policy automation, triggers, targets, collectors

### A3-35 (High) — Policy trigger polls every active policy every 15 s through regional queries, including per-container `pods/log` GETs and Alertmanager GETs
- **Files:** policy-automation.md:31-73
- **Current design:**
  - `PolicyTrigger` polls each active policy every 15 s with `observe-workload-restarts`.
  - Detectors in that poll:
    - Probe: a field-selected Event LIST.
    - Alert: Alertmanager `GET /api/v2/alerts`.
    - Log: one `pods/log` GET per container (≤32 containers, ≤4 MiB, 8 concurrent).
    - Resource: a PodMetrics LIST.
  - One goroutine per policy.
- **Problem class:** polling where event sources exist; fan-out O(policies × containers).
- **Cost:** at 100 log policies × 32 containers that is 213 `pods/log` GETs per second, each re-reading the window. Every API call crosses the hub↔connector channel.
- **Requirement:** triggers are maintainer (expiring policy grants for automatic intrusive actions, detectors). The polling form is agent-added.
- **Replacement:**
  - Restarts, exits and probes: a connector Pod and Event informer that pushes matching deltas.
  - Alerts: an Alertmanager webhook receiver (`webhook_config`), which is the standard push.
  - Logs: `pods/log?follow=true&sinceTime=` streams per armed container, or document a Loki-ruler alert integration.
  - Resource: polling metrics.k8s.io at 15 s is acceptable because there is no watch. HPA does the same.
- **Consistent changes:** `specs/triggers.md`, ADR-228/230/231/241, context-query-capacity.md.

### A3-36 (Medium) — Policy-submission JWS signed and verified only by the hub, with a pinned trust ConfigMap and OpenBao Ed25519
- **Files:** policy-submissions.md:1-27; policy-automation.md:23
- **Problem class:** internal signing without a trust boundary.
- **Requirement:** agent-added. SE#9b verdict REMOVE.
- **Replacement:** the authenticated request plus the SQL acceptance row (nonce becomes idempotency key).
- **Consistent changes:** `submission-trust.schema.json`, ADR-062; delete the doc.

### A3-37 (Medium) — Policy source observation lasts 5 s; DebugPolicy reads re-pinned by namespace/UID; envelope receipts gate eligibility
- **Files:** policy-automation.md:15, 21, 27
- **Problem class:** expiry-driven freshness instead of an informer cache.
- **Replacement:** a DebugPolicy informer (watch). Accepted policy stays valid until replaced or deleted (tombstone on delete event).

### A3-38 (High) — Target resolution by direct API GET/LIST chains per preview and request; double reads
- **Files:** workload-target-resolution.md:38-46, 76-108; pod-resolution.md:7
- **Current design:**
  - Each preview runs: a namespace GET, a workload GET, a Pod LIST (≤256), and per-candidate ReplicaSet and Deployment GETs.
  - Each packet request runs "eight Namespace/Pod/ReplicaSet/Deployment GETs".
  - `ResolvePod` reads namespace, Pod, owner chain and Node, then rereads all of them.
  - A target observation expires after 5 s.
- **Problem class:** chatty per-request reads; self-verification (double read). It cannot provide the specified all-replica monitoring ("does not replace the later all-replica inventory/watch service").
- **Cost:** 8–16 API calls per operation per cluster. API QPS limits throttle a burst of previews. A workload with more than 256 Pods cannot be previewed by name.
- **Requirement:** whole-pod scope, exact target pinning and the "never substitute a replacement Pod" rule are maintainer. Reading through the live API is agent-added.
- **Replacement:** connector shared informers on Pods, ReplicaSets, Deployments, StatefulSets, Namespaces and Nodes, scoped by label or field where possible. Resolve from the cache and verify the UID once at effect time (the node collector already checks the Pod UID when it starts). Precedent: kube-state-metrics, controller-runtime cached client.
- **Consistent changes:** node-collector.md:103-113, regional-context-start.md:194-213, context-execution docs.

### A3-39 (Medium) — Node collector status reports every 15 s per node with full facts; 45 s staleness; long-poll work queue; bespoke enrollment
- **Files:** node-collector.md:25-60, 87-91
- **Current design:**
  - Status: a full report (facts, assessment, budget, receipts) every 15 s from up to 5,000 nodes per connector, about 333 req/s.
  - Work: a 25 s long poll for work.
  - Enrollment: the connector's in-memory issuer signs 20-min leaves after TokenReview plus live Pod/DaemonSet-UID/Node bootID checks. A connector restart triggers re-enrollment of every node (401 → enroll), limited by enrollment admission of 5/s with burst 20.
- **Problem class:**
  - Periodic full resends.
  - Bespoke PKI (SE#9a REDUCE: drop boot-ID equality and epoch binding).
  - A thundering herd after connector restart: 5,000 nodes at 5/s means ~17 minutes with no current collectors.
- **Requirement:** agent-added.
- **Replacement:**
  - One long-lived gRPC/HTTP2 stream per node carries pushed work and status-on-change, plus a small heartbeat (KEP-589 node-lease pattern).
  - Authentication is the projected audience-bound SA token via TokenReview, cached, over server-TLS. Alternatively a cert-manager CA so certificates survive a connector restart.
  - The bound token already carries Pod and Node claims (KEP-4193, cited in SE source 9), so live DaemonSet-UID and boot-ID reads go away.
- **Consistent changes:** peer-identity.md (node URI with boot/epoch), regional-context-start.md:194-213, packet-source observation (:103-122).

### A3-40 (Low) — Disposable-host marker as a hostPath `File` scheduling gate
- **Files:** node-collector.md:25-26
- **Note:** a hostPath of type `File` makes Pods fail on other hosts rather than not scheduling there. A standard nodeSelector or affinity on a node label gives the same safety (no collectors on the workstation) without failing Pods. Low priority, and it may be intentional for dev safety (AGENTS.md "Never enable a privileged collector on this workstation").

### A3-41 (Medium) — Profile acquisition: GoProfileGuard rechecks current state every second during the profile
- **Files:** runtime-profiles.md:49-58
- **Current design:** during profile collection a one-second current-state recheck (grants, permission, deny, recovery, endpoint, target) runs, and a failed recheck stops the socket.
- **Problem class:** per-step revalidation.
- **Requirement:** violates ADR-311/312 (one authorization per operation; started operations run to their original bounds). Stop remains the urgent revocation (SE#7).
- **Replacement:** authorize once at start. Cancel through the Stop/cancel signal only, delivered by push.
- **Consistent changes:** profile specs, `specs/profiles.md`.

### A3-42 (Medium) — Console polls `prepare` every 2 s
- **Files:** public-context-download.md:21-27
- **Replacement:** Server-Sent Events or a long-poll status endpoint fed by PostgreSQL LISTEN/NOTIFY on session state changes. The browser keeps one EventSource. Precedent: Argo CD UI streams application state via SSE.
- **Consistent changes:** console spec, MCP progress (MCP has progress notifications).

---

## 9. Obsolete/installer-era text and runtime walkthrough drift

### A3-43 (Medium) — `provider-installed-pair.md` describes the removed installer
- **Files:** provider-installed-pair.md:1-70 (nineteen resource claims, resource journal, `CompleteInputs` driver, bootstrap v4, 117-connection installer budget, original owner selection ConfigMap)
- **Requirement:** removed by the maintainer's 2026-11-13 Helm-native decision.
- **Action:** delete. Move any surviving SQL-role needs into Helm hook Job docs.

### A3-44 (Medium) — `runtime.md` walkthroughs prescribe polling, synchronous object audit and stream-lease rechecks
- **Files:** runtime.md:25-30 ("Conn->>Cap: Poll compatible eligible work"; "Node->>Conn: Poll"; "Cap->>Audit … Object acknowledgement"), :71 (uncertain spend stays charged), :125 ("C-08 durable audit acknowledgement precedes new recipient reads"), :137 (RecoveryBlocked fencing of issuer epochs), :161 ("stream leases recheck authority"; "scoped acquisition Job")
- **Problem class:** obsolete or contradicting text. R-11 contradicts ADR-312, and R-01/R-03 contradict SE#3/#4.
- **Replacement:** redraw R-01 with pushed work over the tunnel and an audit row in the effect transaction. In R-03 use an idempotency key stored with the effect instead of "keep charge". Change R-11 to "authorized once; runs to original bounds; Stop ends it".
- **Consistent changes:** `specs/execution.md`, `specs/artifact-downloads.md`.

### A3-45 (Low) — Implementation-progress narrative inside architecture docs
- **Files:**
  - node-collector.md:130-148, 170-177, 284-289, 321-332.
  - operation-audit-lifecycle.md:207-215, 239-251.
  - retention-*.md "Verification" sections.
  - owner-* "Qualification" sections.
  - public-context-composition.md:53-60.
- **Problem class:** stale qualification logs, ns timings and failing-before narratives mixed into contracts. They hide the actual design and go stale with every change.
- **Action:** move them to `docs/implementation-progress.md` or `test/results`. Architecture docs should state contracts only.

### A3-46 (Low) — `research.md` justifies JWS-signed internal control work
- **Files:** research.md:15-24
- **Action:** after A3-17 and A3-36, record that mTLS-authenticated channels carry work unsigned. Keep the C4/arc42 rows.

### A3-47 (Low) — `validation.json` is a 2026-10-09 snapshot of design-gate counts
- **Action:** regenerate it or drop it; it is not referenced as evidence.

### A3-48 (Low) — `processing-admission.md` re-reads the root and depends on multi-table lock-order choreography
- **Files:** processing-admission.md:7-16, 31-54
- **Note:** the "then reads the root again" self-check and the five writer-specific lock orders stem from per-purpose roles and roots (A3-21). With one role and a single transaction per admission, one `SELECT … FOR SHARE` on the root suffices. Low impact on its own.

---

## Deletion / merge candidates

Delete outright: obsolete after ADR-328, Helm-native install, SE#5/#9b/#9c, or ADR-221.

| Doc | Reason |
|---|---|
| owner-authentication.md | per-use owner re-auth, replaced by plain mTLS (A3-02) |
| owner-configuration.md | pinned/audited owner ConfigMap (A3-05) |
| owner-credentials.md | process-owned owner PKI renewal (A3-01) |
| owner-deployment.md | 13-file credential loader, guard probes, schedulingLeases (A3-06/04) |
| owner-enrollment-proof.md | pre-Ready token/workload proof (A3-01) |
| owner-forwarding.md | outbound owner relay (A3-03) |
| owner-issuance.md | OpenBao owner leaf issuance (A3-01) |
| owner-registration.md | durable owner registration, signing spend (A3-01) |
| owner-relay.md | owner-relay/v2 receiver (A3-03) |
| owner-startup.md | readiness PKI loop, launch-receipt convergence (A3-07). Keep only the "operator startup diagnostics" idea in a hub runtime doc. |
| owner-workload-protection.md | namespace guard (A3-04) |
| worker-owner-locator.md | superseded by ADR-221 (its own header says so) |
| worker-request-routing.md | superseded by ADR-221 |
| worker-routing.md | per-cluster worker trust catalog (A3-12) |
| worker-configuration.md | guarded/audited worker profile (A3-11) |
| worker-credential-channel.md | worker CSR channel and 9443 ClientHello split (A3-09) |
| worker-enrollment.md | worker PKI enrollment (A3-09) |
| worker-current-lifecycle.md | 5 s request-owned observation across enrollment (A3-13); fold the one-authorization rule into download-authority.md |
| provider-installed-pair.md | installer era (A3-43) |
| policy-submissions.md | SE#9b REMOVE (A3-36) |
| operation-audit-lifecycle.md | deletion certificates and H/B/P (A3-15) |
| operation-audit-overdue.md | overdue certificate fence (A3-15) |
| retention-topology.md | UID/digest-pinned topology ConfigMap (A3-33) |

Merge/rewrite:
- **New `hub-peer-tls.md`**, about 1 page: one hub CA (cert-manager or Helm), mounted certificates with reload, SAN identity, connector reverse tunnel, owner row in SQL if needed. It replaces the 11 owner-* docs, peer-identity.md and hub-owner-discovery.md/native-owner-listener.md (outside this scope; check them).
- **`worker-startup.md`** shrinks to "regional reader Deployment" (A3-09/10).
- **`operation-audit.md`** becomes "append-only audit table plus optional export" (A3-14).
- **retention-catchup/checkpoints/effects/lifecycle/observation** become one `retention.md`: informer, stored effective dates, set-based shortening, CRD validation (A3-29..34).
- **permission-acceptance + permission-observation** become one doc: connector informers on namespaced AccessBindings (ADR-329), stateless evaluation, cached SAR (A3-22..28).
- **pod-resolution.md** folds into workload-target-resolution.md as the informer-cache resolver (A3-38).
- **regional-context-start.md** becomes the "connector tunnel" doc (A3-17/18/19).

Contract schemas that go with the deletions (`specs/contracts/`):
- owner-*: `owner-bootstrap-selection`, `owner-configuration`, `owner-credentials`, `owner-deployment`, `owner-identity-activation`, `owner-identity-credentials`, `owner-identity-roles`, `owner-identity-role-state`, `owner-provider-auth`, `owner-provider-selection`, `owner-relay`, `owner-worker-trust`.
- worker-*: `worker-configuration`, `worker-control`, `worker-enrollment`, `worker-store-credentials`.
- Others: `submission-trust`, `retention-topology`, `history-work`, `history-ciphertexts`, `initial-bootstrap-passive-history`, `configuration-worker-input-*`.
- Also update `docs/architecture/catalog.yaml`, `specs/traceability.yaml` and the AGENTS.md ADR-07x–09x paragraphs.
