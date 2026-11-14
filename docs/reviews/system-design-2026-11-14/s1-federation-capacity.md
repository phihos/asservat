# Spec design audit S1: federation, capacity, persistence, deployment profiles, architecture, domain

Worktree: `/home/phil/Projekte/asservat-specreview` at `f9ccd35b` (after #232/#233/#234). Read-only audit.
Files: `specs/federation.md` (FED), `specs/capacity.md` (CAP), `specs/persistence.md` (DB),
`specs/deployment-profiles.md` (DEP), `specs/implementation-architecture.md` (ARC), `specs/domain-model.md` (DOM).

I checked the status line of every referenced ADR. ADR-080, 092, 093, 095, 097–102, 133, 137, 140, 145, 148, 155, 158, 159, 162 and 164 are
**fully superseded** by ADR-328. ADR-067–070, 073, 076, 077, 081, 083, 085, 086, 088, 090, 091, 094, 096, 126, 141, 144, 147, 151, 161,
168–170, 222, 246, 262 and 326 are **superseded in part**. ADR-078 is superseded. Spec text that still mandates these mechanisms is
obsolete. It contradicts AGENTS.md "Threat model and security evidence (maintainer, 2026-11-13)" and the Helm-native decision.

Legend: **M** = maintainer requirement (AGENTS.md cited); **A** = agent-added.

## Summary by severity

| Severity | Count |
| --- | --- |
| high | 13 |
| medium | 14 |
| low | 6 |

---

## High

### S1-01 Obsolete installer/guard-era requirements in deployment-profiles (bulk)
- **Where:** DEP:7–35 (ADR-140, ADR-148), 77–99 (ADR-137, ADR-151), 117–129 (ADR-164), 150 (ADR-080), 202, 225–247 (ADR-133, 102, 099, 100, 101, 098, 097, 095, 094), 279–283 (ADR-091/092/093), 285–295 (ADR-145 capacity probe).
- **Current design:** These sections cover installer Pods, scheduling gates, witnesses, preparation journals, temporary SQL credentials with fifteen-minute intervals, native dry-run denial probes, UID/resourceVersion pins, launch receipts, GC/kubelet admission exceptions and connection-budget comparisons for "installer pools".
- **Problem class:** Obsolete text. It describes self-verification of installer state and defends against trusted namespace writers and cluster admins.
- **Cost:** About 60% of DEP is normative text for removed mechanisms. Every new contributor or agent has to work out which MUSTs still apply, and `spec-check`/traceability keeps the dead requirements alive.
- **M/A:** A. The maintainer explicitly removed it: AGENTS.md "Security proportionality" 2026-11-13 ("The installer pod goes against all best practices…") and "Threat model" (no UID pins, journals, launch receipts, admission proofs).
- **Replacement:**
  - Replace REQ-DEP-001/005 installer prose with a short Helm contract. Helm renders all objects. Idempotent `post-install,post-upgrade` hook Jobs create SQL schema/roles, key material and buckets with create-if-absent semantics. Secrets come from `existingSecret` references or Job-generated Secrets annotated `helm.sh/resource-policy: keep`.
  - Precedent: cert-manager, Argo CD, GitLab and Keycloak charts all use hook Jobs or `lookup`-guarded Secrets. See docs/reviews/helm-native-install-plan.md.
  - Keep only line 249 (no secrets in values, no rotation on re-render) and 251 (provider migration). Both are maintainer workflow requirements.
- **Consistency:** `specs/traceability.yaml` (TASK IDs pointing at these REQs), `docs/installation/helm.md`, `specs/contracts/initial-*.schema.json`, `owner-deployment.schema.json`, `hub-worker-deployment.schema.json`; persistence.md REQ-DB-004/005 (S1-05, S1-07).

### S1-02 Bespoke hub-owner PKI and routing chain for download-worker enrollment
- **Where:** DEP:131–148 (ADR-126, ADR-081), 158–184 (ADR-066…077), 257–277 (ADR-078, 079, 082–090).
- **Current design:** Each download is a per-request Kubernetes Job (ADR-069). The worker enrolls with a CSR to the hub replica that "owns" the human request. This involves an SQL owner locator (ADR-075), EndpointSlice/Pod/Deployment discovery (ADR-076), and per-hub-process twenty-minute certificates from a private issuer with durable registration, audit and signing spend (ADR-079/082/084). It also needs a private relay with live delivery (ADR-085–087) and per-profile issuer roots (ADR-089).
- **Problem class:** Bespoke PKI/enrollment where standard TLS/Kubernetes suffices. Per-request Jobs. Process affinity in place of stateless replicas. Several fallback and uncertain states.
- **Cost:**
  - Every download pays for a Job create, scheduling, image start, TokenReview, CSR signing (an OpenBao call), encrypted audit, owner lookup and a hub-to-hub mTLS hop. That is seconds of latency and several API, SQL and KMS round trips before the first byte.
  - API-server load grows linearly with downloads.
  - Hub replicas need per-process leaf renewal every twenty minutes, so registry rows grow with replica churn.
- **M/A:** A. The maintainer requires native downloads (AGENTS.md: "native download for all gathered evidence…"), not per-request Jobs or owner affinity.
- **Replacement:**
  - Run a regional `download` Deployment, horizontally scaled, that streams S3 bytes. It unwraps through the key service using a projected, audience-bound ServiceAccount token (TokenReview, KEP-1205) or a cert-manager-issued mTLS certificate.
  - The human's browser or CLI calls the hub. The hub authorizes once (ADR-311/312) and returns a short-lived signed download ticket (JWT/macaroon bound to session, artifact and deadline). Any download replica accepts the ticket.
  - Precedent: Loki/Tempo queriers, Thanos store-gateway, Harbor/registry token auth (Docker distribution token spec), and GitLab Workhorse "send-url" offload.
  - Internal hub TLS comes from cert-manager. Downloads need no cross-replica rendezvous.
- **Consistency:** `specs/artifact-downloads.md`, `specs/evidence.md`, `docs/architecture/download-*.md`, `worker-*.md`, `owner-*.md`, `hub-owner-discovery.md`, `interfaces.md`, persistence.md "Native artifact transfer state" (DB:398–400), CAP:55 (key-provider budgets). Cluster-local SQL migrations 24–30 would become contract removals.

### S1-03 Bespoke connector enrollment and renewal protocol
- **Where:** FED:5–9 (ADR-052, 168, 169, 170); DEP:131–146 (ADR-126 connector process identity).
- **Current design:**
  - Bootstrap enrollment caps provider calls at "two nonrefundable attempts" of five seconds each, with a fixed thirty-minute identity expiry and durable encrypted audit before signing.
  - Restart uses a rotating cluster enrollment credential with "exporter-bound possession proof" and fork fencing.
  - A delegated regional lifecycle channel carries Pod/controller proofs, and a separate federation SQL compartment and credential sit on top.
- **Problem class:** Bespoke PKI and enrollment layers. Spent-on-uncertain accounting. Synchronous encrypted audit on the issuance path. Self-verification of Pod/controller chains, which ADR-168/169 already supersede in part.
- **Cost:**
  - A thirty-minute leaf means renewal traffic of N clusters × two per hour, each with signing, audit and SQL work.
  - Nonrefundable attempts can strand a cluster after transient provider errors, so an administrator has to re-enroll.
  - It adds an extra process compartment and credential.
- **M/A:** Mixed.
  - Maintainer requirements: an outbound connector and central multi-cluster management (AGENTS.md "Authority and invariants": "central multi-cluster management").
  - Agent-added: one-use bootstrap, two-attempt cap, delegated proofs, compartment.
- **Replacement:**
  - Follow kubeadm TLS bootstrap / OCM klusterlet. A bootstrap token (one-use, expiring) leads to a CSR, and the hub CA issues a client certificate (for example 24h–7d).
  - The connector renews at two thirds of the lifetime with its current certificate, like kubelet `rotateCertificates` / OCM `ManagedClusterAddOn` registration. Revocation uses the SQL `cluster.revoked` flag checked at mTLS handshake/connection setup.
  - Issuance audit is an SQL row in the same transaction, shipped asynchronously (S1-05). Retries are idempotent by `(clusterUUID, CSR public key)`, not attempt-counted.
- **Consistency:** `docs/architecture/enrollment-activation.md`, `bootstrap-channel.md`, `fleet-administration.md`, `connector-renewal.md`, ADR-168/169/170 notes, DEP REQ-DEP-003.

### S1-04 Obsolete fresh-install and owner-projection rules in federation
- **Where:** FED:11 (ADR-144 observation bootstrap, common SNI, owner Service UID), FED:13 (ADR-155/161 unchanged-fleet persistence contention exception), FED:15–21 (installer-inventory ServiceAccount UID GET), FED:27–69 (ADR-158, 159, 162 owner startup preflight, projection split, read-only finalization).
- **Current design:** These are installer projection/launch verification rules, exact lock-abort classification of fleet persistence, owner ServiceAccount UID comparison and SQL59 semantic-version pins.
- **Problem class:** Obsolete installer/guard era, self-verification and requirements that defend against trusted actors.
- **Cost:** About 50 lines of MUSTs. Code paths stay alive for ADRs that are now fully superseded (155, 158, 159, 162).
- **M/A:** A. Removed by ADR-328 and AGENTS.md 2026-11-13.
- **Replacement:** Delete. Hub peer authentication is mTLS against the configured hub CA (cert-manager) plus TokenReview. There is no ServiceAccount UID GET.
- **Consistency:** `docs/architecture/owner-*.md`, `fleet-observation.md`, `traceability.yaml` SC-FED-001.

### S1-05 Synchronous object-store audit gates dispatch, disclosure and issuance
- **Where:** DB:308 ("Work remains AwaitingAudit until the encrypted append-only audit intent is durably written to the qualified object backend and its reference acknowledged in SQL. Only then dispatch"); FED:9 ("durably audits the claim before signing", "exact durable encrypted audit … before delivery"); FED:127 ("audit gates"); DEP:166, 172, 259–261 (separately audited enrollment, launch and certificate); DB:298 ("Newly expanded scope is not readable until its durable audit commit is acknowledged").
- **Current design:** Each sensitive operation runs SQL, then encrypts and PUTs to S3 (with KMS wrap), then acknowledges in SQL through a separate credential, and only then acts.
- **Problem class:** Synchronous encrypted/object-store audit and KMS on the hot path. A separate audit SQL role and pool. A duplicated receipt state machine.
- **Cost:**
  - At least two extra SQL transactions, one S3 PUT and one or more KMS calls per action, download, share or certificate. Latency is tens to hundreds of milliseconds per op.
  - S3 or KMS unavailability blocks all collection and downloads, even with SQL healthy.
  - CAP:55 has to budget the KMS calls explicitly.
- **M/A:** A for the synchronous ordering. M only for "encrypted evidence and audit" as a capability (ADR-328 "What remains in scope"; the AGENTS.md product list mentions audit).
- **Replacement:**
  - Use a transactional outbox: insert the audit record into an `audit_event` SQL table in the same transaction as the state change, so atomicity holds with zero extra round trips.
  - A background shipper batches, encrypts (one DEK per batch), PUTs append-only objects to S3 with Object Lock, and is triggered by LISTEN/NOTIFY.
  - Precedent: the Kubernetes API-server audit batch webhook backend, Debezium/outbox pattern, GitLab audit-event streaming, pgaudit plus log shipping.
  - Denials stay effective without audit (already stated).
- **Consistency:** `specs/audit*.md`/`evidence.md` (audit REQs), `docs/architecture/custody-transactions.md`, `context-publication.md`, `download-sessions.md`, `enrollment-activation.md`, CAP:55, ADR-222 separate audit credential (DB:314–326), DOM REQ-DOM-004.

### S1-06 Outbox wake-up by polling; NOTIFY "optional"
- **Where:** DB:310 ("NOTIFY is optional wake-up only; polling recovers missed notifications"); FED:81 (connector long-poll is fine, but the hub side has to learn of new work); CAP:32 ("250 ms polling").
- **Current design:** Workers poll `outbox`/`work_lease` tables periodically, and NOTIFY only shortens latency.
- **Problem class:** Polling where an event source exists. This violates maintainer rule 1 (PR #237).
- **Cost:** Each hub replica times each work family times a poll interval gives a constant SQL load, plus latency equal to the poll interval when NOTIFY is skipped.
- **M/A:** A. Rule 1 is a maintainer rule.
- **Replacement:**
  - LISTEN on a dedicated connection per process. On LISTEN (re)connect, run one catch-up query (`state='ready' ORDER BY due_at`). PostgreSQL guarantees delivery to connected listeners, so loss happens only on disconnect.
  - Schedule a timer only for the earliest known future `due_at`/lease expiry, which is a deadline and not a poll.
  - Connector long-poll handlers wait on in-process signals fed by NOTIFY.
  - Precedent: the Kubernetes informer pattern (list once, then watch, relist on watch restart); PostgreSQL docs on LISTEN/NOTIFY semantics.
- **Consistency:** FED REQ-FED-002/REQ-EVT-002, `docs/architecture/interfaces.md`, ARC REQ-ARC-004.

### S1-07 Database-incarnation fence and activation checks on every authority read; heavy restore protocol
- **Where:** DB:354–356 (ADR-098 witness, both superseded), DB:360–362, DB:372; FED:71–77 ("Fleet freshness MUST bind the exact semantic authority version and accepted database incarnation").
- **Current design:**
  - Every ordinary authority read and final effect checks an activation binding to the accepted PostgreSQL process/database incarnation (ADR-096).
  - Restore replays "independently retained revocation/deletion checkpoints" from object storage, and fleet observation keeps semantic-version records.
- **Problem class:**
  - Per-request revalidation: an extra join or lock on recovery rows in every transaction.
  - A duplicated ledger, since checkpoints live outside SQL.
  - Obsolete witness text.
- **Cost:** Every authority transaction locks or reads recovery and incarnation rows first (DB:290 lock order plus "lock recovery before permission/storage"), which makes those rows hot shared rows across all requests.
- **M/A:** A. The maintainer only requires PostgreSQL as the hub state store; restore semantics are agent-designed. ADR-096 is superseded in part.
- **Replacement:**
  - Restore is an operator runbook or Job, like Velero, GitLab backup-utility or Keycloak restore. The steps are: scale the hub to zero, restore, then run a `recovery` Job that sets `installation_state='recovery_blocked'`, bumps a `fence_epoch`, invalidates grants/sessions issued after the backup's WAL position, and reconciles accounting from bucket inventory (S1-10). After that it clears the flag.
  - Components read the flag at startup and on NOTIFY, not per request. Connector mTLS rejects old epochs at handshake.
  - Delete witness/activation text.
- **Consistency:** `docs/architecture/database-recovery*.md`, `download-recovery.md` (EffectTransactionGuards), `context-admission.md`, FED REQ-FED-003, ARC REQ-ARC-006, DOM REQ-DOM-004.

### S1-08 Hierarchical capacity admission locks pool → cluster → namespace → workload on every reservation
- **Where:** CAP:119 ("Allocate pool → cluster → namespace → workload slices in fixed lock order using short SQL transactions and conditional aggregate updates"); DB:290 lock order "capacity ancestors root-to-leaf".
- **Current design:** Each reservation (capture, download read work, live view, query) row-locks every ancestor account, including the single pool root.
- **Problem class:** Global serialization, because the pool root is a hot row.
- **Cost:**
  - All admissions in an installation serialize on one pool row (and on one row per cluster).
  - In a capture storm across many workloads, or with many live viewers, throughput is about 1/(transaction latency), and the 1-second lock wait (DB:312) turns contention into refusals.
- **M/A:** M for the guarantees: AGENTS.md "protection against capture storms and cross-workload storage exhaustion". A for the locking scheme.
- **Replacement:**
  - Protected allocations are fixed at enrollment and "not lent" (CAP:75), so admission within a workload's protected allocation needs only the workload row.
  - Ancestors change only when allocations change (enrollment, resize) or when a reservation spills into shared burst. Lock the pool only for burst, or pre-grant burst in chunks to workload rows (token-bucket leasing).
  - Precedent: Kubernetes ResourceQuota (per-namespace object, no cluster-wide lock); Google Doorman/Envoy global rate-limit leases; Vitess/Spanner sharded counters.
- **Consistency:** DB:273 (`capacity_account` table), CAP REQ-CAP-004/005, live-watch REQ-LIV-004, `docs/architecture/custody-transactions.md`, `context-query-capacity.md`.

### S1-09 Protected-root context capacity producer, query-capacity extension and five-second negative-write windows
- **Where:** CAP:127–143 (three-phase protected context producer, "fresh protected observation", ADR-141, sixteen-account envelope), CAP:145–165 (approved context queries: "separate original-installation qualification", "acknowledged irreversible claim before native guards", "at-most-five-second write interval", "audited upgrade protocol").
- **Current design:** This is a separate protected capacity root with phase state, guard I/O claims, terminal negatives, restrictive watermarks and installation-qualification provenance for queries.
- **Problem class:**
  - Installer and guard era: ADR-141 is superseded in part ("guard authority, installation…").
  - Spent-on-uncertain claims.
  - Five-second windows, which contradict ADR-311.
  - Duplicated ledgers for the same budget.
- **Cost:**
  - Every approved query does an extra SQL claim, guard read and completion transaction.
  - "Exhaustion … retains one terminal negative" permanently disables a root.
  - Installations without the "original extension" stay unavailable.
- **M/A:** A. ADR-311 (M) caps authority reuse at 30/60 s, and "Do not reintroduce stacked five-second authority windows".
- **Replacement:**
  - Context capture and queries charge the ordinary workload capacity account (S1-08) plus a per-principal/per-workload token-bucket rate limit for query work.
  - EvidenceStoragePool and EvidenceBudgetPolicy CRDs are reconciled by a controller into SQL account rows, following the Kubernetes ResourceQuota controller pattern.
  - Remove phases, guard claims and the upgrade protocol.
- **Consistency:** `docs/architecture/context-query-capacity.md`, `specs/context-*.md`, ADR-141 note, DB:404–406 (combined grants reserve parent disclosure).

### S1-10 Uncertain reservations and copies never released without "verified removal"; second ledger in object storage
- **Where:** CAP:117 ("Long-term immutable charge/copy outcomes also live in encrypted object storage"), CAP:119 ("Expiry/restart alone is not proof"), CAP:123–125, CAP:9 ("Failure after a possible start consumes the start and conservatively reserves bytes until outcome is known"); FED:95 ("cannot mint another copy of an uncertain upload reservation"); ARC:164; DOM:223–227.
- **Current design:** Uncertain uploads and starts keep their charge indefinitely. Charge outcomes are duplicated into encrypted objects. Restore reconciles the SQL ledger with "manifests, intents, copy inventory and lifecycle journal", and bucket listing is "a cross-check only".
- **Problem class:** Spent-on-uncertain accounting where idempotency keys suffice. Duplicated ledgers and journals.
- **Cost:**
  - Leaked charges accumulate with every network fault and eventually exhaust protected allocations with no automatic resolution.
  - Every outcome is written twice (SQL plus an object).
- **M/A:** M only for storage-exhaustion protection; the scheme is A. For dump starts, charging a possibly-started dump to the storm budget is reasonable, because the process may have been paused.
- **Replacement:**
  - Use deterministic object keys `…/<operationID>/<attemptID>/…`, so a retry overwrites or HEADs the same key, and uncertainty resolves with HEAD/ListObjectVersions/ListMultipartUploads under that prefix.
  - Add an S3 lifecycle rule `AbortIncompleteMultipartUpload`.
  - Committed usage is recomputable from bucket inventory per workload prefix. That is the authoritative physical truth after restore, as with Loki/Thanos compactor retention and Velero backup sync.
  - Release a dump-start charge when node boot ID changes or the collector reports a terminal outcome for the start ID.
  - Remove the object-storage charge ledger.
- **Consistency:** DB REQ-DB-005, `docs/architecture/custody-transactions.md`, `retention-*.md`, ARC REQ-ARC-004/006, DOM REQ-DOM-004.

### S1-11 Expiry-driven freshness for configuration projections and capacity bindings
- **Where:**
  - DB:246 (SQL projections carry a "freshness deadline").
  - CAP:29–37 and 43–49 (readiness hint, "one refresh demand and 250 ms polling", "independently refreshed binding", original deadlines of target/eligibility/proof facts).
  - DB:408–413 (ADR-200 "same accepted 30-second projection").
  - FED:71–77 (fleet freshness).
- **Current design:** Kubernetes-sourced configuration (budget policies, pools, fleet, permission sources) is projected into SQL with an expiry. Consumers refuse when the projection is older than its deadline, then poll or demand a refresh.
- **Problem class:** Expiry-driven freshness forcing re-reads, and polling. This violates rule 1 ("Cached state stays valid until replaced").
- **Cost:** Projection rewrites every ≤30 s per source object, even when nothing changes. Admissions fail during brief reconciler pauses, and the readiness code needs extra wait states.
- **M/A:** A. ADR-311's 30 s is for authority (identity/permission) reuse within one operation, not for configuration caches.
- **Replacement:**
  - Use a shared informer. Wait for `HasSynced`, then apply watch events to SQL and NOTIFY consumers. Relist only on watch restart or 410 Gone.
  - Readiness is "informer synced and connected", exposed as a single health condition (controller-runtime pattern).
  - Drop `freshness deadline` columns, ADR-200 timestamps and the 250 ms wait loop.
- **Consistency:** `docs/architecture/retention-observation.md` (bounded window of five LIST observations), `permission-observation.md` (five-second deny interval), `fleet-observation.md`, `capacity` readiness docs, `specs/retention*.md`, `specs/permissions*.md`.

### S1-12 Fragmented, pinned SQL pools and per-duty credentials
- **Where:** DB:314–339 (ADR-222: 18-connection ordinary pool, reserved one-connection journal/ack pools, six-connection owner pool, four role-pinned capture pools, pinned capacity reader, nested worker-configuration pool, separate publisher/federation/collector/key/deletion credentials; installer connection-budget comparison); DB:345–350; ARC:148 ("narrow facets").
- **Current design:** About eight pools under a 32-connection governor per replica, plus a provisioning check that compares the "compiled process/purpose allowance" with server capacity.
- **Problem class:** Bespoke credential compartmentalization. Configuration that only tunes its own machinery. Obsolete installer pools.
- **Cost:**
  - Idle pinned connections waste server slots, while the 18-connection ordinary pool saturates first.
  - Nested pools on one request risk self-deadlock, which is why "reserved" pools exist.
  - Each hub replica multiplies about eight pools.
- **M/A:** A. ADR-222 is itself superseded in part.
- **Replacement:**
  - Use one pool and one runtime role per process type (hub, connector-facing federation, key service, deletion if separate), with transaction-scoped work and no nested pool acquisition.
  - Set the size with Helm values, and offer PgBouncer or CloudNativePG's pooler for scale-out.
  - Precedent: GitLab (one role and pool per service), Keycloak, Grafana.
  - Delete DB:328–339.
- **Consistency:** `docs/architecture/*` SQL facet docs, `docs/decisions/222`, `charts/asservat`, DEP:19–23.

### S1-13 Local Kubernetes capacity/permit slices as a second fenced ledger
- **Where:** CAP:119 ("Local Kubernetes slices remain bounded (128 KiB per object), use resourceVersion CAS and fences, and are prepaid against every hub ancestor … persist the delegated maximum before delivery"); DB:248–250 ("Cluster-local permits, capacity slices, analysis work and local DeliveryWork remain bounded Kubernetes records"); FED:81, 95; DOM:223.
- **Current design:** The hub SQL ledger delegates prepaid slices into CRD objects per cluster. The connector CAS-updates them per reservation and reconciles proven-unused slices back.
- **Problem class:**
  - Duplicated state machines and ledgers for the same fact.
  - Chatty API-server writes per reservation, against etcd's ~1.5 MiB object limit and its write budget.
- **Cost:** One API write per local reservation and release. Reconciliation churn per cluster, and leaked slices on uncertainty (S1-10).
- **M/A:** Partly M: AGENTS.md "Kubernetes configuration/local control" and offline prepaid local work (REQ-FED-003) are product behavior. CAS slices in CRDs are A.
- **Replacement:**
  - The hub grants the connector a budget lease (bytes, starts, expiry) over the existing mTLS connection. The connector keeps it in memory plus one small checkpoint ConfigMap/Lease per connector, written on change with a debounce.
  - On reconnect, report usage and receive a new lease. This is the Doorman/Envoy RLS lease model, and it matches the AGENTS.md "push over existing connections".
- **Consistency:** FED REQ-FED-002/003, ARC REQ-ARC-004, `docs/architecture/local-start.md`, `interfaces.md`.

---

## Medium

### S1-14 Per-step authority rechecks in transaction rules contradict ADR-311
- **Where:** DB:290 ("External checks produce bounded-freshness evidence before the transaction, with source revisions/fences rechecked inside it"), DB:296 ("If additional blocking work is unavoidable after a check, revalidate before publication/permit issuance. Dispatch and delivery independently recheck current authority"), DB:298 ("final delivery rechecks"), DB:304 ("hold a later capacity/artifact lock until the relevant grant expires").
- **Current design:** Authority is revalidated at admission, dispatch, delivery and final publication.
- **Problem class:** Per-step and per-helper revalidation.
- **Cost:** Two to four extra authority observations per operation (IdP/Kubernetes/SQL).
- **M/A:** ADR-311 (M) says once per operation, reused ≤30 s/60 s; ADR-312 (M) says started downloads run to their original bounds.
- **Replacement:** Use one authority observation per operation, carried as an immutable value with `validUntil = min(observedAt+30s, original deadlines)`. SQL effect statements check only SQL-native facts (revocation rows, fence, expiry) with `clock_timestamp()`. Keep the post-lock expiry check, which is cheap and correct. Rephrase DB:304 as a test description.
- **Consistency:** `specs/authorization.md`, `artifact-downloads.md`, `docs/architecture/download-authority.md`.

### S1-15 Hub-to-connector commands "signed" in addition to mTLS
- **Where:** FED:7 ("Hub commands are signed, versioned, expiry-bound and independently checked against that local ceiling").
- **Current design:** Each command carries a separate signature, on top of the authenticated mTLS channel.
- **Problem class:** A bespoke crypto layer with no evidence of benefit (rule 2). The connector already pins hub trust over mTLS.
- **Cost:** A signing key purpose, a KMS sign call per command (or a key in the hub) and verification code.
- **M/A:** A. The local ceiling check is product behavior and should stay.
- **Replacement:** Use mTLS channel authentication, a command expiry and the local ceiling check. Add signatures only if commands are stored and forwarded through an untrusted relay, which is not planned. Precedent: OCM ManifestWork and Argo CD agent rely on transport auth.
- **Consistency:** `docs/architecture/interfaces.md`, key-purpose list in DEP:152.

### S1-16 Delivery-work lease state machine duplicates receiver deduplication
- **Where:** FED:83 (`Queued → Leased → Accepted → Running → terminal`, lease expiry reconciliation), ARC:164 (separate delivery lease, accepted execution, start identity, evidence commit), DB:310–312 (30 s claim lease with renewal and fence).
- **Current design:** Hub SQL leases per work item and fences, plus a connector-local accepted-execution record, plus a start identity.
- **Problem class:** Duplicated state machines. With receiver idempotency by `workID`, the hub-side lease and fence add little.
- **Cost:** Lease renewals per in-flight item every ≤30 s across all clusters.
- **M/A:** A.
- **Replacement:** The hub marks work `Sent(connectionEpoch)` and resends all non-terminal work on reconnect. The connector deduplicates by `workID` against its local durable record and reports state, as with Kubernetes level-triggered reconciliation (OCM ManifestWork status). Keep `Indeterminate` only for intrusive starts.
- **Consistency:** `docs/architecture/interfaces.md`, ARC REQ-ARC-004, DB `work_lease` table (DB:278).

### S1-17 Sensitive plans, reasons, history settings and live-watch filters in encrypted object records
- **Where:** DB:260, 268, 378, 396 ("Source/profile selection and display-filter content stay behind an encrypted expiring reference"); DOM:231.
- **Current design:** SQL keeps only references. Every read of a plan, reason, history setting or live-watch filter needs an S3 GET plus a KMS unwrap, and every write needs an S3 PUT plus KMS.
- **Problem class:**
  - Chatty per-request reads and an N+1 pattern: history listing fetches settings per row.
  - Synchronous KMS and object store on interactive paths.
- **Cost:** Opening a live watch or listing history is bound by object-store latency. Creating a capture needs extra PUTs, and S3 outages break control-plane features.
- **M/A:** A. The maintainer forbids "unencrypted managed evidence storage". Control metadata is not evidence.
- **Replacement:** Use application-level AEAD column encryption in SQL (`bytea`), with a per-installation DEK wrapped by the key service and cached in memory. Precedent: Rails ActiveRecord encryption, GitLab `attr_encrypted`, Vault Transit with data-key caching (AWS Encryption SDK caching CMM). Keep evidence in S3.
- **Consistency:** `specs/capture-history.md`, `live-watch.md`, `privacy.md` (control-data deadlines), `docs/architecture/context-admission.md`.

### S1-18 Ongoing-source resource projection ADR-262: "complete budget projection", watermarks, one-way enrichment
- **Where:** CAP:207–239.
- **Current design:** The source issuer must consume the "original accepted/current complete budget projection". Restrictive watermarks and a one-way parser projection enrichment apply.
- **Problem class:** Over-specified projection machinery. "Protected" here was a runtime proof, which ADR-262 already supersedes in part.
- **Cost:** An extra projection state and generation rules for a min() of three numbers.
- **M/A:** A.
- **Replacement:** The collector watches EvidenceBudgetPolicy and its own Helm config with an informer, and computes `effective = min(nodeHelm, policy)` on each event. Keep the ceilings text (CAP:218–232).
- **Consistency:** `specs/action-lifecycle.md`, `docs/architecture/node-collector.md`.

### S1-19 Circuit breaker by periodic 5-second sampling
- **Where:** CAP:61.
- **Current design:** The breaker trips after three unhealthy 5-second samples and recovers after 60 s healthy.
- **Problem class:** Polling where an event source exists.
- **Cost:** Low CPU, but trip latency is ≥15 s while memory pressure builds.
- **M/A:** A. Storm protection is M.
- **Replacement:** Use Linux PSI triggers (`/proc/pressure/*` with `poll()` thresholds; kernel docs "PSI – Pressure Stall Information", as used by systemd-oomd and Android lmkd), cgroup `memory.events`, and write-error events for scratch. Keep the hysteresis.
- **Consistency:** `docs/architecture/node-collector.md`.

### S1-20 Cross-node per-workload upload rate leases
- **Where:** CAP:57 ("aggregate hierarchical leases so spreading across nodes does not multiply the workload limit"; "Killing/restarting an uploader does not reset its byte-rate lease", SC-CAP-003).
- **Current design:** A global per-workload byte-rate state is coordinated across nodes and persists across restarts.
- **Problem class:** Unbounded coordination fan-out, with per-chunk or per-quantum coordination.
- **Cost:** Each upload quantum needs a lease from the connector or hub, and N nodes multiply that across many uploads.
- **M/A:** Partly M (cross-workload exhaustion protection). The coordination design is A.
- **Replacement:** The connector grants nodes bulk token leases (seconds of budget) per workload, in the Doorman/Envoy global rate-limit style. Lease loss on restart simply forfeits unused tokens, so nothing needs persisting.
- **Consistency:** CAP REQ-CAP-003, `interfaces.md` collector routes.

### S1-21 Processing-history horizon check serialized with configuration and rule writers
- **Where:** CAP:104–114 (ADR-146).
- **Current design:** The admission transaction repeats the coverage check "using the same serialization as processing configuration and rule writers".
- **Problem class:** A shared lock between all admissions and privacy-configuration writers. That is a hot row.
- **Cost:** Every context admission locks the processing configuration root.
- **M/A:** A (privacy-processing records are agent-designed). No AGENTS.md entry.
- **Replacement:** Validate coverage once when the rule or configuration changes, rejecting configurations shorter than the retention maximum (CRD validation or a controller condition). Admission then reads the cached result without a lock.
- **Consistency:** `specs/privacy.md` (REQ-PRV-*), `docs/architecture/retention-*.md`.

### S1-22 Permission assignment continuity across relists
- **Where:** DB:252 ("a relist cannot prove that no intervening ownership change occurred … invalidate uncertain assignment IDs").
- **Current design:** The design requires continuous trusted history for assignment IDs; otherwise it invalidates them on every relist gap.
- **Problem class:** It defends against an A→B→A pattern without external evidence. Watch restarts invalidate assignments, which churns access.
- **Cost:** Access revocation and recomputation after every watch restart or 410.
- **M/A:** A.
- **Replacement:** Key assignments by object UID plus generation and recompute on relist, as every Kubernetes controller does. Retained audiences already bind to original evidence.
- **Consistency:** `specs/permissions*.md` REQ-PER-008, `docs/architecture/permission-observation.md`.

### S1-23 Key-service unwrap slots "irreversible" and per-download bindings
- **Where:** DEP:162 (ADR-066 "one irreversible unwrap slot per physical-object key", "Binding retries and provider errors cannot refill slots"); DEP:158 (Secret UID/digest pin, already superseded in part).
- **Current design:** Each download prepays an audited SQL batch, and each object key can be unwrapped once.
- **Problem class:** Spent-on-uncertain accounting. A transient error makes the download unrecoverable without a new session.
- **Cost:** An SQL transaction per unwrap, plus user-visible failures on retries.
- **M/A:** M: the local key service exists (ADR-063 small deployments) and the hub gets no raw unwrap (AGENTS.md: "wrap-only collectors, no hub raw unwrap"). The slot scheme is A.
- **Replacement:** The key service authorizes unwrap with the download ticket from S1-02 (artifact, session, deadline) and rate-limits per session. Unwrap is idempotent within the ticket's validity.
- **Consistency:** `docs/architecture/download-key-authority.md`, `local-key-service.md`.

### S1-24 Worker PriorityClass/admission specifics and polling readiness
- **Where:** DEP:166–176 (ADR-069 journal plus "verify deletion before releasing worker capacity", "Polling/reconciliation MUST reuse exact acknowledged audit receipts", ADR-070 dry-run probe, ADR-073 control payload digest).
- **Current design:** Readiness is polled (the dispatch doc has "20 observation rounds at 100ms"). An administrator dry-run probe checks configuration, and the actual Job/Pod spec is verified against a digest.
- **Problem class:** Polling, self-verification of installer objects (superseded in part) and per-request Jobs (S1-02).
- **Cost:** About 20 API GETs per download start.
- **M/A:** A.
- **Replacement:** This goes away with S1-02. If Jobs are kept for some purpose, use a Job/Pod watch (informer), not round polling.
- **Consistency:** `docs/architecture/download-worker-*.md`.

### S1-25 ADR-147 OpenBao setup self-verification of provider policies
- **Where:** DEP:212–213 ("Protected setup verifies the complete provider recipes; login, positive renewal and same-token reconciliation verify effective policies").
- **Current design:** On login and renewal the hub reads back its own effective provider policies.
- **Problem class:** Self-verification of installer state (ADR-147 superseded in part).
- **Cost:** Extra OpenBao token lookup and policy reads at each renewal.
- **M/A:** A.
- **Replacement:** A setup Job writes policies idempotently. Runtime uses Kubernetes auth login and renew only, which is the Vault Agent/VSO pattern.
- **Consistency:** `docs/architecture/owner-*` provider docs, chart setup Jobs.

### S1-26 Role split: acquisition vs publication credentials with "fenced encrypted-volume handoffs"
- **Where:** ARC:140, 144.
- **Current design:** Acquisition and publication use different credentials and hand off through fenced encrypted volumes.
- **Problem class:** Bespoke inter-role handoff and extra roles without cited evidence.
- **Cost:** Extra pods and volumes per analysis. ADR-036 requires a qualified encrypted scratch StorageClass.
- **M/A:** Partly M: ADR-036 encrypted scratch for offline analysis (AGENTS.md). The acquisition/publication credential split is A.
- **Replacement:** Keep the analyzer sandbox (no network) as M. Merge acquisition and publication into one regional worker identity unless external evidence supports the split.
- **Consistency:** `docs/architecture/README.md` roles, `specs/analysis*.md`.

### S1-27 Fleet observation heartbeat/expiry and "Fleet freshness" records
- **Where:** FED:7 ("heartbeat summaries are SQL runtime state"), FED:85 (15 s heartbeat / 60 s offline), FED:71–77.
- **Current design:** Each connector heartbeat writes to SQL, and fleet authority uses observation expiry.
- **Problem class:**
  - A periodic SQL write per cluster every 15 s.
  - Fleet authority tied to observation expiry (S1-11).
- **Cost:** N clusters × 4 writes/min. This is modest but is pure churn.
- **M/A:** A. The "last heartbeat visible" requirement is fine.
- **Replacement:** Liveness is the connector's open stream. Record `connected_since`/`disconnected_at` on connection events, and write a last-seen time at most once per minute (OCM ManagedCluster lease, Kubernetes node Lease at 40 s grace).
- **Consistency:** `docs/architecture/fleet-observation.md`, `configuration-reconciliation.md`.

---

## Low

### S1-28 "Local producers keep bounded fenced delivery records" for webhooks
- **Where:** FED:127.
- **Current design:** Cluster-local producers keep their own webhook delivery records alongside the hub outbox.
- **Problem class:** A duplicated outbox per cluster.
- **M/A:** A.
- **Replacement:** Only the hub emits CloudEvents. Connectors forward event facts over their stream, and the hub outbox delivers them.
- **Consistency:** `specs/federation.md` SC-EVT-002.

### S1-29 "Exactly one matching budget policy" with AmbiguousBudgetProfile
- **Where:** CAP:71.
- **Current design:** Overlapping selectors block the workload.
- **Problem class:** An operational foot-gun rather than a scaling problem.
- **M/A:** A.
- **Replacement:** Add a `priority` field with deterministic tie-break (name), as with PriorityClass and Kyverno/Gatekeeper ordering, and report the overlap as a warning condition.

### S1-30 Context-cooldown and suppression windows (positive note plus nit)
- **Where:** CAP:9–11.
- **Current design:** Bounded 30 s aggregation windows, and ADR-228 keeps a fixed suppression row per policy and reason.
- **M/A:** M (capture storms).
- **Assessment:** Sound. The only nit: write suppression counters with debounce or batching rather than on every hit. The spec implies this but does not state it.

### S1-31 ARC REQ-ARC-003 per-message fence/authority fields
- **Where:** ARC:156.
- **Current design:** Every internal message carries a fence, a deadline and resource authority.
- **Problem class:** Generic over-specification. It pushes authority objects into every DTO.
- **Replacement:** Use a fence and operation ID per work item. Authority stays server-side (S1-14).

### S1-32 ARC REQ-ARC-002 "narrow facets" requirement drives credential sprawl
- **Where:** ARC:148.
- **Current design:** Cross-component transactions use narrow facets in the canonical lock order.
- **Assessment:** The architecture rule itself is fine as code structure. It must not imply one SQL credential or pool per facet; see S1-12. Clarify that facets are Go interfaces, not database roles.

### S1-33 Stale pointers to superseded docs in REQ-FED-001 and DB preamble
- **Where:** FED:9 links `enrollment-activation.md`/`bootstrap-channel.md` ("configured secret-channel profile"); DB:242 ("production recovery profile").
- **Problem class:** Obsolete text once S1-03 and S1-07 land.
- **Replacement:** Update the links to the new runbook and enrollment docs.

---

## Cross-file consistency checklist
- Removing the installer/guard text (S1-01, S1-04) touches `specs/traceability.yaml`, `docs/installation/helm.md`, `specs/contracts/initial-*`/`owner-*`/`hub-worker-deployment` schemas, and `docs/architecture/initial-*`, `owner-*` and `fleet-*`.
- Replacing the download/owner chain (S1-02, S1-23, S1-24) touches `specs/artifact-downloads.md`, `evidence.md`, `docs/architecture/download-*`, `worker-*`, `owner-*`, `hub-owner-discovery.md` and DB:398–400.
- Asynchronous audit (S1-05) touches the audit/evidence specs, `custody-transactions.md`, `context-publication.md` and `enrollment-activation.md`.
- Event-driven changes (S1-06, S1-11, S1-19, S1-27) touch `interfaces.md` and the `retention-observation.md`, `permission-observation.md` and `fleet-observation.md` architecture docs.
- Capacity changes (S1-08, S1-09, S1-10, S1-13, S1-20) touch `live-watch.md` REQ-LIV-004, `context-query-capacity.md`, `custody-transactions.md` and `local-start.md`.
