# Spec audit S3 — execution, actions, lifecycle, triggers, targets, assessment, history, profiles

Worktree: /home/phil/Projekte/asservat-specreview (read-only audit). Line numbers refer to current files.

Maintainer anchors used below (AGENTS.md): event-driven/no-polling rule (PR #237, brief rule 1);
"Threat model and security evidence (2026-11-13)" / ADR-328 (trust platform, no guard proofs/UID
pins/journals, every security measure needs external evidence); ADR-311 (one authorization per
operation, 30 s / 60 s); ADR-312; Helm-native install (2026-11-13); "Complexity must pay for itself";
"Authority and invariants" (expiring policy grants for automatic intrusive actions, capture-storm and
cross-workload storage protection, encrypted managed evidence, bounded pcap filters/dynamic peers/
segmented rings, recording saves, live watch, capture profiles, history repeat are maintainer
capabilities and are preserved by every replacement below).

Note: no file in `specs/` mentions ADR-311 or `AuthorityRecheckInterval`; the spec still describes
the stacked five-second observation era throughout.

Severity counts: **high 7, medium 11, low 6** (24 findings).

---

## High

### S3-01 — Trigger detectors are a hub-driven 15 s poll of regional LISTs/GETs
- **Where:** triggers.md:95-116 (restart, "hub polls every active policy every 15 seconds"),
  138-145 (probe: Event LIST per poll), 183-199 (alert: `GET /api/v2/alerts` per poll),
  233-269 (log: per-container `pods/log?sinceSeconds=` GET per poll, window re-read every poll),
  282-305 (resource: metrics LIST per poll). Contradicts own catalogue triggers.md:7, 14
  (CRI tail, Alertmanager webhook). ADR-228 §2 "Polling, no watch"; ADR-241 §9.
- **Current:** hub-api iterates every active policy every 15 s and sends query frames to the
  region, which LISTs Pods/Events, GETs logs per container and pulls Alertmanager; watermarks per
  Pod live in SQL.
- **Class:** polling where event sources exist; chatty per-request reads; periodic full resends;
  hub-side single scheduler.
- **Cost:** ADR-241 itself states ≤512 log GETs per cycle per cluster at the 16-policy cap, ≤64 MiB
  per cycle through API server→kubelet, the connector's 20 req/s limiter stretches the cycle past
  15 s. Restarts between polls coalesce and lose their reasons (triggers.md:105-107); an alert that
  resolves and re-fires between polls is invisible (211-212); log text is re-downloaded every poll
  ("overlong" counts polls, 261-263). Cost grows linearly in policies × pods × containers and adds
  15 s detection latency to every trigger. A 16-policy cap per cluster is itself a symptom.
- **Maintainer requirement?** The detectors and capture-storm protection are maintainer
  capabilities; the polling transport is agent-added (ADR-228/230/241) and violates the
  event-driven rule.
- **Replacement:** the regional connector runs shared informers (one Pod informer per enabled
  namespace or label selector, one Events informer with `reason=Unhealthy` field selector) and
  evaluates restart/probe edges in process on watch events; it pushes only occurrences over its
  existing hub connection. Logs: one `pods/log?follow=true&sinceTime=…` stream per container of
  an armed pod (stern/kubetail/Grafana Alloy `loki.source.kubernetes` use exactly this), or the node
  CRI tail when a node agent exists (Promtail/Vector/Fluent Bit). Alerts: the standard Alertmanager
  v4 webhook receiver (already specified at triggers.md:338) instead of pulling; it also restores
  `resolved` support. Resource: `metrics.k8s.io` has no watch and metrics-server only refreshes
  every 15 s, so a connector-local poll of that one API is the only legitimate remaining poll
  (as KEDA/HPA do). Watermarks stay in memory; SQL keeps only occurrence rows keyed by the
  existing occurrence idempotency key (unique constraint). Resync only on informer relist.
- **Also change:** capacity.md (budget counters fed by pushed occurrences), policy-automation.md,
  apis.md/interfaces.md (query frames 11/12 → occurrence push), federation.md (connector
  responsibilities), targets.md:41 (REQ-TGT-005 "Watch every authorized pod" should say shared
  informer), traceability.yaml (SC-TRG-008/009 "next poll cycle" wording).

### S3-02 — REQ-EXE-002 is a stack of five-second observation leases, proof brackets and per-helper checks
- **Where:** execution.md:31-177 (ADR-212 one-second floor, ADR-135, ADR-171, ADR-216 "at most five
  seconds", ADR-260 target metadata five seconds, ADR-211, ADR-163 transport observation lease,
  ADR-173 work-scoped process observation, ADR-207 proof bracket, "complete native proof" lending,
  "current native workload/settings/input and full source close", "Both remote owner
  authentications remain current"), plus execution.md:74-91 (receipt metadata freshness, ADR-292
  independent five-second phases inside a 15 s request) and capture-history.md:186-193 (ADR-289).
- **Current:** each start reuses multiple distinct short-lived observations (authority, transport
  peer, executor process, target metadata, setup proof), each with its own original cutoff,
  rechecked at every helper/frame boundary; final transfer needs a fresh full peer check.
- **Class:** expiry-driven freshness windows; per-step/per-helper revalidation; self-verification
  of installer/workload state ("native workload" proofs); bespoke transport authentication.
- **Cost:** many SQL/API round trips per start, cascading refusal on any one window expiry,
  several pages of normative text that tests must honour; directly contradicts ADR-311
  (30 s/60 s, one check per operation) and ADR-328 (no runtime re-verification of installer-created
  objects).
- **Maintainer requirement?** No. ADR-311/312 and the 2026-11-13 threat model supersede these.
- **Replacement:** one paragraph: "The hub authorizes a start once (identity, permission, deny,
  retention, capacity) under ADR-311 and reuses it for the operation, never past an original
  deadline. The connector is authenticated by mTLS (cert-manager-issued or hub CA) and its
  Kubernetes ServiceAccount; the region trusts its own RBAC. Target identity (pod UID, PID/start
  time) is checked locally before attach. Effect writes use SQL constraints/idempotency keys."
  Precedent: Kubernetes API server authorizes per request, kubelet trusts its credentials; Argo CD
  and OCM agents authenticate the control-plane connection once per TLS session.
- **Also change:** recording-saves.md, live-watch.md, artifact-downloads.md, authorization.md,
  investigation-approval.md (same five-second idiom), capture-history.md:186-193, mcp.md.

### S3-03 — Ongoing sources renew a ≤30 s authority leaf with full current facts and SQL CAS
- **Where:** action-lifecycle.md:229 (ADR-263), execution.md:15 ("unknown/disconnected change ends
  by its original active leaf plus separately qualified visibility lag"), capture-assessment.md:157-165
  (ADR-261 finite observation: ≤20 s lease, short start bound, "unused/uncertain credit remains
  spent").
- **Current:** every ongoing source renews every ≤30 s; each renewal is a new five-second issuance
  operation requiring exact current policy, delegation/permission, complete deny, recovery,
  retention, target and local process facts, plus expected-credit CAS for positive credit.
- **Class:** expiry-driven lease forcing re-reads; per-step revalidation; spent-on-uncertain
  accounting.
- **Cost:** sources scale with the **observation** pod set (up to 1,000 pods/policy, targets.md:41)
  × ongoing actions; e.g. 1,000 pods × 2 recorders = ~67 full authorization evaluations plus SQL
  locks per second per policy just to keep quiet recorders alive. A hub/SQL hiccup longer than the
  leaf stops all recording fleet-wide and resets coverage (Warming), destroying exactly the
  pre-trigger history the feature exists for.
- **Maintainer requirement?** Expiring policy grants for automatic intrusive actions are
  maintainer; the renewal leaf and its interval are explicitly "an agent engineering choice"
  (ADR-263 text).
- **Replacement:** sources run until the accepted hard end (policy grant expiry, observation budget,
  administrator ceiling). Revocation is event-driven: policy pause/delete, AccessBinding or deny
  changes arrive via watch/LISTEN-NOTIFY at the hub, which pushes `stop(sourceSessionID)` over the
  connector connection; the connector also watches in-region AccessBindings (ADR-329) itself.
  Disconnect handling: one fixed connection-liveness timeout after which the connector stops
  sensitive sources (Kubernetes node Lease / Argo CD agent heartbeat pattern), not per-source
  authority renewal. Observation budgets are counted locally and reported in batches; charge
  actual consumption, not prepaid uncertain credit.
- **Also change:** packets.md, syscalls.md, capacity.md (credit/CAS), live-watch.md, recording-saves.md
  (stopped-source grace), docs ADR-261/263 supersession.

### S3-04 — Policy submissions carry a private JWS signature, intent versions and collection-intent digests
- **Where:** execution.md:9, 21-23 (source collection-intent digest, "persisted monotonic intent
  version fences observed changes and missed spec generations", ADR-062 post-persistence JWS with
  dedicated OpenBao Ed25519 key, "compiler/signature acceptance boundary remains mandatory").
- **Current:** after a DebugPolicy is persisted in Kubernetes, the hub signs a private intent,
  verifies it against Kubernetes-published public-key trust, and fences missed generations with a
  separate monotonic SQL version.
- **Class:** bespoke crypto/self-verification of platform state; duplicated identity of the same
  fact (generation, intent version, submission digest, source-intent digest).
- **Cost:** extra KMS signing per submission, a second version counter that must be reconciled
  with `metadata.generation`, OpenBao Ed25519 key lifecycle; no external evidence of benefit — the
  writer is already authenticated and audited by the API server.
- **Maintainer requirement?** No (agent ADR-062). Kubernetes-only permission configuration and
  approval for intrusive policies are maintainer and remain.
- **Replacement:** the standard controller pattern: reconcile on watch events, record
  `status.observedGeneration`, compute the resolved collection execution digest for approval reuse
  (keep that one — it is what lets label/sharing edits keep approval). Actor provenance comes from
  `metadata.managedFields`/Kubernetes audit log for GitOps writes and from the authenticated hub
  session for browser/MCP writes. Precedent: every Kubernetes controller (Deployment, cert-manager
  Certificate, Argo CD Application) uses generation/observedGeneration; none signs its own CRs.
- **Also change:** policy-automation.md, permissions.md, persistence.md, contracts/
  (submission envelope schemas), traceability.yaml.

### S3-05 — Pre-work target queries on exclusive idle standbys (bespoke outbound transport)
- **Where:** execution.md:52-61, 93-127 (ADR-179 standby target queries, ≤8 queries per exchange,
  "Queries exclusively reserve their standby until completion; capture attachment cannot
  interleave", ADR-211 socket deadline return, ADR-163 transport observation lease).
- **Current:** each region parks idle standby sockets; the hub borrows one exclusively for a
  query exchange or a work item; signed references are attached to a live human request;
  disconnect never retries.
- **Class:** bespoke protocol; serialisation/single-writer bottleneck; chatty per-request reads
  (preview resolves target by live API reads in the region).
- **Cost:** concurrency bounded by the number of parked standbys; previews, policy polls (S3-01)
  and capture starts compete for the same exclusive sockets; head-of-line blocking; complex
  deadline-return rules.
- **Maintainer requirement?** Outbound-only connectivity from regions is a reasonable deployment
  property; exclusivity, standby lifecycle and per-exchange limits are agent-added.
- **Replacement:** one long-lived multiplexed connection per connector (gRPC bidirectional stream
  or HTTP/2 reverse tunnel) carrying many concurrent request/response streams with per-stream
  deadlines — the pattern of OCM klusterlet/cluster-proxy (apiserver-network-proxy/konnectivity),
  Rancher remotedialer, Karmada pull mode and the Argo CD agent. Target metadata for previews comes
  from the connector's informer cache (S3-01), pushed or served from memory, not live LISTs.
- **Also change:** federation.md, interfaces.md, apis.md, implementation-architecture.md, mcp.md
  (preview latency).

### S3-06 — Capture history stores 128 KiB parameter snapshots as encrypted regional object records with four-object receipts
- **Where:** capture-history.md:217, 221-223, 247-252 ("encrypted, scope-bound regional object
  records", "acknowledged four-object receipts", "reads verify encryption, manifest/commit and HMAC",
  "unknown writes and physical storage stay charged until typed writer/deletion completion and
  actual matching-prefix inventory").
- **Current:** every accepted capture synchronously writes an encrypted evidence-style object set
  in the regional object store, charged to quotas and reconciled through custody/inventory cleanup.
- **Class:** synchronous object-store custody on the hot path for control metadata; duplicated
  custody/ledger machinery; spent-on-uncertain.
- **Cost:** ≥4 object PUTs + KMS key wraps + SQL receipts per capture (including automatic policy
  occurrences — trigger storms multiply it), plus inventory scans for cleanup. Parameter records are
  ≤128 KiB control data, not evidence.
- **Maintainer requirement?** History/repeat is maintainer; "no unencrypted managed evidence
  storage" covers evidence. The object-record layout is agent-added (ADR-255).
- **Replacement:** store the snapshot in PostgreSQL next to the accepted capture row as an
  application-encrypted `bytea` (AEAD under the hub data key, like Grafana/Sentry encrypt secrets
  and integration configs in their DB), with `expires_at` and deletion by ordinary row delete in a
  periodic retention sweep. Keyed HMAC selector/settings digests stay as index columns. Atomic with
  acceptance; no receipts, inventory or uncertain charges.
- **Also change:** persistence.md, privacy.md (REQ-PRV-008 backup deletion applies to DB backups
  already), capacity.md (history quota), mcp.md (get_capture_settings).

### S3-07 — Installer/guard-era bindings remain normative in execution start
- **Where:** execution.md:179-189 (`apiContextStart/v1` "binds the protected executor
  Pod/account/process", "original Kubernetes UID/CAS precede capture", "Each installation control
  namespace has its own start admission match plus independent namespace UID checks"),
  execution.md:139-166 (connector observation "checked by its complete native proof", "current
  native workload/settings/input"), execution.md:168-177 (diagnostic stage codes for those proofs).
- **Class:** specs describing the removed installer/guard era; defending against trusted actors
  (Asservat namespace writers).
- **Cost:** keeps UID pins, admission-match proofs and native workload proofs alive in code and
  tests; each start pays the extra reads.
- **Maintainer requirement?** Explicitly rejected (2026-11-13 threat model, ADR-328, Helm-native
  install).
- **Replacement:** delete; the executor is a Helm-rendered Deployment whose identity is its
  ServiceAccount/TLS certificate. The local CapacityReservation can remain an ordinary object
  written with resourceVersion optimistic concurrency where it is genuinely needed.
- **Also change:** federation.md, deployment-profiles.md, implementation-architecture.md, and
  AGENTS.md implementation notes pointing to these ADRs (maintainer-owned; flag only).

---

## Medium

### S3-08 — Execution preparation uses a one-second floor and "passive no-create uncertainty" instead of idempotent resume
- **Where:** execution.md:33-50, 198-207 (SC-EXE-002).
- **Current:** preparation refuses with <1 s left; an existing prepared row whose interval expired
  stays permanently "no-create uncertainty"; a "fresh continuation" may become the first winner.
- **Class:** exactly-once / spent-on-uncertain where idempotency keys suffice.
- **Cost:** captures wedge in an uncertain state after a slow lock; users must create a new capture.
- **Maintainer?** No (ADR-212).
- **Replacement:** execution row keyed by (captureUID, actionID, attempt) with
  `INSERT … ON CONFLICT DO NOTHING RETURNING`; the connector start is idempotent by the same key, so
  a retry either finds the started work or starts it once. Keep "never auto-retry an intrusive start
  with unknown outcome" (actions.md:34) only for process-affecting actions. Precedent: Stripe/AWS
  idempotency keys, Kubernetes `generateName`+ownerRef adoption.
- **Also change:** capacity.md, persistence.md, traceability.yaml SC-EXE-002.

### S3-09 — policyAuthority pins delegation UID/generation/digest and exact assignment IDs
- **Where:** execution.md:13; also 15 (resume "rechecks current authority").
- **Current:** each accepted policy embeds the delegation's UID/generation/digest and sponsoring
  assignment IDs; any change requires fresh acceptance.
- **Class:** UID pins of platform objects; brittle identity → spurious invalidation (an unrelated
  edit of the AccessBinding bumps generation).
- **Maintainer?** Team-policy automation and expiring grants are maintainer (ADR-059); exact
  UID/generation pins are agent-added; ADR-329 now makes AccessBindings ordinary namespace objects.
- **Replacement:** bind the policy to the delegation by namespace/name and the resolved scope
  digest of the fields that matter; evaluate the current binding on its watch events (event-driven
  revocation, S3-03). Precedent: RoleBinding → Role resolution in Kubernetes RBAC is by name, re-
  evaluated on change.
- **Also change:** policy-automation.md, permissions.md, authorization.md.

### S3-10 — Natural-core path pre-provisions single-use prewrapped envelopes under durable audited permits
- **Where:** actions.md:94-98.
- **Current:** a pool of single-use prewrapped encryption envelopes and prepaid storage reservations
  per node, each a durable audited permit; lost entries after restart are never reused or refunded.
- **Class:** per-artifact KMS/audit on a pre-provisioning path; spent-on-uncertain ledger.
- **Cost:** constant background KMS + audit traffic per node to keep pools full; leakage of
  capacity on every collector restart; complex pool state.
- **Maintainer?** Encrypted evidence and no-wait crash path are maintainer-compatible; the envelope
  pool/audit design is agent-added.
- **Replacement:** node collector holds a KMS-wrapped data-encryption key with bounded lifetime/
  usage count and derives per-core keys locally (AWS Encryption SDK data-key caching, Vault transit
  `datakey`, Tink keyset rotation); capacity is a local token bucket reconciled with the hub by crash
  ID idempotency after restart. Audit the core once at upload/registration.
- **Also change:** capacity.md, evidence.md, profiles.md (runtime dumps), privacy.md.

### S3-11 — Recording-save and grouped manual dispatch is serial within a 15 s original interval
- **Where:** execution.md:237-241 (ADR-269 "serial child dispatch", admission observations "retain
  their original five-second freshness", audit dates selected once).
- **Class:** serialisation; deadline stacking; per-group synchronous audit before dispatch.
- **Cost:** latency linear in selected sources (up to the incident cap); late children miss their
  window because earlier ones consumed the shared 15 s.
- **Maintainer?** Save existing recordings is maintainer; serial dispatch and five-second windows
  are agent-added.
- **Replacement:** authorize once (ADR-311), then dispatch children concurrently with bounded
  fan-out (errgroup with limit); audit asynchronously from the accepted SQL row (outbox).
- **Also change:** recording-saves.md, capacity.md.

### S3-12 — Authority/target revalidation "before every attach" conflates authorization with target identity
- **Where:** execution.md:194 ("revalidate identity, authority, current grant, source freshness and
  capacity"), actions.md:153 ("Revalidate before every attach"), targets.md:15, action-lifecycle.md:225.
- **Class:** per-step revalidation.
- **Cost:** for a 64-process batch or 1,000-pod arming, N authority evaluations instead of one.
- **Maintainer?** PID-reuse safety is a genuine correctness requirement (keep); per-attach authority
  checks are superseded by ADR-311.
- **Replacement:** state explicitly: authorization once per operation (ADR-311); before each attach
  only a local identity check (pod UID, host PID + start time, boot ID) — no hub round trip.
- **Also change:** capacity.md, syscalls.md, packets.md.

### S3-13 — Assessment is re-evaluated at preview, submission, source arming and intrusive dispatch with a 60 s metric freshness
- **Where:** capture-assessment.md:98; execution.md:231.
- **Class:** expiry-driven freshness; duplicated enforcement (admission ceilings already enforce).
- **Cost:** extra metric reads and rule evaluation on the arming/dispatch hot path for an advisory
  projection; preview refreshes forced by metric age.
- **Maintainer?** The assessment panel is maintainer; re-evaluation points and windows are agent.
- **Replacement:** compute at preview and submission only; arming/dispatch rely on admission
  ceilings and circuit breakers (already stated in the same paragraph). Show metric age instead of
  invalidating at 60 s.
- **Also change:** capture-profiles.md:317, capture-history.md:207 (wording only).

### S3-14 — Stopped-source grace adds a retired-session state machine and its own tuning knobs
- **Where:** action-lifecycle.md:199 (eight source states), 249-255 (retired sessions: 2/workload/
  node, 32/node, grace 30 s default/60 s ceiling, local collector configuration).
- **Class:** duplicated state machines; configuration that only tunes its own machinery (complexity
  item 7).
- **Maintainer?** Delayed-exit preservation is valuable but agent-added; counts/knobs are agent.
- **Replacement:** keep the ring after target loss for a fixed grace (30 s) inside the existing
  per-node ring byte budget; evict oldest unreferenced ring under pressure. Drop retired-session
  counts and their configuration; states reduce to Arming/Recording/Stopped(grace)/Gone.
- **Also change:** recording-saves.md, live-watch.md, capacity.md.

### S3-15 — Alert episode tombstone store is both required and declared absent
- **Where:** triggers.md:336-340 (bounded durable episode dedup/tombstones, suppress replay when
  forgotten) vs 189-190 ("No hub endpoint, receiver credential or episode tombstone store exists");
  triggers.md:14 webhook vs pull.
- **Class:** spec inconsistency; ledger duplicating the occurrence key.
- **Replacement:** with the webhook (S3-01), dedupe by the occurrence idempotency key
  (receiver, fingerprint, startsAt) as a SQL unique constraint with the occurrence row's own
  retention; no separate tombstone cache. Precedent: Alertmanager receivers (PagerDuty `dedup_key`,
  Grafana OnCall) dedupe by fingerprint.
- **Also change:** capacity.md (suppression), apis.md.

### S3-16 — History listing reauthorizes every row and binds cursors to authorization revisions
- **Where:** capture-history.md:215, 231, 250 ("every row is reauthorized", cursors bind identity
  groups/scopes, permission revision, ≤200 rows examined).
- **Class:** N+1 authorization; cursor invalidation by unrelated permission changes.
- **Replacement:** resolve the caller's authorized selector/namespace set once per request
  (ADR-311), filter in SQL (`WHERE selector_key = ANY($authorized)`), keyset pagination on
  (accepted_at, capture_id); cursor binds only caller and query. Precedent: Grafana/Sentry/GitLab
  filter list queries by membership rather than per-row checks.
- **Also change:** mcp.md, authorization.md.

### S3-17 — Two canonicalization schemes for digests
- **Where:** execution.md:17 (own scope/v1 rules, "Production Go/controller/admission and client
  compatibility fixtures must agree byte-for-byte", Python validator) vs execution.md:21 (RFC 8785);
  capture-profiles.md:277, 307.
- **Class:** bespoke canonicalization; duplicated validators.
- **Replacement:** RFC 8785 JCS everywhere, one Go implementation; clients never compute hashes
  (execution.md:19 already says so), so drop the client byte-for-byte requirement and the Python
  scope checker.
- **Also change:** contracts/ schemas, capture-profiles.md, investigation-approval.md,
  recording-saves.md.

### S3-18 — Capture-profile source UIDs and "propagated to relevant clusters" status
- **Where:** capture-profiles.md:275, 277 (resolver binds namespace/profile UIDs; publisher status
  "accepted, catalog-visible and propagated"); execution.md:217, 221 ("source replacement changes
  scope even if recipe bytes match", "connected revocation/disconnected permit bounds").
- **Class:** UID pins; extra propagation state machine; definition digest already identifies content.
- **Replacement:** identity = (catalog, name, version, definition digest); hub reads profiles via an
  informer cache (valid until replaced, event-driven), checks availability at start from that cache.
  Profiles are compiled on the hub, so no per-cluster propagation status is needed. Keep source
  object reference as provenance only.
- **Also change:** ergonomics.md, guidance.md, capture-history.md:258.

---

## Low

### S3-19 — Encrypted in-memory rings with ephemeral per-ring keys
- **Where:** actions.md:84.
- **Class:** security measure without cited external benefit (key co-resident in the same process).
- **Replacement:** plaintext ring in mlock'ed collector memory; encrypt when bytes leave memory
  (spool/upload) under artifact keys, which already satisfies encrypted managed storage. Keep if a
  source (e.g. memory-scraping threat guidance) is cited.
- **Also change:** packets.md, syscalls.md.

### S3-20 — Execution charges "spent at admission and never refunded" for context-only captures
- **Where:** triggers.md:110-113; actions.md:157.
- **Note:** charging uncertain **process-affecting** starts is a sound storm protection (maintainer
  capability). For the pod-status context recipe, charge by occurrence idempotency key and refund on
  definite pre-start refusal. Low.
- **Also change:** capacity.md.

### S3-21 — Opening-diagnostics catalogue for removed proof stages
- **Where:** execution.md:168-177.
- **Class:** obsolete text; bespoke exponentially-suppressed event-count key.
- **Replacement:** ordinary structured logs/metrics with stage label; delete with S3-07.

### S3-22 — Preview composition window (ADR-289) and phase bounds
- **Where:** capture-history.md:186-193; execution.md:84-91.
- **Class:** deadline stacking (15 s outer, 5 s per stage, no-renew rules).
- **Replacement:** one request context deadline (standard Go `context.WithTimeout`) and ADR-311
  authority reuse. Fold into S3-02 rewrite.

### S3-23 — Log fallback "Kubernetes pods/log degraded fallback, implemented as a bounded poll"
- **Where:** triggers.md:7, 47, 264-267.
- **Note:** even without a node agent the API supports `follow=true` streams; coverage limitations
  (restarted instance missed) disappear for followed streams. Covered by S3-01; listed so the
  catalogue row and REQ-TRG-003 fallback text are updated.

### S3-24 — Peer follow-mode resolution timing unspecified
- **Where:** targets.md:31-37.
- **Note:** not polling today, but say explicitly that follow mode uses EndpointSlice/Pod informers
  on the connector and pushes filter generations to the node collector (Cilium/Hubble pattern),
  so implementers don't add a resolution poll.
- **Also change:** packets.md.

---

## Items checked and kept (no finding)
- Bounded expression language, CEL leaves, RE2, admission limits (triggers.md:23-31) — standard.
- Three-valued detector logic and rearm semantics (triggers.md:33-41, 79-91) — correctness.
- Immutable profile versions, no template language, compile-to-one-recipe (capture-profiles.md) —
  maintainer requirement, simple.
- Whole-pod scope without container selectors (targets.md:5-7, 51-61) — maintainer decision.
- Collection execution digest that survives label/sharing/grant-handle edits (execution.md:10) —
  keeps approvals stable; justified.
- Natural-crash local admission without remote wait (actions.md:94; action-lifecycle.md:185) —
  necessary; only the envelope/audit pool (S3-10) is excessive.
- Gadget digest pinning (actions.md:80) — supply-chain best practice (SLSA/image digest pinning).
