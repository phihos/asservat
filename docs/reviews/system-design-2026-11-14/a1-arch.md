# A1 — Architecture docs audit (api-context-execution.md … context-request-resolution.md, README.md, components.md)

Worktree: `/home/phil/Projekte/asservat-specreview` @ `f9ccd35b`. Read-only audit; no repository file edited.
Paths below are relative to `docs/architecture/` unless stated. Line numbers refer to that commit.

Scope read: api-context-execution, api-context-runner, applications, artifact-format, bootstrap-channel,
bootstrap-issuance, bootstrap-reservation, browser-sessions, build-or-reuse, capacity-production,
capture-intent-lifecycle, cluster-observations, code-organization, components, configuration-credential-provisioning,
configuration-reconciliation, connector-credentials, connector-pki, connector-renewal, connector-retirement,
console-runtime, context-admission, context-assessment, context-capability, context-cases, context-case-transport,
context-control-capacity, context-deletion, context-download-control, context-download-result,
context-evidence-workflow, context-execution, context-investigation, context-native-content, context-native-read,
context-operations, context-progress, context-projection (sections 79–506 in detail, rest by grep),
context-publication, context-query-capacity, context-request-resolution, README. `catalog.yaml` (not .md) grepped only
for installer-era IDs.

Severity counts: **High 11, Medium 9, Low 5** (25 findings) + deletion/rewrite list (§B).

Maintainer-requirement legend (from AGENTS.md "Authority and invariants", "Security proportionality", "Threat model"):
M-native = native download of all evidence; M-storm = capture-storm / cross-workload storage-exhaustion protection;
M-ret = administrator-enforced maximum retention; M-311 = one authorization per operation reused 30 s / 60 s;
M-312 = started downloads run to original bounds; M-328 = Asservat namespaces admin-only, platform trusted;
M-helm = Helm-native install, no installer Pod/guards; M-reads = stored-evidence reads not gated by live workload capacity
(memory 2026-10-23). Everything else cited below is agent-authored (ADRs are not evidence per rule 2).

---

## A. Findings

### A1-01 (High) Remote workload metadata fetched per operation through a HWORK→holder→connector proof chain
- **Where:** cluster-observations.md:1-621 (esp. 21-27, 57-64, 110-195, 197-245, 583-621); capacity-production.md:140-156;
  configuration-reconciliation.md:77-84; connector-renewal.md:25.
- **Current design:** Each hub observation of a remote cluster's namespaces/workloads goes HWORK H → exact owner A
  (which holds a standby stream from connector R) → R, bracketed by "native" proofs (TokenReview, Pod/ReplicaSet/Deployment
  chain, guard policy reads, dry-run denial probes) before and after every one of four numbered source reads, plus two
  SQL "pairs". Measured: 28 observer + 6 probe API calls per operation (~1.4 s each), 50 + 12 per regional operation;
  connector enrollment targets 68 + 12. Everything must fit a 5 s window that the doc says is still unqualified.
- **Class:** chatty per-request reads; bespoke protocol; self-verification of installer state; defends trusted actors;
  polling-equivalent (pull per question instead of watch).
- **Cost/scaling:** O(operations × ~60 API calls) on both API servers; latency 1.4–4.5 s per question; availability
  failures already recorded (native deadline failure, line 19). Grows linearly with workloads × refreshes × clusters.
- **Maintainer req?** No. Central multi-cluster management is required; this mechanism (ADR-144/150/157) is agent-added.
  Guard/proof parts contradict M-328 and M-helm.
- **Replacement:** Connector runs shared informers (namespaces + workloads/Pods filtered to opted-in namespaces) and
  pushes minimized deltas over its existing outbound authenticated hub connection; hub upserts a SQL projection keyed by
  (cluster, UID, resourceVersion). Full resync only after reconnect/watch restart or digest mismatch. Cached state stays
  valid until replaced. Precedent: OCM klusterlet status feedback for ManifestWork, Karmada work-status controller,
  Argo CD cluster cache (watch-based), Rancher cattle-cluster-agent.
- **Change consistently:** capacity-production.md, context-investigation.md, workload-target-resolution.md,
  regional-context-start.md, connector-renewal.md, applications.md (A-CONN row), specs/federation.md, specs/targets.md,
  specs/capacity.md, ADR-144/150/157.

### A1-02 (High) Configuration sources polled every second under five-second expiry; global single-active FIFO
- **Where:** configuration-reconciliation.md:26-30, 50-92; browser-sessions.md:53-57; context-capability.md:17-24;
  capacity-production.md:59-71.
- **Current design:** `ConfigurationReconciler` re-reads fleet/owner ConfigMaps serially with a 1 s delay after each
  completion; each observation expires after 5 s and failure fences/disables the root. The ADR-149 candidate puts five
  purposes into one FIFO with "only one globally active"; per-HWORK budget 140 QPS (280 for two processes). The browser
  settings observer and capability source use the same expiring-observation pattern.
- **Class:** polling where watches exist; expiry-driven freshness; global serialization; config that tunes its own
  machinery (QPS/burst per client).
- **Cost/scaling:** constant API load regardless of change rate; any 5 s API blip disables login/collection; the FIFO
  caps throughput at one source operation at a time; recorded failure at 20 QPS (line 86).
- **Maintainer req?** No (ADR-061/091/149, agent). Contradicts standing rule 1.
- **Replacement:** mount ConfigMaps (kubelet refresh) or controller-runtime informer; validate on change, write SQL
  projection on event, keep it valid until replaced; resync on watch restart. No per-observation deadline, no FIFO.
  Precedent: controller-runtime informers; Prometheus/Grafana/Loki reload on mounted-file change (fsnotify/configmap-reload).
- **Change:** browser-sessions.md, context-capability.md, capacity-production.md, fleet-observation.md,
  owner-configuration.md, specs/persistence.md, ADR-061/091/149/155.

### A1-03 (High) Workload storage-binding freshness (30 s projection, 1 s margin, refresh-demand queue, 250 ms polling)
- **Where:** capacity-production.md:59-97, 293-301; context-investigation.md:110-158; context-admission.md:3-11.
- **Current design:** Admission needs the workload's storage binding observed within 30 s; discovery revisits a
  workload "once per pass, which takes minutes". Preview/request therefore enqueue a refresh demand, wait, and poll SQL
  every 250 ms for a binding with ≥1 s remaining; a cold preview retries once more (ADR-200/213/314). Fifty lines of
  context-investigation describe the wait's interaction with authority cutoffs.
- **Class:** expiry-driven freshness forcing re-reads; timer polling; fallback/degraded states (thin, expired,
  demand-spent, retry).
- **Cost/scaling:** extra latency per request; a demand lane in HWORK; complexity in every request path; one more source
  of "NotAvailable" under load.
- **Maintainer req?** No (agent ADRs). M-storm only needs per-workload quotas, not observation freshness.
- **Replacement:** binding is SQL state maintained from the informer events in A1-01 (created/updated/removed when the
  workload or its allocation changes); admission reads it under normal MVCC/row checks. No readiness wait, no demand
  queue. Precedent: kube-scheduler/controllers act on informer cache, not fresh GETs.
- **Change:** context-investigation.md, capacity-production.md, context-control-capacity.md, specs/capacity.md,
  ADR-200/213/314.

### A1-04 (High) Synchronous encrypted object-store audit (intent/outcome pairs) on every effect and read
- **Where:** capture-intent-lifecycle.md:1-100 (whole); context-admission.md:43-47; context-publication.md:7;
  context-deletion.md:69-91; context-native-content.md:92-98; context-projection.md:450-506;
  context-query-capacity.md:51-60; context-cases.md:113-118; context-case-transport.md:45-47;
  bootstrap-issuance.md:5-7; connector-renewal.md:17; components.md:44, 66-71.
- **Current design:** Each capture writes an encrypted intent object and outcome object to S3 (KMS wrap), verified by
  GET/unwrap ("two irreversible exact GET/unwrap claims per phase"), acknowledged by a separate SQL role, then retired by
  purger/verifier/finalizer credentials with "H-backed cooling"; capture admission alone pins eight SQL logins
  (capture-intent-lifecycle.md:9). Every query invocation **and every poll** gets its own intent/outcome audit
  (query-capacity.md:53-55 counts `2*(1+PollLimit)+2+SigningAttempts` objects per query); every download preflight,
  verification, deletion and certificate gets one. Disclosure is blocked until acknowledgement.
- **Class:** synchronous encrypted audit + KMS on hot path; duplicated journals/receipts/ledgers for one fact;
  "spent on uncertain" audit writes.
- **Cost/scaling:** ≥2 S3 PUT + 2 GET + KMS calls + 3–4 SQL transactions per operation before the user sees a result;
  object count grows with polls; a separate lifecycle (purge, verify, finalize) per audit object; audit/S3 outage blocks
  all reads.
- **Maintainer req?** An audit trail is spec-level (REQ-AUT-005) and "creators remain immutable audit actors" is a
  maintainer decision; the encrypted per-operation object protocol, acknowledgement roles and pre-disclosure gating are
  agent-added.
- **Replacement:** append-only audit rows written **in the same PostgreSQL transaction** as the effect/decision (atomic,
  no acknowledgement protocol, no uncertain state), with INSERT-only grants; optional asynchronous batched export via the
  existing outbox to object storage/SIEM. Retention by partition drop. Precedent: Kubernetes audit backends (batched
  log/webhook, async), GitLab audit events (DB table + streaming), Sentry/Grafana audit logs.
- **Change:** operation-audit*.md, components.md (C-08), context-publication.md, context-deletion.md,
  context-native-content.md, context-projection.md, context-query-capacity.md, specs/persistence.md, specs/privacy.md,
  specs/authorization.md (REQ-AUT-005), ADR-132/134.

### A1-05 (High) A Kubernetes Job (with its own enrollment, certificate and key slots) per download and per query
- **Where:** applications.md:63, 93-95; context-download-control.md:22-59; context-native-content.md:25-64;
  context-download-result.md:1-105; context-projection.md:140, 359-366, 372-406; context-query-capacity.md:41-60,
  168-197, 216-228; context-evidence-workflow.md:40-43.
- **Current design:** `prepare_artifact_download` and every approved query (even 14 lines of pod status) dispatch an
  acquisition Job; the Pod enrolls (TokenReview + Pod proof + CSR, 20-minute signing period), gets one-use unwrap slots
  per batch, then results relay back through two HTTP/2 hops. The client polls (same-key prepare continuation; "Check
  result" button). `context-download-result.md` exists solely to keep metadata after the 5 s first-response lease
  expires. Installed runs failed because Job + enrollment + unwraps did not fit 5 s, then 20 s (query-capacity 168-197).
- **Class:** per-request Jobs; design cannot scale; bespoke enrollment; client polling.
- **Cost/scaling:** seconds of scheduling/image start per read; API-server and kubelet load O(reads); per-read SQL rows
  for worker, enrollment, certificate, key slots, retirement proofs.
- **Maintainer req?** M-native requires native downloads; M-reads requires reads independent of workload capacity.
  Per-request Jobs (ADR-219/221) are agent-added.
- **Replacement:** a long-running regional **reader Deployment** (HPA-scaled, Restricted, own unwrap credential) that
  serves range reads and bounded projections; hub forwards an authorized request (or signed short ticket) over the
  existing connector connection and streams the response. Keep Jobs only for offline analysis (A-ANALYZE) where parser
  isolation justifies them. Precedent: Loki/Tempo/Pyroscope queriers and Thanos store gateway read encrypted/compacted
  object-store blocks from long-running pods.
- **Change:** download-worker-*.md, worker-*.md, native-exchange.md, native-owner-listener.md, context-projection.md,
  context-query-capacity.md, specs/artifact-downloads.md (REQ-DLD-003 Job mode), specs/execution.md, ADR-219/221/307.

### A1-06 (High) Bespoke connector bootstrap/enrollment/PKI with per-process 30-minute certificates
- **Where:** bootstrap-channel.md (whole), bootstrap-reservation.md (whole), bootstrap-issuance.md (whole),
  connector-credentials.md (whole), connector-pki.md:5-9, connector-renewal.md (whole), connector-retirement.md (whole).
- **Current design:** Bootstrap secret in OpenBao KV with a 5-minute deadline and 5 s current authority, issuance-intent
  encrypted audit, separate SQL roles for reservation/recording/ack/activation; connector certificates expire 30 minutes
  after claim with one-minute renewal; every process (Pod UID + process epoch) is a separate SQL identity in five tables
  with six SQL logins, per-attempt encrypted audit, retirement "tickets" with 2100 s retention arithmetic; admission
  re-proves the Pod/ReplicaSet/Deployment chain and workload protection.
- **Class:** bespoke enrollment/PKI where standard TLS bootstrap suffices; journals/receipts duplication; defends
  against trusted cluster admins/namespace writers (M-328).
- **Cost/scaling:** a certificate signing + audit + several SQL transactions per connector process every ~29 minutes;
  dependence on OpenBao PKI availability every 30 min; enormous qualification surface (real-time 65-minute tests).
- **Maintainer req?** No. Central multi-cluster management is required; mechanism is agent-added (ADR-052/126/153).
- **Replacement:** one per-**cluster** identity: administrator creates a registration with a one-time bootstrap token
  (shown once, stored hashed in SQL); connector Helm install supplies it; connector exchanges it for a client cert via CSR
  and renews over the authenticated connection at ~2/3 lifetime (e.g. 30-90 days); revocation = disable registry row
  (checked at connect). Process restarts reuse the cluster Secret. Precedent: kubelet TLS bootstrapping + client cert
  rotation; OCM klusterlet registration (bootstrap kubeconfig → CSR → rotation); cert-manager for hub CA.
- **Change:** enrollment-activation.md, enrollment-claims.md, peer-identity.md, fleet-administration.md,
  fleet-observation.md, components.md (C-04 row), build-or-reuse.md (C-04), specs/federation.md, ADR-051/052/126/153.

### A1-07 (High) Global serialization on the permission-root (and recovery) row
- **Where:** context-admission.md:37; context-progress.md:120-127, 158-163; context-request-resolution.md:99, 120;
  context-deletion.md:52-55; context-publication.md:9; capture-intent-lifecycle.md:11; context-control-capacity.md:24-25;
  browser-sessions.md:59 (session root).
- **Current design:** Admission, verification, publication, deletion, progress **reads**, request resolution and the
  30 s deadline sweep all lock recovery → permission root → pool → allocation → … in a fixed order. Admission
  "serializes a hard ceiling of 1024 retained capture records" at the root (now per-workload, but root lock remains).
  Browser login capacity and logout serialize at the session root.
- **Class:** global lock / single-writer bottleneck; locks on read paths.
- **Cost/scaling:** installation-wide throughput bounded by one row lock; long transactions (with post-lock rechecks)
  stall all users; read polling contends with writes.
- **Maintainer req?** No (agent). M-storm wants per-workload isolation, which a global lock works against.
- **Replacement:** progress/catalog reads as plain MVCC SELECTs; per-workload/per-allocation row locks for quota checks;
  permission changes detected by optimistic revision comparison (`WHERE revision = $n`) or SERIALIZABLE retry instead of
  a shared root lock. Precedent: Kubernetes resourceVersion optimistic concurrency; PostgreSQL guidance on row-level
  vs. hot-row contention.
- **Change:** specs/persistence.md (canonical lock order), components.md:73, all context-* SQL facets, capacity-production.md.

### A1-08 (High) Five-second observation windows plumbed through every read and socket write (contradicts M-311)
- **Where:** context-investigation.md:30-32; context-operations.md:73-86; context-cases.md:46-53;
  context-case-transport.md:23-26; context-capability.md:19-20; browser-sessions.md:28-35; context-projection.md:337-351;
  context-query-capacity.md:91-102, 168-197; connector-pki.md:5; bootstrap-channel.md:7; context-download-result.md:62-68.
- **Current design:** Each request carries an "original at-most-five-second" identity/permission/recovery `ValidUntil`
  that bounds every lock wait, key operation, encoding and the socket write; the shortest of several observations wins
  and a later check cannot restore it. Installed runs failed when Job/unwrap work exceeded 5 s; patched by a separate
  20 s evidence window plus five-second key permits.
- **Class:** expiry-driven freshness; per-step revalidation; fallback states.
- **Cost/scaling:** spurious refusals under normal latency; spent polls/keys on expiry; large proof plumbing.
- **Maintainer req?** M-311 explicitly says: one authorization per operation, reused ≤30 s (60 s policy). The 5 s
  windows are older agent choices the maintainer has superseded.
- **Replacement:** authorize once per operation (ADR-311), keep the decision for the operation's duration (≤30 s), use
  ordinary HTTP server/request timeouts for I/O; drop `ValidUntil` propagation into encoders/sockets.
- **Change:** current-request-identity.md, console-runtime.md, mcp-runtime.md, specs/authorization.md, specs/mcp.md,
  ADR-214/216/260/300.

### A1-09 (High) Per-chunk/per-frame authority leases in streaming paths (contradicts M-312)
- **Where:** artifact-format.md:74 ("each [≤1 MiB chunk] checks the application's exact current permit … independently
  refreshes the at-most-five-second authority lease"); context-native-content.md:100-106 ("each write still installs its
  current short lease"), 151-152; context-query-capacity.md:191-197 ("a projection frame gate repeats its full SQL/peer
  check on every frame"); context-native-read.md:16.
- **Current design:** streaming responses revalidate authority via SQL/peer checks per chunk/frame.
- **Class:** per-step revalidation; chatty per-request SQL.
- **Cost:** O(file size / 1 MiB) SQL + peer checks per download; latency jitter; abort on transient SQL hiccup.
- **Maintainer req?** M-312 (verbatim decision) removes post-start rechecks; text is stale.
- **Replacement:** `DownloadAuthority.Continue` — local comparison against original bounds only (session expiry,
  AccessUntil, Stop, reservation), per ADR-312.
- **Change:** download-responses.md, native-reader-identity.md (already updated) — align these four docs with them.

### A1-10 (High) Non-replenishing counters and "spent on uncertain" accounting cause eventual exhaustion
- **Where:** capacity-production.md:227-232 ("current finite configuration counter does not replenish itself");
  context-control-capacity.md:9-15, 49-57; context-query-capacity.md:37-39, 62-66; context-admission.md:37 (1024 ceiling,
  U13 open); context-investigation.md:205-207; connector-retirement.md:23-37; context-native-content.md:66-81 ("eight
  updates" budget per session); browser-sessions.md:43 (refresh claim never released); context-download-result.md:34-43.
- **Current design:** configuration renewals, metadata rows, polls, key unwraps and transitions are debited from
  finite prepaid pools that are never refunded on timeout/unknown outcome and only released by a not-yet-implemented
  retirement protocol.
- **Class:** exactly-once / spent-on-uncertain accounting where idempotency suffices; configuration solely tuning own
  machinery.
- **Cost/scaling:** installation degrades to refusal over time (configuration counter, U13 retained rows); every
  operation pays SQL/WAL for its own accounting rows; heavy qualification math (WAL floors, H-cooling).
- **Maintainer req?** M-storm and storage-exhaustion protection are required; non-replenishing control-row and
  configuration budgets are agent-added.
- **Replacement:** idempotency keys + lookup reconcile uncertain effects; quotas as counts of live rows/bytes per
  workload (released when rows/objects are deleted), plus token-bucket rate limits for storms. Precedent: Kubernetes
  ResourceQuota (object counts, released on delete); IETF Idempotency-Key header draft / Stripe idempotency; S3
  lifecycle for abandoned multipart uploads.
- **Change:** specs/capacity.md (REQ-CAP-004–006), specs/persistence.md, capacity-production.md,
  context-control-capacity.md, context-query-capacity.md, components.md (C-07 "No refund on timeout").

### A1-11 (High) Guarded/UID-pinned sources, denial probes and installer receipts still specified (contradicts M-328/M-helm)
- **Where:** capacity-production.md:12-19, 41-46, 99-172; context-capability.md:7-24, 68-74, 95-101;
  api-context-runner.md:15-23, 41-57; configuration-reconciliation.md:7-26, 44-46; cluster-observations.md:197-245;
  context-deletion.md:109-118; bootstrap-issuance.md:19-31; configuration-credential-provisioning.md (whole).
- **Current design:** sources accepted only after reading pinned admission policies/bindings, proving a non-admin
  dry-run denial, re-reading twice; installer role receipts (OID/ACL checks), `capacity-root-setup.json`, launch CAS
  from zero to one replica, original UID receipts.
- **Class:** self-verification of installer state; defends trusted namespace writers/cluster admins; obsolete text.
- **Cost:** 118–149 API requests per role-provisioning operation (configuration-credential-provisioning.md:105-117);
  extra probes per observation.
- **Maintainer req?** Removed by maintainer (M-328, M-helm, 2026-11-13).
- **Replacement:** Helm renders RBAC/Secrets/ConfigMaps; hook Job creates SQL roles idempotently; components read
  mounted config and trust RBAC. Capability tuple from Helm values or reported by connector/collector.
- **Change:** see §B deletion list; specs/deployment-profiles.md; docs/installation/helm.md.

### A1-12 (Medium) Timer polling where LISTEN/NOTIFY or push over existing connections exists
- **Where:** context-publication.md:56-58 (publisher "polls a bounded SQL queue"); context-deletion.md:44-50 (16 per
  sweep); context-progress.md:145, 158-163 (clients poll every 2 s; deadline sweep every 30 s); console-runtime.md:146-149;
  context-download-control.md:40-50 (client same-key POST continuation with backoff); context-evidence-workflow.md:121-125;
  context-projection.md:194-198 (manual "Check result"); browser-sessions.md:61 (1 s cleanup loop);
  applications.md:29-30, 58 (connector long poll, node "local work poll", SQL work leases).
- **Class:** polling / timer-driven queues.
- **Cost:** idle load proportional to replicas × users; 0–2 s latency added to every state change; extra HTTP requests
  that each re-authorize and (A1-04) audit.
- **Maintainer req?** No; standing rule 1 requires events.
- **Replacement:** `NOTIFY` on progress_revision/queue insert, workers `LISTEN` with resync on reconnect; browser/MCP
  status via SSE (or MCP progress notifications) fed by those notifications; HTTP/2 or gRPC bidirectional streams
  connector↔hub and node↔connector instead of long-poll. Time-based expiry: single timer to `min(cutoff)` from an index,
  not fixed sweeps. Session cleanup: periodic (minutes) batched DELETE is sufficient. Precedent: River/Oban/graphile-worker
  (LISTEN/NOTIFY job queues), Kubernetes watch streams, kubelet↔API server streaming.
- **Change:** specs/persistence.md, specs/mcp.md, specs/user-experience.md, node-collector.md, regional-context-start.md.

### A1-13 (Medium) Browser session design is heavier than a standard BFF
- **Where:** browser-sessions.md:18, 26, 28-35, 41-47, 53-61.
- **Current design:** server credential envelope KMS-encrypted per row (decrypt on use), refresh at
  min(1 minute, token expiry−15 s); one-use SQL refresh claims that are never released after an uncertain provider call
  (forces re-login); never-reused epochs, BrowserBinding pinning issuer/client/origin per replica; root-row serialization
  for session creation/logout; settings observer with 5 s lease that disables login on failure.
- **Class:** expiry-driven refresh; KMS on hot path; global lock; fallback states.
- **Cost:** a token refresh per active user per minute (IdP load); KMS call per refresh/decrypt; login outage on any
  ConfigMap read blip.
- **Maintainer req?** Keycloak and browser login are required (ADR-053/063 product choices); mechanism details are agent.
- **Replacement:** BFF pattern: opaque session cookie → SQL row with refresh token encrypted by an application key from
  a mounted Secret (or cached DEK); refresh only when access token is near expiry; settings from mounted ConfigMap (A1-02);
  optimistic refresh-token rotation with provider reuse detection. Precedent: IETF "OAuth 2.0 for Browser-Based
  Applications" (BFF), oauth2-proxy, Grafana server-side sessions.
- **Change:** ADR-060/061/300, current-request-identity.md, console-runtime.md:65-71.

### A1-14 (Medium) Many SQL logins per process/facet without isolation benefit
- **Where:** capture-intent-lifecycle.md:9 (eight logins), context-publication.md:13-23 (verify/audit/publish/read),
  context-deletion.md:38-41, 77-84 (cleanup/audit/finalizer), connector-renewal.md:7 (six), configuration-reconciliation.md:9-13,
  configuration-credential-provisioning.md:45-62, context-cases.md:72-77, context-progress.md:169-175.
- **Current design:** each facet has its own PostgreSQL role, pool and grant set, even inside one process.
- **Class:** complexity without evidence; configuration solely for own machinery.
- **Cost:** connection-pool fragmentation under the 32-connection cap; role provisioning/qualification work.
- **Maintainer req?** No. ADR-094 itself concedes same-process credential splits give no isolation; ADR-222 consolidated
  some.
- **Replacement:** one role per deployment (hub-api, hub-worker, publisher, key-service), least-privilege per deployment.
  Precedent: GitLab, Grafana, Harbor use one DB user per component.
- **Change:** specs/persistence.md, ADR-215/217/222, initial-sql-* (other auditor).

### A1-15 (Medium) Separate publication verifier re-decrypts artifacts and writes its own encrypted verification audit
- **Where:** context-publication.md:5-11, 51-66; api-context-runner.md:32-39; context-execution.md:9; artifact-format.md:95.
- **Current design:** asynchronous `asservat publisher` unwraps keys (≤12 per attempt) and fully decrypts/validates each
  artifact, writes `context-verification/v1` encrypted audit, checks a `ContextPublicationGate` three times, then inserts
  catalog rows.
- **Class:** duplicated verification; KMS/object reads per artifact; journals for same fact.
- **Cost:** doubles object reads and key unwraps per artifact; a separate process with unwrap authority.
- **Maintainer req?** No (ADR-181). Under M-328 the acquisition/collector is a trusted platform component; AEAD already
  detects corruption on read.
- **Replacement:** producer validates native schema before encryption; hub publishes on commit after HEAD/ETag+size
  checks against the commit envelope in one SQL transaction. Precedent: Loki/Tempo ingesters/compactors register flushed
  blocks without a separate decrypting verifier; integrity via checksums.
- **Change:** manifest-verification.md, components.md:66-68, specs/evidence.md.

### A1-16 (Medium) Deletion protocol: lease, double full inventory, signed+encrypted deletion record, three credentials
- **Where:** context-deletion.md:36-98, 109-118; capture-intent-lifecycle.md:39; artifact-format.md:97.
- **Current design:** 30 s lease with fence, full version/marker/multipart inventory twice, JWS-signed encrypted record
  via remote Transit signer, separate audit acknowledgement, then finalizer.
- **Class:** bespoke crypto; duplicated receipts; KMS per deletion.
- **Cost:** ≥2 LIST + signing + PUT + GET + 3 SQL txns per artifact deletion.
- **Maintainer req?** M-ret requires enforced deletion; the signed-record protocol is agent-added.
- **Replacement:** delete all versions, verify absence with one LIST/HEAD, mark deleted + audit row in one SQL txn; bucket
  lifecycle rules as backstop for noncurrent versions/incomplete multipart. Precedent: Loki compactor retention, Tempo
  compactor, Velero GC controller, S3 lifecycle `AbortIncompleteMultipartUpload`/`NoncurrentVersionExpiration`.
- **Change:** retention-lifecycle.md, specs/privacy.md (REQ-PRV-004), ADR-111/205.

### A1-17 (Medium) Uncertain-request "resolve/close" state machine and negative fences on top of idempotency keys
- **Where:** context-request-resolution.md:1-151; console-runtime.md:123-144; context-operations.md:57-62;
  context-capability.md:46-64 (`continue_acquisition`); context-investigation.md:90-100, 276-280.
- **Current design:** besides same-key retry, a `resolve_capture_request` operation durably closes unaccepted previews,
  with finite actor/client negative fences for missing previews, plus an explicit continuation branch after lost admission.
- **Class:** duplicated state machine for the same fact; fallback states.
- **Cost:** extra table/facet/credential, public operation and UI state.
- **Maintainer req?** No (ADR-103/134 agent). Requirement is "no duplicate intrusive effects".
- **Replacement:** preview is single-use and bound to its idempotency key; retry with that key returns the stored result;
  editing creates a new preview; expired previews cannot be submitted. Continuation is just the dispatcher resuming
  accepted work from SQL. Precedent: IETF Idempotency-Key draft; Stripe idempotent requests.
- **Change:** specs/apis.md, specs/mcp.md, specs/contracts (resolve_capture_request), console UI specs.

### A1-18 (Medium) Recovery/incarnation fence locked in every effect transaction
- **Where:** context-admission.md:53; context-publication.md:31; context-cases.md:12, 47; context-progress.md:121;
  context-deletion.md:93-98; capacity-production.md:186-197; code-organization.md:70; applications.md:79.
- **Current design:** every transaction locks the recovery row first and compares the PostgreSQL process/database
  incarnation; restore requires an unimplemented recovery coordinator.
- **Class:** defends a rare operational event in every hot path; global row lock (feeds A1-07).
- **Cost:** one more locked singleton per transaction; any PostgreSQL restart invalidates in-flight paths (context-deletion 96).
- **Maintainer req?** No (ADR-096).
- **Replacement:** documented restore runbook: scale hub/connectors to zero, restore, run a migration/hook Job that bumps
  an `installation_epoch`; components read the epoch at startup (and on reconnect) only. Precedent: GitLab and Velero
  restore procedures (stop services, restore, restart).
- **Change:** download-recovery.md, specs/persistence.md, ADR-096.

### A1-19 (Medium) N+1 authorization and repeated identity checks per read
- **Where:** context-cases.md:18-26, 46-53; context-download-control.md:73-79, 104-113; context-native-content.md:43-50.
- **Current design:** `get_case` checks eligibility per artifact target, then rechecks identity after catalog reads,
  recovery again, identity again; download status re-evaluates identity/rights/audience/retention/environment/recovery on
  every status read.
- **Class:** chatty per-request reads; per-step revalidation.
- **Cost:** O(artifacts) evaluator calls; 3× identity resolution per request.
- **Maintainer req?** M-311 says the opposite (one authorization per operation).
- **Replacement:** one authorization per request, batched eligibility query over the case's distinct targets; status
  reads reuse the operation decision within 30 s.
- **Change:** download-authority.md, current-request-identity.md.

### A1-20 (Medium) Capability source as guarded ConfigMap instead of reported capability
- **Where:** context-capability.md:7-24.
- **Current design:** capability (collector image/version, projection digest, epoch) is an administrator ConfigMap with
  installed UID and policy pins, re-read twice per observation with 5 s expiry.
- **Class:** obsolete guard design; polling; configuration duplicating runtime facts.
- **Maintainer req?** No.
- **Replacement:** connector/collector report actual capability on connect (push, A1-01); Helm values provide the
  enable flag. Precedent: kubelet node status/capacity reporting; Karmada cluster status.
- **Change:** specs/execution.md, node-collector.md.

### A1-21 (Low) README.md is a change log, half of it installer-era
- **Where:** README.md:1-230 (entries at 12-19, 46-56, 62-64, 84-110, 194-212, 228-230 describe the removed installer,
  guards, witness, staging, owner-protection).
- **Problem:** obsolete text; no navigation value; contradicts M-helm.
- **Replacement:** reduce to the "Read by question" table (234-254) plus "Selected shape"; move status to
  implementation-progress.md.

### A1-22 (Low) components.md describes agent mechanisms as component contracts
- **Where:** components.md:40 (C-04 "certificate enrollment/rotation", "node-boot identity"), 44 (C-08 "Pending object
  audit blocks sensitive starts/disclosure"), 43 (C-07 "No refund on timeout"), 55 (C-19 "work claims, lease fences"),
  66-71 (audit gate after commit), 73 ("External freshness proofs are gathered first").
- **Replacement:** update after A1-04/A1-06/A1-10: C-08 = SQL audit rows + async export; C-04 = per-cluster registration
  + standard cert rotation; C-07 = live-count quotas + rate limits.

### A1-23 (Low) Go code builds Kubernetes workloads (contradicts M-helm)
- **Where:** code-organization.md:64-68, 90-92; configuration-reconciliation.md:46; configuration-credential-provisioning.md:71-83.
- **Current design:** `kubernetes.BuildHubWorkerWorkload` / `BuildProvisionedHubWorkerWorkload` generate Deployments/RBAC.
- **Replacement:** chart templates; delete builders.

### A1-24 (Low) build-or-reuse.md keeps installer/temporary-SQL-password guidance
- **Where:** build-or-reuse.md:58-62 (ADR-100), 14 and 16 (C-02/C-04 "Enrollment").
- **Replacement:** delete 58-62; C-04 reuse "kubelet-style CSR rotation / cert-manager".

### A1-25 (Low) applications.md role inventory still lists A-INSTALL and partial download-worker
- **Where:** applications.md:56 (A-INSTALL), 95; catalog.yaml:4-5 (A-INSTALL), 241, 293-294, 519 (guard/witness ports).
- **Replacement:** delete A-INSTALL; add "Helm hook Jobs (schema/roles, key/object-store setup)" row; regional reader
  Deployment per A1-05.

---

## B. Docs obsolete after Helm-native install / guard removal — deletion candidates

Delete entirely (content describes deleted installer, guard proofs, UID pins, installer journals/receipts, or a
mechanism replaced by A1-01/A1-06):
1. `configuration-credential-provisioning.md` — installer role claims, UID/resourceVersion launch CAS, guard probes.
2. `configuration-reconciliation.md` — guarded fleet/owner sources, probe tokens, dry-run denial, polling FIFO
   (replace with a short informer-based note if anything).
3. `cluster-observations.md` — H→A→R native-proof observation chain (replace with connector informer push design).
4. `connector-retirement.md` — retirement tickets for per-process connector identities.
5. `connector-renewal.md` — per-process identity tables, proof chains (replace per A1-06).
6. `bootstrap-reservation.md`, `bootstrap-channel.md`, `bootstrap-issuance.md` — consolidate into one short
   enrollment doc after A1-06; bootstrap-issuance.md:19-31 ("promoted installer", "phase-3 provider artifact", guard RBAC)
   is obsolete as written.
7. `context-download-result.md` — exists only to bridge 5 s lease expiry around per-request Jobs (A1-05/A1-08).
8. `context-native-read.md`, `context-execution.md` — superseded status stubs (5 s disclosure lease; pre-runner
   executor); fold remaining facts into artifact/execution docs.

Delete sections:
- `capacity-production.md`:12-19 (ADR-324 guard probes), 41-46 (native guard proof), 99-172 (capacity-root-setup.json,
  role receipts, installed loader, guard RBAC, receipt-gated publisher).
- `context-capability.md`:7-24, 68-74, 95-101 (guarded ConfigMap, denial probe, "protected capability installer").
- `api-context-runner.md`:15-23 (capacity account verifying namespace/start guards, original UID storage), 41-57
  (process guard, namespace-denial proof, foreground-deletion finalizer allowance for the guard).
- `context-deletion.md`:109-118 (optional pins from protected capacity projection).
- `applications.md`:56 (A-INSTALL row).
- `code-organization.md`:64-68 (initial-installation/installer/witness packages), 90-92 (Go-built hub-worker workload).
- `build-or-reuse.md`:58-62 (temporary installation SQL credentials).
- `README.md` entries 12-19, 46-56, 62-64, 84-110, 194-208, 212, 228, 230.
- `catalog.yaml`: A-INSTALL (lines 4-5), `InstallationWitnessReader/Consumer` (293-294), `KeyConfigurationGuard` (241),
  `WorkerConfigurationGuard` (519) — check remaining references with `make architecture-check` after removal.

Out-of-range docs linked from README that are obviously installer-era (for the auditor covering them): `initial-*.md`
(18 files), `installation-witness.md`, `installed-owner-identity.md`, `installed-public-inputs.md`,
`provider-installed-pair.md`, `helm-bootstrap.md`, `owner-workload-protection.md`, `owner-enrollment-proof.md`,
`owner-deployment.md`, `owner-configuration.md`, `download-worker-attestation.md`, `worker-configuration.md`.

## C. Top recommendations (ordered by payoff)
1. A1-01 + A1-02 + A1-03: replace per-operation remote reads and polled/expiring config with connector informers pushing
   to SQL and mounted/watched ConfigMaps — removes the largest API-call and latency costs and three agent mechanisms.
2. A1-04: SQL-transactional audit rows with async export — removes S3/KMS round trips from every capture, read and poll.
3. A1-05: long-running regional reader Deployment instead of per-download/per-query Jobs.
4. A1-06: per-cluster connector identity with standard CSR rotation; delete per-process PKI/tickets.
5. A1-07/A1-08/A1-09: drop global root locks and 5 s windows; apply ADR-311/312 as decided.
