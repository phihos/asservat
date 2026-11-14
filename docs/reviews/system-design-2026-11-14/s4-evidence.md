# Spec design audit — S4: evidence, downloads, saves, live watch, packets, syscalls, profiles

Worktree: `/home/phil/Projekte/asservat-specreview` (read-only audit). Scope:
`specs/evidence.md`, `specs/artifact-downloads.md`, `specs/recording-saves.md`,
`specs/live-watch.md`, `specs/packets.md`, `specs/syscalls.md`, `specs/profiles.md`.

"Maintainer" = a decision listed in AGENTS.md "Authority and invariants",
"Security proportionality and delivery" or "Threat model" (or explicitly quoted
there). Everything else is classed agent-added, even when an ADR or many spec
clauses repeat it (AGENTS.md: "Existing code, tests, ADRs or repeated
instructions do not by themselves turn an agent-added restriction into a user
requirement").

Counts: **high 10, medium 14, low 8** (32 findings).

---

## High

### H1 — Kubernetes peer membership polled with LIST once per second per recording
- **Where:** `specs/packets.md:23`, `:27`, `:184`; ADR-283 part 3 (`docs/decisions/283-cidr-packet-peers.md:190-213`).
- **Current:** For each running manual recording with frozen Kubernetes peers, the connector re-resolves the peer query with a consistent paged LIST once per second (about 4 requests per entry). It stops the capture with `PeerMembershipStale` if no resolution confirms within 1–5 s. ADR-283 caps this at **8 verified recordings per connector** because of the polling load. `follow` is refused "until LIST load is measured".
- **Problem class:** Polling where an event source exists. The freshness window is driven by expiry. A cap exists only to make the polling affordable.
- **Cost/scaling:** About 32 API requests/s per connector at the cap. A hard limit of 8 peer recordings per cluster. A brief API server hiccup longer than 5 s kills an in-progress capture with no refund. That is an availability failure during exactly the incidents people debug.
- **Origin:** Agent-added. The maintainer asked for "dynamic Kubernetes peers" (Authority and invariants), which argues *for* follow, not against it.
- **Replacement:** One shared, label- and namespace-scoped informer per connector for Pods/EndpointSlices/ReplicaSets, the standard client-go pattern. Evaluate each recording's membership on informer events. Treat the cache as valid until a watch error. On a watch break, relist, and only then mark affected membership suspended. Precedent: kube-proxy, Cilium and CoreDNS all derive endpoint state from EndpointSlice informers with no periodic freshness proof. Drop `maxStaleness` and the per-connector cap. This also makes `follow` cheap: a new generation per coalesced event.
- **Consistent changes:** `specs/packets.md:39` (maxStaleness ceiling), `:184` (progress/revalidation requirement), contracts `packet-capture.schema.json` (`maxStaleness`), `specs/capacity.md` if it budgets verifier QPS, ADR-283.

### H2 — Peer-watch "freshness" requires an independent API progress mechanism
- **Where:** `specs/packets.md:27` ("Freshness deadline defaults to 5 seconds after loss of synchronization"), `:184` ("a quiet healthy watch alone neither proves fresh authorization … needs a bounded independent API progress/revalidation mechanism").
- **Current:** A quiet watch is distrusted. The adapter must periodically prove progress against the API, and absence of proof closes membership.
- **Problem class:** Expiry-driven freshness; self-verification of a platform watch.
- **Cost:** Extra periodic API traffic per watch. Captures stop when the API server is merely slow, and `follow` gains failure states.
- **Origin:** Agent-added (rule 1 and rule 3 contradict it).
- **Replacement:** Use standard informer semantics. State stays valid until replaced. Resync only on watch error or 410 Gone, and use client-go `WatchListClient`/bookmarks only to keep resourceVersion fresh, not as an authority clock. Precedent: every Kubernetes controller.
- **Consistent changes:** Same as H1; also `specs/retention*` if it shares the "bounded window of five observations" follower (AGENTS.md describes the same pattern for retention).

### H3 — Per-download regional Kubernetes Job as the download worker
- **Where:** `specs/artifact-downloads.md:127`, `:101`, `:103`, `:121`; `specs/evidence.md:214`; ADR-219/221 (implementation notes).
- **Current:** Each download preparation dispatches a dedicated download-only acquisition Job. Its Pod enrolls a certificate, attests, and streams through a relay. A worker "cannot be safely reused" after an interrupted response, which forces a **Start a new download** flow. The worker polls for its completed operation.
- **Problem class:** One Job per request; scaling and latency; bespoke lifecycle.
- **Cost/scaling:** Seconds of Pod scheduling and image start before the first byte. Pod churn grows with download count. Each Job carries its own enrollment, TokenReview and live Pod/Job reads. The default of 16 concurrent streams per installation (`:119`) mostly reflects that cost.
- **Origin:** Agent-added. The maintainer required native download and "no hub raw unwrap" (wrap-only collectors), not a Job per download.
- **Replacement:** A long-running regional `download-worker` Deployment with its own ServiceAccount, scaled by HPA. It holds exact-object read/unwrap rights through the key provider's policy, authenticates the hub by mTLS/TokenReview, and serves many streams. Precedent: Loki querier / Thanos store gateway (long-running S3 readers), Velero node-agent data mover, Harbor registry core. Per-artifact authorization stays in the hub's decision passed with the request.
- **Consistent changes:** `specs/evidence.md:69-85` (query worker), `specs/syscalls.md:39-49`, `specs/packets.md:132-174`, `specs/profiles.md:95` (all reuse "regional acquisition worker"), `docs/architecture/download-*.md`, worker enrollment/dispatch ADRs 068–073, 221.

### H4 — Bespoke worker PKI/enrollment and live Pod/Job attestation for downloads
- **Where:** `specs/artifact-downloads.md:67-73` (ADR-221), `:121` ("full attestation … the next window fully reattests"), `:151`.
- **Current:** Each worker enrolls a P-256 key through TokenReview plus live account/Job/Pod proofs and receives a 20-minute certificate under audited signing spend. It is reattested every 64 MiB window.
- **Problem class:** Bespoke enrollment/PKI where Kubernetes ServiceAccount tokens/TokenReview or cert-manager suffice; defends against forged Pods in admin-only namespaces.
- **Cost:** Multiple API round trips per window, signing audit, and many failure states.
- **Origin:** Agent-added. It is obsoleted by ADR-328 ("Do not design mechanisms that defend against … forged Pods"; "callers authenticated by TokenReview and TLS").
- **Replacement:** Projected ServiceAccount token (audience-bound) verified by TokenReview once per connection, or a cert-manager-issued Service certificate for mTLS. Precedent: Linkerd/Istio identity, Vault Kubernetes auth, Argo CD repo-server.
- **Consistent changes:** `specs/evidence.md:76-79` ("current worker and live-request proof"), `specs/syscalls.md`, `specs/profiles.md:208-215`, all ADR-068/071/072/221 references.

### H5 — Download streaming split into ≤5 s leases, 64 MiB windows and 60 s conversations with SQL transactions and reattestation
- **Where:** `specs/artifact-downloads.md:36-44`, `:46-52`, `:113`, `:119-121` (ADR-113/288).
- **Current:** A started response is chunked into ≤1 MiB pieces. Each piece checks a ≤5 s delivery lease, and every lease is an SQL transaction that reads retention/deletion. Each 64 MiB window reserves output, read work and "paired durable audit/control capacity". Each 60 s conversation reattests the worker. Unknown window outcomes stay fully spent.
- **Problem class:** Per-step revalidation on the hot path. The design contradicts the spirit of ADR-312 even though leases "do no I/O" for identity, and it chats with SQL per stream.
- **Cost/scaling:** A 2 GiB core produces about 32 windows with paired audit/reservation writes and attestation. Over a 30 min transfer at 5 s leases that is about 360 SQL transactions. Multiplied by concurrent streams, SQL becomes the throughput ceiling. A slow client gets cut at 60 s per window, and any hiccup leaves spent bytes that cannot be refunded.
- **Origin:** Agent-added. The maintainer decision (ADR-312) says a started response runs to its original bounds with no rechecks.
- **Replacement:** One authorization at response start, which fixes `AccessUntil` and the byte allowance. Stream with plain `io.Copy` and a context deadline. Update a byte counter asynchronously (batched every N MiB or at end). Deliver retention shortening, deletion and Stop as events (PostgreSQL `LISTEN/NOTIFY` → cancel the context) instead of reading them per lease. Precedent: S3/GCS presigned-style single authorization per GET; Harbor and Artifactory blob streaming; nginx `X-Accel-Redirect` patterns.
- **Consistent changes:** `specs/capacity.md` (window reservations), `docs/architecture/download-sessions.md`, ADR-113/288, `specs/evidence.md:164` (writer proofs).

### H6 — Synchronous encrypted object-store audit before every download response and per window
- **Where:** `specs/artifact-downloads.md:115` (ADR-136: "encrypted operation intent and outcome … finish … before any representation metadata or conditional response is disclosed"), `:121` ("paired durable audit"), `:109`, `:137`; `specs/evidence.md:25-29`.
- **Current:** Every content GET, including a 304/412 conditional, writes an encrypted, versioned S3 audit object and waits for its acknowledgement (plus key-wrap calls) before sending headers. Each window pairs audit capacity.
- **Problem class:** Synchronous encrypted/object-store audit and KMS on the hot path, per request and per window.
- **Cost:** Two or more S3 PUTs plus key calls of latency per request. A 304 cache revalidation costs as much as a full start. An audit-store outage takes downloads down with it.
- **Origin:** Durable audit itself is reasonable and the spec says "durable audit". *Encrypted per-request S3 objects written synchronously* is agent-added.
- **Replacement:** Insert the audit row in the same PostgreSQL transaction as the authorization/session update (one round trip, durable, append-only role without UPDATE/DELETE), then export asynchronously in batches to object storage for long-term retention. Precedent: Kubernetes API audit (batched webhook/log backends), GitLab/Grafana audit events in the DB, Vault audit devices (append to a local file/socket, not a versioned object per request).
- **Consistent changes:** `specs/evidence.md:25-29` (audit storage model), `specs/recording-saves.md:27`, `specs/live-watch.md`, the audit spec (REQ-AUT-005).

### H7 — Prepaid, independently backed Stop obligation with encrypted retirement and backend-absence proof
- **Where:** `specs/artifact-downloads.md:109` (ADR-119/124).
- **Current:** Each download reserves a "stop obligation" before effects. Stop has its own encrypted audit, pending/recorded/overdue states, "history cooling", signed retirement, verification of full backend absence and SQL/backup/WAL budgets.
- **Problem class:** A duplicated state machine and ledger for a cancel button; exactly-once accounting.
- **Cost:** Several tables, audit objects and a retirement reconciler per download. Large implementation and qualification cost for a capability users expect as "close the connection".
- **Origin:** Agent-added (the maintainer asked only for downloads and audit).
- **Replacement:** Stop = an idempotent SQL `UPDATE … SET state='Cancelled'` keyed by session, plus `NOTIFY` to cancel the stream and one audit row. Precedent: every HTTP download/cancel API (S3 AbortMultipartUpload, GitHub Actions cancel).
- **Consistent changes:** `specs/syscalls.md:127-136` and `specs/profiles.md:76-83` (Stop semantics for recordings are related but separate), ADR-119/124, capacity spec.

### H8 — Audit storage as versioned S3 with full physical-copy accounting and writer-quiescence proofs
- **Where:** `specs/evidence.md:25-29`, `:164`.
- **Current:** Audit objects require versioned buckets with immutable version IDs. Every physical copy is reserved and charged, including failed writes, delete markers and multipart parts. Retirement enumerates all versions, proves "positive writer quiescence", and verifies complete absence before releasing charges. Provider-credential observations must keep their deadlines through response-body closure (`:27`).
- **Problem class:** Bespoke storage accounting; spent-on-uncertain; self-verification.
- **Cost:** Every audit write becomes a multi-state reservation. Retirement is an O(versions) scan with verification. The installation must also qualify backend versioning semantics.
- **Origin:** The text says "accepted installation requirement", but no maintainer decision in AGENTS.md requires versioned-object audit; this is agent-added. The maintainer did require "administrator-enforced maximum evidence retention" and "protection against cross-workload storage exhaustion", which apply to evidence rather than audit metadata.
- **Replacement:** Audit in PostgreSQL (H6) with time-partitioned tables dropped by partition at retention end, the standard approach (pg_partman; GitLab, Sentry). If object export is needed, use a bucket lifecycle rule with optional Object Lock. Precedent: Loki/Tempo retention via compactor and lifecycle, no per-object charge ledger.
- **Consistent changes:** `specs/capacity.md`, `specs/privacy.md` (audit 90-day max), `docs/research/audit-storage-qualification.md`, `specs/artifact-downloads.md:151` (version-ID requirement).

### H9 — Synchronous encrypted intent audit per child before each recording-save snapshot starts
- **Where:** `specs/recording-saves.md:27` ("Grouped dispatch requires each child's own exact acknowledged intent before that child starts"), `:25` (node receipt after t0 loses history).
- **Current:** t0 is fixed at acceptance. Each child snapshot must wait for its own acknowledged encrypted intent audit, and only then dispatch to the node, while the ring keeps rotating.
- **Problem class:** Synchronous encrypted audit on a latency-critical path.
- **Cost:** Every millisecond of audit latency is history evicted from 30 s / 16 MiB rings under traffic. This directly reduces the evidence the feature exists to keep. Up to 16 audit round trips per Save.
- **Origin:** Agent-added. The maintainer requirement is "Save existing recordings now".
- **Replacement:** Commit acceptance, the per-child audit rows and dispatch work in one SQL transaction, then push work to the node immediately over the existing long-poll channel, which the node pins on receipt. Export audit asynchronously (H6).
- **Consistent changes:** `specs/action-lifecycle.md`, capture-request specs that share the "acknowledged intent before start" rule (ADR-268/269).

### H10 — Stacked five-second authority/observation windows in saves, preview and live watch (violates ADR-311)
- **Where:** `specs/recording-saves.md:27` ("admission facts retain their original five-second interval … Ordinary, automatic and singleton builders retain five seconds"); `specs/live-watch.md:60` ("five-second freshness re-check interval"); `specs/artifact-downloads.md:54-60` ("capped at five seconds"); `specs/profiles.md:208-215` (8 s composition, recovery proof, re-read of final facts after readiness).
- **Current:** Individual steps hold 5 s observation lifetimes and re-read identity/target/recovery facts within one operation.
- **Problem class:** Per-step revalidation and expiry-driven freshness.
- **Cost:** Repeated identity/SQL/K8s reads per operation. Spurious expiry failures under load: any operation step slower than 5 s fails.
- **Origin:** Contradicts the maintainer decision ADR-311 (AGENTS.md: "authority is checked once per operation and reused for at most … 30 s; 60 s … Do not reintroduce stacked five-second authority windows").
- **Replacement:** One authorization per operation reused up to `identity.AuthorityRecheckInterval` (30 s), with no separate admission-fact or helper intervals. Remove the "recovery proof / issuer epoch" re-reads in profile preview.
- **Consistent changes:** `specs/capture-*`, `specs/investigation-approval.md`, ADR-214/216/268/269 text.

---

## Medium

### M1 — Live watch: client polling with a server-provided minimum poll interval; paused views poll status
- **Where:** `specs/live-watch.md:31`, `:23` ("Visible paused views perform bounded status-only reads to learn expiry or access changes").
- **Current:** The browser issues `read_live_watch` (wait ≤ 5 s, normally 1 s), and empty batches count as heartbeats. Paused views poll for revocation.
- **Problem class:** Polling where push exists over the existing HTTP connection.
- **Cost:** One request per second per open view, multiplied by viewers, plus cursor, replay and heartbeat-position machinery (`:33-35`).
- **Origin:** Agent-added. The maintainer asked for "finite UI/MCP views", and MCP genuinely needs bounded tool calls.
- **Replacement:** For the browser, one Server-Sent Events stream per watch (standard `EventSource`, `Last-Event-ID` for reconnect) that pushes rows, gaps and state changes such as expiry, revocation and pause. Keep `read_live_watch` batches for MCP only, implemented as a long-poll that returns on the first new row. Precedent: Grafana Live, Kubernetes watch over HTTP chunked streams, Argo CD UI resource streams.
- **Consistent changes:** `contracts/live-watch.schema.json`, `docs/research/live-watch.md`, `specs/packets.md:200-202`, `specs/syscalls.md:91-93`.

### M2 — Live watch re-checks read authority on every batch read
- **Where:** `specs/live-watch.md:60`, `:9`, `:15`.
- **Current:** "Read authority is re-checked by every read". Executor authority, grant, lease and deny are also checked continuously.
- **Problem class:** Per-request revalidation.
- **Cost:** A full authority evaluation (identity + SQL + K8s-derived permission) roughly every second per viewer.
- **Origin:** Violates the maintainer decision ADR-311 (one decision per operation, ≤ 30 s reuse).
- **Replacement:** Authorize at open; reuse for 30 s; push revocation as an event (AccessBinding watch → connector → close the watch). That matches ADR-311 and rule 1.
- **Consistent changes:** `contracts/live-watch.schema.json`, ADR-310.

### M3 — Live-watch rows expire 30 s after observation, and browser rows are cleared at 30 s
- **Where:** `specs/live-watch.md:59`.
- **Current:** `expires_at = min(observedAt + 30s, …)`. The browser keeps at most 30 s of rows, and paused or selected rows still expire.
- **Problem class:** Expiry-driven privacy control without cited external evidence (rule 2).
- **Cost:** Users cannot scroll back more than 30 s in a live view, so they need a separate Save to look at a row they just paused on. That is a usability regression against the maintainer's "approved projections live" decision.
- **Origin:** Agent-added (ADR-310 calls itself an "engineering revision"). The maintainer chose "approved projections live and saving before raw inspection", which concerns *raw* data, not row lifetime.
- **Replacement:** Keep displayed approved-projection rows for the watch lifetime within the 500-row / 1 MiB browser bound. Clear them on close, logout or access loss. Precedent: `kubectl logs -f`, Grafana Explore live tail and Wireshark live views keep the buffer while the view is open.
- **Consistent changes:** Schema `expires_at` fields, SC-LIV-005.

### M4 — Live-watch owner routing via SQL durable control, owner enrollment certificates and domain-separated cluster digest
- **Where:** `specs/live-watch.md:35` (owner forwarding / durable control close), `:49` (counts only while "owner enrollment and an activated unexpired owner certificate still resolve that owner"; SHA-256 digest of the cluster ID), `:57`.
- **Current:** Each watch has a minimized SQL control row with fences. Hub-owner PKI (ADR-082–088) routes to the owning process, and the capacity view depends on owner certificate state.
- **Problem class:** Bespoke enrollment/PKI; journals for transient state; obfuscating a non-sensitive identifier.
- **Cost:** An SQL write per open/update/close, owner-locator lookups per read, and capacity metrics that depend on PKI health.
- **Origin:** Agent-added.
- **Replacement:** Route the stream to the owning hub replica with session affinity (Service `sessionAffinity`/ingress cookie), or terminate live streams at the connector. Keep watch state in memory and lose it on failover with a reconnect gap, as the spec already allows. Store the plain cluster UUID. Report capacity as Prometheus gauges/counters (`asservat_live_viewers`, drop counters) instead of the bespoke `get_live_capacity` aggregator. Precedent: Grafana Live HA (Redis optional, in-memory default), Loki tail via querier affinity.
- **Consistent changes:** `docs/architecture/hub-owner-*.md`, ADR-317, `specs/capacity.md` operator views.

### M5 — Download preparation continuation via client backoff loop and status polling
- **Where:** `specs/artifact-downloads.md:99` (UI shows preparation progress), `:107` (`continue_preparation` with finite backoff), `:117` ("Polling cannot repeatedly consume native observations"), `:145`.
- **Current:** The console repeatedly calls prepare/status until Ready, with special rules to stop polling from draining budgets.
- **Problem class:** Polling where an event exists (the worker reports Ready).
- **Cost:** Repeated authorized requests per download, plus machinery to protect budgets from the polling.
- **Origin:** Agent-added.
- **Replacement:** If the long-running worker (H3) removes the Job start, prepare can return Ready synchronously in most cases. Otherwise use one SSE/long-poll status request woken by `NOTIFY` on the session row. Precedent: GitHub Actions log streaming, Docker registry blob upload status.
- **Consistent changes:** `docs/architecture/context-download-control.md`, MCP `get_artifact_download` contract.

### M6 — Download policy observation TTL (60 s) instead of a watched ConfigMap
- **Where:** `specs/artifact-downloads.md:21-27` (ADR-214).
- **Current:** The protected download policy is re-read when its 60 s observation expires.
- **Problem class:** Expiry-driven refresh where a Kubernetes watch exists.
- **Cost:** Small, but it is one of several stacked caches with their own deadlines.
- **Origin:** The 60 s figure is in ADR-311 (maintainer), but as a *maximum reuse* for the shared delivery-policy observation. A watch-fed cache satisfies it better.
- **Replacement:** A ConfigMap informer or mounted-file inotify. The cached policy stays valid until replaced (rule 1). Precedent: Prometheus/Alertmanager config reload, ingress-nginx ConfigMap watch.
- **Consistent changes:** `specs/identity*.md` (identity settings 30 s observation — same pattern), ADR-214.

### M7 — "Spent on uncertain / never refunded" accounting throughout
- **Where:** `specs/artifact-downloads.md:103`, `:105`, `:121`; `specs/recording-saves.md:38`; `specs/profiles.md:62`, `:83`, `:264-270`; `specs/packets.md:23`, `:167-171`; `specs/syscalls.md:42-49`, `:132-134`; `specs/evidence.md:79`, `:122-124`.
- **Current:** Any ambiguous reply keeps the full charge permanently. Retries must resolve the exact same worker/operation, workers cannot be reused, and positive joined closure is required before release.
- **Problem class:** Exactly-once / spent-on-uncertain accounting where idempotency keys suffice.
- **Cost:** Quota leaks accumulate under normal network faults, and users hit exhausted budgets they never used. A reconciliation state is needed for every resource type.
- **Origin:** Agent-added. The maintainer required "protection against capture storms and cross-workload storage exhaustion", which bounded reservations and idempotent retries satisfy.
- **Replacement:** Idempotency key per operation. The reservation has a TTL, and a reconciler releases it when the owning operation reaches any terminal state or its deadline passes, using the operation row as the source of truth. Precedent: Stripe idempotency keys, Kubernetes ResourceQuota (released on object deletion), S3 multipart lifecycle abort.
- **Consistent changes:** `specs/capacity.md` (owner of the rule), `specs/action-lifecycle.md`.

### M8 — Each query/download re-unwraps three keysets; cross-operation key caching forbidden
- **Where:** `specs/evidence.md:13` ("do not introduce cross-operation plaintext key caching"), `:76-77`, `:113`; `specs/syscalls.md:42-49` (per-page key use); `specs/profiles.md:158-159` ("two independent key-use identities").
- **Current:** Every query page, summary, comparison or download window opens a new reader with three key-service unwraps and "irreversible unwrap slots".
- **Problem class:** KMS calls on the hot path; exactly-once key slots.
- **Cost:** Paginating a 100-row syscall view costs 3 unwraps per page. Key-service load and latency scale with UI clicks.
- **Origin:** Agent-added (maintainer: no hub raw unwrap, wrap-only collectors; no rule against worker-side caching).
- **Replacement:** Cache unwrapped data keys in the regional worker's memory per artifact for a short TTL, bounded by `AccessUntil`. Precedent: AWS Encryption SDK caching CMM; Google Tink/KMS envelope guidance; Vault Transit datakey pattern. Drop per-key "irreversible slots".
- **Consistent changes:** `docs/architecture/download-key-authority.md`, ADR-066, `specs/deployment-profiles.md` (local key service).

### M9 — Every saved-artifact query page fully authenticates and scans the whole source
- **Where:** `specs/syscalls.md:51-53`, `:60-61`; `specs/packets.md:160-162`; `specs/profiles.md:93` ("recomputed for each query").
- **Current:** Each page must reach complete authenticated EOF of the whole native file before releasing ≤ 100 rows. Profile semantic facts are recomputed for each query.
- **Problem class:** O(file) work per page (N+1 shape).
- **Cost:** k pages × full decrypt/decompress/parse, which is fine at today's 8 MiB but blocks the stated 1 GiB scan ceiling and larger sources.
- **Origin:** Agent-added. ADR-048 frames are independently authenticated, and the encrypted manifest binds totals/native hashes.
- **Replacement:** Authenticate only the frames a page touches, plus the manifest (which binds frame count and hashes, so truncation is detected). Verify the full file once at publication and record the verdict, which already exists via the verification audit. Cache per-artifact semantic facts (profile units/types) at publication. Precedent: Parquet/ORC footers, Loki chunk indexes, Tink segment authentication.
- **Consistent changes:** `docs/architecture/artifact-format.md`, ADR-303/305/306.

### M10 — Live watch and saves bind handles, previews and cursors to 60 s expiries plus re-authorized cursors
- **Where:** `specs/recording-saves.md:11`, `:23`; `specs/live-watch.md:11`.
- **Current:** Inventory handles and previews expire within 60 s, and cursors "expire/re-authorize normally".
- **Problem class:** Expiry-driven freshness forcing re-reads.
- **Cost:** A user who reads a preview for more than a minute must start over, and MCP agents re-list frequently.
- **Origin:** Agent-added. Acceptance already re-checks current authority and source epoch, so the handle lifetime adds nothing.
- **Replacement:** Handles are opaque IDs of (source epoch, policy execution digest). Validity is checked against current state at use, with no wall-clock TTL. Preview validity is invalidated by events (source epoch change, policy change), not by a timer.
- **Consistent changes:** `contracts/recording-save.schema.json`, `contracts/live-watch.schema.json`.

### M11 — Encrypted out-of-SQL storage of control metadata (reasons, save settings, selection manifests)
- **Where:** `specs/recording-saves.md:58`, `:60`, `:62`; `specs/live-watch.md:57` (scope/filters never in SQL); `specs/evidence.md:59`, `:188`.
- **Current:** Save reasons (≤ 512 chars), repeat settings, source selections and case details are stored as encrypted objects with their own retirement lifecycle. SQL holds only digests.
- **Problem class:** Duplicated state (SQL digest + encrypted object for the same fact); synchronous object writes.
- **Cost:** Extra object writes, key wraps and retirement jobs per save and case edit. Reading history requires object reads.
- **Origin:** The maintainer forbids *unencrypted managed evidence storage*. Control metadata is not evidence, so this rule is agent-added.
- **Replacement:** Store control metadata in PostgreSQL columns. Rely on the database's at-rest/TLS protection, as the hub already does for identities, and on row retention by partition/TTL job. Precedent: Sentry, GitLab and Grafana keep incident/annotation text in their DB.
- **Consistent changes:** `specs/privacy.md` (metadata minimization), ADR-267/310.

### M12 — Per-download "processing decision" re-verifies the complete installed storage/acquisition/connector/hub route
- **Where:** `specs/artifact-downloads.md:79` (ADR-127).
- **Current:** Every metadata read and download checks a current processing decision covering the whole installed route plus client/purpose/class policy. Privacy-operator release needs an "independently acknowledged decision".
- **Problem class:** Chatty per-request reads; self-verification of installation topology (rule 3).
- **Cost:** Additional SQL reads per request, plus a large state machine.
- **Origin:** Mixed. Processing restriction (GDPR Art. 18 style) is a legitimate privacy feature, but the route attestation is agent-added.
- **Replacement:** Represent restriction as a flag on artifact/workload rows checked in the same authorization query. Placement is static Helm configuration and is not re-attested per request.
- **Consistent changes:** `specs/privacy.md`, ADR-127/318.

### M13 — Analysis/publication split into three Jobs with fenced encrypted PVC handoff
- **Where:** `specs/evidence.md:128-135`.
- **Current:** Separate acquisition, analysis and publication Jobs. Encrypted RWOP PVCs are handed off only after "verified old-writer termination/unmount". An independent scratch reconciler and copy ledger complete the design.
- **Problem class:** Heavy orchestration and fencing; per-request Jobs.
- **Cost:** Three Pod startups per analysis, plus a CSI encrypted StorageClass prerequisite and a reconciler.
- **Origin:** **Maintainer-accepted** (AGENTS.md: "Accepted ADR-036 requires qualified encrypted scratch StorageClass for offline analysis; no cross-Job emptyDir"). The *fencing/verified-unmount and ledger details* are agent-added.
- **Proposal (keep capability):** Keep ADR-036 but rely on Kubernetes semantics: Job completion and RWOP mean the old Pod is gone. Drop separate unmount verification and node-partition blocking, which defend against the trusted platform. Optionally re-ask the maintainer whether a single Pod with credentialed init container + credential-free main container (per-container volume mounts, same emptyDir) is acceptable, since NetworkPolicy is the only pod-scoped residual. Precedent: Argo Workflows artifact passing, Tekton workspaces.
- **Consistent changes:** `specs/profiles.md:95`, ADR-036.

### M14 — ADR-290 temporary multipart reservations, durable connector-process binding and protocol-marker capacity roots
- **Where:** `specs/profiles.md:263-276`.
- **Current:** Profiles above 8 MiB need atomic final plus temporary multipart reservations, a durable binding to one connector process, and no release before "verified writer quiescence and complete backend inventory cleanup". Capacity roots carry `go-profile/v1` markers alongside legacy roots.
- **Problem class:** Spent-on-uncertain accounting; versioned capacity machinery.
- **Cost:** Reconciler, inventory listing and two reservation types per large profile.
- **Origin:** Agent-added.
- **Replacement:** Reserve the max native size once. Rely on the bucket lifecycle rule `AbortIncompleteMultipartUpload` (AWS/MinIO/SeaweedFS standard), and release on complete/abort or operation terminal. Precedent: Velero, Loki and Harbor upload paths.
- **Consistent changes:** `specs/capacity.md`, `specs/evidence.md:23`, `:29`.

---

## Low

### L1 — Spec text mixes implementation status, run IDs and commit hashes
- **Where:** `specs/profiles.md:39-41`, `:58-60`, `:173-178`, `:269-270`; `specs/syscalls.md:101-105`, `:117-119`; `specs/artifact-downloads.md:143-153`; `specs/evidence.md:45`, `:57`, `:164`.
- **Problem:** Requirements carry qualification status ("passed installed41916430295 at abf25590", "pod-status-only until increment 4"), so specs churn with every run.
- **Origin:** Agent-added.
- **Fix:** Move status to `docs/implementation-progress.md`; keep normative text only.

### L2 — Installer/guard-era wording ("protected source acceptance", "immutable input bundle", recovery proofs, issuer epochs)
- **Where:** `specs/profiles.md:202-204`, `:48-50`, `:210-213`; `specs/artifact-downloads.md:70-71` ("workload proof, configuration, recovery … finite signing"); `specs/evidence.md:166` ("fence old execution authority").
- **Problem:** This text describes the removed installer/guard era (rule 3/4; ADR-328, Helm-native install).
- **Fix:** Replace it with "configuration from mounted ConfigMaps/Secrets rendered by Helm". The credential header can come from a Secret mounted into the connector.

### L3 — Raw-byte pcap predicates require a sensitive acquisition grant
- **Where:** `specs/packets.md:9`.
- **Current:** `tcp[13] & 2 != 0` needs an independent adHocCapture approval, plus observation-spend charging before the recorder can run it.
- **Problem:** No external evidence is cited that predicate-based payload inference is a real risk worth an approval step (rule 2). TCP-flag tests are among the most common tcpdump filters.
- **Origin:** Agent-added (ADR-249); the maintainer required "bounded pcap filters".
- **Fix:** Allow offsets within L2–L4 headers under ordinary permission. Keep approval only for payload offsets, if evidence supports it.

### L4 — Manual frozen-peer recordings stop permanently on any membership change
- **Where:** `specs/packets.md:23` (`PeerMembershipChanged` → stop, no refund).
- **Problem:** A rollout, which is exactly the event under investigation, kills the capture.
- **Fix:** With H1's informer, exclude the changed member from the compiled program (new generation) and record the gap. This is already the specified behavior for `follow` and "frozen still removes deleted/reassigned IPs" (`:27`).

### L5 — Download session state machine and metadata-group rules are larger than needed
- **Where:** `specs/artifact-downloads.md:99-101`.
- **Problem:** 9 states, and the metadata group must be all-or-nothing per state. Terminal-status readability has its own authorization rules. Much of this exists because of Job-based preparation (H3).
- **Fix:** After H3/H5, reduce to Preparing/Ready/Completed/Failed/Cancelled; Range resume is standard HTTP.

### L6 — Duplicated case/tombstone state in S3 and SQL
- **Where:** `specs/evidence.md:59`, `:176-188`.
- **Problem:** Immutable S3 case revisions and plaintext tombstones duplicate SQL associations/tombstones "for recovery".
- **Fix:** SQL is authoritative and backed up with pgBackRest (accepted). Drop S3 case revisions; keep tombstones only if restore replay needs them, and then in SQL.

### L7 — Download concurrency defaults (2/principal, 16/installation) as a hard installation cap
- **Where:** `specs/artifact-downloads.md:119`.
- **Problem:** 16 concurrent streams installation-wide reflects per-Job cost (H3). It will bottleneck multi-team installations.
- **Fix:** Derive the limit from worker replicas × per-replica concurrency; keep per-principal fairness.

### L8 — `get_live_capacity` rates "only when every node has a valid report predecessor"
- **Where:** `specs/live-watch.md:49`.
- **Problem:** A bespoke metrics aggregator with unavailable-states.
- **Fix:** Export Prometheus counters and let `rate()` compute rates (standard). This overlaps with M4.

---

## Maintainer-requirement capabilities preserved by the proposals
Native download of all evidence (PCAPNG, cores, companions), encrypted managed storage, wrap-only collectors with no hub unwrap, Save existing recordings, finite live views with approved projections only, bounded pcap filters, dynamic Kubernetes peers, segmented rings, HTTP header extraction, first-class pprof, ADR-036 encrypted scratch, investigation approval/raw grants, ADR-311/312 authority timing, and the ADR-059 policy identity for saves. None of the replacements removes a capability. They change mechanisms only.
