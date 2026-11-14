# S5 spec audit: APIs, interfaces, MCP, UX, ergonomics, guidance

Scope: `specs/apis.md`, `specs/interfaces.md`, `specs/mcp.md`, `specs/user-experience.md`,
`specs/ergonomics.md`, `specs/guidance.md`, `specs/README.md`, a skim of `specs/contracts/`
(138 files) and `specs/changes/postgresql-hub-state/proposal.md`, in
`/home/phil/Projekte/asservat-specreview`. I also read neighbouring text where these files point
to it: `specs/live-watch.md` REQ-LIV-003, `specs/federation.md` REQ-FED-002,
`docs/interfaces/README.md` and `docs/architecture/interfaces.md` I-01. Line numbers refer to
each file. No repository files were edited.

Counts: **high 7, medium 11, low 6** (24 findings).

---

## High

### S5-01: Browser live view polls instead of streaming
- **Where:** `specs/apis.md:125`, `specs/mcp.md:311-313`; the text it implements is
  `specs/live-watch.md:31-35` and `docs/interfaces/README.md:70-74` ("no websocket, infinite
  response"; "browser normally waits up to one second and applies a server-provided minimum poll
  interval").
- **Current design:** The browser and MCP both read live rows through repeated `read_live_watch`
  POSTs with `wait_ms ≤ 5000`. A SQL `LiveWatch` control row, a fenced "projection owner",
  internal replica-to-owner routing, a 5 s / 1 MiB replay buffer per watch, cursor-replay
  re-charging and "empty batch is a heartbeat" semantics make polling work across stateless
  replicas.
- **Problem class:** Polling where an event source exists. Bespoke stream protocol. Duplicated
  state (SQL control row plus owner fence plus replay buffer).
- **Cost:** One authenticated POST per viewer per second, each with full authorization, a SQL
  lookup and a cross-replica forward. The installation default allows 128 watch slots, which is
  up to about 128 req/s of pure polling overhead before any rows. Replay buffers and cursor
  bookkeeping exist only to make polling lossless-ish.
- **Maintainer or agent:** The maintainer requires finite approved live views (AGENTS
  "Accepted live-watch refinement"). The transport is agent-added; nothing in AGENTS forbids
  streaming.
- **Replacement:** For the browser, use one Server-Sent Events (`text/event-stream`) response per
  watch, bounded by the watch's lifetime and byte budget. The handling replica subscribes to the
  source and pushes rows; reconnect uses `Last-Event-ID` = `(sourceSessionId, sequence)`, and a
  gap event is sent when the position has aged out. Precedents: Kubernetes `?watch=1` chunked
  streams with resourceVersion resume, Loki `/tail` (WebSocket), Grafana Live, GitHub Actions log
  streaming. Authority is checked once at open and reused under ADR-311 (30 s). For MCP, keep the
  bounded `read_live_watch` tool as the baseline: MCP tools are request/response, and
  `notifications` are optional. The SQL control row then shrinks to slot accounting, and the
  replay buffer shrinks to the SSE resume window.
- **Must change consistently:** `specs/live-watch.md` REQ-LIV-003/004,
  `docs/interfaces/README.md:70-74`, `docs/interfaces/browser-openapi.yaml` (live operations),
  `specs/contracts/live-watch.schema.json`, `docs/architecture/console-runtime.md`.

### S5-02: Capture, query, grant and download status is polled, with no server wait or push
- **Where:** `specs/mcp.md:39` (`get_grant` "Poll"), `:43`, `:66`, `:79`, `:89-92` ("Four paid
  polls ... Clients honor the returned not-before interval"), `:263` ("retry interval"), `:317`;
  `specs/interfaces.md:34`; `specs/guidance.md:103`; `docs/interfaces/browser-openapi.yaml:767`,
  `:1210` (`PollInput`, `retry_after_seconds` everywhere).
- **Current design:** Clients (browser console and agents) re-POST `get_capture`,
  `get_query_result`, `get_grant` and `get_artifact_download` on a server-advised retry interval.
  The pod-status profile also counts and charges polls ("four paid polls").
- **Problem class:** Client polling where server-side events exist (PostgreSQL row changes,
  connector receipts). Bespoke poll budget accounting.
- **Cost:** Each poll is a full authorization, SQL read and envelope build, multiplied by open
  console tabs and agents. Human approvals take minutes, so `get_grant` polling is pure waste.
  Charged polls add a ledger and an error path that clients must handle.
- **Maintainer or agent:** Agent-added. The maintainer asked for the discovery → preview →
  request → status flow, not for a polling mechanism.
- **Replacement:**
  1. Add a bounded server-side wait to every status read: `wait_for_revision_after: <rev>`,
     `timeout ≤ 25 s`, satisfied by PostgreSQL `LISTEN/NOTIFY` on the capture/query/grant
     revision channel (Kubernetes watch with resourceVersion; GitHub/Consul blocking queries
     with `?index=`). This works unchanged for MCP and stateless replicas, and matches the
     standard MCP polling model (MCP 2025-11-25 Tasks use `tasks/get`, with
     `notifications/tasks/status` optional).
  2. Give the console one SSE stream per open case/capture page, pushing revision changes.
  3. Delete "paid polls", poll ceilings and not-before advice for pending reads. A poll is a free
     read of current state; only actual source-read batches cost anything.
- **Must change consistently:** `specs/interfaces.md` REQ-INT-003, `specs/mcp.md` REQ-MCP-002 and
  REQ-MCP-005, `docs/interfaces/browser-openapi.yaml`, `specs/contracts/mcp-tools.json` and
  `mcp-result.schema.json` (retry fields), `docs/architecture/context-projection.md`,
  `docs/architecture/console-runtime.md`.

### S5-03: Pod-status read profile uses an at-most-five-second authority interval and reconstructs authority per poll
- **Where:** `specs/mcp.md:85-103` ("Each public request retains its own original
  at-most-five-second authority interval; polls reconstruct that request authority"), `:129-132`;
  `specs/interfaces.md:34` ("Reauthorize every poll and result delivery"); `specs/mcp.md:43`,
  `:289`.
- **Current design:** Each request and each poll rebuilds a five-second authority observation.
- **Problem class:** Per-step revalidation and expiry-driven freshness. Directly contradicts the
  maintainer rule.
- **Cost:** Identity, permission and deny reads on every poll and delivery. Five-second windows
  expire during the 60 s cold-start query lifetime, which forces repeated full authorization.
- **Maintainer or agent:** The maintainer decided the opposite. ADR-311 (AGENTS "Security
  proportionality") checks authority once per operation and reuses it for 30 s (60 s for the
  delivery policy), and says "Do not reintroduce stacked five-second authority windows."
- **Replacement:** Authorize at query creation. Reuse that decision for
  `identity.AuthorityRecheckInterval` (30 s), capped at the original deadline, then do one
  recheck for the next delivery. Rewrite REQ-INT-003 to "authorize each operation and reuse
  within the ADR-311 interval". SC-INT-003 can then say "a revoked share fails within 30 s".
- **Must change consistently:** `specs/interfaces.md` REQ-INT-003 and SC-INT-003,
  `specs/mcp.md` REQ-MCP-002 and SC-MCP-006, `specs/syscalls.md`, `specs/packets.md` (query
  delivery), `docs/architecture/context-projection.md`.

### S5-04: Each approved pod-status read is a Kubernetes Job plus worker enrollment
- **Where:** `specs/mcp.md:83-103` ("finite 60-second query lifetime for cold Job startup and
  independent worker enrollment (ADR-219 and ADR-221)"), `:123-132` ("positively joined private
  read", "remote quiescence", "uncertain worker, key or provider spend"); contracts
  `worker-enrollment.schema.json` ("queryID (approved pod status)").
- **Current design:** Reading a ≤ 4096-byte stored extract dispatches an acquisition Job. The
  Job enrolls a CSR-based worker identity, unwraps keys through the key service, reads and
  returns the result. Uncertain closure keeps worker, key and provider spend charged.
- **Problem class:** A per-request Job does not scale. Bespoke enrollment and PKI. "Spent on
  uncertain" accounting.
- **Cost:** Seconds to tens of seconds of latency (image pull, scheduling, CSR signing) to show
  4 KiB. One Job per read is etcd and scheduler churn that grows with agent query volume. The
  60 s query lifetime exists only to absorb cold start.
- **Maintainer or agent:** Agent-added (ADR-219/221 implementation notes). The maintainer
  requirements are wrap-only collectors with "no hub raw unwrap" and native downloads. Neither
  requires a Job per read.
- **Replacement:** Run one long-lived regional query/download worker Deployment (HPA-scaled),
  authenticated with a mounted cert-manager or Helm-issued certificate and TokenReview (ADR-328:
  trust the platform). It serves reads over a pooled connection, the way Loki queriers, Tempo
  queriers and Pyroscope serve object-store reads. Approved extracts like pod-status could even
  be decrypted by the hub's key-service client, since they are not raw. Reads become idempotent
  and free to retry, with no positively-joined-cleanup accounting.
- **Must change consistently:** `specs/artifact-downloads.md` (same Job model),
  `docs/architecture/context-projection.md`, ADR-219/221 text, `worker-enrollment`,
  `worker-control` and `worker-configuration` schemas, `specs/capacity.md` (query worker spend).

### S5-05: CapacityReservation and DeliveryWork are per-operation CRDs that duplicate hub SQL state
- **Where:** `specs/apis.md:15-16`, `:23`, `:25`, `:27`; contract `local-start.schema.json`;
  `specs/ergonomics.md:13-19`.
- **Current design:** Every on-trigger attempt creates a `CapacityReservation` object (Pending →
  Ready → Spent/Committed → Released | Indeterminate, pinned to the "original object UID"). Every
  record or event delivery creates a `DeliveryWork` object. The hub keeps central
  CapacityAccount, CapacityReservation and DeliveryWork *rows* for the same facts (line 25).
- **Problem class:** Kubernetes CRDs used for high-churn runtime records. Duplicated state
  machines and ledgers. UID pins and journals ("Missing, replaced or uncertain state cannot
  authorize a retry").
- **Cost:** Object writes and watch events scale with capture and delivery rate per cluster.
  The project's own PostgreSQL proposal cites the Kubernetes guidance against this
  (`specs/changes/postgresql-hub-state/proposal.md`, "Evidence behind the reassessment").
  Two reconcilers keep hub and local copies in agreement.
- **Maintainer or agent:** The maintainer requires storm protection and durable quota (AGENTS
  "Authority and invariants"). Per-attempt CRDs, UID pins and the start journal are agent-added.
  ADR-328 forbids UID pins and journals for installer-trusted state.
- **Replacement:** The hub SQL reservation stays authoritative (already in REQ-DB). The connector
  holds a prepaid local allowance as aggregate counters in one `CapacityAccount.status` per
  namespace/node, written with resourceVersion CAS, and keeps per-attempt state in memory plus
  idempotent operation IDs. The hub de-duplicates by operation ID on reconnect. Delivery uses an
  in-memory queue rebuilt from hub work state after reconnect, as Argo CD agent, OCM work-agent
  and Karmada pull-mode agents do. Retries are idempotent by `operationID`, replacing
  "cannot authorize a retry".
- **Must change consistently:** `specs/capacity.md` REQ-CAP-005, `specs/federation.md`
  REQ-FED-002, `specs/persistence.md`, `docs/architecture/local-start.md`, contracts
  `local-start`, `capacity-local-owner` and `live-capacity`, and the Helm CRD set.

### S5-06: Preview handles are stored server-side, which forces a separate recovery mutation
- **Where:** `specs/mcp.md:58`, `:68`, `:247` (5-minute handles, 10 per principal / 1,000 per
  installation storage), `:255-261` (`resolve_capture_request`, "permanently closes an
  unaccepted reviewed request", "Only an acknowledged `closed` result permits editing"),
  `:261` (`continue_acquisition`); `specs/guidance.md:105` (recommendation handles with
  "bounded encrypted content storage", same allocation); `specs/ergonomics.md:47`.
- **Current design:** Preview creates a stored, expiring, principal-bound handle. Submit
  references it. A lost reply needs a dedicated `resolve_capture_request` mutation that either
  returns the accepted capture or permanently closes the preview. Only then may the user
  re-preview.
- **Problem class:** Expiry-driven state. Exactly-once machinery where an idempotency key
  suffices. A global 1,000-entry cap (one contention point; 100 active users exhaust it).
- **Cost:** A SQL planning store with eviction, a nondisclosure-sensitive recovery tool, a
  closure race with in-flight submitters ("Server closure must prevent later admission"), and
  confusing UX: users cannot simply edit after a timeout.
- **Maintainer or agent:** The maintainer requires preview before submit and the
  discovery → preview → request → status flow (`specs/ergonomics.md:109`, the "MCP uses ..."
  sentence). The handle store and resolve/close protocol are agent-added (ADR-103 notes).
- **Replacement:** Keep preview stateless: a dry-run returning the resolved plan plus a
  `plan_digest`. Submit carries the request, `expected_plan_digest` and `Idempotency-Key`. The
  server recomputes and rejects on digest mismatch (precedents: Kubernetes `dryRun=All` +
  apply, Terraform plan/apply with saved plan hash, HTTP `If-Match`). A lost reply is retried
  with the same key, which returns the original capture, per Stripe/IETF
  `draft-ietf-httpapi-idempotency-key-header`. An abandoned preview needs no closure because
  nothing was stored. Delete `resolve_capture_request`, preview storage quotas and
  `continue_acquisition` (a connector resumes accepted work by operation ID; see S5-09).
- **Must change consistently:** `specs/capture-history.md` (history_capture_id preview),
  `specs/recording-saves.md`, `specs/guidance.md` REQ-GDE-006, `specs/capture-assessment.md`
  (validity), `specs/execution.md`, `docs/interfaces/browser-openapi.yaml`,
  `specs/contracts/mcp-tools.json`, `guidance.schema.json`, `recording-save.schema.json`.

### S5-07: Disclosure blocks on encrypted object-store audit per read or poll
- **Where:** `specs/mcp.md:127-128` ("Audit failure before outcome acknowledgement prevents
  disclosure"), `:131` ("exact outcome audit"), `:188` ("Each invocation still has its own audit
  request ID"), `:235` (`AuditUnavailable`); `specs/interfaces.md:9-14` ("no new
  capture/custody/audit writes", ADR-160 purpose split).
- **Current design:** Every read, query batch or delivery writes an encrypted audit object
  (KMS-wrapped, object store) and waits for acknowledgement before returning data.
- **Problem class:** Synchronous encrypted, object-store and KMS work on the hot path for every
  request.
- **Cost:** Each MCP extract call or delivery adds an object PUT and key wrap on top of SQL,
  plus another unavailable state. Throughput is limited by object-store PUT latency; audit-store
  outages take down reads of already authorized evidence (contrary to REQ-UI-003 "Stored
  authorized evidence remains usable").
- **Maintainer or agent:** The maintainer requires audit and creators as immutable audit actors.
  Synchronous per-request encrypted objects are agent-added.
- **Replacement:** Append the audit row in the same PostgreSQL transaction as the
  disclosure/charge (durable, synchronous, cheap). A background exporter batches rows into
  encrypted object-store segments and hash-chains them if tamper evidence is needed
  (precedents: Kubernetes API audit `--audit-webhook-mode=batch`, Teleport audit log to
  DynamoDB/S3 via async uploader, Sentry/Grafana audit tables). Fail closed only when the SQL
  append fails.
- **Must change consistently:** `specs/evidence.md` (audit), `specs/persistence.md`,
  `specs/artifact-downloads.md`, `specs/authorization.md` (audit), `specs/syscalls.md`,
  `specs/packets.md`, the history-ciphertext and audit contracts.

---

## Medium

### S5-08: AccessBinding location is obsolete (ADR-329)
- **Where:** `specs/apis.md:18`, `specs/changes/postgresql-hub-state/proposal.md` (ownership
  table).
- **Current design:** "Hub control namespace; authorized permission administrators/provisioners".
- **Problem class:** Obsolete text contradicting a maintainer decision.
- **Cost:** Implementers keep a central hub-namespace binding store and cross-cluster
  propagation.
- **Maintainer or agent:** Maintainer decision 2026-11-13 (AGENTS "Threat model"): "AccessBindings
  move to the application namespaces they grant, managed by ordinary namespace RBAC and observed
  by each region's connector (ADR-329)."
- **Replacement:** Change the row to "Application namespace; namespace RBAC writers; observed by
  the regional connector via informer". Annotate the proposal table as superseded.
- **Must change consistently:** `specs/permissions.md`, `specs/authorization.md`,
  `specs/ergonomics.md:21` ("No per-workload AccessBinding"; still true),
  `access-binding.schema.json`, Helm RBAC.

### S5-09: Uncertain starts stay spent, and a separate `continue_acquisition` flag exists
- **Where:** `specs/mcp.md:101` ("Prior spend and uncertainty remain charged"), `:126`, `:132`,
  `:193-194` ("Failure or uncertain closure does not refund either budget"), `:261`
  (`continue_acquisition: true`), `:265` ("never refunds uncertain spend"); `specs/apis.md:27`.
- **Current design:** Any uncertain start, read batch or disclosure stays charged permanently.
  Resuming accepted work needs an explicit user-supplied flag with a "fresh-current attempt".
- **Problem class:** "Spent on uncertain" accounting where idempotency keys suffice.
- **Cost:** Quota leaks on every timeout. Users exhaust grants through network blips. More
  states (Indeterminate everywhere) and support load.
- **Maintainer or agent:** The maintainer's "retain uncertain spend" appears in AGENTS only for
  database restore (ADR-096) and crash finalization research notes. Per-read query spend and
  continue flags are agent-added.
- **Replacement:** Use idempotency keys on all paid operations and execute-at-most-once by key.
  A retry with the same key returns or resumes the same attempt. Reconcile charges from the
  connector's terminal receipt, refunding unused reservation when the receipt says not-started
  (Stripe idempotency; Kubernetes Job `backoffLimit` with pod UID tracking). Keep
  "Indeterminate" only for intrusive actions (dumps, liveCore) where the side effect matters,
  which REQ-FED-002 already covers. Delete `continue_acquisition`.
- **Must change consistently:** `specs/capacity.md`, `specs/investigation-approval.md` (parent
  pool spend), `specs/syscalls.md`, `specs/packets.md`, `specs/artifact-downloads.md`.

### S5-10: ExecutionPermit carries a signed plan; work items are signed on top of mTLS
- **Where:** `specs/apis.md:21` ("Prepaid grant slice and signed immutable plan"); `:90-93`;
  related `docs/architecture/interfaces.md:35` ("up to 16 signed items"); contracts
  `work-trust.schema.json` and `api-context-work-trust.schema.json`.
- **Current design:** The hub signs each work item and plan. The connector verifies against
  pinned work-signing trust, inside an mTLS channel and inside an administrator-only namespace.
- **Problem class:** Bespoke crypto layer defending against trusted actors (namespace writers,
  ADR-328) and duplicating TLS channel authentication.
- **Cost:** A signing key service, trust ConfigMaps, rotation, verification per item, and two
  extra contracts.
- **Maintainer or agent:** Agent-added. ADR-328 says "Do not design mechanisms that defend
  against ... tampered ConfigMaps or Secrets in those namespaces".
- **Replacement:** Rely on mTLS peer identity for hub → connector authenticity, as OCM
  ManifestWork, Argo CD agent and Karmada do (no per-object signatures). The permit is a plain
  CR or in-memory record written only by the connector service account (RBAC). Drop `work-trust`
  and `api-context-work-trust`.
- **Must change consistently:** `specs/federation.md` REQ-FED-002, `docs/architecture/interfaces.md`
  I-01, `specs/execution.md`, `docs/interfaces/README.md:22` ("signed permits").

### S5-11: Internal endpoint table is stale, and the long-poll wake-up source is unspecified
- **Where:** `specs/apis.md:84-95`.
- **Current design:** `/internal/v1/enroll|heartbeat|work:poll|work/{id}:ack|records|query-results`,
  long poll at most 30 s. The architecture uses `/internal/v1/federation/negotiate|poll|receipts|heartbeat|resolve-reference`
  with 25 s and 16 items (`docs/architecture/interfaces.md:31-35`).
- **Problem class:** Duplicated, drifting contracts. A potential timer-driven queue (the spec
  never says what wakes a parked long poll).
- **Cost:** If the hub implementation re-queries SQL on a timer to answer parked polls, cost
  becomes clusters × poll rate. Heartbeat is a separate POST every 15 s on its own connection.
- **Maintainer or agent:** Agent-added. "No mandatory broker" is the maintainer's constraint.
- **Replacement:** Replace the table with a link to I-01. State that parked long polls are woken
  by PostgreSQL `LISTEN/NOTIFY` (or an in-process signal on the owning replica), with a full
  resync only after reconnect or cursor mismatch. Count an active long poll as liveness and drop
  the separate heartbeat POST, or keep a `coordination.k8s.io` Lease-style 15 s heartbeat only
  while idle (node Lease precedent). Long polling itself is acceptable push over an outbound
  connection; the maintainer rule targets polling where events exist.
- **Must change consistently:** `specs/federation.md` REQ-FED-002, `docs/architecture/interfaces.md`
  I-01/I-02, `docs/architecture/node-collector.md` (25 s hold).

### S5-12: PermissionSource still carries guard qualification
- **Where:** `specs/apis.md:20` ("Typed derivation rule, scope, trusted mapping, guard
  qualification and freshness").
- **Current design:** The permission source includes a guard qualification and freshness.
- **Problem class:** Obsolete installer/guard-era text. Expiry-driven freshness.
- **Cost:** Implementers keep admission-guard proofs and five-second complete-deny refresh loops
  (`docs/architecture/permission-acceptance.md:13`).
- **Maintainer or agent:** The maintainer removed guards (2026-11-13: "Plain RBAC replaces
  UID-pinned admission guards and their proofs"; memory "Trust the platform").
- **Replacement:** "Typed derivation rule, scope and trusted mapping; readiness Condition". Use
  informer-cached state that stays valid until replaced (event-driven rule).
- **Must change consistently:** `specs/permissions.md`, `permission-source.schema.json`,
  `docs/architecture/permission-observation.md` and `permission-acceptance.md`.

### S5-13: Installer-era composition rules in interfaces and ergonomics
- **Where:** `specs/interfaces.md:9-18` (ADR-160: "fixed SQL purposes", "Missing or foreign
  installation dependencies MUST reject startup", "An incomplete older credential layout MUST
  reject; runtime MUST NOT silently manufacture its missing purpose receipts");
  `specs/ergonomics.md:13-19` ("Regional context-executor installation MUST require the
  operator-managed local start API before creating installation resources ... The installer
  must not create or adopt the cluster-scoped CRD").
- **Current design:** Startup validates installer-produced receipts and credential layouts. A
  regional installer checks CRD discovery before creating objects.
- **Problem class:** Obsolete installer era and self-verification of installer state.
- **Cost:** Startup failure modes and receipt contracts that Helm no longer produces.
- **Maintainer or agent:** The maintainer replaced the installer with Helm (2026-11-13, AGENTS
  "Security proportionality"). ADR-328 says "Do not add runtime re-verification of
  installer-created objects ... journals or launch receipts."
- **Replacement:** In interfaces.md, keep "one shared application assembly; browser and MCP use
  the same services" and delete the receipt and credential-layout rules. In ergonomics.md: "Helm
  installs the CRDs (crds/ directory, CRD upgrade ordering per ADR-058); the chart fails
  rendering/install if a prerequisite CRD is missing".
- **Must change consistently:** `docs/decisions/160-*`, `docs/installation/helm.md`,
  `charts/asservat/README.md`, the ~33 installer-era contracts (S5-19).

### S5-14: Capture progress has several overlapping state machines
- **Where:** `specs/apis.md:49-82` (Capture, Artifact, Analysis machines); `specs/mcp.md:265`
  (ADR-105 durable intent → custody → verification → audit → publication revisions);
  `specs/apis.md:16` (CapacityReservation states); `specs/federation.md` REQ-FED-002 (Queued →
  Leased → Accepted → Running → terminal).
- **Current design:** One manual capture traverses roughly four separately persisted machines.
  "Only audited verified catalog publication is Succeeded".
- **Problem class:** Duplicated state machines, journals and receipts for the same fact.
- **Cost:** Each transition is a SQL write, some with object-store audit. More Indeterminate
  combinations and harder status projection.
- **Maintainer or agent:** Agent-added (ADR-105).
- **Replacement:** One capture/attempt phase (Kubernetes Job-style phase plus Conditions:
  `Accepted`, `Collected`, `Verified`, `Published`). The artifact keeps its own lifecycle. Work
  lease state becomes an implementation detail of the work queue, not a public state.
- **Must change consistently:** `specs/execution.md`, `specs/federation.md`,
  `specs/persistence.md`, `specs/evidence.md`, `capture.schema.json`, `action-lifecycle.schema.json`.

### S5-15: Assessment and planning freshness windows force re-reads
- **Where:** `specs/mcp.md:255` ("assessment's original five-second validity"),
  `specs/guidance.md:105` (handles "expire within five minutes or earlier source expiry"),
  `specs/guidance.md:32` ("Reuse sufficiently fresh authorized evidence").
- **Current design:** Assessments are valid for 5 s. Submission must re-read current facts
  anyway.
- **Problem class:** Expiry-driven freshness windows.
- **Cost:** The 5 s validity serves no purpose, because submission re-evaluates (mcp.md:255
  already says it rechecks). It invites UI regeneration loops that the spec then has to forbid
  ("must not generate a replacement preview every five seconds").
- **Maintainer or agent:** Agent-added.
- **Replacement:** The assessment has a digest and no validity. Submission recomputes it and
  rejects on digest change, the same mechanism as S5-06. Cached capability, rule and catalog
  data stays valid until the informer replaces it.
- **Must change consistently:** `specs/capture-assessment.md` (validity),
  `capture-assessment.schema.json` (`valid_until`), `specs/guidance.md`.

### S5-16: Raw-query idempotency adds a one-use disclosure reservation and ledgers
- **Where:** `specs/mcp.md:136-143`, `:184-194`.
- **Current design:** The idempotency key binds the query. Separately, a "one-use disclosure
  reservation", "immutable grant-use ledgers" and a worst-case bytes reservation are kept with
  no refund. Subsequent pages need fresh keys.
- **Problem class:** Multiple ledgers for the same fact; no refund on uncertain outcomes.
- **Cost:** Every page is a new key, reservation and ledger row, and every retry needs careful
  replay comparison.
- **Maintainer or agent:** The finite parent disclosure pool is maintainer-selected (AGENTS
  "one bounded independent approval ... finite parent disclosure pool"). The reservation, ledger
  and no-refund details are agent-added.
- **Replacement:** One `grant_use` row per (grant, idempotency key) holding charged bytes and
  operations. Debit actual returned bytes at delivery in the same transaction as the audit row
  (S5-07). A retry returns the stored result reference. Pages use the authenticated cursor under
  the same key.
- **Must change consistently:** `specs/syscalls.md` REQ-SYS-003, `specs/packets.md`,
  `specs/investigation-approval.md`, `specs/authorization.md` (grant spend).

### S5-17: Cursors expire and bind revisions
- **Where:** `specs/mcp.md:77`, `specs/interfaces.md:34`, `specs/guidance.md:107` ("Recheck every
  source artifact, including on pagination").
- **Current design:** Cursors are authenticated and expire within 15 minutes. They bind
  grant/share revisions and dataset generation. Each page fully re-authorizes.
- **Problem class:** Expiry to force refresh and per-page revalidation. Mild, but it compounds
  with S5-03.
- **Cost:** Paging a long timeline fails whenever an unrelated share revision ticks. Each page
  repeats authorization.
- **Maintainer or agent:** Agent-added.
- **Replacement:** Use an HMAC-authenticated cursor bound to principal/client and query (keep).
  Drop the expiry and revision binding. Authorize each page through the ADR-311 cached decision;
  a revoked share fails within 30 s. Kubernetes `continue` tokens expire only when etcd
  compaction makes them unusable, and GitHub/Slack cursors don't expire.
- **Must change consistently:** `specs/contracts/mcp-result.schema.json`, `specs/live-watch.md`
  (cursor), `specs/capture-history.md`.

### S5-18: Global 1,000-handle planning allocation
- **Where:** `specs/mcp.md:247`, `specs/guidance.md:105`.
- **Current design:** Preview and recommendation handles share 10 per principal and 1,000 per
  installation.
- **Problem class:** Global bounded shared resource (cross-user denial of service), only needed
  because of S5-06.
- **Cost:** About 100 active planners exhaust installation previews, and eviction breaks other
  users' reviews.
- **Maintainer or agent:** Agent-added.
- **Replacement:** Disappears with stateless previews (S5-06). Otherwise keep only the
  per-principal cap.
- **Must change consistently:** Same as S5-06.

---

## Low

### S5-19: About 33 installer, guard and journal contracts remain in `specs/contracts/`
- **Where:** for example `initial-installer`, `initial-preparation*`, `initial-bootstrap-*`
  (10 files), `installation-witness`, `capacity-root-setup-claim`, `*-projection-claim`,
  `configuration-role-installer`, `hub-worker-activation`, `owner-identity-role-state`,
  `owner-relay`, `owner-worker-trust`, `submission-trust`, `work-trust`.
- **Current design:** Their descriptions say "Exact Pod/account/source/admission pins",
  "creation journal", "one-use installation witness", "five-second claim inside the original
  thirty-minute role setup".
- **Problem class:** Obsolete installer and guard era. UID pins and journals.
- **Cost:** Schema-check gates, docs and code keep machinery alive.
- **Maintainer or agent:** The maintainer removed the installer Pod and guards (2026-11-13).
- **Replacement:** Delete them together with the Helm-native migration
  (`docs/reviews/helm-native-install-plan.md`). Keep only schemas for user-authored CRDs and
  public DTOs. Mark `specs/apis.md:103` "Schema scope" accordingly.
- **Must change consistently:** the `specs/traceability.yaml` and `scripts/*schema*` bundles.

### S5-20: Reauthorizing session state on page-cache restore is fine; progress transport is unspecified
- **Where:** `specs/user-experience.md:21-30` (REQ-UI-003).
- **Current design:** States are listed. "Disconnected" and progress updates have no transport.
- **Problem class:** Missing event-driven requirement, which invites ad-hoc polling in the
  console.
- **Cost:** Each tab polls each operation.
- **Maintainer or agent:** n/a.
- **Replacement:** Add "progress updates are pushed via the S5-02 stream; disconnected = stream
  closed and resync on reconnect".
- **Must change consistently:** `docs/architecture/console-runtime.md`.

### S5-21: Oversized special result budget for `preview_recording_save`
- **Where:** `specs/mcp.md:75` (128 KiB / 256 KiB to carry up to 64 retention-policy digests
  per source × 16 sources).
- **Current design:** A tool-specific budget exception exists to ship policy digests to an
  agent.
- **Problem class:** A configuration exception for internal provenance the agent cannot use.
- **Cost:** It breaks the uniform 24/32/64 KiB contract.
- **Maintainer or agent:** Agent-added.
- **Replacement:** Return one aggregate effective-retention summary per source plus an
  authenticated navigation link for details. Remove the exception.
- **Must change consistently:** `recording-save.schema.json`, `specs/recording-saves.md`.

### S5-22: `AnalysisRequest` is a CRD per analysis job
- **Where:** `specs/apis.md:22`.
- **Current design:** Each analysis creates a local CR, the controller creates a Job, and bounded
  results go into status.
- **Problem class:** Per-request objects (moderate; analysis is rare and Jobs are already
  objects).
- **Cost:** Two objects per analysis.
- **Maintainer or agent:** Agent-added.
- **Replacement:** Create the Job directly from hub work, labeled with the operation ID. Results
  return via the existing receipt channel, like Argo Workflows or Tekton task runs, without an
  intermediate CR. Acceptable to keep if analysis volume stays low.
- **Must change consistently:** `specs/evidence.md` (analysis), `specs/federation.md`.

### S5-23: Survey rate ceilings are hard-coded design values
- **Where:** `specs/guidance.md:58`.
- **Current design:** One in-flight survey per workload, one start per 30 s, ten per hour, on
  top of shared capacity accounts.
- **Problem class:** Rate limits layered on top of the capacity accounts that already protect
  against storms.
- **Cost:** A small extra limiter and configuration.
- **Maintainer or agent:** The maintainer requires storm protection, so the ceilings are
  defensible. They duplicate the shared rate account.
- **Replacement:** Express them as defaults of the existing per-workload rate budget, not a
  separate limiter.
- **Must change consistently:** `specs/capacity.md`.

### S5-24: Sticky-free MCP fine, but live owner routing contradicts "stateless"
- **Where:** `specs/mcp.md:313`.
- **Current design:** "Any authenticated hub replica can resolve its SQL control record and
  dispatch a bounded read to the current fenced projection owner through internal service
  routing".
- **Problem class:** Bespoke internal routing and fencing to emulate a session.
- **Cost:** Cross-replica hop per read, owner fencing and failover gaps.
- **Maintainer or agent:** Agent-added.
- **Replacement:** With S5-01's SSE stream, the replica serving the stream owns the subscription
  for its lifetime. For MCP reads, route to the connector/node source directly (the source
  already holds the 5 s buffer), so there is no hub projection owner.
- **Must change consistently:** `specs/live-watch.md`, `docs/architecture/*live*`.

---

## Items checked and found acceptable
- Connector outbound HTTPS long poll (`specs/federation.md:81`). This is push over an existing
  connection and matches the event-driven rule, provided the wake-up uses NOTIFY (S5-11).
- MCP stateless Streamable HTTP and tool polling as the MCP baseline: standard per MCP
  2025-11-25. The fix is a server-side wait, not notifications (S5-02).
- Browser mutation `ETag`/expected revision plus `Idempotency-Key` (`specs/apis.md:99`): standard.
- Browser-only approvals, no MCP approve tool, typed `debugger_command` and `pcap_query` grammar:
  maintainer and safety requirements with clear precedent.
- CRD structural schemas, CEL, VAP and Conditions conventions (`specs/apis.md` REQ-API-002):
  standard Kubernetes API conventions.
