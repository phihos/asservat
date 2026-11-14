# Live observation of ongoing captures

Live watch shows rows from already running packet and syscall recorders in the browser and MCP. Watching never starts a collector, widens acquisition or pins a recording window. The [wire contract](contracts/live-watch.schema.json), [research](../docs/research/live-watch.md) and [mockups](../docs/ux/README.md) define the boundary. The projections are packet/flow metadata, HTTP headers and syscall metadata; packet bytes, bodies, memory and syscall arguments need saved artifacts and the existing raw-query review.

## REQ-LIV-001 — Eligible sources and current authority

`list_recordings(target_ref)` (shared with [recording saves](recording-saves.md)) lists the workload's policy and manual-session recorders with state, supported projections, history, hard end, save eligibility and blockers. Opening the page arms nothing. With no source, it links to a bounded capture or policy setup.

A viewer needs evidence-read entitlement for the source's audience (`evidence:read` for OAuth clients), and the CollectionCeiling must allow live reads. Viewing acquires nothing, so it needs no collection entitlement (ADR-335 D5). The source's executor authority and sensitive grant must still hold. A share, creator status or handle alone is not enough. Opening needs no human approval.

A watch selects one or more running (`Warming`, `Ready`, `Degraded`) sources of one workload, so a viewer can watch all authorized replicas. The projection must be authorized for every selected source; mixed selections are refused, not trimmed. Audiences are never unioned. New pods and replacement sources are not added automatically. Stopped sources are inspected through saved evidence.

### SC-LIV-001

Given an evidence reader, a share-only recipient and a replaced pod, when they request live sources, then only the reader sees them, without collection rights, and an old handle cannot reach the replacement recorder. Revoking the policy executor's authority ends delivery even if the viewer keeps their role; for a team policy, creator departure alone does not. A departed viewer loses access independently.

## REQ-LIV-002 — Watch lifetime and filters

A `LiveWatch` is a caller-bound view separate from the capture and the source. It starts at the current head with no backfill. It stays open while a browser stream is connected or MCP reads arrive at most 10 minutes apart (ADR-335 D9), and ends at Close, at the source's hard end or on loss of access. It never extends the source.

Opening authorizes the viewer and every source once, reused under [REQ-INT-003](interfaces.md#req-int-003--bounded-errors-retries-and-asynchronous-work) and then re-evaluated from the hub's event-fed permission state. Revocation, deny, grant loss, source end, pod replacement and retention cut-offs reach the watch as events and end the affected delivery (ADR-330 D1, D5). No per-row check is made.

Display filters narrow approved projected fields only: protocol, peer identity, remote IP, port, HTTP status and method, syscall name, error and PID, with literal values and field-specific operators. They never change acquisition filters, peers, ring or grant. No CEL, regex, payload or header-name expressions. A filter change or Pause/Resume carries the `expected_revision` it read (a stale one is refused), increments the `revision` and resumes at the current head with a `filterChanged` or `paused` gap. Pause stops delivery for that viewer only; state changes still arrive. Reconnecting resumes from the current head with a gap; no cached rows are replayed beyond REQ-LIV-003.

### SC-LIV-002

Given two viewers with different filters, when one changes filters or pauses, then the other view and the recorder are unchanged. Resuming does not backfill, no new source is substituted, and a stale-revision update cannot overwrite a newer view.

## REQ-LIV-003 — Delivery and gaps

The browser receives rows, gaps and state changes over one Server-Sent Events stream per watch and reconnects with `Last-Event-ID`. MCP uses `watch_live(action=read)`: batches of default 20 rows within the MCP result bound ([apis.md](apis.md#bounds-in-the-contracts)), `wait_ms` 0–30000, returning on the first row or state change (ADR-330 D1). One read is outstanding per watch; a new read supersedes it. An empty batch is a timeout, not end of stream. Open and close are idempotent.

Every row carries the watch revision, its identity `(sourceSessionId, sequence)`, observed and received times, coverage and gap reasons; sequence is monotonic per source, with no cross-node order. HTTP rows appear only after a complete bounded projection. Cursors and event IDs are bound to the caller and watch; they are not grants.

Each watch keeps replay for 16 s of its delivery rate (1 MiB at the default 64 KiB/s) for reconnects; an older position yields a gap and the current head. Watch state lives in memory on the serving hub replica, which receives source rows over the connector connection (ADR-330 D2); if it fails, the client reconnects to another replica, which resumes with a gap. Gaps distinguish filtered rows, sensor loss, sampling, overflow, reconnect and unknown coverage; unknown counts are never shown as zero.

### SC-LIV-003

Given a slow reader or lost response during source rotation, when the client resumes, then duplicates are identifiable, gaps are explicit and no other source fills them. A quiet, fully observed interval is distinguishable from a disconnected source.

## REQ-LIV-004 — Protect collection and workload resources

Live views have one rate limit and one concurrency limit, both derived and adjustable by administrators:

- **Delivery rate per watch:** 64 KiB/s by default; it bounds hub egress and replay memory per watch. Hub-api memory bounds the number of open watches.
- **Projection headroom per node:** the node collector's CPU request minus what armed sources and saves reserve ([capacity](capacity.md)); subscriptions beyond the measured parser cost of that headroom are refused.

A projection is shared by all viewers of the same source and projection, so more viewers cost only delivery. Slow readers are sampled or disconnected with visible loss; they never hold the collector, freeze rings or slow the workload. Saves have priority, and overload sheds live projections first. Live views reuse the recorder's grant and never parse beyond it. Streaming needs no broker, per-row SQL write or upload. Hub and collectors export watch, subscription, byte, refusal and drop metrics labelled only by cluster and projection.

### SC-LIV-004

Given a syscall storm and many viewers, when live budgets are exhausted, then views show sampled or missing data or stop, while recording and saves keep their resources. Another tab, a retry or a filter change cannot exceed the per-watch rate or the node headroom.

## REQ-LIV-005 — Privacy, transient data and saving

Projections have fixed approved fields, minimized before leaving the collector; HTTP header values use the saved-extract allowlist, and syscall metadata never reads buffers, filenames or arguments. Live data can still identify users. The browser keeps at most about 16 MiB of rows in a virtualized list, never past the source's content deadline, and clears them on close, logout or access loss; nothing is cached, persisted or put in URLs. A reload restores only the watch settings. MCP results state that rows are transient and that Asservat cannot recall what a client copied.

The watch is an SQL row (ADR-330 D8): caller, sources, projection, filters, revision, serving replica, last activity and delivered bytes. Open and close each write one audit row in the same transaction (ADR-330 D6). Row content never enters SQL, logs or audit.

Viewing is not evidence. **Save last N seconds** is the [recording save](recording-saves.md): it saves the source's window ending at acceptance, not the displayed rows, and may report rows already rotated out. It is offered for policy sources; a manual session already stores its own recording.

### SC-LIV-005

Given an approved HTTP row with a sensitive identifier, when the viewer closes or loses rights, then the browser clears it and no row enters SQL or audit. A later save reports its actual window. An evidence share grants no live access.

## REQ-LIV-006 — Human and agent experience

**Watch live** appears beside eligible recordings, policies, workloads and running manual captures; visiting a page never attaches. The view shows Live/Paused/Disconnected/Closed, hard end, last row times, loss and lag, and offers **Pause view**, **Resume from now**, **Close view**, **Save last N seconds** and **Connect agent**, with click-to-filter chips. Unsupported details link to saved-artifact inspection.

MCP uses `list_recordings` and `watch_live(action=open|read|update|close)`, all needing `evidence:read` and the rights of REQ-LIV-001, not `evidence:capture`. Agents read bounded batches. Browser and MCP share the row, gap, state and bound schemas; only the transport differs.

### SC-LIV-006

Given an evidence reader or agent, when they watch packet, HTTP and syscall metadata, then they can filter, pause, resume, close and save without confusing display and acquisition filters. An agent that reasons for several minutes between reads keeps its watch; share recipients have no live view.
