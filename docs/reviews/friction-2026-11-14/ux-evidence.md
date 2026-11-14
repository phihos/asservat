# UX friction audit — using evidence (downloads, saves, live watch, MCP, retention/sharing)

Worktree: /home/phil/Projekte/asservat-ux @ 5d4667715 (ADR-330 spec rewrite). Read-only.
Known items from the brief (join Secrets, bootstrap records, four connector endpoints, digest pinning) are excluded.

Severity: **high** = blocks or angers typical users; **medium**; **low**.
"Origin" says whether the friction comes from a MAINTAINER decision in AGENTS.md "Authority and invariants" (M) or was added by an agent (A).

## Step counts: "pod misbehaves" → local tool

| Path | Steps today (spec) | Comparable |
| --- | --- | --- |
| PCAP, a policy ring already armed with `recordingSaves.enabled: true`, header representation | Workload → Recordings → "Save last 30 s" → wait for Published → Case → Artifact → Download → open `artifact-<uuid>.pcapng`. ~6 clicks, no approval. **Acceptable.** | Kubeshark: dump the buffer, 1–2 clicks |
| PCAP, no armed recorder | Workload → goal/diagnostic → packet profile/peer picker → preview → Collect → (raw packets or a raw-byte filter: **second human approver with step-up**, and the requester must submit within **5 min** of approval) → capture records **from now** (no prehistory) → Download → (raw PCAP without `result_access` selected: **another independent review** via `request_raw_access`) → open. ~10 steps, 1–2 approvals by another person. | `kubectl sniff` / Kubeshark / `ksniff`: one command, no approver |
| Core from a policy-triggered crash | Case → core → Download → no covering raw grant → prefilled `request_raw_access` → **another human with `action-approver` + step-up approves** → Download core → download **each companion executable/library separately** (2 concurrent streams max) → arrange a sysroot by hand → `gdb`. ~9 steps plus a second person, inside a default **72 h** (example **6 h**) lifetime. | `coredumpctl gdb` (1 command); Sentry minidump: download in 1 click for project members |
| Live core (manual) | Compose → tick "Include my inspection and downloads in this review" → one independent approval → submit within 5 min → Download core + companions → sysroot → gdb. One approval if the user remembered the checkbox, otherwise two. | `kubectl debug` + `gcore`: no approver for someone with pod exec |

## Findings

### EVD-01 — Raw downloads of your own workload's core/PCAP need a second human approver — **high**
- Where: specs/artifact-downloads.md:23, :29, :31; specs/authorization.md:45; specs/investigation-approval.md:3, :15; docs/interfaces/mcp-workflows.md ("Download this capture/core…").
- What users do today: a workload maintainer whose policy captured a core (always raw), or who captured raw packets, cannot download it without a covering `rawQuery` grant with `download_artifact`, exact digests and byte budget. Getting one takes a review by a *distinct* human with `action-approver` and recent step-up. Self-approval is forbidden.
- Why it is friction: people who could debug the pod anyway have to wait for a second person. AGENTS.md says permission inheritance includes **pod exec rights**, and anyone with `pods/exec` can already `gcore`/`tcpdump` the live process. Sentry, coredumpctl, Pyroscope and Kubeshark let project or namespace members download their own dumps and captures without a co-signer. Out of hours, the approver is often missing while the artifact runs into a 6–72 h expiry.
- Origin: M in part. The maintainer chose "one bounded independent approval for manual collection and the same human's selected result inspection/download" (investigation-approval). That covers *manual* one-off captures. Treating every raw artifact as needing independent review before download, including policy-triggered cores whose collection was already reviewed, is A.
- Fix: (a) Let the reviewed policy grant carry result access for the workload's current maintainers, so download happens without a new review. (b) Add an installation setting (default on) that lets a principal who holds pod-exec-equivalent rights on the recorded workload download raw artifacts of that workload with audit only. Keep independent review for non-maintainers and for raw sharing. (c) Pre-tick "Include my inspection and downloads" by default for raw captures.

### EVD-02 — Started downloads are cut at the OAuth access-token expiry, and sessions default to 30 min — **high**
- Where: specs/artifact-downloads.md:19, :53, :55.
- What users do today: a started content GET ends at "the caller's session/token expiry". For OAuth clients that is the presented **access token**'s expiry, which is 5 min by default in Keycloak, the first supported IdP. The download session also defaults to **30 min**, and the transfer allowance is a "30-minute default" narrowed by grant `maxDuration`. A multi-GiB core over VPN gets cut every few minutes and needs Range resume with a fresh token. Once the session deadline passes, the user prepares again, and possibly needs a new approval if the grant has run out.
- Why it is friction: S3 presigned GETs, Artifactory and GitHub release downloads let a started transfer finish. ADR-312 already says started responses continue without rechecks, so cutting them at a short-lived token's expiry is an extra limit with no stated benefit.
- Origin: A. ADR-312 is a maintainer-approved *relaxation*. Token-expiry bounding and the 30-min default were agent-chosen.
- Fix: bound a started response only by `AccessUntil`, Stop, retention cut-off and its byte allowance, and drop token/session expiry once the response has started. Default sessions to `min(AccessUntil, 24 h)`. Allow resume while the covering grant and retention last.

### EVD-03 — Approval → submit window of 5 min; ad hoc approvals expire in 1 h; raw grants max 8 h — **high**
- Where: specs/investigation-approval.md:35; specs/authorization.md:45.
- What users do today: after an independent approval, "the same human submits it" and acceptance fixes a capture start window of at most **5 min**. Ad hoc capture approvals default to **1 h** and raw-query grants max out at **8 h**. A requester who goes to lunch while the approver decides finds the approval stale. An overnight investigation needs a new raw grant the next morning.
- Why it is friction: GitHub Environments wait up to 30 days for approval and run automatically once approved. Argo CD sync windows and PagerDuty-style approvals do not make the requester re-press a button within minutes.
- Origin: A (the "independent approval" is M; the timings are not).
- Fix: start the capture automatically on approval. If a manual submit must stay, let it be valid for the grant lifetime. Default raw-query grants to the artifact's `AccessUntil`, capped by the admin maximum.

### EVD-04 — Default retention is 72 h for evidence (the example uses 6 h for cores); shares last 24 h by default, 7 days max — **high**
- Where: specs/privacy.md:29; specs/evidence.md:103; specs/authorization.md:77, :113, :131; specs/privacy.md:88 (a hold cannot exceed the maximum).
- What users do today: a Friday-evening crash is unreadable by Monday morning. A postmortem a week later cannot cite or share the core. Shares default to 24 h with a hard 7-day ceiling, and capture-time sharing `notAfter` is also ≤ 7 days. A debugging hold cannot extend past the maximum. Recurring policy sharing is limited to ≤ 100 captures and ≤ 7 days after activation, so teams redo it weekly.
- Why it is friction: Sentry keeps events 30–90 days, Grafana snapshots and Loki use operator-chosen retention, Velero backups default to 30 days. A 72 h default fails the normal "investigate after the weekend" workflow.
- Origin: M that administrators enforce a *maximum*. The specific 72 h / 24 h / 7-day values and the hard-coded share ceiling are A.
- Fix: default evidence retention to 14 days (cores 7 days), case metadata 30 days. Make share default/max follow the artifact's `AccessUntil` (admin-configurable). Let recurring sharing run until the policy grant ends, or until an admin-configurable maximum.

### EVD-05 — Survey (discovery) evidence lives 15 min — **medium**
- Where: specs/guidance.md:60.
- What users do today: an "Inspect processes" or "Sample traffic for 10 s" result, and the recommendations built on it, expire after **15 min**. A user who is interrupted has to sample again, which uses up survey rate budget (1 per 30 s, 10/h, guidance.md:58).
- Why it is friction: comparable discovery views (Kubeshark service map, Pixie) stay available for the session or the normal retention.
- Origin: A.
- Fix: use the ordinary evidence retention (the header survey is already minimized), or at least 24 h.

### EVD-06 — Core companions are separate downloads with no gdb-ready bundle — **medium**
- Where: specs/artifact-downloads.md:11, :53 (two concurrent streams per principal); specs/evidence.md:132.
- What users do today: they download the core, then each executable/library companion one by one (max 2 at a time), rename the `artifact-<uuid>` files back to their library names, build a sysroot by hand and work out `set sysroot` / `solib-search-path`.
- Why it is friction: `coredumpctl gdb`, Sentry's debug-file bundles and `debuginfod` deliver a ready layout. The spec's "GDB opens it" test (SC-DLD-001) silently assumes this manual assembly.
- Origin: A (M requires native download plus "available exact companions"; the delivery shape is open).
- Fix: offer one "Core + companions" tar download that has original relative paths under `sysroot/` and a generated `gdb.cmd`/`README`. It would be authorized as the union of the selected artifacts and count as one stream.

### EVD-07 — Downloaded files are named `artifact-<uuid>.<ext>` — **medium**
- Where: specs/artifact-downloads.md:9 (ADR-244).
- What users do today: five PCAPs from one incident arrive as `artifact-3f2a….pcapng`, and Wireshark tabs and the Downloads folder say nothing about where each came from. Users rename files by hand.
- Why it is friction: Kubeshark, k9s and Velero name exports by resource plus timestamp.
- Origin: A.
- Fix: generate `<namespace>_<workload>_<pod>_<action>_<UTC-timestamp>.<ext>` on the server, restricted to `[A-Za-z0-9._-]` and truncated, with the UUID as a suffix. The name is still server-generated, so there is no injection risk.

### EVD-08 — MCP exposes 55 tools (63 in the catalog), the prose table is out of date, and capture is disabled by default — **medium**
- Where: specs/contracts/mcp-tools.json (63 tools; 8 `transports: ["browser"]` → 55 on MCP); specs/mcp.md:19-68 (table lists ~50 and omits `activate_policy`, `deactivate_policy`, `get_policy_status`, `request_policy_grant` and the three download tools, which are only described further down); docs/interfaces/mcp-workflows.md:3; `request_capture`/`cancel_capture` have `enabledByDefault: false`.
- What users do today: an agent loads 55 tool schemas, most with idempotency keys, `expected_plan_digest`, `expected_revision`, `after_revision` and opaque handles. Out of the box it cannot collect anything.
- Why it is friction: agent tool-selection accuracy drops past roughly 30–40 tools. The GitHub MCP server and Grafana MCP group tools into *toolsets* that are enabled by flag or scope. The rest of this audit already finds overlapping concepts: `list_recordings` versus `list_live_sources`, `preview_recording_save` versus `preview_capture`, 5 live tools, 3 download tools, and 9 separate `get_*_summary`/extract readers.
- Origin: A (M: MCP parity and no agent approval; tool count is not mandated).
- Fix: (a) toolsets (`read`, `raw`, `capture`, `live`, `share`, `download`), with `capture` advertised only when the client has `evidence:capture`. (b) Merge `preview_recording_save` into `preview_capture` (source handles as one more branch), and the live watch tools into `watch_live(open|read|update|close)`. (c) Regenerate the mcp.md table from the catalog.

### EVD-09 — MCP downloads need a second OAuth protected resource plus extra scopes; the fallback is a browser re-prepare — **medium**
- Where: specs/mcp.md:201, :289-293; specs/artifact-downloads.md:45.
- What users do today: the download content endpoint has its own `/.well-known/oauth-protected-resource/downloads` resource and audience, so "an MCP audience alone does not authorize the content endpoint". The client must authorize again for that resource and also step through `evidence:download` (and `evidence:raw`) insufficient-scope challenges. No current mainstream MCP client streams a second OAuth resource to disk. The documented fallback, "browser handoff", prepares a *new* session under the browser identity.
- Why it is friction: the user ends up re-consenting 2–4 times to get one file. GitHub MCP and the Atlassian MCP return a normal web URL for files.
- Origin: A.
- Fix: have `prepare_artifact_download` return one authenticated console URL (`/downloads/{id}`) that the browser opens with its existing session and that automatically re-binds or re-prepares. Request `evidence:read evidence:download` together at the first consent. Rely on grants rather than a separate `evidence:raw` scope for raw gating.

### EVD-10 — A live watch closes after 30 s without a read; agents cannot keep up — **high (MCP), low (browser)**
- Where: specs/live-watch.md:173 (idle 30 s), :187 (`wait_ms` ≤ 30 s, one outstanding read).
- What users do today: an agent calls `read_live_watch` with `wait_ms=30000`. The model then takes longer than 30 s to reason before the next call, and the watch closes as idle. The agent reopens it, which loses position, writes another audit row and counts against the 2-per-principal limit.
- Why it is friction: the timeouts guarantee watches close mid-task for LLM clients. Kubeshark and `kubectl logs -f` sessions stay open until the client disconnects or the deadline passes.
- Origin: A.
- Fix: for MCP, idle-close after max(5 min, 2× the last `wait_ms`); keep 30 s only for SSE disconnects.

### EVD-11 — Live view works only after operators supply CPU/examined-event ceilings — **medium**
- Where: specs/apis.md:111-113 ("Before enabling a projection, operators must supply finite CPU-time and examined-event/byte ceilings"); specs/live-watch.md:201 ("Installation aggregate limits are required configuration").
- What users do today: a maintainer clicks Watch live and gets CapabilityUnavailable until an operator researches per-node parser limits that have no defaults.
- Why it is friction: Kubeshark and Pixie ship working defaults. Prometheus Operator sets every resource with defaults.
- Origin: A.
- Fix: ship conservative defaults for every live-view limit (the spec already proposes the rest) and treat operator values as narrowing only.

### EVD-12 — Watching live requires four separate rights — **medium**
- Where: specs/live-watch.md:163; specs/authorization.md:235.
- What users do today: a viewer needs organization eligibility, whole-pod maintainer/collection entitlement, ordinary evidence-read under the source audience, `evidence:read` plus an allowed client, and the CollectionCeiling live-read allowance. The executor's grant must also still be valid. If any one is missing, the SRE on call cannot see live traffic of a recorder their own team runs.
- Why it is friction: in Kubeshark or Grafana, viewing a running stream needs the same right as reading the namespace's data.
- Origin: A (M: whole-pod public scope; nothing requires the intersection).
- Fix: allow live view for anyone with ordinary evidence-read on the source audience plus the ceiling switch. Drop the collection-entitlement requirement, since viewing an already approved projection acquires nothing.

### EVD-13 — Raw-grant byte accounting charges retransmissions and repeat downloads — **medium**
- Where: specs/artifact-downloads.md:29, :53.
- What users do today: each response start reserves bytes against the raw grant's cumulative output, "including retransmission after a resume". Downloading the same 4 GiB core to a second machine, or after a corrupt local copy, can exhaust the grant and require a new independent review.
- Why it is friction: no comparable artifact store meters re-downloads of a file you are already entitled to.
- Origin: A.
- Fix: count disclosure once per (principal, artifact version) against the grant. Keep the transfer/bandwidth limits as separate fairness counters.

### EVD-14 — Manual saves of a running ring need `recordingSaves.enabled`; turning it on later requires re-review — **medium**
- Where: specs/recording-saves.md:76; specs/apis.md:103.
- What users do today: if a policy was authored without it (existing and hand-authored policies are "never silently changed"), the maintainer cannot dump the ring during an incident. Enabling it changes the collection execution digest and triggers a fresh grant approval, while the incident is happening.
- Why it is friction: a ring buffer whose owner cannot dump it on demand is surprising. `tcpdump -W`, Kubeshark and flight recorders all allow it.
- Origin: M ("Preserve reviewed policy opt-in"). Putting it inside the execution digest, so that enabling it invalidates approval, is A.
- Fix (honors M): keep the opt-in but default it to `true` in schema defaults for ongoing actions. Bind it to the *approval display* rather than the collection digest, so flipping it means a lightweight owner acknowledgement rather than re-approval. Saving only freezes bytes that were already approved for observation.

### EVD-15 — Saved packet artifacts are effectively bounded at 8 MiB — **medium**
- Where: specs/mcp.md:155 ("8 MiB published packet bound"); docs/decisions/305-bounded-saved-packet-queries.md:73-74; specs/packets.md:37 (default ring 30 s / 16 MiB per target).
- What users do today: "PCAP in Wireshark" holds about 30 s of traffic on a moderately busy pod, and query qualification stops at 8 MiB.
- Why it is friction: Kubeshark and ksniff produce PCAPs limited only by disk.
- Origin: A (qualification bound). Uncertain: the published-size cap may be a qualification statement rather than a product limit. Confirm in packets/capacity owners' audit.
- Fix: qualify larger published packet artifacts (≥ 256 MiB per capture) and state the ring default as a starting point, sized by the recommendation formula.

### EVD-16 — Capture-time and recurring sharing have tight hard caps — **low**
- Where: specs/authorization.md:77 (1–8 recipients), :113, :131 (`maxCaptures` ≤ 100, `notAfter` ≤ 7 days).
- What users do today: sharing with more than 8 people or groups needs several shares. Recurring sharing has to be renewed weekly.
- Why it is friction: groups cover most cases, but the weekly renewal is the same complaint as EVD-04.
- Origin: A.
- Fix: tie the recurring-sharing lifetime to the policy grant. Raise recipients to 32.

### EVD-17 — Status `Completed` may drop native metadata after the "regional result cache" is gone — **low**
- Where: specs/mcp.md:289; specs/artifact-downloads.md:41.
- What users do today: a user re-checking a finished download may not see its checksum to verify a local file.
- Why it is friction: checksum and size are artifact facts, available while the artifact is readable.
- Origin: A.
- Fix: always return the artifact's verified size and SHA-256 from the catalog while metadata access lasts.

### EVD-18 — Repeating a recording save never restores its reason or source; mixed concepts — **low**
- Where: specs/recording-saves.md:126, :130; specs/mcp.md:277.
- What users do today: "Repeat" on a save goes to a fresh inventory selection. Users have to learn `recordingSave` versus capture versus live watch versus history repeat as four different paths for "keep the last N seconds".
- Why it is friction: this is a conceptual load. Comparable tools have one "Save buffer" action.
- Origin: M (Save existing recordings, live watch) plus A (separate repeat semantics).
- Fix: one "Save last N s" action wherever a source is shown (inventory, live view, history). Repeat preselects the same policy/action on current pods.

## Not friction (checked)
- No forced checkbox or consent modal on download; a persistent notice only (artifact-downloads.md:63). Good.
- A covering grant needs no re-review; one approval covers several raw queries (ergonomics.md:53). Good.
- Prepare is idempotent, server-side status waits, and no polling. Good.
- "Save last 30 s now" is one click when eligible (recording-saves.md:142). Good.
- Step-up reuse within the IdP session (ergonomics.md:53). Good.

## Counts
18 findings: 5 high (EVD-01, -02, -03, -04, -10), 10 medium, 3 low. Maintainer-rooted with a lower-friction alternative: EVD-01 (partly), EVD-04 (maximum only), EVD-14, EVD-18. The rest are agent-added.
