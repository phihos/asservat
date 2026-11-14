# Numeric limit audit — specification, contracts, architecture, examples

Repository: /home/phil/Projekte/asservat-friction, branch docs/friction-audit. Audit started at 902f532e7. HEAD is now 9fce7bf8b, and part of the schema section has moved since extraction: schema part 0 has a drift note. Read-only; no repository file was changed.

Rule: "If you can not give a good reason for a limit then remove the limit." Verdicts:
- **KEEP(a):** a resource cost with a derived bound.
- **KEEP(b):** an external protocol or API constraint.
- **KEEP(c):** a maintainer decision, from the AGENTS.md maintainer sections, ADR-311/312, ADR-330 or ADR-335.
- **REMOVE:** no good reason; each row names the replacement.
- **RAISE/DERIVE:** a reason exists but the number is arbitrary.

Skipped: identifier formats (UUID, DNS label/subdomain, sha256) and the share recipient caps 8/32.

## Totals

| part | scope | KEEP | REMOVE | RAISE/DERIVE |
|---|---|---|---|---|
| S1 | specs/authorization, mcp, triggers | 24 | 28 | 21 |
| S2 | specs/privacy, capacity, permissions, profiles | 21 | 27 | 26 |
| S3 | specs/packets, evidence, actions, persistence, ergonomics | 49 | 35 | 34 |
| S4 | specs/guidance, action-lifecycle, execution, capture-profiles, capture-history, artifact-downloads, recording-saves | 28 | 22 | 11 |
| S5 | the remaining specs/*.md, examples.yaml, changes/ | 53 | 34 | 26 |
| Arch A | docs/architecture (50 files) | 54 | 37 | 36 |
| Arch B | docs/architecture (16 files + catalog/validation) | 39 | 27 | 26 |
| IFX | docs/interfaces prose/yaml, examples/** values | 43 | 16 | 5 |
| Schema 0 | schema keyword groups A–max_* (per group) | 109 | 258 | 36 |
| Schema 1 | schema keyword groups max_*–z (themed rows) | 38 | 39 | 12 |
| **Total** | | **458** | **523** | **233** |

How rows were counted:
- Prose rows are one limit per file location; repeats within a file are collapsed into one row.
- Schema part 0 counts (property, keyword, value) groups. Schema part 1 merges groups that share one rationale into themed rows.
- Each schema group stands for every copy of the limit: mcp-tools.json, its implemented/ copy, and both browser-openapi.yaml copies.
- Identifier and format groups (133 + 11) are excluded.
- Rows with mixed verdicts count under their first verdict.

## Cross-cutting findings

1. **Every MCP limit exists four times.** Copies are in mcp-tools.json, implemented/mcp-tools.json and two browser-openapi.yaml. Generating the browser copies from mcp-tools.json lets each fix land once.
2. **Removed machinery is still described as current.** Seven contract schemas (local-start, installation-witness, retention-topology, work-trust, submission-trust, small-services-preparation, small-openbao) and many architecture documents still describe it as current. Examples: enrollment and certificate slots, key slots, budget leases, WAL/backup prepayment, 5 s windows, start rights, proof windows. Most of their limits go when the documents are deleted (ADR-330 D3/D7/D13).
3. **Seconds-scale human deadlines contradict ADR-335 D9:**
   - a 5-minute approved-submit window
   - a 24 h pending review
   - query results gone after 60 s
   - a 60 s start right
   - a 30 s queue age
   - 15 s save start
   - MCP downloads ending when the access token expires
4. **Lifetime run and byte counts on policies contradict ADR-335 D6.** Examples: maxExecutions, maxObservedBytes, max_grant_starts, maxOccurrencesPerHour on non-intrusive policies. Rates (D8) and ring sizes replace them.
5. **Hardcoded maxima on administrator-configured values:**
   - a 365-day grant ceiling
   - 180 days for approval policy
   - a 30-day session maximum
   - a 10-minute post-trigger window
   - a 1 h manual recording
   - an 8 GiB core
   - "administrators may only narrow" the live defaults

   The administrator value is the bound (c). The schema needs only an integer guard.
6. **List caps without pagination:**
   - list_reviews at 100 with no cursor
   - cases over 100 artifacts
   - the retention preview at 10,000
   - the impact preview at 1,000 targets
   - explain_access at 32/256 assignments
   - artifact selection at 64
   - the identity picker at 20
   - SSE subscriptions at 16 IDs

   Each should paginate or stream (AGENTS: "Prefer pagination or streaming over caps on lists").
7. **Artifact-size caps from the prototype single-frame layout.** Examples: 4096-byte pod status (8 files), 8 MiB pcap/syscall/HTTP-header artifacts, 16 MiB profile verification and 1 GiB scan, all below the configured capture maxima. Artifacts are framed and streamed, so the capture's own byte cap and ring size are the bound.
8. **Limits that contradict each other:**
   - The pcap compiled-program cap of 256 instructions cannot hold the 128–4096 allowed peers. The kernel limit is BPF_MAXINSNS 4096.
   - HTTP reassembly allows 16 MiB / 256 KiB = 64 flows, while maxFlows allows 1024.
   - The memory query is 16 KiB, which is 32 KiB as hex, against a 24 KiB MCP envelope.
   - Profiles may be collected up to 64 MiB but are verified only up to 16 MiB.
   - The command frame is 32 KiB in one document and 64 KiB in another.
   - The MCP envelope is 24/32/64 KiB in some places and 160 KiB in others.
9. **Identity and session caps:**
   - Tokens with more than 256 groups or 64 scopes are rejected.
   - A capture audience is capped at 256 entries.
   - A user gets 32 sessions with least-recently-used eviction.
   - maxLogins/maxSessions/maxLogoutEvents exist although ADR-335 D8 says "sessions unlimited (bounded by rate limits)".


---

<!-- part: s1 -->
## Limit audit — specs/authorization.md, specs/mcp.md, specs/triggers.md

Branch docs/friction-audit, read-only. Scenario (SC-*) example numbers are illustrations, not limits, and are not listed unless they encode a limit.
Skipped per brief: share recipient caps 1–32 (authorization.md:89, :125; mcp.md none). Flagged but not counted: management groups 1–8 / `ManagementTooBroad` (authorization.md:195, :197) — if the share-cap agent's "8" does not mean this, it is REMOVE (manager check is one group-membership test per managing group; cost trivial; replacement: K8s/SQL row size, no cap, never truncate).

### specs/authorization.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 3, 247 | 30 s; 60 s | Reuse of one authorization decision; live-view authorization reuse uses the 60 s delivery-policy interval | "never past an original deadline (ADR-311)" | KEEP(c) | ADR-311 / ADR-330 D5: 30 s, 60 s for shared policy observation. |
| 57 | 24 hours (default review `notAfter`) | How long a pending review stays decidable | none | REMOVE | ADR-335 D9/ADR-330 D9: approvals stay valid while unchanged. A pending review is one SQL row; drift already ends it with `TargetChanged` (line 63). Replacement: decidable until the request changes, the requester cancels, or an optional requester-set `notAfter`. |
| 57, 89, 131 | Default/maximum = the covered evidence's access end | Raw-query grant, capture result access, share expiry | "never exceeds, the artifact's access end" | KEEP(c) | ADR-335 D7 (shares until evidence retention ends) and D9 (result handles last as long as the evidence). |
| 57 | 90 days (`approvals.policyGrantSeconds`) | Policy (automatic intrusive) grant lifetime, renewable in place | none in text, matches decision | KEEP(c) | ADR-335 D6: admin-configured period, default 90 days. |
| 57 | "up to 365 days" | Hardcoded ceiling on the administrator's grant maximum | none | REMOVE | Hardcoded max on an admin-configurable value (brief note). The administrator's own maximum (D6 "administrator-configured finite policy approval periods") is the bound; wire bound int64 seconds. |
| 51, 73 | `maxExecutions`, "finite future budgets" on policy grants | Run count of an accepted intrusive policy | none (accounting only) | REMOVE | D6 bounds automatic intrusive actions by grant expiry; D8 bounds runs by rate/concurrency limits. A second run count forces mid-period renewal. Replacement: grant expiry + workload rate limits (triggers.md:55). For ad hoc grants the count is the plan's own action count (derived, not a configured limit). |
| 75 | 64 | Active reservations per grant | none | REMOVE | Reservations are already bounded by the grant's remaining bytes/ops and by capacity/concurrency (D8). Replacement: those existing budgets. |
| 75 | 4 per principal | Concurrent queries per principal | none | DERIVE | Real cost (reader CPU/memory per running query) but number arbitrary. Derive as a fair share of the installation limit: `max(1, installationQueryConcurrency / 4)`, configurable. |
| 75 | 32 per installation | Concurrent queries per installation | none | DERIVE | Derive from reader capacity: `readerReplicas × floor(readerMemoryRequest / perQueryScanBuffer)`; scales when readers scale (ADR-330 D4). Queue requests rather than reject (MCP status wait covers it). |
| 127 | at most 16 | Explicitly selected shared outputs (action IDs) | none | REMOVE | Outputs must name action IDs of the compiled plan, so the plan's action count already bounds the list. Replacement: the plan. |
| 143 | `futureCaptures.maxCaptures` required, 1–1000 | Count of captures a recurring sharing instruction may share | none (ADR-239) | REMOVE | Maintainer decision is "explicitly bounded recurring-policy sharing"; the required absolute `notAfter` already makes it explicitly bounded, and D7 removed weekly renewal friction. Replacement: make `maxCaptures` optional (no 1000 cap); `notAfter` is the bound; storm rate limits bound volume. |
| 143 | 90 days default `notAfter` | Recurring sharing end | none in text | KEEP(c) | "explicitly bounded recurring-policy sharing" + D7; default matches the D6 grant period. |
| 143 | at most 365 days | Hardcoded ceiling on sharing `notAfter` | none | REMOVE | Replacement: administrator-enforced maximum evidence retention (D7) — shares never outlive evidence anyway; optional admin maximum, no hardcoded ceiling. |
| 161 | at most 64 | Artifacts shared per capture | none | REMOVE | A capture's artifacts are bounded by its plan's outputs and capacity; share rows are small SQL rows (D8). Replacement: the plan output count. |
| 161 | "installation share quotas" (unspecified) | Total shares | none | REMOVE | No resource cost grows meaningfully (one SQL row per share); creation is already rate-bounded by captures/storm limits. Drop `SharingCapacityUnavailable`. |
| 201 | `limit ≤ 100` | `list_shares(view=administration)` page size | none | DERIVE | Pagination exists; page max should follow the response byte budget: `floor(responseBudget / adminRowBytes)` (rows carry no recipients, so >100 fit). |
| 219, 221 | `maxBytesPerSecond`, `maxSessionSeconds` | Sensitive observation rate and finite session length | "authority before any sensitive observation" | KEEP(c) | "manual requests finite", "bounded independent approval", "syscall argument mode needs reviewed observation budgets", D6 (always-on bounded by rates and ring sizes). |
| 219 | `maxConcurrentSessions` | Concurrent sensitive sessions per grant | none | KEEP(c) | D8 concurrency limits / storm protection. |
| 219, 221 | cumulative `maxObservedBytes` (manual/onTrigger) | Lifetime observed bytes of a finite session | none beyond the rate | REMOVE | Redundant: reservation is already `maxBytesPerSecond × (session seconds + 1)` (line 221), so rate × finite duration bounds it. Replacement: rate × maxSessionSeconds. |
| 221 | +1 second | Initial token-bucket burst | "the extra second is the initial burst" | KEEP(a) | Derived from the configured rate; standard token bucket. |
| 233 | observed-event and pre-read byte limits | Syscall argument tracing | "missing limits cannot authorize it" | KEEP(c) | Maintainer: "syscall argument mode needs reviewed observation budgets". |
| 37, 253 | grant query/output budget; one finite parent pool | Disclosure per raw grant / combined investigation | none in text | KEEP(c) | "bounded independent approval", "finite parent disclosure pool". |

### specs/mcp.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 7 | unspecified "excess request bytes, nesting, tool concurrency" | MCP request size, JSON nesting, concurrent tool calls | none | DERIVE | Request bytes: derive from the largest valid input schema (e.g. max filter + handles + selectors) with headroom; HTTP body only, not headers. Nesting: the schemas' own depth. Tool concurrency: covered by query concurrency (authorization.md:75); drop a separate cap. |
| 21, 33, 59, 147, 217, 221 | default 20, max 100 (`list_cases`, `list_diagnostics`); ≤ 100 (`list_shares` admin); up to 10 name candidates; ≤ 100 rows (`query_artifact`); ≤ 100 records (`httpHeaders`) | Page/list sizes | none | DERIVE | Pagination exists (cursors). Page max = rows that fit the response byte budget (`floor(budget / rowBytes)`), default page smaller for agents; candidates for an ambiguous name page like any search instead of a fixed 10. |
| 43 | at most four | Discovery captures given to `recommend_diagnostics` | none | REMOVE | Reading each discovery artifact is bounded by the query scan budget; inputs must resolve to the caller's same target scope (line 251). Replacement: scan budget + request size. |
| 43 | at most eight choices | Recommendations returned | none | REMOVE | Output bounded by the response byte budget; return ranked results with a cursor. |
| 63, 65, 117, 147 | 24 KiB default, 32 KiB spec ceiling, 64 KiB per response, "no caller-selected response budget", ~5,000–8,000 tokens | Structured tool result / whole MCP response | "actual safety bound is bytes/items" (token estimates) | DERIVE | MCP spec sets no size limit; the real external constraint is client limits (Claude Code: warns at 10,000 tokens, default `MAX_MCP_OUTPUT_TOKENS` 25,000 ≈ 100 KB). Keep 24 KiB as default, let the caller request a larger budget up to a ceiling derived from that client limit (≈ 96 KiB), drop the separate 32 KiB "spec ceiling". |
| 65, 101 | revoked share fails "within 30 s" | Cursor page reuse after revocation | REQ-INT-003 | KEEP(c) | ADR-311 30 s reuse; cursors themselves do not expire (consistent with D9). |
| 67 | handle valid while source evidence readable | Query handle lifetime | "ADR-335 D9" | KEEP(c) | D9 result handles last as long as the evidence. |
| 29, 31, 47, 67, 283 | ≤ 30 s | `after_revision` status waits; `watch_live` `wait_ms` | ADR-330 D1 | KEEP(c) | ADR-330 D1: MCP status waits at most 30 s. |
| 67 | 10 s default, administrator maximum 60 s | Query wall time | none | RAISE | Queries return `pending` handles, so a seconds-scale cap contradicts D9 (never seconds). Real cost is reader CPU, already bounded by scan bytes and concurrency. Proposed: default derived from scan budget / reader throughput (minutes, e.g. 5 min), admin-configurable with no hardcoded 60 s max; 5 s stays only as I/O timeout (ADR-330 D5). |
| 67, 150 | 256 MiB default, 1 GiB maximum "without an explicit larger profile" | Input scan bytes per query (`max_scan_bytes`) | none (bounds reader work) | RAISE | Cost grows with value (decrypt + parse), so a bound is justified, but the numbers are arbitrary. Derive: default = the artifact size when ≤ the configured capture/ring byte size (an always-on ring artifact is bounded by its ring size, D6), else `readerThroughput × queryWallTime`; remove the hardcoded 1 GiB max (admin value). |
| 129 | 512 bytes | Public packet filter text | "bounded pcap filters" | RAISE | Bounding is a maintainer decision; the real bound is the compiled program (BPF_MAXINSNS 4096). 512 bytes rejects ordinary multi-host filters. Proposed: text cap 4 KiB (fits HTTP/JSON comfortably), compiled-instruction bound authoritative. |
| 129 | "existing token/instruction bounds" | Compiled packet filter | "bounded pcap filters" | KEEP(b) | Classic BPF instruction limit 4096 (BPF_MAXINSNS), plus maintainer "bounded pcap filters". |
| 147 | 32 | Selected fields per packet query | none | REMOVE | The field catalog is closed (line 135); its size is the bound. Replacement: catalog size + response byte budget. |
| 170 | 1 GiB | Query-only raw grant request ceiling (disclosure pool) | none | RAISE | "finite parent disclosure pool" requires finiteness, not 1 GiB. Make it an administrator-configurable maximum; default the request to the verified native size of the covered artifacts. |
| 179 | 16 KiB per call | `query_artifact(operation=memory)` returned bytes | none | DERIVE | Derive from the response budget and encoding: hex doubles size, so 16 KiB raw = 32 KiB + wrapper, which already exceeds the 24 KiB default result budget (inconsistency). Formula: `floor((responseBudget − envelope) / encodingFactor)`. |
| 225 | `max_bytes=4096` | `pod-status/v1` preset output | none | RAISE | A Pod status of a multi-container Pod easily exceeds 4 KiB; the object itself is bounded by Kubernetes (1.5 MiB etcd request limit). Derive from the projection's actual size, ceiling 1.5 MiB (KEEP(b) then). `pod_count=1`, `max_process_starts=0` are the preset's definition, not limits. |
| 227 | 1 through 315360000 s (10 years) | `requested_retention_seconds` | none | REMOVE | The administrator-enforced maximum retention (D7) already clamps it; wire bound is int64/JS safe integer. Replacement: admin max (KEEP(c)) + positive integer. |
| 247 | up to 16 process references, 16 flow references | `recommend_diagnostics` focus | none | REMOVE | References must resolve against the supplied discovery captures, so the captures' contents bound them; request size covers the rest. |
| 249 | `preferences.max_bytes`, `max_ring_bytes` | Caller's aggregate acquired bytes / ring allocation | "neither overrides administrator resource accounts" | KEEP(c) | "segmented rings", "independently cap per-incident collection"; caller preferences within admin ceilings. |
| 283 | reads at most 10 minutes apart | Live watch idle lifetime | REQ-LIV-003 | KEEP(c) | ADR-335 D9: 10-minute idle window. |
| 283, 285 | bounded rows, resume window, delivery rate (unspecified values) | Live replay/backlog | "rather than an unbounded backlog" | KEEP(c) | Maintainer: "live watch finite views with bounded transient rows/replay". Values belong in live-watch.md. |
| 176 | finite user-data retention | Stored numeric addresses | none | KEEP(c) | Administrator-enforced retention (D7). |
| 295 | `result_access` aggregate limits/deadline | Combined investigation result access | "finite instruction" | KEEP(c) | "finite parent disclosure pool". |

### specs/triggers.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 27 | 16 | Detectors per policy | none ("Default ceilings") | REMOVE | D8: policies unlimited, bounded by Kubernetes object limits; detectors inside one policy likewise. Replacement: CRD object size (1.5 MiB) + evaluation cost budget. |
| 25, 27 | nesting depth 8; "evaluation budget" (no value) | `when` expression depth/cost | "excessive depth" | REMOVE | Replace the arbitrary depth with the standard CEL mechanism: cel-go parser recursion limit (default 250) and a per-expression cost limit like Kubernetes CEL validation (PerCallLimit 1,000,000). State the cost value. |
| 27 | 64 KiB | Policy text | none | REMOVE | Kubernetes object limit (≈1.5 MiB etcd request) already bounds a DebugPolicy (KEEP(b) at that value). |
| 7, 27, 268 | 64 KiB per assembled record; `maxRecordBytes` 1–65536 (default 65536) | Connector memory per log record | SC-TRG-001 "cannot allocate beyond the record/buffer limits" | DERIVE | Real memory cost. Default 64 KiB is fine (containerd splits lines at 16 KiB, kubelet rejoins partials); the hard max should derive from the per-Pod buffer (`maxRecordBytes ≤ perPodBuffer / followedContainers`), not a fixed 65536. |
| 27, 272 | 1 MiB per pod | Buffered log data per Pod | "cannot allocate beyond" | DERIVE | Derive from connector memory: `connectorMemoryLimit × logShare / followedPods`, with 1 MiB as floor default. |
| 27, 83, 85, 179, 270, 304 | 5 minutes max (correlation window, eventWindow, hold/`for`, probe `window`, `sampleInterval`) | Temporal window length | none | RAISE | D9: human timescales are minutes to days. State per Pod is a count plus at most `minimumFailures` timestamps or the newest match instant, so memory does not grow with window length. Proposed: probe window max = Kubernetes Event TTL (kube-apiserver `--event-ttl`, default 1 h, KEEP(b)); other windows up to hours (e.g. 24 h) or uncapped. |
| 83, 179, 270 | 30 s minimum (`window`, `eventWindow`) | Shortest window | none | REMOVE | A short window only makes firing easier; storms are bounded by cooldown/workload budgets (D8). Keep 30 s as default; minimum = one sample/second. |
| 27, 85, 305 | 5 s default; minimum 1 s | Node-local cgroup sample interval | none | DERIVE | Cost grows as interval shrinks (CPU per sample × pods): minimum from the collector CPU budget. Also ADR-330 D1: PSI triggers (kernel `poll()` thresholds, window 500 ms–10 s) and `memory.events` change notifications are event sources and should not be sampled; only `cpu.stat`/`memory.current` need sampling. |
| 27, 297 | 15 s | metrics API sampling | "metrics-server's default resolution" | KEEP(b) | metrics-server `--metric-resolution` default 15 s; better read the API's reported `window`. |
| 37 | `evaluation.rearmFor` default 10 seconds | Re-arm hysteresis | none | DERIVE | Re-fire storms are bounded by cooldown/budgets. Derive default from the detector: one `eventWindow`/`window` (as the connector sections already do) or two sample intervals for levels. |
| 308 | `rearmFor` at most 15 s | Resource detector re-arm | none | REMOVE | No cost or protocol reason; with 15 s samples a longer rearm just needs more samples. Replacement: `rearmFor ≤ sampleInterval`-style consistency check only if needed, else none. |
| 55 | 1 per workload per 5 min, burst 2 | Expensive occurrences (dump, command, intrusive profile, save) | storm protection | KEEP(c) | ADR-335 D8 rate limits (storm protection); configurable default. Matches kubelet CrashLoopBackOff max back-off 5 min. |
| 55 | `cooldown` default 1 minute | Non-intrusive occurrence rate per policy | storm protection | KEEP(c) | D8 rate limits; configurable. |
| 55 | `maxOccurrencesPerHour` default 60 | Non-intrusive occurrences per hour per policy | none | REMOVE | Redundant with the 1-minute cooldown (≤ 60/h already) and contrary in spirit to D6 (non-intrusive policies have no run count). Replacement: cooldown. |
| 55 | one intrusive action per pod at once | Per-Pod concurrency | storm protection | KEEP(c) | D8 concurrency limits. |
| 55 | ≥ 4 artifact streams, ≥ 16 active actions per node, from collector resource limits | Per-node concurrency | "defaults from the node collector's resource limits" | KEEP(a) | Derived from collector resource limits; Helm tuning values. |
| 57, 133 | 30-second correlation window | Appending crash/exit/probe/alert signals to one occurrence | none | REMOVE | Time-window merging is arbitrary (core handoff can exceed 30 s). Replacement: join by identity (Pod UID + container restart count / process), which is exact; already not applied to connector detectors. |
| 87 | five-field minute cron; jitter < minimum interval | Schedule granularity | standard cron | KEEP(b) | Five-field cron format has minute granularity; jitter bound is definitional. |
| 179 | `minimumFailures` 1–1000 | Probe failures threshold | none | REMOVE | State is one count per Pod; no cost grows with the threshold. Replacement: positive int32 (CRD integer). |
| 220 | at most 16 | Alert `matchLabels` | none | REMOVE | Bounded by the CRD object size; matching is a map lookup. |
| 239 | over 1 MiB rejected | Alertmanager webhook body | REQ-TRG-006 "limit body size" | DERIVE | Real receiver memory cost; derive from connector memory and concurrent receiver requests (e.g. `receiverMemoryShare / maxConcurrentRequests`); 1 MiB acceptable default. |
| 239 | more than 1024 alerts rejected | Alerts per webhook batch | none | REMOVE | The body cap already bounds memory; rejecting the whole batch drops real alerts. Alertmanager's own `max_alerts` (default 0 = unlimited) truncates and reports `truncatedAlerts`, which the spec already handles (line 353). |
| 266 | 4096 compiled instructions | Log regexp program size | none (implied CPU) | DERIVE | Real cost: RE2 matching is O(record bytes × program size) per log line. Derive from the connector CPU budget per log byte, or adopt RE2's default program memory budget (8 MiB) as the precedent; Go's regexp/syntax already rejects repeats > 1000 and over-deep nesting. |
| 266 | `pattern` 1–1024 bytes | Log pattern text | none | REMOVE | The compiled-instruction bound is the actual cost bound; text length adds nothing. Replacement: instruction bound + CRD size. |
| 267 | at most 8 object keys | `jsonField` path depth | none | REMOVE | Walking a path is trivial and bounded by the record size. Replacement: record size + CRD size. |
| 271 | at most 32 followed containers per Pod (more makes the Pod Unknown) | Log streams per Pod | none here; line 282 "one long-lived API server connection" | DERIVE | Cost is per stream (API server connection + buffer), but it sums per connector, not per Pod. Replace with a per-connector stream budget derived from connector memory (`connectorMemory × logShare / perStreamBuffer`), reported in status; never make a Pod Unknown for having many containers. |
| 299 | at most 1024 items | `pods.metrics.k8s.io` list per namespace | none | REMOVE | A namespace with > 1024 Pods would silently lose detectors. Replacement: list with the policies' label selectors (bounded by the namespace's Pods, which Kubernetes bounds). |
| 304 | `sampleInterval` default 30 s; below 30 s evaluated as 30 s on the metrics API | Freshness of a resource sample | none stated | DERIVE | Make it explicit: effective minimum = 2 × the metrics API's reported resolution/`window` (15 s default → 30 s). Default derived the same way. |

COUNTS: KEEP=24 REMOVE=28 RAISE/DERIVE=21

Most user-visible REMOVE items:
1. specs/authorization.md:143 — recurring policy sharing requires `maxCaptures` (1–1000) and caps `notAfter` at 365 days; the explicit end alone satisfies "explicitly bounded".
2. specs/authorization.md:57 — pending reviews expire after 24 h by default, contrary to D9 "valid while unchanged".
3. specs/authorization.md:57 — hardcoded "up to 365 days" ceiling on the admin's grant maximum.
4. specs/mcp.md:227 — `requested_retention_seconds` hard max 315360000; the admin retention maximum already clamps.
5. specs/triggers.md:55 — `maxOccurrencesPerHour` 60 is redundant with the 1-minute cooldown and is a run count on non-intrusive policies.
6. specs/triggers.md:239 — Alertmanager batches with > 1024 alerts are rejected wholesale.
7. specs/triggers.md:299 — metrics list capped at 1024 items per namespace silently breaks resource detectors in big namespaces.
8. specs/triggers.md:266 — log `pattern` 1–1024 bytes and `jsonField` ≤ 8 keys (:267).
9. specs/triggers.md:27 — 16 detectors/policy, depth 8, 64 KiB policy text (CRD size and CEL cost limits suffice).
10. specs/authorization.md:161 — at most 64 shared artifacts per capture plus unspecified installation share quotas (`SharingCapacityUnavailable`).

---

<!-- part: s2 -->
## Limit audit — part s2 (privacy, capacity, permissions, profiles)

Source: /home/phil/Projekte/asservat-friction (branch docs/friction-audit), read-only. Scenario-only example numbers (SC-PRV-002/003/005/008, SC-CAP-001, the 128 GiB example, SC-PRF-004/005) are not limits and are only listed where they contradict a stated default. Rows whose value is "unspecified" are bounds that a spec mandates without a number; they are listed because each one will turn into a number during implementation.

### specs/privacy.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 29 | evidence 14 d (including cores and heap dumps), default = maximum | baseline evidence retention | "product choices, not legally approved periods" | KEEP(c) | ADR-335 D7 (evidence 14 d, cores 14 d). Administrator-configurable on `helm upgrade`. Shares last until evidence access ends, with no separate cap (D7), consistent. |
| 29, 148 | case metadata 30 d, audit metadata 90 d; share rows deleted at share expiry + case-metadata period; known-principals rows deleted after audit-metadata period of inactivity | metadata retention | "product choices" | KEEP(c) | Configurable defaults under the administrator retention control (AGENTS "administrator-enforced maximum evidence retention"; finite retention of identity metadata). Note: D7 only names evidence figures, so this KEEP rests on the same administrator control rather than an explicit number. No hard maximum on the configured value is stated (good). |
| 31 | at most 64 applicable retention policies per plan; overflow fails planning | number of EvidenceRetentionPolicies matched by one capture | none ("consolidation diagnostic") | REMOVE | Shortest-wins is a min() over the matching set, O(n) and cheap. ADR-335 D8 makes policies unlimited (bounded by Kubernetes object limits). The manifest lists applied UIDs/generations/digests, but it is an encrypted object-store object with no 1.5 MiB limit. Replacement: none. Policies are admin-only objects bounded by etcd. |
| 41, 45 | 1–16 changes per `preview_retention_change` | proposal size | none | REMOVE | Each change is a CRD spec (≤1.5 MiB). The only real cost is request-body size. Replacement: the API's general HTTP request body limit. |
| 41, 45 | scan of at most 10,000 retained artifacts; "a truncated scan says so" | retention impact preview | none | REMOVE | The event path already applies the same predicate as one set-based `UPDATE … LEAST()`. The preview is the same predicate as a `SELECT count(*) … GROUP BY cluster, class, type` and can run in the database without loading rows. Truncation makes an administrator preview wrong exactly for large installations. Replacement: one aggregate SQL query under the ordinary statement timeout. |
| 60, 45, 70 | deletion budget "proposed 5 minutes" (configurable); access ends budget before hard deadline | gap between access cutoff and hard delete | "sits inside the maximum" (deletion must finish before hardDeleteBy) | DERIVE | Real reason (deletion time), arbitrary number. Derive the default from the retention worker's measured time to delete one artifact: two sweeps + object/version listing of the largest artifact prefix + node-copy acknowledgement. Keep 5 min as the documented default only if measurement supports it. Keep it administrator-configurable. |
| 122 | export pages with an unspecified "selection ceiling" | processing-inventory JSON export page | none | DERIVE | Paging is fine, but the page size has no number. Derive it from the hub-api per-request response memory budget (for example, reuse the 256 KiB page convention of `preview_access_change`). It must not cap the total; completion = all sections exhausted (already stated). |
| 154 | "bounded memory indexes", unspecified | in-memory evidence-text index size | memory | DERIVE | Derive from the reader/index Pod memory request (for example, a fixed fraction of the request), reported as `IndexRebuilding`/partial when exceeded. No number is given today. |
| 154 | durable index cohorts "default at most five minutes" wide | expiry-cohort width | deletion granularity (whole cohort deleted at earliest member deadline) | DERIVE | Width trades early index loss against file count. Derive it from the deletion budget (cohort width ≤ deletionBudget, so index deletion never exceeds the budget). This avoids a second independent 5-minute knob. |
| 154 | "Shard and file counts and rebuild work are capped", unspecified | durable index shards/files/rebuild | none | DERIVE | Derive from the reader Pod's file-descriptor limit and CPU request. Alternatively, drop the cap and let cohort width (above) bound file count = retention / width. |
| 166 | 15-minute requested lifetime for guided-selection acquisition recipes | retention of discovery samples | none | REMOVE | No reason given. A 15-minute lifetime can expire a discovery result while the user is still working, which conflicts with D9 (result handles last as long as the evidence). Replacement: the ordinary baseline retention with clamping; an administrator who wants shorter discovery copies adds an evidence-type rule to the EvidenceRetentionPolicy. |
| 170 | "seven-day summary default" for capture-history summaries (REQ-HIS-003) | history summary retention | none here | REMOVE | Summaries are content-minimized case metadata. Replacement: the case-metadata retention (default 30 d). Content-bearing snapshots already carry the shorter evidence deadline. (The owning file is capture-history.md; cross-check there.) |
| 180 | server replay at most 1 MiB per watch (REQ-LIV-003) | live-watch replay memory | bound memory (implicit, REQ-LIV-003) | DERIVE | Bounded replay is maintainer-required ("bounded transient rows/replay"), but 1 MiB is arbitrary. Derive: replay bytes per watch = (hub-api memory budget for live replay) / (configured viewer slots per replica). Show the derived figure. |

### specs/capacity.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 9 | minimum 15 minutes between dump episodes per workload (configurable) | dump episode rate | storm protection ("configurable starting budgets") | KEEP(c) | ADR-335 D8 rate limits, administrator-configurable default. |
| 9 | at most 2 individual process starts per rolling hour per workload (configurable) | dump process starts | storm protection | KEEP(c) | D8 rate limit, configurable. |
| 9 | 4 GiB uncompressed input reservations per rolling hour per workload | dump input bytes | storm protection | DERIVE | Retained bytes are already bounded by the workload storage account (`capacity.workloadLimit`). The remaining cost is node scratch/CPU for processing input. Derive from the node scratch reservation and the compression CPU budget (for example, hourly input ≤ 2 × the per-node scratch ceiling), or set it to the workload hard limit. A fixed 4 GiB blocks a single large JVM core (8–32 GiB heaps are common). |
| 9 | "initial contract keeps episode burst fixed at one" | dump bucket burst | none | REMOVE | This is a hardcoded value inside a configurable storm budget. Make burst an ordinary budget-profile value (default 1) like the interval and hourly ceilings (D8: limits configurable, defaults from cluster size). |
| 9 | maxProcessesPerEpisode default 1, raisable by administrator budget profile | processes per dump episode | multi-process recipes are explicit | KEEP(c) | D8 concurrency limit, administrator-configurable, no hard max. |
| 11 | suppression aggregation in 30-second windows; counters written once per window | suppression-summary SQL writes | "Write suppression counters once per window, not per hit" | DERIVE | Real cost (SQL write rate grows with hits), arbitrary window. Derive: one write per (workload, policy, reason) per window, with the window chosen so total writes stay within a stated hub write budget. 30 s (= AuthorityRecheckInterval) is acceptable if documented as that derivation. Internal only, not a human wait. |
| 21 | expensive concurrency one per workload | concurrent expensive actions per workload | storm protection | KEEP(c) | D8 concurrency limits. |
| 21 | one expensive action per target process | per-process serialization | "conflicts inside one runtime serialize" | KEEP(b) | Linux allows one ptrace tracer per tracee; the Go runtime allows one CPU profile per process (`StartCPUProfile` fails when one is active). |
| 21 | "proposed two expensive actions/node", intersected with node configured limit | node expensive concurrency | storm protection | KEEP(c) | D8 concurrency limit, configurable node limit. Memory/scratch reservations bound it independently. |
| 21 | concurrent captures per cluster = max(8, node count) (`capacity.capturesPerCluster`) | cluster concurrency | ADR-335 D8 | KEEP(c) | D8 verbatim ("at least 8", default from cluster size). Policies/sessions uncapped, as D8 requires. |
| 21 | queued requests: one expensive request per workload | queue depth per workload | "carry no unbounded retained data" | KEEP(c) | Equals the per-workload concurrency of one; storm protection (D8). |
| 21 | queued requests: ten per node | queue depth per node | "no unbounded retained data" | REMOVE | Already bounded by one per workload × workloads on the node; entries are small metadata. Replacement: the per-workload queue bound. |
| 21 | queued requests expire after at most 30 seconds or earlier request/target deadline | queue wait | "Expired triggers produce a gap, not a dump of whichever process now occupies that PID" | REMOVE | Stale-PID protection already comes from the process-start identity check ("its process identity valid", line 11). Replacement: the request/target deadline plus the process-start identity check. A fixed 30 s drops legitimate triggers behind a 64-second dump (line 43 example). |
| 23 | `core_pipe_limit` | concurrent kernel core pipes per node | kernel last-resort bound | KEEP(b) | Linux kernel sysctl (`/proc/sys/kernel/core_pipe_limit`). |
| 39 | key-provider request rate, concurrency, wait time and retry work "MUST bound", unspecified | KMS/OpenBao load | protect existing reads | DERIVE | No number. Derive from the provider's qualified throughput (release qualification already required) and split across hub replicas. With static local keys (ADR-335 D11, default) there is no remote provider and the bound should not apply. |
| 41 | node token leases of "a few seconds of budget" | upload token lease size | spreading across nodes must not multiply the workload limit | DERIVE | Real reason. Derive: lease = min(workload burst / active uploading nodes, rate × lease seconds), where lease seconds is chosen so the sum of outstanding leases ≤ workload burst. Give the number. |
| 41 | "small protected context/control service class", unspecified | reserved worker/buffer/IO share for context | large dumps must not starve context | DERIVE | Derive as a fraction of worker/buffer slots, at least one slot per replica. No number today. |
| 45 | circuit breaker recovers after 60 seconds without a new trip event | breaker hysteresis | hysteresis | DERIVE | Thresholds are already administrator breaker profiles. Put recovery in the same profile and derive the default from the PSI trigger window (kernel PSI windows are 500 ms–10 s), for example 2–6 × window. |
| 55 | `capacity.evidenceStorage` default = bundled object store volume size | pool capacity | ADR-335 D2 | KEEP(a) | Derived from the actual backing volume (the cost itself). Required for an external store. |
| 55 | `capacity.workloadShare` default 2 % of pool, protected and **not lent** | per-workload protected allocation | ADR-335 D2 lists "per-workload share" as an operator value | DERIVE | D2 asks for defaults derived from the cluster. A fixed 2 % plus the pool invariant (line 64) and enrollment refusal ("More protected allocations than the pool can back are rejected at enrollment") lets only ≈ (100 − 5 − 5 − burst)/2 ≤ 45 workloads per pool be enrolled. The default policy covers every namespace, so clusters with more workloads get `CapacityNotAllocated`. Derive: share = (usable − burst) / max(eligible workloads, 8), recomputed on enrollment (the allocation can only shrink for unused workloads). Alternatively, allocate protected capacity at first capture. |
| 55 | `capacity.workloadLimit` default 10 % | per-workload hard maximum | ADR-335 D2 | KEEP(c) | D2 operator value, cross-workload exhaustion protection (AGENTS invariant). Configurable. |
| 55 | system reserve 5 %, safety headroom 5 % (controller-derived) | pool reserves | system reserve "covers bounded catalog/audit/deletion work" | DERIVE | The reason exists, but the percentages are arbitrary. Derive the system reserve from the estimated catalog/manifest/tombstone bytes (manifests per artifact × max artifacts). Derive headroom from the backend's documented full threshold (for example, the SeaweedFS volume reserve or the operator-entered replication overhead). Also: the 128 GiB example (line 74) uses 16 GiB headroom (12.5 %) and 8 GiB system (6.25 %), which contradicts the 5 %/5 % defaults. |
| 57 | collector Helm defaults: source-ring memory 256 MiB, frozen-snapshot memory 256 MiB per node | node collector memory | ADR-246 collector-wide ceilings | DERIVE | Concrete cost (node memory), arbitrary numbers. Derive both from the collector Pod's memory limit (ring + frozen + baseline ≤ limit), so changing the memory value changes the ceilings. |
| 57 | collector upload 32 MiB/s, burst 64 MiB per node | node upload rate | ADR-246, storm/rate protection | KEEP(c) | D8 rate limits, configurable Helm value. |
| 57 | policy `node.maxRingBytes`/`node.maxFrozenBytes` "at most 4 GiB" | budget-policy node fields | none | REMOVE | These fields can only lower the node ceiling, so the node ceiling already bounds them. Replacement: int64/Kubernetes quantity validation only. |
| 72 | "finite record and object ceilings" for context and packet records, unspecified here | context/packet record counts | none here | DERIVE | Numbers live in other specs. Each must be derived from the object/record size budget there (cross-check owner files). |
| 90 | per-principal and per-workload token-bucket rate limits and concurrency caps on query and download read work | reads/downloads | none | REMOVE | ADR-335 D9: downloads have no request-count cap and run to original bounds. Reader capacity scales by replicas (ADR-330 D4). Replacement: reader concurrency derived from reader replicas × streams per replica (HTTP/2 `MAX_CONCURRENT_STREAMS`), with fair queuing. Keep the query CPU/output bounds that exist in evidence.md. |
| 92 | budget lease expiry, unspecified | connector local spend lease | disconnected spend | DERIVE | The amount already bounds spend. The expiry is only needed so the hub can reclaim capacity from a vanished connector. State it as that reclaim bound (for example, connector certificate validity), not as a refresh timer (ADR-330 D1). |
| 112 | "account-count limits" for namespace/cluster, unspecified | number of enrolled workloads | many workloads must not monopolize enrollment | REMOVE | The protected-allocation invariant plus namespace/cluster envelopes already prevent monopolization (bytes, not counts). Replacement: those envelopes. |
| 122 | survey defaults: one concurrent survey per workload, 30-second start interval, ten starts per hour across users and clients | guided surveys | storm protection | REMOVE | The same sentence says surveys "use the existing workload rate budget" and are "ordinary admitted capture episodes". A second survey-only budget duplicates it; ten per hour across a whole team is user-visible. Replacement: the workload's ordinary capture rate/concurrency limits (D8). |
| 128 | syscall event/rate/thread caps; argument reads consume cumulative grant events/bytes | syscall acquisition | reviewed observation budgets | KEEP(c) | AGENTS invariant: "syscall argument mode needs reviewed observation budgets". Numbers live in syscalls.md. |
| 132 | "Source/session lifetimes … have separate finite limits" | ongoing recorder lifetime | none | REMOVE | ADR-335 D6: always-on recorders are bounded by rates and ring sizes, not lifetime budgets. D8: sessions unlimited (bounded by rate limits). Replacement: ring sizes + rate limits, with the policy grant expiry only for intrusive automatic recorders. |
| 132 | per-incident action deadlines finite | incident saves | independent per-incident cap | KEEP(c) | AGENTS "independently cap per-incident collection"; D8 post-trigger windows up to the capture's configured duration. |
| 140 | viewer slots, scan/CPU, replay memory, output/transfer counters (REQ-LIV-004) | live views | finite views | KEEP(c) | AGENTS "live watch finite views with bounded transient rows/replay". Numbers in live-watch.md need their own derivation check. |
| 144 | policy automation `maxObservedBytes`, cumulative observed credit; zero denies | lifetime observed bytes for ongoing sources | none here | REMOVE | ADR-335 D6: "Always-on recorders are bounded by rates and ring sizes, not lifetime byte budgets". Keep it only for syscall argument mode (reviewed observation budget, KEEP(c) there). Replacement: rate (`inputBytesPerSecond`) + ring size. |
| 146 | development reference defaults: 16 active sources, 16 MiB/s aggregate input, 16 MiB burst per node | node ongoing-source ceilings | "development reference defaults … not qualified profiles" | DERIVE | Concrete costs (kernel maps/perf buffers, CPU). Derive maxActiveSources = ring-memory ceiling / minimum per-source ring; derive the input rate from qualified per-byte CPU × collector CPU limit. Pending native qualification. |
| 146 | structural validation ceilings 1,024 sources, 10 GiB/s, 10 GiB | Helm value validation | "parser/arithmetic bounds" | REMOVE | Arithmetic needs only int64 (2^63−1) or the JS-safe 2^53−1 for browser display. Replacement: int64 / positive-quantity schema validation. |
| 148 | collector CPU request 20m, limit 500m | collector user-space CPU | none (only "bound its user-space cgroup") | DERIVE | Concrete node cost. Derive the limit from qualified per-source CPU × maxActiveSources (and set the request near steady-state use). A 500m limit can throttle compression/encryption during an incident upload. Configurable Helm value. |

### specs/permissions.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 45, 57 | 1–16 changes per `preview_access_change` | proposal size | none | REMOVE | Specs are CRDs (≤1.5 MiB each). Replacement: the general HTTP request body limit. "More than 16 changes … are refused" (line 57) goes. |
| 45, 57 | at most 1,000 cells per namespace snapshot; larger refused | access-preview evaluation size | none | REMOVE | Results are already paged through `next_cursor` bound to the snapshot revision. Page the cells the same way. Refusing namespaces with more than about 1,000 named workloads blocks administrators exactly in large shared namespaces. Replacement: cell paging + request timeout. |
| 45, 57 | result pages within 256 KiB | response page size | none | DERIVE | Paging is fine. Derive the page size from the hub-api per-response memory budget and document it (256 KiB is reasonable). It caps pages, not totals. |
| 70 | 32 observed keys per PermissionSource | keys pushed per source | none | REMOVE | A source reads one configured key plus selector keys. Replacement: the Kubernetes object size of the admin-only PermissionSource (1.5 MiB). |
| 70 | 65,536 namespaces with an observed key per cluster | pushed namespace digests | none | REMOVE | Upstream Kubernetes scalability thresholds put namespaces per cluster at 10,000, so the cap never binds. Replacement: nothing (the cluster's own size). Digest pushes are per change (ADR-330 D1). |
| 70 | optional `maxNamespaces` per source | per-source namespace count | none | REMOVE | Configuration whose only purpose is tuning its own machinery (complexity gate item 7). Scope is already defined by the selector and exclusions. Replacement: selectors. |
| 97, 121, 131 | review allow cached ≤ 30 s; snapshot reuse ≤ `identity.AuthorityRecheckInterval` 30 s | authority reuse | ADR-311 | KEEP(c) | ADR-311 maintainer decision (30 s). |
| 97 | at most 16 `kubernetesAccessReview`/`kubernetesExec` review sources per cluster | review sources | none | REMOVE | The cost (SubjectAccessReviews per read) is already bounded by the 30 s allow cache, batching and the connector's client-go QPS/burst limiter. Sources are admin-only objects. Replacement: the client-go rate limiter + cache. |
| 125, 149, 153 (+43 `AudienceOverflow`) | at most 256 audience entries per artifact; more are refused at planning | recorded audience `(issuer, group/subject, role)` | none ("never by silently omitting an owner") | REMOVE | Audience rows are small SQL rows; the manifest is an object-store object without a size limit. For review sources, the audience is the principal's current groups that SAR allows, and enterprise users with hundreds of directory groups hit the cap and cannot capture. Replacement: unbounded SQL audience rows (bounded by the bindings, which are Kubernetes objects, and by the token's group list, itself bounded by HTTP header/JWT size). Drop `AudienceOverflow`. |

### specs/profiles.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11 | kernel 5.10+ for the eBPF CPU sampler | node eligibility | pinned OpenTelemetry eBPF profiler | KEEP(b) | External constraint: the upstream profiler's supported kernel floor (eBPF verifier/BTF features). |
| 31 | explicit certificate roots "at most 8 KiB PEM" | named endpoint TLS trust | none | REMOVE | One PEM certificate is about 1.5–2 KiB, so 8 KiB rejects ordinary corporate chains/bundles. Roots live in Helm-rendered regional configuration. Replacement: the ConfigMap/Secret object size (1 MiB) plus a PEM parse check. |
| 58, 110, 157, 199 | CPU profile default 10 s, maximum 60 s "under the administrator ceiling" | CPU profile duration | none | RAISE | A default of 10 s is fine (Parca/Pyroscope use 10 s; net/http/pprof defaults to 30 s). The hardcoded 60 s max on top of an administrator ceiling is the "hardcoded max on a configurable value" pattern. Bytes are already bounded by the output cap. Remove the 60 s max and make the administrator ceiling configurable, default 5 min (D8/D9 minutes timescale). For the eBPF sampler, also see the per-node exclusivity row. |
| 58 | trace default 5 s, maximum 15 s | Go execution trace duration | "higher data volume and overhead" (line 10) | REMOVE | Trace is already intrusive (needs approval) and its volume is bounded by the trace output cap. Replacement: the trace output byte cap + the administrator duration ceiling (the approval states the window, D5). Keep 5 s only as the editable default. |
| 58 | profile output default 16 MiB, maximum 64 MiB | profile native bytes | none | DERIVE | Costs: storage quota (already reserved per capture) and node/reader memory. Line 27 says "bounded in-memory result", but lines 159 and 246 say it streams. If it streams, the only cost is the storage reservation: remove the max and use the workload quota. If it is in memory, derive max = collector frozen/in-memory ceiling / node expensive concurrency. |
| 58 | trace output default 32 MiB, maximum 128 MiB | trace native bytes | none | DERIVE | Same derivation as the profile output cap. |
| 58 | snapshot profiles 5-second default acquisition deadline | snapshot GET | none | KEEP(c) | ADR-330 D5: five seconds only as an I/O timeout. Specify it as an idle/read I/O timeout rather than a total deadline: a goroutine profile with very many goroutines can take longer to serialize. |
| 62 | one Asservat CPU/trace recording per conflicting runtime domain; `ProfilerBusy` when the application owns one | per-process profiler exclusivity | runtime conflict | KEEP(b) | The Go runtime permits one CPU profile at a time per process (`runtime/pprof.StartCPUProfile` returns "cpu profiling already in use"). The same applies to an active execution trace. |
| 62, 77 | eBPF sampler: "at most one sampler session runs on a node"; second request for any pod on that node gets `ProfilerBusy` | per-node eBPF CPU profiling | "the qualified profiler has no cgroup filter" | REMOVE | The profiler samples host-wide anyway and the collector already attributes every sample to a verified pod (line 23). Concurrent sessions for different pods can share the single sampler and be demultiplexed by pod. Replacement: one shared per-node sampler with per-session pod filters; per-node CPU is bounded by the existing node expensive-concurrency limit. |
| 81 | capped decompression 16 MiB for Go pprof verification; profile beyond it "refused, never truncated" | publication verification | bound parser memory | DERIVE | It contradicts line 58: the maximum output is 64 MiB compressed, so profiles that can be collected may never be verifiable or published, which wastes the capture. Derive from the regional reader's memory request / concurrent verifications ÷ the measured google/pprof allocation factor, and keep the collection cap ≤ that bound. |
| 81 | allocation-shape limits: 100,000 samples/locations/functions each; 64 labels per sample; 300,000 strings; 1,048,576 location refs and inline lines (4,096 per sample/location); 16 values per sample; 4,096 comment indices; `2*samples + locations + functions + 8*labels ≤ 662144`; 16 sample types; 4,096 mappings | pprof parse preflight | "empirical units are not a heap-memory guarantee" (pprof-allocation-preflight review) | DERIVE | The reason (parser allocation amplification) is real, but 14 fixed numbers are arbitrary and refuse real large-service profiles (100k+ unique stacks in big binaries). Replace them with one derived allowance: Σ(count × measured Go bytes per entry) ≤ reader per-query memory budget (the same budget as the decompression cap). Make it a single derived value instead of fixed constants. |
| 81 | Go execution trace "within an event cap", unspecified | trace verification | parser memory | DERIVE | Derive from the same reader memory budget. No number is given. |
| 116 | `get_profile_summary` top-N default 20, maximum 100 | summary rows | none | REMOVE | The same paragraph applies "Cursors … output ceilings … normally". Replacement: the MCP/browser output ceiling and cursor. Keep 20 as the default. |
| 83 | "bounded call-tree edges", unspecified | extract size | none | REMOVE | Replacement: the existing extract/output ceiling and cursors (as for top-N). No separate edge count. |

COUNTS: KEEP=21 REMOVE=27 RAISE/DERIVE=26

Most user-visible REMOVE items:
1. specs/capacity.md:21: 30-second queue expiry drops triggers that wait behind a running dump; the process-start identity check already prevents stale-PID dumps.
2. specs/profiles.md:62: one eBPF sampler session per node blocks CPU profiling of a second pod on the same node (`ProfilerBusy`).
3. specs/permissions.md:125: 256 audience entries refuse capture planning for users or bindings with many groups (`AudienceOverflow`).
4. specs/capacity.md:122: survey-only budget (10 starts/hour across all users, 30 s interval) duplicates the workload rate budget.
5. specs/privacy.md:166: 15-minute lifetime on guided-selection samples expires results mid-investigation.
6. specs/profiles.md:31: 8 KiB PEM cap rejects ordinary corporate CA chains for TLS pprof endpoints.
7. specs/capacity.md:90: per-principal token buckets on downloads/queries contradict D9 (no request-count cap).
8. specs/capacity.md:132 and 144: finite source lifetimes and cumulative `maxObservedBytes` for always-on recorders contradict D6.
9. specs/permissions.md:45/57: preview refuses more than 16 changes or 1,000 cells even though results are already paged.
10. specs/privacy.md:41/45: retention preview truncates at 10,000 artifacts, which makes the administrator preview wrong exactly for large installations.

Notable non-REMOVE findings:
- specs/capacity.md:55/64: `workloadShare` 2 % that is never lent, plus refusal at enrollment, caps protected enrollment at ≤ 45 workloads per pool. The default policy covers every namespace, so any larger cluster gets `CapacityNotAllocated` (DERIVE).
- specs/profiles.md:58 vs 81: a 64 MiB maximum profile output against a 16 MiB decompressed verification cap means collected profiles can be unpublishable.
- specs/capacity.md:74: the worked example's headroom/system figures (12.5 %/6.25 %) contradict the 5 %/5 % defaults on line 55.

---

<!-- part: s3 -->
## Limit audit — part s3 (packets, evidence, actions, persistence, ergonomics)

Repository: /home/phil/Projekte/asservat-friction (read-only). Baseline: ADR-330, ADR-335.
Not counted: UX release targets in ergonomics.md:89 (3 min / 2 min are goals to measure, not limits); pure uniqueness rules (packets.md:57 "one protocolSnaplen rule per transport"); version baselines (PostgreSQL 18).

### specs/packets.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 9, 57 | snapshot length 65,535; `snaplen`/`protocolSnaplen` 1–65,535 | dead-handle compile snaplen; raw prefix caps | "may be narrowed by engine capability" | KEEP(b) | libpcap/tcpdump maximum snaplen (MAXIMUM_SNAPLEN 262144 since 4.9, but 65,535 = IP total-length field max); per-frame byte cap is a real storage cost |
| 9 | 4,096 expression bytes | acquisition pcap filter text | none | REMOVE | Text size costs nothing that the compiled-instruction bound does not already bound; the CRD is bounded by the 1.5 MiB object limit and the API body size. Keep only the instruction bound ("bounded pcap filters", maintainer) |
| 9 | 256 syntax tokens | pre-libpcap screen | "a conservative bound on syntax nodes" | DERIVE | The real cost is libpcap compile/optimizer CPU on the hub. Derive from a measured compile time under the 5 s I/O timeout (ADR-330 D5) for the worst token shape, or simply from the instruction bound: tokens ≤ BPF_MAXINSNS (4,096). 256 is far below what fits 4,096 instructions |
| 9 | 256 compiled instructions | accepted cBPF program | none (besides "bounded") | RAISE | External limit is BPF_MAXINSNS = 4,096 (KEEP(b) at that value). cBPF has no backward jumps, so per-frame cost ≤ program length; the user-space `x/net/bpf` VM CPU is bounded by the node CPU profile. Raise to 4,096. Also needed by REQ-NET-002: peers compile into this same program (see 4,096-endpoint row) |
| 9 | fixed protocol header sizes ether 14, ip 20, ip6 40, tcp 20, udp 8, icmp 8 | ordinary-permission byte predicates | protocol header layout | KEEP(b) | IEEE 802.3 / RFC 791 / 8200 / 9293 / 768 / 792 fixed header sizes |
| 9 | `proto[off:size]` size 1, 2 or 4 | byte-access widths | libpcap syntax | KEEP(b) | libpcap/BPF load widths (BPF_B/H/W) |
| 9 | REQ-AUT-006 observation limits for `rawBytePredicate` | raw-byte filter plans | grant | KEEP(c) | Maintainer: one bounded independent approval for intrusive collection; "syscall argument mode needs reviewed observation budgets" applies analogously |
| 23 | "bounded IP/CIDR sets" (no number) | CIDR peer list | none | REMOVE | CIDRs compile into the accepted program, so the instruction bound (4,096) already bounds them; no separate count |
| 25 | "bound their membership lifetime" for terminating/not-ready endpoints (no number) | how long terminating endpoints stay peers | none | REMOVE | EndpointSlice removal is an informer event (ADR-330 D1); the endpoint leaves the peer set when Kubernetes removes it. No timer |
| 27 | default max 4,096 endpoints | `follow` peer membership per generation | "Exceeding map capacity fails closed" | DERIVE | Inconsistent with the 256-instruction cap: per ADR-283/248 members join the cBPF expression as host prefixes (≈2–4 instructions each), so 4,096 endpoints cannot fit even BPF_MAXINSNS. Either (a) bound = what fits the 4,096-instruction program (≈1,000 hosts), stated as derived, or (b) evaluate membership as a Go set lookup in the user-space collector, where cost is ~32 B/member and the bound becomes collector memory (e.g. 1 MiB → ~32k members). Prefer (b) |
| 27 | max 16 authored peer entries | peer query entries | none | REMOVE | Authored entries live in the CRD (1.5 MiB object limit) and resolve into the member/instruction budget above; a separate count adds friction (e.g. 17 Services) with no cost of its own |
| 37, 45 (actions.md:83) | default ring 30 s, 16 MiB per target | in-memory pre-trigger ring | memory; "segmented rings" | KEEP(a) | mlocked collector memory grows with maxBytes; maintainer requires bounded segmented rings. Admin/user-configurable default |
| 37 (actions.md:83) | 256 MiB aggregate per node | sum of rings per node | actions.md:83 "sized from the node collector's memory limit" | DERIVE | packets.md states a fixed 256 MiB, actions.md says it is sized from memory. Single formula: aggregate ring ≤ collector container memory limit − (reassembly budget + frozen snapshot budget + process overhead); default the chart's collector memory request so 256 MiB results only for the default request |
| 39 | initial maximum maxAge one hour | ring age | none | REMOVE | Memory grows with bytes, not age: maxBytes bounds cost. Age is already bounded by "retention cutoff" (same sentence) and ring lifetime by the source's hard end; administrators may still set a ceiling. Drop the hardcoded hour |
| 39 | four segments default | ring granularity | none | KEEP(a) | Default only; eviction granularity trades 1/N history loss against per-segment overhead. Not a user-facing ceiling |
| 41 | concurrent snapshots default one, hard maximum four | frozen snapshots per target | memory | REMOVE | Memory is already bounded by the frozen-bytes budget; trigger frequency by the per-workload rate limit (ADR-335 D8). The count cap only adds refusals; keep "coalesce or refuse before allocating" against the byte budget |
| 41 | 64 MiB frozen/unuploaded per target | pinned snapshot bytes | memory | DERIVE | Derive from the same collector memory formula (per-target frozen ≤ node frozen budget / armed targets, or = per-target ring maxBytes, since a snapshot pins at most one ring's worth) |
| 53 | 134 bytes per frame (networkHeaders) | gadget capture length | "Ethernet + largest IPv4 + largest TCP header" | KEEP(b) | 14 + 60 + 60 from protocol maximum header lengths |
| 63 | 1,024 flows | HTTP parser flow table | "explicit contract bounds requiring measurement" | DERIVE | Flow state is memory: flows = total reassembly budget / minimum per-flow state, not an independent constant |
| 63 | 32 KiB header block | HTTP/1 header section per message | none | KEEP(b) | Matches common server limits (nginx `large_client_header_buffers` 4×8 KiB; Apache 8,190 B/field, 100 fields); headers above what servers accept are rare. Brief: HTTP header sizes ~8–16 KiB |
| 63 | 256 KiB reassembly per flow | per-flow buffered bytes | none | DERIVE | Only headers are retained; per-flow = header block cap × in-flight messages (request + pipelined responses), e.g. 2–4 × 32 KiB, or one shared budget with no per-flow constant |
| 63 | 16 MiB total reassembly | per-target parser memory | "CPU bounded by the node profile" | DERIVE | Derive from the collector memory limit together with ring and frozen budgets (see 256 MiB row) |
| 63 | 30-second idle timeout | idle HTTP flow state | none | REMOVE | Typical keep-alive idle (nginx 75 s) exceeds 30 s, so idle keep-alive connections lose state and later requests become midstream/partial. Memory pressure is already handled by eviction when slots are full; flows end on FIN/RST or source end |
| 63 | two-second no-frame eviction when all slots are held | slot reclaim under pressure | "bounds the coverage loss ... without raising the flow cap" | REMOVE | Replace the fixed 2 s with standard LRU eviction of the least recently seen flow (conntrack-style) when the table is full; no time constant needed |
| 66 | fixed 1,500-byte acquisition prefix | ongoing HTTP source frame prefix | none | DERIVE | 1,500 is Ethernet MTU, but Pod-side capture hooks see GRO/TSO aggregates up to 64 KiB, so a 1,500-byte prefix creates reassembly gaps on normal traffic. Bytes are transient (discarded after parsing), so derive the prefix from interface MTU/GSO max (`gso_max_size`, default 65,536) or use 65,535 |
| 93 | generation history default 1,024 entries per artifact | peer-generation provenance | "close a segment/artifact or stop with a visible limit" | REMOVE | Record only generations overlapping the saved window; entries are tiny and live in the encrypted manifest. A visible stop of a running recording because membership churned is user-hostile; the window bounds the list |
| 102, 115 | top 100 conversations | saved pcap summary output | none | REMOVE | Replace with cursor pagination over the computed aggregate list (default page 100); the full list is computed once per artifact anyway |
| 102 | at most 16,384 aggregates | summary aggregation map | none | DERIVE | Memory: ~100 B per aggregate → 16k = 1.6 MiB. Derive from the reader's per-query memory budget (reader memory limit / concurrent query slots); state the overflow behavior (currently unspecified) |
| 137 | 512-byte filter cap for saved queries | saved-PCAPNG query filter | none | REMOVE | Inconsistent with the 4,096-byte acquisition cap; same compiler/VM, so the instruction bound suffices (see row above) |
| 154 | scan bound, API ceiling 1 GiB | bytes visited per query | none | REMOVE | Scanning is streaming with constant memory and paged output; cost is bounded by the artifact size (packet recordings may be up to the admin byte cap, currently 4 GiB, so 1 GiB cannot scan a full file) and the operation deadline. Continue via cursor |
| 157 | ≤100 rows, ≤24 KiB per page | transient query page | none | DERIVE | Page size is a client concern: let the caller choose a page size, default to fit the MCP client's tool-output limit (Claude Code default 25,000 tokens ≈ 100 KiB); browser pages need no 24 KiB cap |
| 157 | ≤32 fields per page | selected fields | none | REMOVE | The field catalog is finite; the catalog size bounds selection |
| 163 | grant disclosure pool (operations + output bytes) | raw query disclosure | grant | KEEP(c) | Maintainer: "finite parent disclosure pool" |
| 176 | maxFrozenBytes ≤ action output reservation; timeout = post-trigger + margin | snapshot vs reservation | consistency | KEEP(a) | Derived relation between existing budgets, not a new number |

### specs/evidence.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11 | 8 MiB native frames | authenticated frame size | ADR-048 format | KEEP(a) | Reader must buffer and authenticate a whole frame before releasing bytes: per-stream memory = frame size × concurrency. Format constant, not a user-visible limit |
| 13 | three keysets per attempt, each ≤ 4,096 bytes | key-service request payload | "independently of native size" | DERIVE | A single-key Tink AES-GCM-HKDF streaming keyset serializes to ~100–200 B; state the bound as "one-key keyset of the fixed template" rather than an arbitrary 4,096 (harmless, low priority) |
| 13 | unwrapped keys cached until earliest `AccessUntil` | reader key cache lifetime | ADR-312 bounds | KEEP(c) | ADR-312: started operations run to original bounds |
| 13 | "or a short idle timeout" (no number) | reader key cache eviction | none | REMOVE | Reference-count keys by active operations and drop on the last release; no timer (ADR-330 D1 "every new timer loop must justify") |
| 25 | "bounded durable completion references" during outage (no number) | connector offline completions | none | REMOVE | Offline production is already bounded by the connector's budget lease (artifact count/bytes); the references cannot exceed what the lease admits |
| 29 | Object Lock "within the audit maximum" | audit export lock duration | retention | KEEP(c) | Administrator-enforced retention |
| 41 (ergonomics.md:33, 39) | pod-status projection ≤ 4,096 bytes | saved native status | none | REMOVE | The schema has only fixed identity/status/count fields (no labels, messages, container names), so its size is inherent; an explicit cap only adds a failure mode. If any arrays remain, the Pod object (1.5 MiB) bounds them |
| 67, 71 | per-query input/decompressed/parser/output/time limits "within the reader container's memory and CPU limits"; concurrency slots (no numbers) | reader analyzers | memory containment | DERIVE | Reason is concrete; state the derivation: slots = reader memory limit / measured worst-case per-query peak; per-query decompressed limit from that peak. Time limit = operation deadline (D9), not a separate constant |
| 79 | scratch PVC deleted at earliest parent retention deadline | scratch lifetime | retention | KEEP(c) | Administrator-enforced retention |
| 79 | scratch "bounded capacity" (no number) | PVC size | none | DERIVE | Size = artifact native size × tool-specific factor (input + output), requested per analysis |
| 103 | evidence including cores 14 days default | evidence retention | ADR-335 D7 | KEEP(c) | ADR-335 D7 |
| 103 | content-minimized case metadata 30 days default | case metadata retention | "product defaults" | KEEP(c) | Admin-configurable retention default (maintainer: administrator-controlled retention); should not be shorter than evidence retention, which holds |
| 103 | audit 90 days default | audit retention | "product defaults" | KEEP(c) | Admin-configurable; floor must stay ≥ backup retention (persistence.md:87 relies on exported audit for restore) |
| 103, 105 | holds cannot bypass cap; deadlines never move later | retention | maintainer max | KEEP(c) | Administrator-enforced maximum retention |
| 132 | "bounded companion bundle", "approved cache budget" (no numbers) | executable/symbol companions | grant/quota | KEEP(a) | Charged to the same acquisition grant and workload storage quota; no separate number needed |
| 144 | bounded tool pipes (no number) | child stdout/stderr | evidence leakage | KEEP(a) | Same byte budget as the action's output cap (actions.md table) |
| 148 | publication file count, size, decoding/time, aggregate quotas (no numbers) | analyzer output tree | hostile output | DERIVE | Derive from the output PVC capacity and the projection's declared file set; time = operation deadline |

### specs/actions.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 32 | at most 16 typed actions per recipe | recipe graph size | none | REMOVE | Cost comes from each action's byte/time budgets and capacity admission, not action count; the recipe CRD is bounded by the 1.5 MiB object limit |
| 44, 120 | 64 MiB log native ceiling; 64 MiB / 60 s administrator maximum | logs | none | REMOVE | Hardcoded maximum on an admin value; storage is bounded by capacity admission and the per-workload share (ADR-335 D2). Admins set their own ceiling |
| 120 | log window default 10 MiB/pod | logs default | none | DERIVE | Kubelet API logs return the current file only, bounded by `containerLogMaxSize` (default 10 MiB) per container. Default = containerLogMaxSize × sources (current + previous per container), so multi-container pods are not truncated by a per-pod 10 MiB |
| 120 | log timeout 10 s | logs action | none | DERIVE | Use the 5 s no-progress I/O timeout (ADR-330 D5); total time from bytes / qualified throughput |
| 59 | pseudo-file worker "concurrency ceiling" (no number) | collector read workers | blocking pseudo files | DERIVE | Concrete cost (threads stuck in uninterruptible I/O); derive from collector CPU/thread budget |
| 83 | ring 30 s / 16 MiB default; "maximum 256 MiB aggregate per node by default, sized from the node collector's memory limit" | rings | memory | DERIVE | Same item as packets.md:37; write one formula (collector memory limit minus other budgets) instead of a fixed number plus "sized from" |
| 93 | data key "bounded ... usage count" | cached KMS data key | data-key caching | KEEP(b) | AES-GCM with random nonces: NIST SP 800-38D limits a key to 2^32 invocations; state that value (AWS Encryption SDK caching uses the same idea) |
| 93 | data key "bounded lifetime" (no number) | cached KMS data key | none | DERIVE | Tie to the collector's connector certificate/lease lifetime (rotated with it, ADR-330 D3) rather than an extra timer |
| 93, 157 | provisional storm limit; crash-path token bucket; workload dump interval/burst; rolling-hour individual starts | crash/dump admission | storm protection | KEEP(c) | ADR-335 D8 rate and concurrency limits |
| 93 | nonzero qualified `core_pipe_limit` | concurrent kernel core pipes | kernel | KEEP(b) | Linux `kernel.core_pipe_limit` semantics |
| 67 | command grant binds deadline, output cap, execution count | approved command | approval | KEEP(c) | One bounded independent approval covering its stated window (ADR-335 D5); manual requests finite |
| 119 | one file default 1 MiB | fileRead | none | KEEP(a) | Configurable default; storage per action. /proc and config files fit |
| 119 | one file timeout 2 s | fileRead | "pseudo files may block" | DERIVE | Use the 5 s no-progress I/O timeout (ADR-330 D5) instead of a 2 s total; total from bytes/throughput |
| 119 | one file admin maximum 16 MiB / 10 s | fileRead | none | REMOVE | Hardcoded ceiling on an admin value; capacity admission bounds storage |
| 121 | process/network metadata default 4 MiB, 5 s | snapshots | none | KEEP(a) | Configurable default; 5 s is an I/O timeout (ADR-330 D5) |
| 121 | process/network metadata admin max 16 MiB / 15 s | snapshots | none | REMOVE | Hardcoded ceiling on an admin value |
| 122 | custom stdout+stderr default 4 MiB | command output | none | KEEP(a) | Configurable default; storage cost |
| 122 | custom command timeout 10 s; admin max 16 MiB / 60 s | command | none | REMOVE | The approved grant already binds a deadline and output cap (line 67); default the timeout to the approved deadline. Diagnostic commands (jcmd, scripts) routinely exceed 60 s; human timescales (ADR-335 D9) |
| 123 | packet default 256 MiB; policy window 30 s + 30 s; manual duration 60 s | packet recording defaults | none | KEEP(a) | Configurable defaults; bytes are storage cost |
| 123 | packet timeout "window or duration + 60 s" | finalization margin | none | DERIVE | Margin = upload bytes / qualified upload throughput (+ I/O timeout), not a fixed minute |
| 123 | packet admin maximum 4 GiB | packet bytes | none | REMOVE | Hardcoded ceiling on an admin value; capacity admission/per-workload share bounds storage (ADR-335 D2) |
| 123, 124 | 1 h manual duration maximum (packets, syscalls) | manual recording | none | REMOVE | Maintainer requires manual requests to be finite, not ≤1 h; a duration is always present and bytes are capped. Admin may set a ceiling |
| 123, 124 | 10 min post-trigger window maximum (packets, syscalls) | post-trigger window | none | REMOVE | Contradicts ADR-335 D8: "post-trigger windows up to the capture's configured duration (minutes)" |
| 124 | syscall default 64 MiB; window 30 s + 10 s; manual 60 s | syscall defaults | none | KEEP(a) | Configurable defaults |
| 124 | syscall admin maximum 1 GiB | syscall bytes | none | REMOVE | Hardcoded ceiling on an admin value |
| 125, 126, 128 | core / .NET dump / Python core default 2 GiB input | dump size | "sacrifice completeness before sacrificing a node" | DERIVE | A core is ≤ the target's address space in RAM; default = target container memory limit (plus small ELF overhead), bounded by node-local spool/memory and workload quota. A fixed 2 GiB silently truncates any process above 2 GiB, a common JVM/Go service size |
| 125, 126, 128 | dump timeout 30 s | crash/dump handoff time | process held while piping | DERIVE | Real cost: the crashed process cannot be reaped while the pipe is open. Timeout = input cap / qualified local encrypt+spool throughput; state the throughput |
| 125, 126, 128 | admin maximum 8 GiB / 120 s | dump ceiling | none | REMOVE | Replace with the memory-limit derivation and capacity admission; no hardcoded ceiling on admin values |
| 127 | JVM/Node heap admin max 4 GiB / 120 s; 30 s when enabled | heap snapshots | "plus memory-headroom gate" | DERIVE | The headroom gate is the real bound; derive size from heap size/container memory and headroom, time from throughput |
| 129 | "GPU dump / >8 GiB core" disabled; "100+ GiB experiment" | large dumps | node safety | DERIVE | Threshold should be "exceeds node-local spool/memory budget", not a fixed 8 GiB |
| 141 | pending approval waits default 1 hour | WaitingApproval actions | none | DERIVE | ADR-335 D5: an approval covers its stated window; the wait should be the request's stated window (the incident deadline it is useful for), defaulting to the capture's own deadline |
| 141 | administrator maximum 24 hours | approval wait | none | REMOVE | Hardcoded max on an admin value; ADR-335 D9 allows days |
| 151, 135 | descendant `maxDepth`, "bounded enumeration" (no numbers) | descendant processes | none | REMOVE | Pod membership and the pod's PID cgroup limit (`pids.max`, external) bound enumeration; `maxProcesses` bounds the dump set |
| 155 | initial configurable maximum 64 processes | matchedProcesses batch | none | REMOVE | Cost is pause time and bytes, already bounded by `maxTotalStop`, `maxBytesPerProcess` × count ≤ aggregate cap and the dump rate limit |
| 155 | podMainProcesses default one dump process per episode | default batch | none | RAISE | Every pod with a sidecar (service mesh, log shipper) has ≥ 2 main processes, so the default rejects with TooManyProcesses. Default = resolved main-process count, still bounded by aggregate bytes and `maxTotalStop` |
| 155, 157 | maxBytesPerProcess, maxStopPerProcess, maxTotalStop | target pause and bytes | target impact | KEEP(a) | Concrete cost (application paused, bytes stored); grant-bound finite batch (maintainer approval) |

### specs/persistence.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11 | "one bounded local checkpoint" per connector (no number) | connector local state | none | KEEP(a) | One object per connector, bounded by the Kubernetes object limit (1.5 MiB) and lease contents |
| 21 | "bounded JSONB", "bounded reasons", "explicit control-data deadlines" (no numbers) | SQL plan/reason rows | none | DERIVE | Plans come from CRDs: bound = 1.5 MiB object limit (KEEP(b) at that value). Reasons: HTTP request body limit. Control-data deadline = the owning capture's evidence retention (ADR-335 D9 "result handles last as long as the evidence") |
| 29, 97, 99 | capture_history "bounded" listing, "independent summary/settings expiry", "history-only caps/eviction" (numbers in capture-history.md) | history rows | none here | REMOVE | Listing → cursor pagination (already indexed for it, line 97); count caps/eviction → none; settings expiry → evidence/metadata retention of the capture |
| 31 | "bounded lineage traversal" | artifact parent graph | none | REMOVE | Derivation graph is acyclic and finite by construction; a recursive CTE with cycle guard needs no depth constant |
| 33 | ≤ 64 active reservations per grant | concurrent operations per grant | none | REMOVE | Grant counters (executions, bytes, disclosure pool) and per-workload concurrency limits (ADR-335 D8) bound concurrent use |
| 37 | finite tombstone retention covering the restore horizon | deletion tombstones | restore | KEEP(a) | Derived: = backup retention (line 87); tombstones must outlive any restorable backup |
| 53 | serialization retry bounded to three attempts with jitter | whole-transaction retries | none | DERIVE | Bound by the request deadline with exponential backoff and jitter (cost bounded by deadline); a fixed 3 fails requests under brief contention that the deadline would tolerate |
| 71 | default pool total ≤ 30 connections | SQL connections | ADR-335 D11 | KEEP(c) | ADR-335 D11 |
| 71 | ≤ 100 rows per claim | work claim batch | none | DERIVE | Claim = worker's free concurrency slots; internal batch size, no user-visible constant |
| 71 | ≤ 5-second statement timeout (online requests) | SQL statement | I/O timeout | KEEP(c) | ADR-330 D5 five seconds as I/O timeout |
| 71 | ≤ 1-second lock wait (online requests) | `lock_timeout` | none | REMOVE | Lock wait is part of the statement; the 5 s statement timeout already bounds it. A 1 s lock_timeout turns brief contention into user-visible failures |
| 71 | completed work rows expire "after the replay window" (no number) | work row retention | none | REMOVE | Delete when terminal and acknowledged by the connector (event, ADR-330 D7 idempotency by work ID); no window |
| 87 | backup retention default 14 days | pgBackRest retention | privacy notice | KEEP(c) | Aligned with ADR-335 D7 evidence default; admin-configurable |
| 87 | exported audit retained ≥ backup retention | audit export | restore re-application (line 85) | KEEP(a) | Derived floor: restore needs post-restore-point audit batches |
| 89 | TLS 1.2 or newer | DB connections | none | KEEP(b) | Protocol floor (RFC 8996 deprecates TLS 1.0/1.1); Go default minimum |
| 115 | live_watch idle deadline | live watch | ADR-335 D9 | KEEP(c) | ADR-335 D9 10-minute idle window |
| 115 | live_watch "hard deadline" | live watch lifetime | none stated | DERIVE | ADR-335 D9 keeps a watch open while connected; hard end = the observed source's hard end / session deadline, no separate constant |
| 115 | query/output counters, reserved view resources | live watch | live-watch contract | KEEP(c) | Maintainer: finite views with bounded transient rows/replay |
| 119 | artifact_download deadline, read-work reservation | downloads | ADR-312 | KEEP(c) | ADR-312 / ADR-335 D9 original bounds, no request-count cap |
| 123 | finite output/count/operation pool, original expiry | combined result-access grant | approval | KEEP(c) | Maintainer: finite parent disclosure pool |

### specs/ergonomics.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 31 | 5-minute cooldown / burst 2 (workload-failure/v1) | automatic incident captures | "existing ... ceilings" | KEEP(c) | ADR-335 D8 rate limits; should be shown as the configurable default |
| 31 | one contributing pod collected per incident by default | per-incident fanout | maintainer | KEEP(c) | Maintainer: "independently cap per-incident collection" |
| 31 | all authorized replicas under administrator observation ceilings | monitored replicas | maintainer | KEEP(c) | Maintainer: "monitor all replicas within administrator ceilings" |
| 33, 39 | fixed 4,096-byte pod-status projection | saved status | none | REMOVE | Same as evidence.md:41: fixed schema bounds its own size |
| 33 | five-second action deadline (pod-status/v1) | whole pod-status action | none | RAISE | ADR-330's complexity gate cites "5 s/20 s deadline failures in installed runs"; ADR-330 D5 allows 5 s only as an I/O timeout. Use 5 s per API call (I/O) and a human-timescale action deadline (ADR-335 D9) |
| 43 | example "access ends 14 days after acquisition" | retention | ADR-335 D7 | KEEP(c) | ADR-335 D7 |
| 43 | example "managed deletion follows within a day" | `deleteBy` − `expiresAt` gap | none | DERIVE | Deletion runs from stored deadlines on events (ADR-330 D12); gap = reconciler retry schedule, state it as derived (or the privacy spec's value) |
| 53 | raw analysis grants: bounded operations + cumulative budget | MCP raw queries | approval | KEEP(c) | Maintainer: finite parent disclosure pool |
| 53 | "sufficiently recent step-up session" | step-up reuse | IdP policy | KEEP(b) | Off by default (ADR-335 D5); recency is the IdP's `max_age`/`auth_time` (OIDC Core) |
| 75 | "Share future captures" lasts as long as the policy's grant, optional maximum count | recurring sharing | ADR-335 D7 | KEEP(c) | Maintainer: explicitly bounded recurring-policy sharing, no weekly renewal (D7). Gap: non-intrusive policies have no grant (D6), so the end of their future sharing is undefined — state it (until Stop / policy deletion) |
| 103 | policy grant default 90 days; administrator default and finite maximum | automatic intrusive grants | ADR-335 D6 | KEEP(c) | ADR-335 D6; "administrator-configured finite policy approval periods" |

COUNTS: KEEP=49 REMOVE=35 RAISE/DERIVE=34

Most user-visible REMOVE items:
1. specs/actions.md:123-124 — 10-minute post-trigger window maximum contradicts ADR-335 D8 (up to configured duration).
2. specs/actions.md:123-124 — 1-hour manual recording duration maximum (packets and syscalls); finite duration + byte cap suffice.
3. specs/actions.md:122 — 10 s default / 60 s max custom-command timeout; the approved grant already binds a deadline.
4. specs/actions.md:155 — 64-process hard maximum for matchedProcesses dumps (pause/byte budgets already bound it).
5. specs/actions.md:32 — at most 16 actions per recipe.
6. specs/actions.md:141 — 24-hour administrator maximum on approval waiting (D9 allows days).
7. specs/packets.md:27 — 16 authored peer entries per packet capture.
8. specs/packets.md:39 — one-hour maxAge ceiling for rings (maxBytes bounds memory).
9. specs/packets.md:154 — 1 GiB per-query scan ceiling (smaller than a 4 GiB recording; streaming + cursor instead).
10. specs/actions.md:119-128 — all hardcoded "initial administrator maximum" byte ceilings (16 MiB file, 64 MiB logs, 4 GiB packets, 1 GiB syscalls, 8 GiB cores).

---

<!-- part: s4 -->
## Limit audit — part s4

Scope: /home/phil/Projekte/asservat-friction (branch docs/friction-audit), read-only. Files: specs/guidance.md, specs/action-lifecycle.md, specs/execution.md, specs/capture-profiles.md, specs/capture-history.md, specs/artifact-downloads.md, specs/recording-saves.md. Judged against ADR-330, ADR-335 and AGENTS.md "Limits need a reason". Worked examples (e.g. 512 KiB/s, a 16 MiB ceiling, 20 replicas, a five-minute token) are skipped because they are illustrations, not limits.

### specs/guidance.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 32 | 64 runtime instances / 256 processes per pod ("existing ceilings") | process-discovery inventory per pod | none (only "existing"); the same sentence already has "pagination and explicit incompleteness" | REMOVE | Pagination already bounds each response, and the inspect-processes output budget bounds total bytes. The kernel's pod `pids.max` cgroup bounds real process counts. A fixed cap only produces artificial "incomplete" results. |
| 32 | default one pod | discovery pod selection | "A one-pod sample says nothing conclusive about every replica" | KEEP(a) | This is a default, not a cap. Acquisition cost grows per selected pod, and the user can add authorized replicas. |
| 50 | 2 MiB total output (inspect-processes) | process/socket snapshot size | none | DERIVE | Output grows with process and socket count. Derive the cap from pod `pids.max` × the serialized row size, or bound it by the per-workload storage quota, instead of using a fixed 2 MiB. |
| 50, 51, 52 | 5 s action deadlines | individual snapshot actions in the surveys | none | KEEP(c) | Keep this only as a per-read I/O timeout (ADR-330 D5: "Five seconds remains only as an I/O timeout"). It must not be a whole-action deadline. |
| 50, 51, 52 | 10 s overall (processes), 20 s overall (network, protocols) | whole survey capture deadline | none | REMOVE | Use the generic manual-capture deadline in execution.md L43 (sample duration + finalization margin) together with the 5 s I/O timeout. A separate fixed overall deadline is a second, unrelated clock. |
| 51, 52, 102 | 10 s sample ("Sample traffic for 10 seconds") | survey acquisition duration | none | DERIVE | Make it an editable default of the manual recording `duration` (REQ-LIF-005), bounded by the same administrator manual-session maximum. Cost grows with duration, but that is already bounded by the rate × duration observation budget. |
| 51, 52 | 4 MiB packet output (header survey), 8 MiB packet output (protocol survey), plus 2 MiB context each | survey output bytes | none | DERIVE | Derive from the configured observation rate × sample duration (the sensitive grant for protocols, the header impact rate for headers), capped by the workload storage quota. The fixed MiB figures do not follow from any cost. |
| 52, 56 | 2,048-byte snaplen | raw prefix length in protocol reconnaissance | "byte/diagnostic tradeoff" (L85); "Increasing snaplen ... produces a new reviewable plan" | DERIVE | It is an editable default, so a limit is fine, but the number needs a derivation. 2,048 ≥ the common 1,500-byte MTU, so on ordinary interfaces it captures whole packets rather than "prefixes". Only GRO/loopback super-packets get truncated. Derive the default from what the classifiers need (TLS ClientHello including ML-KEM key shares, HTTP/1 request line plus headers, DNS) and say plainly that it is full packets on a 1,500 MTU path. libpcap's 262,144-byte maximum is the external ceiling (KEEP(b) for the maximum). |
| 54 | header ring: four 1 MiB segments; protocol ring: four 2 MiB segments | in-memory survey rings | none | REMOVE | Surveys are `before: 0s` forward recordings, and REQ-LIF-005 manual sessions already "stream ... encrypted to storage". No history ring is needed, so the output/observation budget replaces it. If a ring stays anyway, size it with the L89 formula rather than fixed numbers. |
| 56 | sensitive grant default: 64 MiB observed wire bytes, 8 MiB/s, 10 s (clamped to admin limits) | protocol-reconnaissance observation grant | "Raw prefixes can contain credentials" (justifies a reviewed bound) | DERIVE | A bounded reviewed observation budget is KEEP(c) ("bounded independent approval"; "reviewed observation budgets"). The numbers are internally inconsistent: 8 MiB/s × 10 s = 80 MiB > 64 MiB, so the cumulative cap ends the 10 s sample early at full rate. Derive the cumulative figure as rate × duration and drop the separately chosen 64 MiB. Derive the rate default from collector CPU request / per-byte cost. |
| 58 | survey defaults: 1 in flight per workload, 1 start / 30 s, 10 starts / hour; "administrators may lower them" | survey start rate and concurrency | storm protection (implicit) | RAISE | Rate/concurrency limits stay (ADR-335 D8), but D8 says they default from cluster size, and administrators must be able to raise them, not only lower them. Drop the one-way "may lower". Keep the values as cluster-size-derived defaults. |
| 60 | 14 days default survey retention | survey evidence and recommendation drafts | ADR-335 D7 | KEEP(c) | Administrator-enforced retention, D7 default. |
| 60 | "finite expiry" for plans that persist observed paths/peers | evidence-derived plan content | privacy provenance | KEEP(c) | The value is inherited from the source evidence's retention (D7), with no separate number. Keep. |
| 89 | `N = max(2, …) + 1` segments (minimum 2), burst factor f default 2 | ring sizing recommendation | "extra segment accounts conservatively for writable/eviction slack" | KEEP(a) | A segmented ring structurally needs at least one writable and one evictable segment. f is an explicit, editable estimate parameter, not a limit. |
| 89 | `N > 64` segments → offer less history | ring segment count | none | REMOVE | Per-segment overhead is a few bytes of metadata. What costs memory is M = N × S, which the ring storage ceiling (admin) and node aggregate already bound. Replace with "M must fit the ring storage ceiling". |
| 104 | `recommend_diagnostics` consumes at most four discovery captures | recommendation inputs | none | REMOVE | Each input is one authorized SQL read of bounded projections, already paginated (L103). Use the ordinary MCP output limit and per-request authorization. |
| 104 | returns up to eight ranked choices | recommendation list length | none | REMOVE | The rule catalog is finite (9 goals × a few diagnostics). Return all applicable choices ranked, paginated with the normal cursor/MCP output limit. |

### specs/action-lifecycle.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 22 | "qualified 64 MiB logs limit" (plus mention of a "legacy single-frame recorder cap") | finite logs retrieval output | "qualified" (a test result, not a cost) | DERIVE | History is naturally bounded by kubelet log rotation (`containerLogMaxSize` default 10 MiB × `containerLogMaxFiles` 5), and `pods/log` supports `limitBytes`. The future `after` part grows with duration × log rate. Derive the cap from the requested window and the workload storage quota. Delete the "legacy single-frame recorder cap" sentence as obsolete machinery. |
| 30 | observation pod set "within admin ceilings"; separate smaller `target.maxPods` incident cap | armed replicas vs incident collection | AGENTS.md "Monitor all authorized replicas within administrator ceilings, independently cap per-incident collection" | KEEP(c) | Maintainer decision. |
| 46 | post-trigger window ≤ "administrator ceiling (default maximum 10 minutes)" | ongoing snapshot `after` window | none in addition; the same sentence says bytes stream encrypted, "so a long window is bounded by the snapshot output cap, not by ring memory" | REMOVE | ADR-335 D8: "post-trigger windows up to the capture's configured duration (minutes)". The spec itself states that bytes are bounded by the snapshot output cap. Replace with D8 (capture duration) plus the snapshot output cap. |
| 58, 60 | per-second rates, ring sizes, memory ceilings, cooldowns; "never by a cumulative observed-byte total" | always-on recorders | ADR-335 D6/D8 | KEEP(c) | Maintainer decisions D6 (rates and ring sizes, not lifetime byte budgets) and D8 (storm protection). |
| 60, 68 | cumulative observed-byte/event limits of a finite manual sensitive session | manual raw/argument sessions | "syscall argument mode needs reviewed observation budgets"; bounded independent approval | KEEP(c) | Maintainer decision (reviewed observation budget of one approved finite request). The value should be rate × duration (see guidance L56). |
| 62, 68 | administrator session ceiling "default 1 hour", after which the hub re-arms a new session/epoch | lifetime of one policy source session | "bounds one session's memory and accounting interval" | REMOVE | Memory is bounded by ring size and rates (D6), not elapsed time. Accounting is already "reported to the hub in batches" (same paragraph). The forced re-arm creates an hourly coverage gap and a new epoch for no resource reason, which contradicts D6. Replacement: the source runs while the policy applies (and its intrusive grant is unexpired), with stops via events. |
| 72 (also execution.md L43) | manual session `duration` default 60 s, "administrator maximum 1 hour" | manual forward recording | "manual requests finite" (AGENTS.md); ADR-313 | KEEP(c) | Manual requests finite is a maintainer decision. State explicitly that 1 h is a configurable default of the administrator maximum, not a hardcoded cap. D9 human timescales allow longer. |
| 84, 92 | stopped-source grace "fixed 30 seconds" | how long a stopped source's ring stays snapshot-able | delayed exit/crash events | REMOVE | Memory is already bounded: the stopped ring "never allocates a second ring" and the "oldest unreferenced stopped ring is erased first" under the per-node ring budget (L86). Privacy is bounded by earliest content expiry and the original authority. Replacement: hold until ring-budget eviction, content expiry or authority end. The fixed, non-configurable 30 s only loses late crash/exit events (e.g. delayed watch or Alertmanager delivery). |

### specs/execution.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 15 | intrusive policy grant expires after admin-configured period, default 90 days; non-intrusive: no expiry, no run count | policy grant lifetime | ADR-335 D6 | KEEP(c) | Maintainer decision D6. (`renewalNoticeSeconds` has no stated value here.) |
| 19 | numbers outside the portable exact-integer range fail | canonical digest inputs | RFC 8785 / JS interoperability | KEEP(b) | IEEE-754 / JS safe integer 2^53−1, the limit RFC 8785 canonicalization depends on. |
| 33 | `AuthorityRecheckInterval` 30 s; 5 s only as I/O timeout | authorization reuse | ADR-311, ADR-330 D5 | KEEP(c) | Maintainer decisions. |
| 35 (used by capture-history.md L21) | interactive request deadline "at most 15 seconds" | one browser/MCP request incl. admission, start, history write, repeat preview | none | RAISE | No cost derivation is given. It conflicts with ADR-330 D1, where MCP status tools wait up to 30 s within one request. Either exempt status waits explicitly or raise it to ≥ 30 s (the D1 wait plus margin). A held request costs one goroutine, not a pooled SQL connection (connections are taken per statement). |
| 43 | manual capture deadline = longest duration (default 60 s, admin max 1 h) + finalization margin | manual capture lifetime | "manual requests finite"; "not a fixed five minutes" | KEEP(c) | Same decision as action-lifecycle L72. The 1 h should be a configurable default. |
| 43, 53 | approval window "default 1 h, administrator maximum 24 h" | how long a request waits for an approval decision | none | RAISE | A finite approval is a maintainer decision ("bounded independent approval", D5), but D9 says human waits are "minutes to days", and a 1 h default fails across time zones and nights. Raise the default to 1 day and remove the hardcoded 24 h maximum. Administrators set it, bounded only by the evidence retention the request could produce. |
| 43, 81 | `podBindings` ≤ `target.maxPods`; recording-save pods ≤ policy incident cap | pods per manual capture / save | AGENTS.md "independently cap per-incident collection" | KEEP(c) | Maintainer decision. |
| 85 | manual group children dispatched "at most eight at a time" | dispatch concurrency of one group | none | REMOVE | Dispatch is a stream message per child over the single connector connection. Real execution concurrency is already bounded by per-cluster/node/workload concurrency limits (D8, ≥ 8 per cluster). Replacement: the existing D8 concurrency limits. |

### specs/capture-profiles.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 15 | "up to eight `definition.origins`" records | attribution records in a derived profile | none ("for attribution") | REMOVE | Each record is a small identity/digest pair inside a Kubernetes object. The 1.5 MiB etcd/object limit (b) already bounds it, and nothing iterates over them at runtime. |
| 41 | `profileComposition` "one to eight" components | components per composition | none | REMOVE | Cost is per expanded action and per reserved budget, not per component. The aggregate budgets/administrator ceilings and the Kubernetes object size bound it. |
| 41 | "zero to 32 typed overrides" per component | edits per component | AGENTS.md "finite typed edits" (requires a finite, typed registry, not a count) | REMOVE | Duplicate edits are refused (L27) and only fields the version exposes may be edited. The override count is therefore bounded by the profile's exposed editable-field list. "Finite typed edits" is satisfied by that registry. |
| 47 | final plan "at most 16 actions and 16 endpoint bindings" ("under existing contracts") | expanded recipe size | none beyond "existing contracts" (agent-authored) | REMOVE | Every action is already charged against aggregate output/ring/CPU/concurrency budgets and administrator ceilings (same paragraph). The Kubernetes object size bounds authored size. Replacement: those budgets, plus "one combined review" readability handled by grouping in the UI. |
| 41 | aggregate `maxTotalBytes`/`maxDuration`, defaulting to sum of outputs / longest duration | composed recipe aggregate | "Omitted aggregate bounds resolve to the sum" | KEEP(a) | Derived from the components' own costs; the user may only lower them and admin ceilings apply. |
| 66, 70, 96 | shipped network/syscall profiles: 30 s history + 10 s after; HTTP headers 30 s before/after | default windows of shipped profiles | none (defaults) | KEEP(a) | Editable defaults; ring cost grows with history and is bounded by the admin ring ceiling. Not caps. |
| 68, 69 | `go-cpu` 10 s profile duration | default pprof CPU duration | none | KEEP(a) | Default only, editable via `go-profile`; cost (sampling overhead) grows with duration. (Go's `net/http/pprof` default is 30 s; 10 s is a reasonable shorter default.) |

### specs/capture-history.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 47, 49 | case-metadata lifetime default 90 days, "bounded by the administrator maximum" | history summaries and settings snapshots | administrator-enforced retention | KEEP(c) | Administrator retention (AGENTS.md; D7 style). It is configurable; there should be no hardcoded max on the administrator value. |
| 51 | at most 1,000 summaries per selector (admins may only lower) | history rows per selector | none ("trigger storms" handled separately by filters, L9) | REMOVE | Rows already expire at the 90-day metadata lifetime. Listing uses keyset pagination (L61), and storms are bounded by policy rate limits (D8). Eviction makes "Repeat" silently unavailable for older entries. |
| 51 | at most 100,000 summaries per installation | history rows per installation | none | REMOVE | Same reasons. PostgreSQL handles millions of narrow indexed rows, so rate limits × 90 days bounds growth. The installation-wide cap also lets one noisy workload's growth evict others' history at the margin. |
| 51, 63 | 128 KiB serialized parameter snapshot per request | settings snapshot size | none directly | DERIVE | The snapshot is the authored spec plus the expanded recipe. Derive the maximum from the Kubernetes object limit for the authored DebugCapture/DebugPolicy (1.5 MiB) plus the expanded recipe. Drop the "accepted without a snapshot / SettingsUnavailable" branch, which exists only because of the cap. |
| 63 | fixed 160 KiB browser response budget for `get_capture_settings` | browser settings read | "covering the bounded 128 KiB snapshot and its envelope" | REMOVE | The authenticated browser reads over HTTP and can stream. The only real bound is the snapshot's own size (above). The MCP byte limit applies separately to MCP, unchanged. |
| 61, 77 | page default 20, maximum 100 | `list_capture_history` page size | pagination | KEEP(a) | A page size is the pagination itself (AGENTS.md "Prefer pagination"); response memory grows with page size. A maximum could be derived as MCP output limit / row size, but 100 is conventional. |

### specs/artifact-downloads.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11 | generated filenames "at most 200 bytes" | download/bundle file names | none stated | KEEP(b) | Linux NAME_MAX is 255 bytes (also the NTFS/APFS component limit). 200 leaves room for `.core.tar` and the `-<8 hex>` disambiguator (≤ 18 bytes). Note: bundle member paths `<base>/<base>.core` can reach ~400+ bytes, which exceeds the ustar 100+155-byte field. The tar must use pax extended headers; state this. |
| 37, 48 | `AccessUntil` = effective retention end, narrowed to share/grant end; grant covering download defaults to `AccessUntil`, "capped by the administrator maximum" | download authority lifetime | ADR-312, ADR-335 D7/D9 | KEEP(c) | Retention and bounded approvals are maintainer decisions. The administrator maximum is configurable. |
| 39 | prepare/status reuse authorization ≤ 30 s | download authorization reuse | ADR-311 | KEEP(c) | Maintainer decision. |
| 62 | MCP status waits server-side at most 30 s | `download_artifact(action=status)` | ADR-330 D1 | KEEP(c) | Maintainer decision. |
| 74 | "two concurrent streams per principal" | per-user download parallelism | "Fairness limits" | DERIVE | Fairness is a real cost (reader replica streams), but 2 is arbitrary. Downloading a core bundle plus a pcap plus a profile already hits it, and browsers parallelize. Derive it as a fair share of installation concurrency (e.g. max(2, replicas × per-replica limit ÷ 4)), or rely on fair queuing across principals. |
| 74 | installation concurrency = reader replicas × configured per-replica stream limit, narrowed by bandwidth budgets | total download streams | reader capacity | KEEP(a) | Derived from the actual resource (reader replicas). Give the per-replica default a derivation from reader memory request / per-stream buffer. |

### specs/recording-saves.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11 | pages default 20, maximum 100 | `list_recordings` inventory pages | pagination | KEEP(a) | Pagination page size (same as capture-history). |
| 19, 55 | 1–16 distinct source handles per save; "1–16 action rows" in grouped progress | sources per save | none | REMOVE | The same sentence already applies "the policy's incident pod cap and local ceilings" (KEEP(c)). Sources per pod are bounded by the policy's ongoing actions. Replacement: incident pod cap × the policy's ongoing actions. |
| 19, 81 (execution.md) | the policy's incident pod cap | pods per save | AGENTS.md "independently cap per-incident collection" | KEEP(c) | Maintainer decision. |
| 27 | StartBy = min(t0 + 15 s, caller/session end, source/processing limits) | when a save child must start | none | REMOVE | L25 already says "Node receipt later than t0 may lose history; it never captures newer bytes", and coverage is reported truthfully. A late child yields partial coverage, not a correctness problem. Failing it at t0+15 s throws away still-retained history. Replacement: source hard end / processing authority / ring eviction plus truthful coverage. |
| 37 | policy authority `maxExecutions` counter "charges once per Save" ("maintainer decision, 2026-10-30") | number of saves/executions of a policy | cited dated decision (not in the accepted maintainer-decision set; it only fixed per-Save charging) | REMOVE | ADR-335 D6: non-intrusive policies "have no run count", and always-on recorders are bounded by rates and ring sizes. Recording saves only freeze already-observed packet/syscall bytes. Replacement: the D8 rate/cooldown/concurrency limits (L37) and the intrusive grant's expiry. |
| 37 | occurrence cooldown/rate, concurrent snapshot/output, per-node, storage, fair upload limits | manual saves | storm protection | KEEP(c) | ADR-335 D8 (rate and concurrency limits stay). |
| 39 | grant budgets reserve "one sensitive snapshot start per source plus worst-case output bytes" | cumulative per-grant save budget | none beyond grant accounting | REMOVE | D6: recorders are bounded "by rates and ring sizes, not lifetime byte budgets". The sensitive bytes were already authorized when observed. Replacement: storage quota + rate limits; the grant's expiry bounds its lifetime. |
| 61 | reason "1–512 Unicode scalars" | optional free-text reason | none | REMOVE | Descriptive SQL text with negligible cost. 512 is short for an incident description. Replacement: the HTTP request body size limit (b); if a field bound is wanted for UI, derive it from that. |
| 73 | "Save last N seconds", N = approved lookback, default 30 | one-click save window | "N = the approved lookback" | KEEP(a) | Not an independent limit: it is the policy's own `before`, bounded by its ring size. |

COUNTS: KEEP=28 REMOVE=22 RAISE/DERIVE=11

Most user-visible REMOVE items:
1. specs/action-lifecycle.md:62 — forced 1-hour re-arm of policy recorders, which causes hourly coverage gaps with no resource reason (contradicts D6).
2. specs/action-lifecycle.md:46 — separate 10-minute post-trigger admin ceiling (D8 says up to the capture's configured duration).
3. specs/recording-saves.md:37 — `maxExecutions` run count charged per Save (D6: no run count).
4. specs/recording-saves.md:27 — StartBy t0+15 s fails a late save that could still return retained history.
5. specs/capture-history.md:51 — 1,000/selector and 100,000/installation history caps, which evict "Repeat" before the 90-day lifetime.
6. specs/action-lifecycle.md:84 — fixed 30 s stopped-source grace, which loses delayed crash/exit saves even though the ring budget already bounds memory.
7. specs/capture-profiles.md:47 — 16 actions / 16 endpoint bindings per plan.
8. specs/capture-profiles.md:41 — 8 components / 32 overrides per composition.
9. specs/guidance.md:32 — 64 runtime instances / 256 processes per pod in discovery (pagination exists).
10. specs/recording-saves.md:19 — 1–16 sources per save (incident pod cap already applies).

---

<!-- part: s5 -->
## Limit audit — part s5

Scope: specs/capture-assessment.md, deployment-profiles.md, apis.md, syscalls.md, live-watch.md, policy-automation.md, federation.md, targets.md, investigation-approval.md, user-experience.md, implementation-architecture.md, interfaces.md, domain-model.md, README.md, examples.yaml, changes/postgresql-hub-state/proposal.md (branch docs/friction-audit, read-only). Measured against ADR-330, ADR-335 and the AGENTS.md rule "Limits need a reason".

### specs/capture-assessment.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 34 | per-capability "freshness limit" (no number) | age after which a metric input counts as unknown | "counts as unknown rather than invalidating the preview" | DERIVE | It only labels the input, which is fine, but the number has no basis. Derive it from the source's own sampling interval (metrics.k8s.io resolution / the configured sample interval, ADR-330 D1), e.g. staleness = 2 × sample interval. Don't set it per capability by hand. |
| 32 | "bounded, actionable alternatives" (no number) | number of alternatives returned | none | REMOVE | The list is finite by construction: at most one narrowing per applicable action and dimension. Drop the "bounded" cap and order the list by impact. |
| 73 (SC-ASM-004), cf. apis.md 17 | "five-minute deletion budget" (access ends 17:55, deletion due 18:00) | gap between access cutoff and the deletion-due deadline | implicit: deletion must complete by the max age | DERIVE | The reason holds: the administrator's maximum (335 D7) has to be met by *completed* deletion. The number, though, should be the measured or estimated object-store delete time for the artifact's object count (plus one I/O timeout), not a fixed administrator figure. The 6-hour core maximum in the same example is only an illustrative admin value (KEEP(c) as admin-configured). The default is 14 d (335 D7), so the example could use the default instead. |
| 80 | "shorter expiry" for live-metric/evidence-derived assessment details | stored assessment details on accepted records | "do not enter long-lived audit" | REMOVE | Previews are stateless (ADR-330 D9), and the details can be recomputed from the plan digest plus rule revision. Store only the assessment identity and rule digests with the accepted record. That leaves no detail rows that need a separate expiry. |
| 82 | MCP "ordinary result limits"; "cannot fit → bounded error with authenticated navigation" | size of the preview_capture assessment | "must not silently omit the most consequential warnings" | REMOVE | Remove the error fallback. Return the combined summary and consequential warnings first, then per-action detail through a cursor (AGENTS: "prefer pagination or streaming over caps"). The envelope size itself is covered under live-watch.md 33. |
| 97–99 | rate and ring ceilings; observed-byte limit for a finite manual sensitive session | policy recorder sources; finite manual sensitive sessions | "Show rate and ring ceilings … observed-byte limit" | KEEP(c) | 335 D6: recorders are bounded by rates and ring sizes. AGENTS: "syscall argument mode needs reviewed observation budgets" and "manual requests finite". |

Not limits (illustrations only): 19 "a 10-second stop budget is not a predicted 10-second pause" (an example showing that limits are not forecasts).

### specs/deployment-profiles.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 27 | per-client and per-subject authentication rate limits (no number) | local login attempts | "bounded by per-client and per-subject rate limits, not by an installation-wide session ceiling" | KEEP(a) | Each attempt runs a memory-hard hash, so CPU and memory grow with the attempt rate. Derive the default from the hash cost parameters and the hub-api CPU request. The installation-wide session ceiling is already removed (consistent with 335 D8). |
| 29, 33 | `identity.AuthorityRecheckInterval` (30 s) | delay before disable or membership changes take effect | ADR-311 | KEEP(c) | ADR-311 / ADR-330 D5. |
| 39 | "bounded closed JSON" local-key Secret | key Secret payload | schema | KEEP(b) | Kubernetes Secret size of 1 MiB (etcd). Number of retained versions: none needed beyond that. |
| 41 | key service "finite payload … limits" | wrap/unwrap request size | none | KEEP(a) | Requests carry fixed-size keysets. Derive the cap from the keyset size and record it as such. |
| 41 | key service "concurrency … limits" | concurrent wrap/unwrap calls | none | REMOVE | Callers are mTLS-authenticated installation workloads. Their rate is already bounded by capture concurrency (335 D8), at 3 wraps per attempt, and by the reader replica count. Standard HTTP server limits are enough. |
| 41 | key service "deadline limits" | per-call deadline | none here | KEEP(c) | Five seconds only as an I/O timeout (ADR-330 D5). |
| 41 | "bounded number of key wraps per attempt" (3: data/index/manifest) | KMS calls per artifact | "independent of payload size" | KEEP(a) | Fixed by the artifact format (ADR-048/066). It keeps KMS load independent of size. |
| 49 | "bounded resource/storage settings" for bundled PostgreSQL and object store | Pod requests and limits, PVC sizes | sized by PVC values | KEEP(a) | Real disk and memory cost. Kubernetes scheduling needs requests. Per 335 D2, defaults should be derived from the cluster/storage size values. |
| 51 | pgBackRest "finite encrypted base/WAL recovery", configurable schedule/retention | backup and WAL retention | privacy (backups retain deleted rows) | KEEP(c) | Administrator-enforced maximum evidence retention (335 D7) also has to bound backups. Make the default retention equal to the configured maximum evidence retention (14 d) rather than an independent number. |
| 53 | ≥ 2 hub-api replicas available; standby hub-worker | availability | ADR-335 D13 | KEEP(c) | 335 D13. |
| 53 | rollback window = previous minor release (expand/contract N-1) | supported `helm rollback` distance | "that is the supported `helm rollback` window" | KEEP(a) | Each additional supported schema generation adds migration and test cost. Matches the N/N-1 connector rule (federation.md 27). |
| 61 | setup Job `activeDeadlineSeconds` (no value) | how long setup retries unreachable providers | none | DERIVE | Helm's `--wait-for-jobs` already enforces `--timeout` (default 5 m). Derive the default from that timeout: deadline = Helm timeout minus margin. A separate unjustified number would make slow bundled Keycloak first starts fail spuriously. |

### specs/apis.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11, 89 | "optional bounded future-result sharing"; SharingRegistration "bounded counters" | recurring policy sharing | maintainer | KEEP(c) | AGENTS: "explicitly bounded recurring-policy sharing". 335 D7: no weekly renewal. Recipient caps 8/32 are out of scope here (other agent). |
| 13 | EvidenceStoragePool "transfer ceiling" | upload bandwidth | none | KEEP(a) | Network and object-store bandwidth is a real cost. Per 335 D2 it should default from the cluster/store (or be unset = unlimited) and must not be a required operator figure. |
| 13–14 | protected workload slots, burst, system/headroom reserves; per-workload protected/hard/context capacity; dump/rate/queue limits | evidence storage and capture storms | capacity isolation | KEEP(c) | AGENTS: protection against capture storms and cross-workload storage exhaustion. 335 D2/D8: defaults derived from cluster size. |
| 15 | CollectionCeiling "maximum budgets" | per-cluster admin ceilings | admin | KEEP(c) | Administrator ceilings (335 D8). |
| 17 | EvidenceRetentionPolicy "finite default/max ages" | retention | maintainer | KEEP(c) | 335 D7 (14 d evidence, 14 d cores). |
| 17 | EvidenceRetentionPolicy "deletion budget" | access cutoff before the deletion deadline | see capture-assessment 73 | DERIVE | Derive it from measured delete latency, as in the capture-assessment row. |
| 32 | "bounded arrays/strings/maps" in all CRD schemas | CRD field sizes | none (implicit) | KEEP(b) | The Kubernetes CEL cost estimator needs maxItems/maxLength, and objects are capped at 1.5 MiB. Choose each bound so CEL rules fit the per-expression cost budget and the object fits 1.5 MiB. Small arbitrary per-field numbers are not justified. |
| 36 | "Deletion/finalizer logic has bounded retries" | finalizer retry count | "documented operator recovery" | REMOVE | Use standard controller exponential backoff with capped delay that retries until success, plus a Condition reporting the failure. A retry count that gives up leaves stuck finalizers that need manual work. |
| 81 (and federation 11, 23) | work/commands "expiry-bound" | lifetime of a pushed command | original bounds | KEEP(c) | ADR-311/312: expiry equals the admission's original hard end and is not a separate TTL. Keep it worded that way. |
| 107 | analysis profile "bounded input/output/aggregate capacity" | encrypted scratch usage | scratch is a PVC | KEEP(a) | Disk cost. Bound = provisioned scratch PVC size of the qualified StorageClass. |
| 111 | CollectionCeiling per-scope live view limits | live view admission | finite views | KEEP(c) | AGENTS: "live watch finite views with bounded transient rows/replay". |
| 111 | "Administrator values can only narrow effective admission" (live-view defaults) | admin's ability to raise live defaults | none | REMOVE | Brief note: a hardcoded max on a configurable value. Let administrators raise or lower the defaults. The resource-derived bounds (live-watch.md 47) are the real constraint. |
| 111 | watch closes after 10 idle minutes | live watch idle lifetime | ADR-335 D9 | KEEP(c) | 335 D9. |
| 113 | live CPU-time and examined-event/byte limits "typed and bounded in generated schemas" | live projection work | see live-watch 47 | DERIVE | See live-watch.md 47. |

### specs/syscalls.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 7 | tracked threads default 4,096, portable maximum 16,384 | eBPF tracked-thread map per pod | none ("cap concurrently tracked threads separately") | DERIVE | It's a real eBPF map memory cost, but the numbers are arbitrary. Size the map to the pod cgroup's `pids.max` (kernel-enforced thread limit, external), capped by the collector memory share ÷ entry size. Overflow stays a coverage gap. |
| 9 | include list of at most 128 syscall names | syscall filter length | none | REMOVE | The qualified ABI table bounds it (~460 syscalls on x86_64, external), and unknown names are already refused. |
| 19 | shipped ongoing metadata profile: before 30 s, after 10 s, four 2 MiB segments, maxEventsPerSecond 10,000, one snapshot | default ring size, rate and per-incident snapshots | profile defaults | KEEP(c) | Configurable defaults of exactly what 335 D6/D8 keep: "bounded by rates and ring sizes"; "independently cap per-incident collection". |
| 19, 85 | maxEvents 100,000 (ring and snapshot); portable 1,000,000 resident ring events | event count in ring and snapshot | 85: "limits resident ring entries and each saved snapshot separately" | REMOVE | Segment bytes already bound ring memory. An event count adds a third truncation reason and a second shortened-history mode with no extra resource protection. Replacement: segment byte size, plus the before window as age. |
| 19 | maxFrozenBytes 16 MiB | frozen copy per incident | none | DERIVE | maxFrozenBytes = ring bytes (8 MiB) + after × maxEventsPerSecond × record size. With a fixed 16 MiB, a larger ring silently truncates. |
| 19 | per-incident action deadline = window + 60 s | snapshot/upload completion | none | DERIVE | Slack = maxFrozenBytes ÷ effective upload rate + one I/O timeout (ADR-330 D5) instead of a fixed 60 s. |
| 19 | manual duration default 60 s, administrator maximum 1 hour (also "one-hour manual duration" portable ceiling) | finite manual recording session | "Administrators may change these ceilings" | KEEP(c) | AGENTS: "manual requests finite". 335 D8: windows up to the capture's configured duration (minutes). The admin can change the 1 h default ceiling. Consider a minutes-scale default (e.g. 5 min) per 335 D9, because 60 s is short for a human-started session. |
| 19 | portable 100,000 events/s | event rate ceiling | none | KEEP(c) | Storm and rate protection (335 D8). The default should be derived from qualified collector CPU throughput. |
| 19 | portable 256 MiB ring/frozen memory | collector memory for rings | none | DERIVE | Derive it from the node collector's memory request/limit minus its baseline, divided among armed rings. The fixed figure has no tie to the DaemonSet's actual memory. |
| 19 | portable 64 segments | segment count | none | REMOVE | Total ring bytes is the resource. The segment count is an implementation detail; replacement: ring byte budget. |
| 19 | portable one-hour ring age | maximum ring history age | none | REMOVE | Ring bytes bound memory. Privacy is bounded by first-acquisition evidence retention (335 D7, 14 d), and `before` is the user's choice. |
| 19 | 10-minute default maximum post-trigger window | after window | none | REMOVE | 335 D8: "post-trigger windows up to the capture's configured duration (minutes)". Replacement: the capture's configured duration plus the frozen-byte budget. |
| 21 | "Periodic circuit-breaker checks" (no interval) | impact sampling | impact limits | DERIVE | ADR-330 D1 allows sampling only for sources without events. Use the configured metrics source interval (metrics.k8s.io resolution), and use kernel/ring overflow events where they exist. |
| 23 | maxBytesPerEvent maximum 4 KiB | user-memory bytes read per event | implicit (bounded reads) | KEEP(b) | Linux PATH_MAX 4096 for path arguments, and eBPF per-CPU scratch buffer / verifier-bounded `bpf_probe_read_user` sizes. |
| 25, 107 | finite argument session `maxObservedEvents` + cumulative byte limit | sensitive observation spend | reviewed observation budget | KEEP(c) | AGENTS: "syscall argument mode needs reviewed observation budgets". |
| 25 | fixed 256-byte charge per probe event | accounting unit for argument observation | "conservative fixed 256-byte charge … cannot undercharge larger fixed records" | DERIVE | Charge the adapter's actual fixed record size, which is pinned in the accounting digest. 256 is a guess. |
| 25 | policy argument recorder bounded by grant expiry, per-second rate and ring size | policy argument tracing | 335 D6 | KEEP(c) | 335 D6. |
| 44–46 | each delivered query page consumes 24 KiB and one operation from the grant pool | disclosure pool spend | "finite disclosure pool" | DERIVE | The pool is KEEP(c) (AGENTS "finite parent disclosure pool"). Charge actual delivered bytes, settled per ADR-330 D7 as investigation-approval.md 21 already does. A flat 24 KiB charge makes small pages expensive. |
| 46 | argument source limit 8 MiB | size of an argument artifact that can be queried | none | REMOVE | Pages stream frames in order ("read frames … until the page is full or the scan bound"). The artifact size is already bounded by the capture's output limit. Replacement: streaming reads in the reader. |
| 48 | 20 KiB private page, 24 KiB direct/nested public envelope | MCP syscall_query page | none here (mcp.md) | DERIVE | Page = envelope − fixed envelope overhead. Derive the envelope itself from the MCP client's tool-result limit (e.g. Claude Code default `MAX_MCP_OUTPUT_TOKENS` 25,000 tokens, ≈ 80–100 KB), with a client-chosen page_size. 24 KiB is about a quarter of what typical clients accept. |
| 53 | 128-byte memory-value check, 8192-byte line check | one recorded value; one JSONL line | "stricter than public schema ceilings" | DERIVE | They contradict maxBytesPerEvent 4 KiB: a 4 KiB buffer cannot be returned through a 128-byte value. Derive value max = maxBytesPerEvent, and line max = Σ(argument bytes × base64 4/3) + fixed record. |
| 59 | per-page "scan bound" (no number) | frames scanned per page request | none | DERIVE | It protects reader CPU per request. Bound by elapsed reader time per page (return the partial page with continuation), not by a frame count. Or drop it, since the artifact size is already bounded by the output limit. |
| 123 | "kernel-enforced original deadline" | stopped finite session | ADR-312 | KEEP(c) | ADR-312 / ADR-313. |

### specs/live-watch.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11 | 1–16 distinct sources per open | fanout of one watch | "live-view fanout limits" | REMOVE | Projections are shared per source/cohort (49), so the per-viewer cost is delivery only. Replacement: per-node subscription/CPU limits and the per-watch delivery rate. Watching all replicas fits the maintainer's "monitor all authorized replicas". |
| 19, 26, 81 | 10-minute idle window; open while connected | watch lifetime | ADR-335 D9 | KEEP(c) | 335 D9. |
| 21 | authority reuse ≤ 30 s | live authority | ADR-311 | KEEP(c) | ADR-311 / ADR-330 D5. |
| 23 | "bounded literal values" in display filters | filter literal count/size | none | REMOVE | Filters travel in the request body, not the URL (63). The HTTP request-body limit already bounds them, and filtering is per-viewer CPU on already-projected rows. |
| 33 | MCP batch default 20 rows, maximum 100 | rows per watch_live read | none | REMOVE | The byte envelope already bounds the result, so drop the row max. A default of 20 rows is fine as a default. |
| 33 | 24 KiB target / 32 KiB structured / 64 KiB combined MCP limits | MCP result size | "no unbounded tool results or model-context flooding" (78) | DERIVE | A reason exists (client context). Derive the limits from MCP client tool-result limits (Claude Code default 25,000 tokens ≈ 80–100 KB) and let the caller pick a smaller size. |
| 33 | `wait_ms` 0–30000 | long-poll hold | ADR-330 D1 | KEEP(c) | 330 D1: MCP waits at most 30 s. |
| 33 | at most one outstanding read per watch | concurrent long-polls per watch | none | KEEP(a) | Each held read occupies a server connection/goroutine, and rows are a single ordered cursor. Let a new read supersede the old one (as SSE reconnect does) instead of refusing it. |
| 37 | 1 MiB replay buffer per watch | hub memory per watch | "inside shared workload/node/hub ceilings" | DERIVE | Replay = delivery rate × reconnect allowance (64 KiB/s × 16 s = 1 MiB). Write the formula, then check that installation watches × replay fits the hub-api memory request. |
| 47 | 128 watches per installation | hub watch slots | "configuration limits" | DERIVE | Derive it from hub memory: hub-api memory share for live ÷ (replay + per-watch state) × replicas (2, 335 D13). |
| 47 | 2 watches per principal | per-user concurrency | none | REMOVE | A user with two tabs plus an agent is refused. Replacement: per-node CPU/examined-bytes budgets, per-watch delivery rate and installation slots. These already bound cost, and 335 D8 says sessions are bounded by rate limits. |
| 47 | 4 watches per workload | per-workload viewers | none | REMOVE | The projection is shared per cohort, so extra viewers cost only delivery. Replacement: delivery rate and node projection CPU. |
| 47 | 16 subscriptions per node | node projection fanout | none | DERIVE | Derive it from the node projection CPU budget ÷ measured per-subscription parser cost. |
| 47 | 64 KiB/s delivery per watch | hub egress per watch | none | DERIVE | It's a real network cost, but the number is arbitrary. Derive it from a hub egress budget ÷ watch slots, or from human-readable row rate × row size. |
| 47 | per node 250 millicores projection CPU, 50,000 examined events/s, 16 MiB/s examined bytes | collector work on workload nodes | "configuration limits, not measured overhead" | DERIVE | Workload-node CPU is a real cost. Set projection CPU as a fraction of the node collector's CPU request/limit, and derive events/bytes from measured parser throughput at that CPU. |
| 47 (and apis 111) | "administrators may only narrow" | admin raising live defaults | none | REMOVE | A hardcoded max on a configurable value. Let administrators raise them. |
| 47, 57 | rolling hourly scan/delivery budgets per principal and workload (SQL counters) | cumulative live use | "closing and opening a fresh watch does not reset them" | REMOVE | These are lifetime-style budgets on a viewer. The per-second rates and node CPU budgets already bound cost, and reopening cannot exceed a rate. They also add an SQL counter write path. An agent watching for an hour gets cut off. Replacement: the existing rate limits (335 D8). |
| 63 | browser row bound 500 rows / 1 MiB | rows kept in the browser | "unbounded DOM growth" | RAISE | Browser memory is a real cost, but with a virtualized list DOM cost is constant. Raise to a memory-derived bound (e.g. ≈ 16 MiB of rows) or at least the replay size × N. 500 rows of HTTP headers scroll away in seconds. |
| 63 | rows never kept past the source/content privacy deadline | browser row lifetime | retention | KEEP(c) | 335 D7, administrator retention. |

### specs/policy-automation.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11 | `maxExecutions` default 1,000 for intrusive kinds | lifetime run count of an automatic intrusive policy | none | REMOVE | 335 D6 keeps expiring grants (90 d), not run counts. Storms are bounded by rate/concurrency limits (335 D8). A team hitting 1,000 dumps in 90 days stops silently. Replacement: grant expiry + D8 rate limits. A team may still set an optional field, with no default. |
| 11, 43 | `maxGrantSeconds` default = admin policy-grant period (90 d); grant ≤ envelope maxGrantSeconds | automatic intrusive grant lifetime | 335 D6 | KEEP(c) | 335 D6: admin-configured periods, default 90 days. |
| 19 | 1–8 sponsoring groups | groups recorded on acceptance | none | REMOVE | Bounded by the binding's group subjects, i.e. the AccessBinding object's 1.5 MiB size (K8s). |
| 23 | number of policies not limited beyond K8s object limits | policy count | 335 D8 | KEEP(c) | 335 D8 (consistent). |
| 43 | `RenewalDue` from 14 days before expiry | renewal warning lead time | none | DERIVE | With an admin period of a few days, 14 d makes the policy "RenewalDue" for its whole life. Use lead = min(14 d, ~15 % of grant period). |
| 61 | policy-shared "native-output and observed-byte counters with the limits" | lifetime byte pools per policy | none | REMOVE | Obsolete per 335 D6: "always-on recorders bounded by rates and ring sizes, not lifetime byte budgets". syscalls.md 25 already says a policy argument recorder is bounded by grant expiry, rate and ring. Replacement: rate + ring + grant expiry. The execution counter goes with maxExecutions above. |

### specs/federation.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 7 | cluster count "bounded only by the installation's sizing" | registered clusters | 335 / ADR-332 | KEEP(a) | Not a hard cap. The cost per cluster (connection, pushed state) is real, and sizing covers it. |
| 9 | fallback join token default validity 24 h, reusable within it | bearer join token lifetime | none (precedent kubeadm) | KEEP(b) | Matches the kubeadm bootstrap-token default TTL (24 h). It limits the window for a leaked bearer secret, and the administrator can configure it. Strictly a precedent, not a hard protocol limit. |
| 11, 23 | commands/work "expiry-bound" | work lifetime | original bounds | KEEP(c) | ADR-311/312: expiry = admission hard end. |
| 23 | connector "bounded local state" of accepted workIDs | dedup state size | none | REMOVE | Keep each workID until the hub acknowledges its terminal state. In-flight work is already bounded by concurrency limits (335 D8), so a count cap would only risk duplicate intrusive starts. |
| 25 | last-seen time written at most once per minute | SQL write rate per cluster | none | REMOVE | A periodic write contradicts ADR-330 D1 ("An open connection is liveness"). `connected_since`/`disconnected_at` events plus the replica-owner row are enough. A crashed replica's rows are released by its Lease/connection loss. |
| 25 | offline display after 60 s closed | console offline badge | "display status, not an authority bound" | DERIVE | It suppresses flapping, which is a valid reason. Derive it from the connector's maximum reconnect backoff (e.g. 2 × max backoff). |
| 35, 37 | connector budget lease; "reserved local spool" | disconnected execution and storage | storm and storage protection | KEEP(c) | AGENTS: capture storms / storage exhaustion. Spool size = configured spool volume (`emptyDir.sizeLimit` / PVC), which is KEEP(a). |
| 37 | "bounded local queue" for metadata events | connector memory | backpressure | KEEP(a) | Connector memory cost. Derive it from the connector memory request ÷ event size, with drop/gap counters. |
| 61 | "bounded DNS resolution/redirect behavior" for webhooks | SSRF exposure | SSRF | KEEP(b) | Standard Webhooks/SSRF practice; prefer "no redirects". |
| 69 | webhook retries up to 24 h by default, then dead-letter | outbox retry duration | none | KEEP(b) | Matches the Standard Webhooks / Svix reference retry schedule (≈ 1 day). Outbox rows grow with it (a). It's an admin-configurable default. |
| 69 | rate limit on recurrence events (no number) | outgoing recurrence event rate | "without losing aggregate counts" | KEEP(c) | Storm protection (335 D8). The default should derive from cluster size like the other rate limits. |

### specs/targets.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 7, 9, 47 | `target.maxPods: 1` default | pods collected per occurrence | maintainer | KEEP(c) | AGENTS: "independently cap per-incident collection". It's a default the user can change. |
| 35 | follow-mode peer membership "changes are bounded" | peer set size / generation churn | none | KEEP(b) | The peer IP set must fit the eBPF map / BPF instruction limit (4096 cBPF instructions for compiled filters), which bounds set size. Do not add a separate change-rate cap, since generations follow EndpointSlice events (ADR-330 D1). |
| 43 | portable ceiling 1,000 pods per policy, "intersected with the qualified installation envelope" | observed replicas per policy | none | REMOVE | AGENTS: "monitor all authorized replicas within administrator ceilings". The admin's workload/node/cluster sensor ceilings and per-pod ring reservations already bound cost. The 1,000 figure comes from the old test envelope (proposal.md 96). |
| 43 | optional `observation.maxPods` (narrow only) | user narrowing of observation | user choice | KEEP(c) | It's a user-chosen narrowing under the admin ceilings (AGENTS). |
| 59 | 64 container instances and 256 processes per pod, "initially, with administrator narrowing" | runtime fanout per pod | "no unbounded per-container multiplication" | REMOVE | The same paragraph already makes byte/time/concurrency reservations aggregate per pod ("maxBytes is the aggregate per action per selected pod"), so fanout cannot multiply cost. Containers are bounded by the Pod object (1.5 MiB) and processes by the pod cgroup `pids.max`. Replacement: the aggregate per-pod reservations. |

### specs/investigation-approval.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 9, 21 | `maxArtifacts`, `maxBytes`, `maxOperations`, `notAfter` | result-access disclosure pool | maintainer | KEEP(c) | AGENTS: "one bounded independent approval", "finite parent disclosure pool". The UI fills them in. |
| 9 | "Each count is installation-bounded" | hardcoded installation maxima on those counts | none | REMOVE | A hardcoded max on a reviewer-approved value. The reviewer already approves exact counts. Bound only by int64 / JS safe integer 2^53−1 (b). |
| 11 | `notAfter` default = access end of the collected evidence | result access lifetime | 335 D9 | KEEP(c) | 335 D9: result handles last as long as the evidence. |
| 31 | at most 16 actions | output actions in result_access | none | REMOVE | Bounded by the compiled plan's actions (recipe CRD object size). Replacement: none needed. |
| 31 | 256 GiB pool | maximum result-access byte pool | none | REMOVE | Derive the pool from the selected outputs' maximum sizes × planned full downloads (line 9 already requires the review to show coverage). A >256 GiB core would be undownloadable. Replacement: int64 bytes. |
| 35 | review decidable until request `notAfter` (default 24 hours) | pending approval request lifetime | none | REMOVE | 335 D9: "previews and approvals stay valid while unchanged"; 335 D5: approval covers its stated window. A Friday-evening request is dead on Monday. Changed Pods/plans already end as `TargetChanged` at approval time. Replacement: decidable while the plan is unchanged; requester withdraws; an optional requester-set notAfter. |

### specs/user-experience.md

No numeric limits. Line 25 "reconnects with backoff" names no interval; WCAG 2.2 AA (line 48) is a conformance target, not a limit.

### specs/implementation-architecture.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 23 | HTTP/IPC caps applied before decompression/allocation (no number) | internal message size | "before decompression or allocation can escape the budget" | DERIVE | It's real memory protection. Set per-message caps from the largest legitimate message, e.g. a pushed Kubernetes object ≤ 1.5 MiB (etcd), and stream chunks for evidence bytes. Don't use free-chosen numbers. |
| 31 | Indeterminate starts stay charged until outcome or node boot-ID change | uncertain charges | ADR-330 D7 | KEEP(c) | Resolved by operation ID (330 D7). No time limit, which is consistent. |
| 47, 51 | "bounded local budget leases" | disconnected spend | storm protection | KEEP(c) | AGENTS capture-storm protection. |

### specs/interfaces.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 25, 29 | authority reuse ≤ 30 s; "revoked share fails within 30 s" | authorization reuse | ADR-311 | KEEP(c) | ADR-311. |
| 25 | status reads wait server-side at most 30 s | long-poll hold | ADR-330 D1 | KEEP(c) | 330 D1. |
| 25 | "Specify byte/item/time limits" | generic instruction | none | REMOVE | Contradicts AGENTS "Prefer pagination or streaming over caps on lists". Reword to "paginate or stream; specify a limit only with its reason". |

### specs/domain-model.md

No numeric limits. Line 39 "overflow-checked counters" is KEEP(b) by nature (int64), not a limit to change.

### specs/README.md

No numeric limits.

### specs/examples.yaml

No numeric limits (it's an example→schema index). See "surprising" below for stale entries.

### specs/changes/postgresql-hub-state/proposal.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 27 | up to 10,000 hub control objects, 1,000 active shares, 500 sharing intents; audit 7.8 M calls / 90 d | historical CRD-era planning numbers | "planning numbers, not measured traffic" | REMOVE | Historical pre-SQL sizing. Label it historical or delete it so nobody reads it as a cap. With SQL rows and pagination, none of these counts is a limit. |
| 75, 77 | "finite retention" for identity/control fields; "finite backup/WAL retention" | SQL/backup retention | privacy | KEEP(c) | Administrator-enforced maximum retention (335 D7). Default = configured evidence maximum. |
| 88, 94 | "does not remove admission quotas, row/history limits …"; "Active application limits remain until measurements justify changes" | general rule that keeps existing limits | "until measurements justify changes" | REMOVE | Obsolete per AGENTS "Limits need a reason" (2026-11-14). The burden is on the limit, not on a measurement to remove it. Row/history limits are replaced by pagination. Admission quotas stay only as KEEP(c) storm protection. |
| 96 | initial envelope: 10 clusters, 100 nodes, 1,000 selected containers, 200 policies | test load profile (also reused as "qualified installation envelope", targets.md 43) | test envelope | REMOVE | Keep it only as a test load profile, never as an admission limit. 200 policies contradicts 335 D8 (policies unlimited), and 1,000 containers feeds the removed targets.md 43 ceiling. |
| 96 | 1 occurrence/s sustained, burst 100 over 10 s | trigger rate (test envelope) | test envelope | DERIVE | As a runtime default it is a storm limit (KEEP(c), 335 D8) but has to default from cluster size, e.g. per-workload rate scaled by node count, not a fixed installation figure. |

COUNTS: KEEP=53 REMOVE=34 RAISE/DERIVE=26

Most user-visible REMOVE items:
1. Pending approval requests expire after 24 h by default — investigation-approval.md:35
2. Two live watches per principal (a second tab plus an agent is refused) — live-watch.md:47
3. Rolling hourly per-principal/workload live scan/delivery budgets cut off long watches — live-watch.md:47
4. maxExecutions default 1,000 stops automatic intrusive policies — policy-automation.md:11
5. Lifetime native-output/observed-byte pools on policies (contradicts 335 D6) — policy-automation.md:61
6. 256 GiB result-access pool and 16-action cap (large cores become undownloadable) — investigation-approval.md:31
7. 1,000 observed pods per policy portable ceiling — targets.md:43
8. 10-minute default maximum post-trigger window (contradicts 335 D8) — syscalls.md:19
9. 8 MiB argument-source query limit — syscalls.md:46
10. 1–16 sources per live watch and four watches per workload — live-watch.md:11, 47

---

<!-- part: arch-a -->
## Limit audit — docs/architecture part A

Scope: 50 files under /home/phil/Projekte/asservat-friction/docs/architecture/ (all read in full). Baseline: ADR-330, ADR-335, ADR-311/312, AGENTS.md maintainer decisions. Line numbers refer to the files on branch docs/friction-audit.

Cross-cutting observations (each also appears in the per-file rows):

- **4096-byte pod-status projection** repeats in 8 files (api-context-runner, api-context-execution, context-assessment, context-admission, context-investigation, manifest-verification, console-runtime, context-query-capacity). No reason is stated anywhere; a Pod with many containers/conditions can exceed it and the capture then fails. The connector already caps the API response at 2 MiB (about the etcd 1.5 MiB object limit plus JSON overhead). Proposal: drop the separate 4096-byte projection ceiling and use the response cap as the bound (KEEP(b) by derivation). If a smaller projection is still wanted, derive it from the schema maxima (container count × per-container fields).
- **24 KiB structured / 64 KiB MCP output**: the stated reason is "so MCP can carry structured and text copies within 64 KiB". MCP has no message-size limit, so this reason is self-imposed. Oversized results are returned as "unavailable", which is a user-visible failure. Replace with pagination for list-shaped results. Any remaining buffer bound should come from per-request memory (pod memory ÷ concurrent requests).
- **Bearer-token expiry as a download bound**: 335 D9 says downloads run "regardless of access-token expiry (session-bound)". native-reader-identity and the bound lists in download-authority, worker-startup, context-native-content, native-exchange and download-responses still end a started bearer (MCP) download at token expiry. With Keycloak's default 5-minute access token, any MCP or CLI download that takes longer than 5 minutes stops.
- **Five-minute deadlines**: there are still two that 335 D5/D9 remove (context-admission L23, context-investigation L73).
- **64 policy references per artifact**: this cap contradicts 335 D8 ("policies unlimited"). It appears in context-admission, retention-lifecycle and context-assessment.
- **Obsolete fleet machinery** (fleet-administration, enrollment-activation): bootstrap-slot, retained-record and cluster ceilings, issuer epoch, operator lists and `fleet_certificate_issue` audit rows. These are still described as current, although ADR-330 D3, ADR-332 and 335 D3/D14 remove them.
- **Inconsistent frame ceilings**: command/control frames are 64 KiB in native-exchange L62 but 32 KiB in regional-context-start L90.

### native-download-retry.md

No numeric limits. SHA-256 is skipped as a format.

### native-reader-identity.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 12–13 | 2 s | GET waiting without output for a concurrently refreshing session | none | REMOVE | Wait for the refresh under the ordinary 5 s I/O timeout (330 D5). A separate 2 s timer only adds spurious failures when the IdP round trip is slow. |
| 21–23, 27–28 | bearer token expiry / group-freshness bound | started native download for MCP/OAuth clients | "keeps that identity until its bound" | REMOVE | 335 D9: downloads run to original bounds "regardless of access-token expiry (session-bound)". With Keycloak's 5-min default token, MCP downloads cut off after 5 min. Bound bearer downloads by the download session deadline, `AccessUntil`, Stop and revocation events only. |

### context-control-capacity.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 5–6, 13–15 | per-workload limit on retained capture records (from `EvidenceBudgetPolicy`), plus pool total | SQL capture metadata rows per workload | "keep one workload from exhausting it for others (REQ-CAP-006)" | DERIVE | Cross-workload exhaustion protection is a maintainer decision (c), but 335 D2 says "row … figures are internal estimates, not values". Derive the record count from the workload's storage share: (workload share of the hub SQL volume) ÷ (estimated bytes per capture row incl. audit/idempotency). No separate operator-facing row limit. |

### context-capability.md

No numeric limits.

### context-case-transport.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 25–26 | 24 KiB metadata ceiling / 64 KiB MCP envelope; oversized → unavailable | `get_case` projection size | "so MCP can carry structured and text copies within 64 KiB" | REMOVE | MCP defines no 64 KiB limit. A case with many artifacts becomes "unavailable" instead of readable. Paginate the artifact list (cursor), then drop the ceiling. |

### api-context-runner.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 4 | 4096 bytes | Pod status projection captured by the connector | none ("fixed") | DERIVE | The source Pod object is already bounded by etcd (1.5 MiB). The API read is capped at 2 MiB (api-context-execution L39). Use that as the bound, or derive the projection maximum from the schema (containers × fields). A larger Pod should not fail. |

### context-deletion.md

No numeric limits. "write interval" and "deadline" are unnumbered references to stored deadlines (330 D12).

### connector-credentials.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11–12 | bootstrap token expiry (unnumbered) | validity of the one-time registration token | none | KEEP(a) | A single-use secret needs a bound, and a leaked token's exposure grows with lifetime. No number is given; the default should be in hours to days (human timescale, 335 D9), following the kubeadm bootstrap-token 24 h precedent. Note only. |
| 24–25 | ≈ 2/3 of certificate lifetime | when the connector rotates its certificate | none (precedent kubelet) | KEEP(b) | Renewal must precede X.509 notAfter. The fraction matches kubelet rotation (70–90 % jittered). The lifetime itself is questioned under peer-identity L23. |

### download-recovery.md

No numeric limits. The per-effect `FOR SHARE` lock on the recovery row is not numeric. It also contradicts fleet-administration L41–43 and custody-transactions L60 ("without a lock"), so the inconsistency is flagged here.

### processing-admission.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 49–50 | "bounded queries" (no number) | operator inventory queries | none | REMOVE | No number. Use pagination (cursor) instead of an implicit cap. |

### context-progress.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 32–34 | 30 s | MCP `get_capture` server-side wait | ADR-330 D1 | KEEP(c) | 330 D1: MCP status waits at most 30 s. |

### context-assessment.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 11–12 | 4096 bytes | pod-status native output ceiling ("configured limit") | none | DERIVE | Same as api-context-runner L4: bound by the 2 MiB API response cap / etcd object limit, or derive from the schema maxima. |
| 42–44 | 64 policies per response; 24 KiB output ceiling | policy list in the assessment response | "fits the 24 KiB output ceiling" | REMOVE | 335 D8: policies are unlimited. The 24 KiB ceiling has no external basis (MCP has no size limit). Paginate or summarize policy provenance; drop both numbers. |

### download-responses.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 32–33 | "at most one bounded chunk" (size in native-exchange: 1 MiB) | hub per-response buffer | memory / backpressure | KEEP(a) | Memory grows with buffer × concurrent responses. The size is set in native-exchange L62. |
| 41 | write timeout (unnumbered) | stalled client write | none | KEEP(c) | I/O timeout (330 D5: five seconds only as an I/O timeout). |
| 43–44 | "caller's session or token expiry" | started response | ADR-312 | REMOVE | Token expiry is removed per 335 D9 (see native-reader-identity). Keep the session deadline, `AccessUntil`, the stored deletion deadline and Stop. |

### local-start.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 5, 14 | 60 s | original start interval (`start_not_after`) of a one-shot start right | none | REMOVE | Start-at-most-once comes from the conditional state update (330 D7), not from expiry. A 60 s window fails captures when the node collector is slow (image pull, reconnect backoff up to 60 s per regional-context-start L23). Bound the start by the capture's own deadline / approved window (335 D5). |
| 32 | 64 MiB | `logs` native output of `apiContextStart/v1` | none | DERIVE | The storage cost is real, but the number is arbitrary. Derive the maximum from the workload's storage share / per-capture byte budget (335 D2), capped only by the configured capture duration. |

### current-request-identity.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 27 | 30 s | identity handle reuse (`AuthorityRecheckInterval`) | ADR-311 | KEEP(c) | ADR-311 maintainer decision. |

### cluster-observations.md

No numeric limits.

### context-query-capacity.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 9 | per-principal token-bucket rate + concurrency cap (no numbers) | query load per principal | reader starvation | DERIVE | The reader CPU/memory cost is real. Derive the defaults from reader replicas × per-replica concurrency (download-worker-dispatch L25) rather than fixed values. State the formula. |
| 10 | per-workload query concurrency cap (no number) | queries against one workload's evidence | "so one workload's investigation cannot starve the reader for others" | DERIVE | Fairness on a shared reader is a concrete cost. Set the cap to a fraction of total reader concurrency (e.g. ½ of replicas × streams), not a constant. |
| 11 | 4 MiB read work per query | stored-evidence read per query | none (source is 4096 B) | DERIVE | Read work costs reader memory/IO. Derive it from the reader memory limit ÷ per-replica concurrency. 4 MiB for a 4 KiB source is arbitrary. |
| 11 | 24 KiB structured result, 64 KiB wire response | query result size | none | REMOVE | No external MCP limit. Paginate excerpts/results (cursor) and stream. |
| 12 | reader queue full → busy | reader admission | load shedding | KEEP(a) | Shedding is bounded by reader replicas/memory (Helm values). Already derived. |
| 20 | 60 s | shared delivery-policy observation reuse | ADR-311 | KEEP(c) | ADR-311 (60 s shared policy observation). |
| 26 | 80 MiB work per profile summary | `get_profile_summary` read work | "64 MiB maximum source plus framing, index and manifest" | KEEP(a) | Derived from the source maximum plus format overhead. |
| 26 | 64 MiB maximum pprof source | largest raw profile admitted to a summary | none | DERIVE | Derive it from the reader memory limit (memory − baseline) ÷ concurrent summaries, or stream-parse so the source size no longer drives memory. |
| 26 | 256 MiB chart default reader memory | reader container memory | "must cover this bound" | KEEP(a) | A Helm default derived from the 80 MiB summary bound. The administrator can change it. |

### public-context-download.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 20–21 | 30 s | MCP download `get` wait | ADR-330 D1 | KEEP(c) | 330 D1. |
| 54–56 | process-local concurrency slots (normal / Stop lanes) | concurrent download operations per hub process | "a saturated normal lane cannot block Stop" | KEEP(a) | Hub memory/connections grow with concurrency. Derive slot count from pod memory ÷ per-response buffer (1 MiB frame). A separate Stop lane is justified. |
| 55–56 | per-principal download limits | download requests per principal | none | REMOVE | 335 D9: "no request-count cap". Process slots and the reader busy status already protect capacity. |

### download-environment.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 7 | 128 KiB | `download-environment.json` ConfigMap | none | REMOVE | Kubernetes already bounds ConfigMaps (1 MiB). Use that as the limit. |
| 13 | 64 lineage nodes, 16 parents each, 1,024 rules; overflow denies | processing-lineage traversal | none | REMOVE | Deny-on-overflow is a user-visible failure without reason. A recursive CTE with cycle detection handles loops, and the graph is bounded by stored rows. Use an indexed rule query instead of a 1,024-rule cap. If a memory bound is needed, derive it from the request's memory budget. |

### context-download-control.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 15–16, 56–58 | per-workload transfer budget reserved per session | downloaded bytes per workload | none here | REMOVE | Downloads read existing evidence and use no storage. 335 D9 says downloads have no request-count cap. Reader concurrency/busy shedding bounds the real cost. The raw-approval "finite parent disclosure pool" stays (KEEP(c)) for raw grants only (download-authority L18). |
| 32 | 30 s | MCP `get_artifact_download` wait | ADR-330 D1 | KEEP(c) | 330 D1. |

### context-publication.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 51–53 | `maxCaptures` share slots, `notAfter` | recurring-policy share materialization | ADR-239 | KEEP(c) | AGENTS.md: "explicitly bounded recurring-policy sharing". Per 335 D7 it must not need weekly renewal, and the default `notAfter` should be the evidence retention end rather than a separate short cap. Check the ADR-239 defaults. |

### api-context-execution.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 38–39 | 2 MiB | Kubernetes API response for the pinned Pod | none | KEEP(b) | A Pod object is ≤ 1.5 MiB (etcd request limit), so 2 MiB covers JSON plus headroom. Externally derived. |
| 39, 41–42 | 4096 bytes | projected output / accepted expectation ceiling | none | DERIVE | See api-context-runner L4. |
| 53–54 | `AuthorityRecheckInterval` (30 s) | start authorization reuse | ADR-311 | KEEP(c) | ADR-311. |

### download-worker-dispatch.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 19–20 | "small ephemeral-storage limit" (no number) | reader scratch storage | none | KEEP(a) | The reader streams and needs almost no disk; a limit prevents node disk pressure. The number should be stated. |
| 25–28 | configured concurrent streams per replica | reader concurrency | busy instead of queueing | DERIVE | Memory per stream ≈ open keys + one 1 MiB frame per hop. Default = (memory limit − baseline) ÷ per-stream memory, documented as a formula. |
| 58–60 | `terminationGracePeriodSeconds` | open streams at rollout | none | KEEP(a) | The Kubernetes Pod lifecycle bounds it; interrupted downloads resume with `Range`. |

### peer-identity.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 23 | connector certificates ≤ 1 hour | connector client-certificate validity | none | RAISE | Revocation is handled by the SQL `cluster` row plus a change event (connector-credentials L26–28), so short validity adds nothing. L35–36 ("a reused connection never outlives its certificate") turns 1 h into connection resets that interrupt downloads and live watches hourly, and a hub outage over 1 h strands connectors. Use a kubelet/cert-manager-like lifetime (e.g. 30–90 days, rotated at 2/3) and close connections on renewal only gracefully. |
| 28 | TLS 1.3 | protocol version | — | KEEP(b) | External protocol choice (RFC 8446); no value to tune. |

### context-cases.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 16, 44–45 | at most 100 artifact locators per case (fetch 101, reject overflow); oversized case → unavailable (L12) | `get_case` artifact list | none | REMOVE | A case with more than 100 artifacts (e.g. a ring of segments, a recurring policy) becomes unreadable. Paginate with the existing `(root_id,case_id,artifact_id)` index as cursor; L53 already lists pagination as missing. |

### context-operations.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 16–17 | "excessive nesting" (number in mcp-runtime: depth 32) | wire JSON depth | parser safety | DERIVE | Derive from the deepest canonical schema plus a margin (see mcp-runtime L58). |
| 18–19 | 24 KiB metadata / 64 KiB MCP | all investigation results | "so MCP can carry structured and text copies within 64 KiB" | REMOVE | Same as context-case-transport L25: no MCP limit. Paginate. |
| 51–52 | browser global and per-principal concurrent requests (no numbers) | console API concurrency | none | DERIVE | Global: derive from hub pod memory ÷ per-request buffer. Per-principal: replace with the per-principal rate limit (token bucket) already used elsewhere. SSE streams must not count against it. |

### local-keys.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 7, 13 | 16 KiB (+1 overflow byte) | `keys.json` key Secret | none | REMOVE | The Kubernetes Secret limit (1 MiB) is the external bound. 16 KiB combined with the version cap blocks rotation. |
| 15 | keyset 1–4096 bytes; caller binding 1–2048 bytes | wrap input/AAD sizes | none | KEEP(a) | These are internal, code-generated fixed-shape values. The caps bound key-service memory per request (body cap derived from them, local-key-service L30). No user impact. |
| 27 | at most sixteen versions per purpose | key rotation history | none | REMOVE | Rotation is additive, and removal is refused while ciphertext references a version. After 16 rotations the administrator cannot rotate without an explicit retirement procedure. The Secret 1 MiB limit (≈ thousands of versions at ~150 B each) is the real bound. |

### fleet-administration.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 22–24 | 1–128 active bootstrap slots; 1–65,536 retained bootstrap records (≥ active); 1–1,024 registered clusters; "no silent defaults" | fleet enrollment | "rejection bounds, not supported-scale claims" | REMOVE | Obsolete machinery per ADR-330 D3 / ADR-332 / 335 D3 ("connector counts (none exist)"). One bootstrap token per cluster registration needs no slot ceiling, and mandatory values with no defaults violate 335 D1. Cluster count is bounded by the cluster rows themselves, and records follow audit retention. Replace with nothing. |
| 14, 18–19 | issuer epoch, monotonic revision, operator subject/group lists (empty denies) | fleet trust configuration | none | REMOVE | 335 D14 collapses `fleet.groups` into the administrator group / AccessBinding model. 335 D3 removes write-once/compared configuration. Not numeric, but it gates every enrollment by default. |

### worker-startup.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 18 | exponential backoff (unnumbered) | reader reconnect | avoid reconnect storms | KEEP(a) | Reconnect load grows with replicas. Standard client-go/gRPC practice; give numbers as in regional-context-start L23. |
| 37 | "caller session/token expiry" | reader stream bound | ADR-312 | REMOVE | Token expiry is removed per 335 D9; keep the other bounds. |

### context-native-content.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 7, 18 | transfer budget charge; "caller session or token expiry" | download preparation / started response | none / ADR-312 | REMOVE | The transfer budget goes as in context-download-control L15. The token-expiry bound goes per 335 D9. |
| 25 | "within seconds" | best-effort Stop delivery | NOTIFY latency | KEEP(a) | A description of event latency, not an imposed cap. |
| 29 | 30 s | MCP `get_download` wait | ADR-330 D1 | KEEP(c) | 330 D1. |

### public-context-composition.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 46–47 | 30 s / 60 s | authority reuse | ADR-311 | KEEP(c) | ADR-311. |
| 61 | 30 s | MCP status wait | ADR-330 D1 | KEEP(c) | 330 D1. |

### download-sessions.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 26–28 | per-workload transfer allocation (`used + n <= limit`) | ordinary download bytes per workload | none | REMOVE | Same as context-download-control L15. Downloads consume no storage, and 335 D9 sets no request-count cap. Keep only the raw-grant parent disclosure pool (maintainer "finite parent disclosure pool", KEEP(c)). |
| 29–31 | per-principal and per-workload download concurrency (administrator settings) | concurrent downloads | none | DERIVE | Reader capacity is the real cost. Default = reader replicas × streams per replica, with a per-workload fair share (e.g. ½). Make it configurable with a derived default, not a separate guess. |
| 34–36 | reservation released at the response's hard deadline when the end is unknown | uncertain byte reservation | "no writer can emit after it" | KEEP(a) | Follows from the original bound (ADR-312). No extra number. |

### capacity-production.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 45–47 | count of retained capture metadata rows per workload | SQL metadata per workload | REQ-CAP-006 | DERIVE | See context-control-capacity L13. Derive from the workload storage share ÷ row size estimate (335 D2). |
| 54–55 | per-workload token-bucket rate limits from the budget policy | capture admission rate | storm protection | KEEP(c) | 335 D8: rate and concurrency limits stay, with defaults derived from cluster size. |
| 59–62 | `records = min(bytes/1544192, objects/4, 512)`; `min(bytes, records × 9928704)`; `records × 4` objects | packet reserve funding | ADR-257 | KEEP(a) | 1,544,192 and 9,928,704 are per-record footprint estimates derived from the artifact format (internal estimates per 335 D2). |
| 60 | 512 records cap | maximum packet records per reserve | none | REMOVE | The byte/object budget in the same formula already bounds records. A fixed 512 only caps long rings (335 D8: post-trigger windows up to the configured duration). |
| 63 | 8 MiB packet output cap | packet capture output per record/save | none (prototype baseline per AGENTS.md) | DERIVE | An 8 MiB pcap is too small for minutes-long windows (335 D8). Derive it from the capture's configured duration × the configured ring/segment size, bounded by the workload's storage share. |

### enrollment-activation.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 25 | CSR ≤ 8192 bytes | enrollment request body | none | KEEP(b) | The largest accepted key (RSA-4096) with no subject/SAN/extensions yields a CSR under 2 KiB. 8 KiB matches common HTTP header/body defaults and has no user impact. |
| 28 | RSA 2048–4096, exponent 65537 | accepted key sizes | none | KEEP(b) | External crypto standards (NIST SP 800-57 minimum 2048; Go stdlib verifier). |
| 39–40 | retries "until the token expires" | enrollment retry window | token expiry | KEEP(a) | Follows the token lifetime; no additional number. |
| 43 | ≤ 1 hour validity | connector certificate | none | RAISE | Same as peer-identity L23. |
| 45 | chain ≤ 48 KiB | stored certificate + chain | none | REMOVE | The chain comes from the installation CA (trusted, depth 2), not from user input. No cap is needed; the PostgreSQL row size is the bound. |
| 57–59 | two certificate slots | rotation overlap | overlap during renewal | REMOVE | Obsolete per ADR-330 D3: "Removed: … registration and activation tables, certificate audits". Rotation by CSR plus the `cluster` row needs no slot table, and the old certificate expires on its own. |
| 64–68 | ceilings on active tokens, retained bootstrap records, registered clusters; `fleet_certificate_issue` + immutable audit triggers; issuer epoch (L14) | fleet enrollment | see fleet-administration | REMOVE | Obsolete machinery per ADR-330 D3 / ADR-332 / 335 D3. See fleet-administration L22. |

### download-authority.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 16 | 30 s / 60 s | `DownloadAuthority` reuse | ADR-311 | KEEP(c) | ADR-311. |
| 16, 22 | "caller session or token expiry" | authority and started-response bound | ADR-312 | REMOVE | Token expiry is removed per 335 D9 (session-bound). Session expiry, session deadline and `AccessUntil` stay. |

### context-admission.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 10 | five seconds of collection | pod-status action duration | none | KEEP(c) | This is a single API GET, so five seconds acts as its I/O timeout (330 D5). |
| 11 | 4096 native bytes | pod-status output | none | DERIVE | See api-context-runner L4. |
| 23–24 | original request deadline ≤ five minutes | request/submission deadline | none | REMOVE | 335 D5 ("not a 5-minute submit deadline") and D9 (stateless previews valid while unchanged). Bound the request by the approval's stated window / capture duration. |
| 24 | dependency limit 64, overflow fails "with a consolidation diagnostic" | policy/rule references in one scope | none | REMOVE | 335 D8: policies unlimited (bounded by K8s object limits). Scope is SQL metadata (330 D8), so store the reference list as rows. |
| 32 | "excessive inputs fail" (no number) | retention resolver inputs | none | REMOVE | No number and no reason. Drop it, or derive it from request memory. |

### mcp-runtime.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 49–51 | 30 s | MCP status-tool wait | ADR-330 D1 | KEEP(c) | 330 D1. |
| 56–57 | request lives at most until its identity handle ends (≤ 30 s) | every MCP tool call | none | REMOVE | ADR-311 limits reuse of an authorization to 30 s; it does not cap request duration. Long tool calls (query excerpts, profile summaries, grouped saves) must re-authorize or run to the operation deadline. Keep the 30 s wait only for status tools (330 D1). |
| 58 | input ≤ 32 KiB, depth 32 | MCP request body | none | RAISE | Tool inputs include policy/profile documents that may be as large as a K8s object (1.5 MiB). Derive the body cap from the largest tool input schema (≤ K8s object size). Derive depth from the deepest canonical schema plus margin. |
| 62–63 | 1–64 requests per process; 1–4 per principal/client | MCP concurrency | "local transport limits" | DERIVE | Per-process: derive from pod memory ÷ (output buffer per request). Per-principal 4 is too low because status waits hold a slot for 30 s, so an agent waiting on 4 statuses is locked out. Replace it with a per-principal token-bucket rate, or exclude waits. |
| 65–67 | 64 KiB hard output; 256 KiB frame for 128 KiB `preview_recording_save`; 24 KiB default / 32 KiB hard evidence envelope | MCP responses | none | REMOVE | MCP defines no output limit, and these are per-response buffers. Paginate list-shaped results. If a memory bound is needed, derive it from per-request memory (pod memory ÷ concurrency). |

### operation-audit.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 44–45 | fixed saturating counters, rate-limited logs | unauthenticated failure records | DoS protection | KEEP(a) | Log volume grows with attack traffic; rate-limiting log lines is a standard cost bound. |
| 69–73 | administrator audit-metadata maximum; pgBackRest/WAL retention ≤ audit retention | audit row and backup lifetime | retention maximum | KEEP(c) | Administrator-enforced maximum retention (AGENTS.md; 335 D7). |
| 80–81 | per-principal rate limits at ingress | audit volume | bound audit | KEEP(c) | Storm protection rate limits (335 D8). Defaults should derive from cluster size. |

### native-exchange.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 38 | "caller session/token expiry" | stream bound | ADR-312 | REMOVE | Token expiry is removed per 335 D9. |
| 62 | command/control frames ≤ 64 KiB | non-data frames | none | KEEP(a) | Commands carry IDs/version/range only, so memory per stream is bounded. This conflicts with the 32 KiB in regional-context-start L90; pick one. |
| 62–64 | data frames ≤ 1 MiB; one pending frame per hop | per-hop buffering | "a slow client slows the reader, not memory" | KEEP(a) | Memory = frame × hops × concurrent streams. A bound with a stated cost reason; HTTP/2 SETTINGS_MAX_FRAME_SIZE allows up to 16 MiB. |

### workload-target-resolution.md

No numeric limits.

### context-evidence-workflow.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 55 | one active download request per tab | console concurrency | none | REMOVE | A user cannot download a core and its executable/debug companions in parallel (335 D17 bundle). Server concurrency slots and the reader busy status already bound load. |

### context-investigation.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 10–11 | 4096-byte native ceiling | pod-status recipe | none | DERIVE | See api-context-runner L4. |
| 73–74 | capture deadline "within five minutes" of submission | approved recorder submission | none | REMOVE | 335 D5: "An approval covers its stated window, not a 5-minute submit deadline: the approved request is submitted by the approval itself." Use the approved window / grant expiry. |

### manifest-verification.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 22 | 30-second I/O bound | reader verification of envelope/manifest/index | none | DERIVE | 330 D5 sets five seconds as the I/O timeout. Use 5 s per object read (small objects), not a separate 30 s total. Low user impact. |
| 28, 32, 36 | pod-status document ≤ 4096 bytes | decrypted pod-status frame | none | DERIVE | See api-context-runner L4. |
| 32 | envelope ≤ 32 KiB | `artifact-commit/v1` envelope | none | DERIVE | A fixed-shape document. Compute the cap from the schema maxima instead of a round number. |
| 32 | decoded manifest ≤ 1 MiB; ciphertext ≤ 1088 KiB | manifest size in reader memory | none (1088 = 1 MiB + framing) | DERIVE | Manifest size grows with policy references (unlimited per 335 D8), gap reasons and lifecycle provenance. Derive the maximum from the expectation stored in SQL (manifest ≤ expectation size × constant), or from reader memory ÷ concurrency. 1088 KiB is correctly derived from 1 MiB. |
| 32 | depth 32; 32,768 tokens | strict JSON parsing | none | DERIVE | Derive depth from the deepest schema. The token count is redundant with the byte bound (tokens ≤ bytes ÷ 2); with more than about 1,000 policy references 32,768 tokens could be hit before 1 MiB. |

### keycloak-profile.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 23 | "oversized" groups claim fails (no number) | group claim size | none | KEEP(b) | Bounded by JWT/header size (~8–16 KiB HTTP header, 4 KiB cookie does not apply to bearer). Name the number (e.g. the HTTP header limit). |
| 50–51 | Keycloak default access-token lifetime 5 min | group freshness | Keycloak default | KEEP(b) | External provider default. It must not bound downloads (335 D9; see native-reader-identity). |

### local-key-service.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 27–28 | binding 1–2048 bytes; keyset 1–4096 bytes | wrap/unwrap RPC members | none | KEEP(a) | Internal fixed-shape RPC between Asservat components. Per-request memory is bounded (see local-keys L15). |
| 30 | body ≤ 32,768 bytes; sealed reference ≤ 256; ciphertext ≤ 8,192 | key-service RPC | none | KEEP(a) | Body cap ≈ base64 of the member caps (4096 + 2048 + 8192) plus JSON. Memory per request × 64 concurrent requests is bounded. Internal only. |
| 58 | 1–64 concurrent operations, 429 beyond | key-service concurrency | none | DERIVE | Crypto is CPU-bound. Default = CPU cores × small factor; drop the hard max of 64 (Helm-configurable). |
| 58 | five seconds | per-request I/O timeout | ADR-330 D5 | KEEP(c) | 330 D5. |
| 58 | 4096-byte response headers | client header bound | none | KEEP(b) | HTTP header sizes (8–16 KiB typical); a fixed internal response. |
| 58 | at most eight connections per transport | client connection pool | none | DERIVE | Derive it from the server concurrency ÷ expected client replicas, or use HTTP/2 multiplexing with one connection. |

### research.md

No numeric limits. (Dated 2026-10-09 source table.)

### console-runtime.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 36–38 | decoded-body ceilings: 32 KiB session, 128 KiB `preview_recording_save`, 160 KiB `get_capture_settings` | browser-side response parsing | none | REMOVE | Responses come from the same-origin server, which already bounds/paginates. Client-side ceilings break the UI when server results grow (e.g. unlimited policies, 335 D8). |
| 66 | 4 KiB output limit (shown in review) | pod-status | none | DERIVE | See api-context-runner L4. |

### regional-context-start.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 22–23 | backoff 1 s doubling to 60 s with jitter | connector reconnect | avoid reconnect storms | KEEP(a) | Hub load after an outage grows with cluster count. This is the standard gRPC/client-go pattern (gRPC default max 120 s). |
| 29 | N−1 skew | supported hub/connector/collector version skew | R-10 | KEEP(a) | Test cost grows with supported versions. Matches the Kubernetes skew policy precedent. |
| 30–31 | per-stream deadlines and byte/frame ceilings "fixed by message type" | each stream | none | DERIVE | Give the ceilings derived from the message schema (see below). |
| 90 | command frame 32 KiB | hub → connector commands | none | RAISE | `start-policy-recording` carries "frozen instructions" (L76–77). A maximal libpcap/BPF program is 4096 instructions × 8 B = 32 KiB alone, so it cannot fit together with the other fields. Derive the cap as BPF max program + envelope (≈ 40–64 KiB), and align it with native-exchange's 64 KiB. |
| 91 | operation request/reply 32 KiB each | regional operations | none | DERIVE | Derive from the largest operation schema (same BPF consideration for `resolve-packet-source` / recording start). |
| 92 | context-start stream: 36 frames, 2 MiB, ≤ 16 sequential operations | one context-start command stream | none | DERIVE | The operation list is fixed (≈ 8 operations: resolve, read process, prepare/ready/consume start, prepare output, acquire, complete). Derive frames/operations from that list × retries. 2 MiB matches the API response cap. Not user-visible, but the numbers are unexplained. |
| 93 | concurrent captures per cluster = cluster capture capacity (C-07) | concurrent captures | storm protection | KEEP(c) | 335 D8: ≥ 8 per cluster, default from cluster size. |
| 94 | connector settings 16 KiB | connector settings document | none | REMOVE | The Kubernetes ConfigMap/Secret limit (1 MiB) is the external bound. |

### retention-lifecycle.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 17 | "bounded selectors" (CRD/CEL, no number) | retention policy selectors | CEL cost | KEEP(b) | The Kubernetes CEL cost budget / CRD validation limits are external. Use the K8s limits, no extra number. |
| 49–51 | at most 64 applicable policy references per artifact; overflow fails planning | policies matching one artifact | none ("never truncated") | REMOVE | 335 D8: policies are unlimited (bounded by K8s object limits). Store references as SQL rows (330 D8) instead of a bounded array. |
| 87 | `LIMIT <batch>` (no number) | rows per retention update batch | lock duration | KEEP(a) | Lock/WAL cost per statement grows with batch size. Derive it from the 5 s statement timeout (rows updated per second × margin). |

### custody-transactions.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 26 | charge covers ADR-048 worst-case data/index ceilings + 1088 KiB manifest + 32 KiB envelope + four object slots | per-attempt storage reservation | worst-case accounting | KEEP(a) | Real storage cost; settled to the actual size at publication (context-publication L17). Derived from format ceilings. |
| 26 | allocation limits from Helm-rendered configuration | per-workload storage | REQ-CAP-006 | KEEP(c) | Protection against cross-workload storage exhaustion (AGENTS.md; 335 D2/D8). |
| 40 | pool rejects more than 32 connections | per-process PostgreSQL pool | none | DERIVE | 335 D11: the chart sets the pool size (default total ≤ 30 across processes). Use the chart value and PostgreSQL `max_connections` instead of a hardcoded 32 per process. |
| 42 | five-second statements | statement timeout | I/O bound (330 D5) | KEEP(c) | 330 D5. |
| 42 | one-second lock waits | lock timeout | "I/O bounds" | RAISE | A lock wait is not I/O; under contention (deletion vs admission) 1 s causes spurious failures. Use the same 5 s statement bound (330 D5). |
| 44 | serialization/deadlock retries up to three | transaction retries | none | KEEP(a) | Each retry costs a transaction. The bounded retry is standard (PostgreSQL docs recommend retrying serialization failures). |
| 52 | at most 128 entries per inventory API per pass | S3 cleanup LIST/DELETE per pass | none | RAISE | The S3 API allows 1,000 keys per ListObjectsV2/ListObjectVersions page and 1,000 per DeleteObjects. Use 1,000 (KEEP(b)). Segmented rings produce many objects, so 128 multiplies passes. |

COUNTS: KEEP=54 REMOVE=37 RAISE/DERIVE=36

Most user-visible REMOVE items:
1. native-reader-identity.md:21–28 (plus download-authority:16,22; download-responses:43; worker-startup:37; native-exchange:38; context-native-content:18): a started MCP/bearer download ends at access-token expiry (Keycloak default 5 min), contradicting 335 D9.
2. context-investigation.md:73–74: approved recorder submission must happen "within five minutes" (335 D5 removes this).
3. context-admission.md:23–24: request deadline ≤ five minutes, and the 64-reference dependency limit that fails captures (335 D8/D9).
4. retention-lifecycle.md:49–51: at most 64 applicable retention policies per artifact; overflow fails planning (335 D8).
5. context-cases.md:16,44–45: cases with more than 100 artifacts are "unavailable" instead of paginated.
6. mcp-runtime.md:56–57,65–67: MCP requests capped at 30 s total and 64 KiB output, with 24/32 KiB evidence envelopes; context-case-transport.md:25 and context-operations.md:18 repeat the same "MCP 64 KiB" rationale.
7. local-start.md:5: 60 s start window for every capture start right.
8. download-sessions.md:26–28 / context-download-control.md:15: per-workload transfer byte budget on ordinary downloads (335 D9).
9. fleet-administration.md:22–24 / enrollment-activation.md:57–68: mandatory enrollment ceilings with no defaults (128 slots, 65,536 records, 1,024 clusters), certificate slots and issue tables, all obsolete per ADR-330 D3 / ADR-332 / 335 D1/D3.
10. context-evidence-workflow.md:55: one active download per browser tab (blocks parallel core + companion downloads, 335 D17); local-keys.md:27: at most 16 key versions blocks rotation.

---

<!-- part: arch-b -->
## Limit audit — docs/architecture (part B)

Scope: browser-sessions, identity-eligibility, policy-automation, README, code-organization,
permission-observation, context-projection, artifact-format, implementation-slices,
node-collector, applications, runtime-profiles, build-or-reuse, components, interfaces,
runtime (.md), catalog.yaml, validation.json. Paths relative to
`/home/phil/Projekte/asservat-friction/docs/architecture/`.

Files with no numeric limits: `README.md`, `code-organization.md` (only generic "enforce byte
limits"), `implementation-slices.md` (no numbers; "bounded resume" unnumbered),
`catalog.yaml` (responsibility strings only, no numbers), `validation.json` (check counts, not
limits), `runtime.md` (only the illustrative "1,000 matches during cooldown" storm example,
L42 — a scenario, not a limit). `build-or-reuse.md` L22 "10,000-match storm" is a qualification
scenario, not a limit (not counted).

### browser-sessions.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 15–16 | 5 minutes | Login row (state/PKCE/nonce) lifetime between redirect and callback | none | RAISE | Human time at the IdP (password + MFA, LDAP lag) easily exceeds 5 min and yields a failed callback. Rows are tiny and login creation is already bounded by the ingress rate limit. Match the IdP's own login timeout (Keycloak "Login timeout" default 30 min): propose 30 min, or derive from the configured provider. |
| 38 | default 7 days max session lifetime | Absolute session lifetime | none (configurable default) | DERIVE | The session cannot outlive the provider refresh token anyway (refresh failure ⇒ new login, L74–77). Default to the provider's session max (refresh-token lifetime) and keep an optional administrator override; no separate Asservat number is needed. For internal users (ADR-063) keep a configurable default. |
| 38 | "configurable up to 30 days" | Hardcoded ceiling on the administrator's lifetime setting | none | REMOVE | A hardcoded max on an admin-configurable value (brief note). Replacement: the administrator's value, bounded only by the provider's refresh-token lifetime. |
| 39 | default 24 h inactivity | Idle timeout | none (configurable default) | DERIVE | Same as above: the provider's refresh-token idle timeout (Keycloak SSO Session Idle) already ends idle sessions. Derive the default from the provider; keep it configurable for internal users. |
| 40–41 | ≤ 1 write per minute | Sliding-inactivity update frequency | implicit: avoid a write per request | KEEP(a) | SQL write cost grows with request rate; 1 min is negligible precision loss against an hours-scale idle timeout. |
| 43–44 | ≤ 32 active sessions per subject, LRU eviction | Sessions per user | none (doc itself says "no installation-wide cap; rows are small") | REMOVE | No resource reason (rows small, login rate-limited). Eviction silently signs a user out of another device/browser. Replacement: ingress rate limit + session expiry; ADR-335 D8 "sessions unlimited (bounded by rate limits)". |
| 69–70 | refresh when access token expires within 60 s | Refresh lead time | implicit: token must remain valid while the identity is reused | KEEP(c) | Must exceed the ADR-311 30 s authority reuse plus clock skew; 60 s = 30 s reuse + 30 s skew. Write that derivation next to it. |
| 91 | 25 hours | Retention of back-channel logout event IDs (replay cache) | "so a delayed duplicate cannot be replayed" | DERIVE | Reason exists; number arbitrary. Replay is only possible while the token passes the "recent issue time" check, whose window is itself unnumbered. Derive: retention = accepted `iat` age window + clock skew (e.g. 10 min + 1 min), and state that window. |
| 111 | 256 KiB ciphertext per session | Session row size | implicit "Rows are bounded" | DERIVE | Contents are the encrypted refresh/access/ID tokens. Derive from the token cap in identity-eligibility (32 KiB compact) × 3 tokens + fixed fields ≈ 100 KiB, or simply "3 × token cap + 4 KiB". |
| 116–117 | batches ≤ 256 rows; timer ≤ once per minute | Expired-row cleanup | "no event source" | DERIVE | Timer at earliest expiry is justified. The batch number only bounds transaction/lock duration; loop until no expired row remains (batch size an internal tuning, e.g. 1,000), so a backlog cannot trail by hours. No user-visible cap. |

### identity-eligibility.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 31 | compact token 32 KiB; decoded claims 24 KiB | Bearer token size | implicit parse bound | KEEP(b) | Token travels in the `Authorization` header; ingress header limits are 8–16 KiB by default (often raised for large group claims). 32 KiB covers raised limits; 24 KiB claims = base64-decoded 32 KiB (derived). |
| 31 | decoded header 2 KiB | JOSE header | none | REMOVE | Already bounded by the 32 KiB compact cap; separate number adds a failure mode with no cost reason. |
| 32 | 64 / 2048 JSON tokens; depth 4 / 8 | Header/claims JSON complexity | none (implicit DoS) | REMOVE | Input is already ≤ 24 KiB and Go JSON decoding is linear; token-count/depth caps add rejection paths with no resource reason. Replacement: the byte cap. (Duplicate-key/Unicode rejection is not numeric — keep.) |
| 33 | JWKS response 128 KiB | Fetched key-set size | implicit | KEEP(a) | Memory/network per fetch from the configured issuer; 128 KiB ≈ 32 RSA-8192 JWKs with x5c chains. State that derivation. |
| 33 | 8192 JSON tokens, depth 8, ≤ 32 keys in JWKS | JWKS complexity/key count | none | REMOVE | Byte cap (128 KiB) already bounds cost; key count cap rejects a provider mid-rotation with many keys. Replacement: 128 KiB byte cap. |
| 34 | RSA 2048–8192 bits | Accepted signature key sizes | implicit | KEEP(b) | Lower bound: RFC 7518 §3.3 / NIST SP 800-131A minimum 2048. Upper bound KEEP(a): verify CPU grows with modulus; 8192 is the largest common size. |
| 36 | ≤ 1 refresh attempt per second per issuer | Unknown-`kid` JWKS refetch | "no per-attacker-key cache" | KEEP(a) | Each unknown `kid` would otherwise cost one outbound fetch; per-issuer rate bound matches go-oidc `RemoteKeySet` behaviour. |
| 37 | 5 seconds | Network I/O timeout | — | KEEP(c) | ADR-330 D5: five seconds only as an I/O timeout. |
| 38 | ≤ 256 group names, each ≤ 255 bytes; ≤ 64 scopes | Signed groups/scopes claim | none | REMOVE | Enterprise/LDAP users routinely exceed 256 groups → token rejected → user cannot sign in. Cost is already bounded by the 24 KiB claims cap. Replacement: claims byte cap. |
| 70–71 | picker limited to 20 results | User/group prefix search | none | REMOVE | Cap with no continuation hides matches. Replacement: page size 20 with cursor pagination (AGENTS.md "prefer pagination"). |
| 85–87 | 30 s eligibility reuse | Identity/eligibility reuse | ADR-311 | KEEP(c) | ADR-311 `identity.AuthorityRecheckInterval`. |
| 124–126, 130 | ≤ 256 default-audience entries (fail, no truncation); stored artifact ≤ 256 audience entries | Audience per capture/artifact | none | REMOVE | A workload with many reader/owner bindings would be uncapturable. Row cost is small and the entry count is already bounded by the bindings that exist (Kubernetes object limits). Replacement: store the audience as rows in an audience table (or a JSON column under the 1 GiB PostgreSQL value limit), no count cap. |

### policy-automation.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 15 | grant period for intrusive kinds | Automatic intrusive grant expiry | ADR-059 / maintainer | KEEP(c) | ADR-335 D6: expiring grants for automatic intrusive actions, admin-configured, default 90 days. Make the default (90 d) explicit here. |
| 15, 31 | execution count in `spec.automation` envelope; evaluator "checks the action, count …" | Number of automatic intrusive runs per grant | none | REMOVE | ADR-335 D6 keeps expiry, not run counts (non-intrusive: no count; intrusive: only the period is named). Storm protection is rate/concurrency limits (D8) and per-incident caps. Replacement: grant expiry + D8 rate/concurrency limits. (Borderline: confirm with maintainer if "reviewed finite automatic grants" was meant to include a count.) |
| 31 | "byte envelope" checked per policy use | Lifetime byte budget per accepted policy/grant | none | REMOVE | ADR-335 D6: bounded by rates and ring sizes, not lifetime byte budgets. Replacement: per-incident cap (maintainer), per-workload storage quota, retention. |
| 47–48 | number of policies per cluster not limited beyond Kubernetes object limits | Policy count | ADR-335 D8 | KEEP(c) | Matches D8 "policies unlimited (bounded by Kubernetes object limits)". |
| 95 | ≤ 32 containers per policy (log streams) | Armed `pods/log?follow` streams per policy | none | DERIVE | Real cost: one API-server log stream per container on the connector. But the maintainer decision is "monitor all replicas within administrator ceilings"; a fixed 32 silently caps replica coverage. Derive: admin replica ceiling × containers per Pod, bounded by the connector's stream budget (from its memory request / per-stream buffer). |
| 95 | records ≤ 4 MiB per window | Log bytes evaluated per detector window | none | DERIVE | Memory cost per armed stream is real; derive from the connector memory request ÷ max armed streams (per-stream buffer), not a fixed 4 MiB. Single-record "overlong" bound: CRI splits log lines at 16 KiB (KEEP(b)) — state which is meant. |
| 96 | resource sampled at the policy's configured interval | metrics.k8s.io sampling | ADR-330 D1 | KEEP(c) | D1: sources without events are sampled at their configured interval. |
| 120–127 | bounded `spec.sharing`; each capture consumes one slot | Recurring-policy sharing | ADR-239 / maintainer | KEEP(c) | "explicitly bounded recurring-policy sharing" (AGENTS.md). Per ADR-335 D7 no weekly renewal; ensure no time cap is attached to the slots. |

### permission-observation.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 65 | 1,024 bindings per namespace | AccessBindings accepted per namespace | "Fail-closed bounds (no silent truncation)" — no cost reason | REMOVE | Overflow rejects the whole namespace's bindings (L70–71). The doc itself says delivery and storage are paged and otherwise bounded only by memory. Replacement: paging + Kubernetes object/etcd limits. |
| 65–66 | 1,024 ClusterAccessBindings; 1,024 sources per cluster | Cluster-scoped bindings, PermissionSources | same | REMOVE | Admin-only objects; Kubernetes object limits bound them; paging exists. |
| 66 | 64 KiB per spec | Binding/source spec size | same | REMOVE | Kubernetes already bounds an object at 1.5 MiB (etcd request limit) — use that. |
| 66–67 | ≤ 32 selected label keys per source | Keys a PermissionSource selects | same | REMOVE | Admin-authored (ADR-328); cost scales with keys × namespaces, which is the memory bound the doc already accepts. Replacement: K8s object limit. |
| 67–68 | 65,536 namespaces carrying a selected key per cluster | Watched namespace metadata | same | REMOVE | Contradicts L68–69 ("bounded only by memory"). Replacement: paged delivery; connector memory request. |
| 68 | 256 rows for one Pod | Allow/deny basis rows matching one Pod | same | REMOVE | Bounded by the bindings that exist; overflow would deny a legitimately bound Pod. |
| 128–130 | SAR allow cached ≤ 30 s, denial not cached | kubernetesExec/AccessReview cache | ADR-311 | KEEP(c) | ADR-311 30 s. |
| 132–133 | ≤ 256 groups reviewed per principal at capture time (batched) | SubjectAccessReviews for audience recording | none | DERIVE | Real cost: one SAR per group. But the group list is already bounded by the signed token size; derive batching from the connector's API-client QPS, no separate count cap (a user with 300 groups must not fail capture). |

### context-projection.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 7 | 4096-byte native limit | `asservat-pod-status/v1` artifact size | none here (ADR-206 profile constant) | DERIVE | Closed 14-scalar format; derive from the schema's per-field maxima (UID 36, resourceVersion, counts as int64) — likely < 1 KiB, so state the computed bound rather than an arbitrary 4096. |
| 28 | absent `max_lines` = 200 | Lines per excerpt | "within the canonical bounds" | REMOVE | The result has exactly 14 lines; a line-count parameter/cap adds nothing. Return all 14. |
| 28 | envelope 24 KiB structured / 64 KiB wire | Result page size (all projections) | none | DERIVE | Acceptable only as a page size with pagination (pod-status fits; syscall/packet queries page). Derive from MCP client context budget; make it the page size, with cursors for continuation, not a result cap. |
| 40, 49 | MCP wait ≤ 30 s | `get_query_result` server-side wait | ADR-330 D1 | KEEP(c) | ADR-330 D1. |
| 47 | query deadline ≤ 60 s | Reader execution time for one query | none | RAISE | Human-facing wait (ADR-335 D9: minutes to days, never seconds). Execution cost is already bounded by the scan cap (query capacity). Propose: execution deadline derived from scan cap ÷ reader throughput, minutes-scale (e.g. 10 min). |
| 50, 60 | result available until the query deadline (≤ 60 s); browser clears at expiry | Result-handle lifetime | none | REMOVE | ADR-335 D9: "result handles last as long as the evidence". Replacement: result lives until the artifact's retention deadline / revocation (events remove it). |
| 52 | retried once; second failure terminal | Reader retries per query | none | REMOVE | Read is idempotent under the same query ID. Replacement: retry with backoff until the query deadline. |
| 67 | 20 KiB private ceiling within 24 KiB envelope (syscall query page) | Syscall query page | none | DERIVE | Same as envelope row: a page size with pagination; derive = envelope − wrapper overhead. |
| 69 | pcap filter 512-byte cap | `pcap_query` filter text | maintainer "bounded pcap filters" | KEEP(c) | AGENTS.md "bounded pcap filters". Better bound: the compiled program ≤ 4096 instructions (BPF_MAXINSNS, KEEP(b)); the 512-byte text cap could be raised accordingly. |
| 69 | page ≤ 100 rows, 24 KiB | Packet-query page | none | DERIVE | Page size with continuation (pagination) — fine as a page, not as a result cap; derive from the envelope. |
| 69 | ≤ 32 fields | Fields per packet-query page | none | REMOVE | Fields come from a closed field catalog; the catalog size is the bound. |
| 69 | "scan cap" (value in context-query-capacity.md) | Records scanned per query | implied CPU bound | KEEP(a) | Per-query reader CPU grows with records scanned (value audited in the other file). |

### artifact-format.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 24, 31 | 8 MiB frames; decoder window/output 8 MiB | Frame size / decompression memory | implicit (encoder "holds one frame") | KEEP(a) | Memory per in-flight frame; range reads cost ≤ 2 boundary frames extra. Internal format constant, not user-facing. |
| 24, 25, 35, 55 | native size ≤ 1 TiB (index ceiling 160 MiB at 1 TiB) | Largest artifact (e.g. a core) | derived from 512 index pages × 256 entries × 8 MiB | RAISE | The 512-page cap is itself arbitrary. External bound is S3's 5 TiB max object (KEEP(b)); allow more index pages so the limit = 5 TiB (index ≈ 800 MiB at that size). Hosts with > 1 TiB RAM exist. |
| 25 | ≤ 256 entries and 256 KiB decoded JSON per index page | Index page | implicit (reader retains one page) | KEEP(a) | Memory per page held by the reader. |
| 26 | manifest ≤ 1 MiB decoded JSON | Manifest size | none | DERIVE | Manifest holds the page directory; derive = fixed fields + pages × directory-entry size (so it scales with the raised page count). |
| 27 | commit ≤ 32 KiB | Commit receipt | none | DERIVE | Contents are IDs, digest, size, one wrapped key; derive from schema field maxima (~4 KiB). Harmless but arbitrary. |
| 31 | encrypted frame ≤ native + 64 KiB | Ciphertext overhead per frame | implicit | KEEP(b) | Tink AES256_GCM_HKDF_1MB header + 16-byte tag per 1 MiB segment plus zstd worst-case expansion; 64 KiB covers it. State the derivation. |
| 39 | 1 MiB segments, 32-byte keys | Tink streaming parameters | Tink key template | KEEP(b) | External crypto template. |
| 41 | keyset ≤ 4 KiB | Serialized keyset buffer | implicit | KEEP(b) | Tink keyset for one RAW AES-GCM-HKDF key is a few hundred bytes; fixed format. |
| 51 | integers < 2^53 | AAD numeric fields | — | KEEP(b) | JS safe integer / RFC 8785 number canonicalization. |
| 55 | charge: L + N × 64 KiB data, P × 320 KiB index, 1088 KiB manifest, 32 KiB commit, four object slots | Admission charge per attempt | derived from the layout | KEEP(a) | Derived from the format bounds above (update when manifest/commit are derived). ADR-335 D2: internal estimates, not operator values — fine. |
| 57, 59 | range decodes ≤ length + two frames; pull buffer ≤ 1 MiB | Range-read work / cursor memory | implicit | KEEP(a) | Memory per stream; derived from frame size. |
| 35 | part size below S3 part-count limit for 1 TiB | Multipart part size | S3 10,000-part limit | KEEP(b) | External S3 limit (10,000 parts × ≤ 5 GiB). Re-derive for 5 TiB. |

### node-collector.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 61 | kernel ≥ 5.15 | Collector prerequisites | BTF/BPF features | KEEP(b) | External kernel feature availability (BTF, cgroup v2 BPF, tc). |
| 93 | ≤ 5,000 nodes per connector | Nodes served | none | KEEP(b) | Kubernetes' published scalability threshold is 5,000 nodes per cluster; state that reason. |
| 93 | 64 queued items per node | Per-node work queue | none | DERIVE | Hub admission already caps concurrent work per node/cluster (D8 concurrency ≥ 8). Derive queue = admitted per-node concurrency + pending stop/cancel items; queue overflow must not refuse admitted work. |
| 93–94 | 64 receipts per report | Receipts per status message | none | REMOVE | Send several messages; the message byte limit suffices. |
| 94 | 64 KiB per message | Node-stream message size | none | DERIVE | Memory per decoded message; but a `packetCapture`/profile work item can carry TLS bundles up to 64 KiB aggregate plus an Authorization value (runtime-profiles L126, L137) — it cannot fit. Derive = largest typed work payload + headroom (e.g. 1.5 MiB, the K8s object size of the source config) or gRPC default 4 MiB. |
| 94–95 | TokenReview 50/s, burst 200 per connector (default) | New-stream authentication rate | implicit API-server cost | KEEP(a) | TokenReview cost per new stream; configurable default; 5,000 nodes reconnect in ~100 s. Note derivation from API-server client QPS. |
| 95–97 | 256 MiB ring, 256 MiB frozen, 32 MiB/s upload (64 MiB burst); memory limit = ring + frozen + 128 MiB | Node buffers, upload rate | "bound the container memory limit" | KEEP(a) | Memory/network cost grows with value and the memory limit is derived from it; rings are maintainer-approved bounds (ADR-335 D6). Configurable defaults; ADR-335 D2 suggests deriving the default from node allocatable memory. |
| 104 | 16 active sources / 16 MiB/s input / 16 MiB input burst (chart dev references) | Ongoing sources per node | none | DERIVE | Concurrency limits stay (D8) but defaults "from cluster size". Derive: active sources = node ring budget ÷ per-source ring minimum; input rate from upload/CPU budget. Note: "development references" means no production default is defined. |
| 116–118 | 134-byte prefix; X ≤ 60 (4 × nibble ≤ 60) | cBPF prefix-proof reads | protocol header maxima | KEEP(b) | 134 = Ethernet 14 + IPv4 max 60 (IHL 15 × 4) + TCP max 60; MSH bound = IPv4 IHL maximum. |

### applications.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 60 | hub-api two replicas, ≥ 2 available during RollingUpdate | Hub API availability | ADR-335 D13 | KEEP(c) | D13 / brief "Two hub-api replicas". |
| 61 | hub-worker two replicas, leader + standby | Worker availability | ADR-335 D13 | KEEP(c) | D13. |
| 62 | SAR allow reused ≤ 30 s, denial not cached | Connector access-review cache | ADR-311 | KEEP(c) | ADR-311. |
| 92 | "fixed share of installation DB connections" | Per-process pool | ADR-335 D11 | KEEP(c) | D11: total ≤ 30 by default; the doc should name the default split. |

### runtime-profiles.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 21–22 | "a 60-second CPU profile plus setup and finish margin fits" (implied maximum) | Profile action interval | none | RAISE | Reads as a 60 s ceiling on CPU profile duration. ADR-335 D8/D9: windows up to the capture's configured duration (minutes). Allow the recipe's configured duration; the remote cost is the application's own pprof load, bounded by D8 concurrency/rate. |
| 28 | setup/finish margin 2–10 s, "synthesizes no defaults" | Profile action margin | none | DERIVE | It is an I/O margin: derive = connect + finish I/O timeouts (2 × 5 s, ADR-330 D5) and default it, instead of forcing every caller to supply a value in a range. |
| 29–30 | defaults: 10 s CPU, 5 s trace, 5 s snapshot | Default profile durations | none | DERIVE | Use Go's own `net/http/pprof` defaults (CPU `seconds=30`, trace `seconds=1`) unless there is a measured reason; recipe-configurable either way. |
| 86 | ≤ 128 template/profile entries in the endpoint catalog | Admin endpoint catalog size | none | REMOVE | Admin-authored Kubernetes configuration; bounded by K8s object limits (1 MiB ConfigMap / 1.5 MiB object). |
| 86 | ≤ 16 bindings per recipe | Endpoint bindings per recipe | none | REMOVE | Recipe is a K8s object; bounded by object size. Cost per binding is a lookup. |
| 116 | ≤ 256 declared ports | Ports read per Pod | none | REMOVE | Kubernetes has no port-count limit; Pod object size (1.5 MiB) bounds it; reading is from the informer cache (no cost). |
| 116 | two Pod IPs | IPs per Pod | Kubernetes dual-stack | KEEP(b) | Kubernetes allows at most one IP per family (`podIPs` ≤ 2). |
| 126–127 | TLS bundle ≤ 8 KiB each, 64 KiB aggregate | Endpoint CA bundles | none | REMOVE | 8 KiB ≈ 4–5 PEM certificates; corporate bundles exceed it. Replacement: the containing ConfigMap/object limit (1 MiB, KEEP(b)); and per ADR-335 D12 system trust is default. Also must fit node message size (see node-collector L94). |

### build-or-reuse.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 15 | SAR allow reused ≤ 30 s, deny not cached | C-03 Kubernetes access review | ADR-311 | KEEP(c) | ADR-311. |

### components.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 39 | `identity.AuthorityRecheckInterval` (30 s), never past original deadline | Authorization reuse | ADR-311 | KEEP(c) | ADR-311. |

### interfaces.md

| line(s) | value | bounds what | stated reason (short quote or "none") | verdict | justification / replacement |
| --- | --- | --- | --- | --- | --- |
| 15 | one-hour cap on `saveRecording` lookback | Save-now lookback window | "a transport ceiling" | REMOVE | No transport constrains a duration; lookback is already bounded by actual ring coverage (ring size, maintainer-approved) and the source's retention. Replacement: ring coverage. |
| 31 | work message ≤ 128 KiB; decoded control payload ≤ 64 KiB | I-01 hub→connector work message | none | DERIVE | Memory per message is a real cost, but derive from the largest typed payload (profile work with TLS bundles/credential, plan) — and keep it consistent with the node stream (64 KiB there). Propose: largest payload + headroom, e.g. 1.5 MiB (K8s object bound of the source config) or gRPC default 4 MiB. |
| 31 | receipts ≤ 64 KiB or 100 entries per message | Receipt batch | none | REMOVE | Entry count: send several messages; byte limit suffices. (Also inconsistent with node-collector's 64 receipts.) The 64 KiB byte bound: DERIVE with the message row above. |
| 51 | core handoff header ≤ 4 KiB | I-03 fixed header | implicit (helper runs while crashed process is held) | KEEP(a) | Fixed small allocation in the crash path, fixed-format numeric fields; one page. |
| 59 | ≤ 16 source references per view | Live-watch sources | ADR-310 (agent ADR); maintainer "finite views" | DERIVE | Finite views are a maintainer decision, but 16 is arbitrary. Real cost is per-source fanout charged by C-07 view slices; derive from the admin live-viewer budget (charge per source), not a fixed count. |
| 59 | ≤ 16 typed predicates per view | Display filter predicates | none | DERIVE | CPU per row grows with predicate evaluation; derive a cost budget (predicates × rows/s within the view's CPU slice) or bound by filter-expression size. |
| 61 | MCP waits ≤ 30 s | Live MCP read | ADR-330 D1 | KEEP(c) | ADR-330 D1. |

### runtime.md

No numeric limits (L42 "1,000 matches during cooldown" is an illustrative storm scenario).

---

Obsolete-machinery notes (no numeric limits, so not counted): interfaces.md L45 and runtime.md
L40/L72/L143 still describe the connector "budget lease" and "unexpired local policy permits"
with "prewrapped envelopes … finite pool" — prepaid/never-refunded spend that ADR-330 D7
removes ("No never-refunded charges, prepaid renewals"); the crash-path pool may survive only
as idempotent local admission. interfaces.md L39 says the connector "issues its client
certificate" to collectors, contradicting node-collector.md L33–35 ("No node certificate, CSR")
and ADR-330 D3. interfaces.md L41 work kinds `packetSource`/`stopPacketSource` vs
node-collector.md L53 `packetCapture`.

COUNTS: KEEP=39 REMOVE=27 RAISE/DERIVE=26

Most user-visible REMOVE items:
1. identity-eligibility.md:38 — ≤ 256 signed groups (≤ 255 bytes each) / 64 scopes: users in many LDAP groups cannot sign in.
2. identity-eligibility.md:124–130 — ≤ 256 audience entries: a widely bound workload cannot be captured.
3. context-projection.md:50,60 — query results vanish after ≤ 60 s (contradicts ADR-335 D9 handles live as long as evidence).
4. browser-sessions.md:43–44 — 32 sessions per subject with LRU eviction signs users out of other devices.
5. browser-sessions.md:38 — admin may set session lifetime only up to 30 days.
6. permission-observation.md:65 — 1,024 bindings per namespace; overflow rejects the namespace's bindings.
7. policy-automation.md:15,31 — execution count and lifetime byte envelope on automatic grants (ADR-335 D6).
8. interfaces.md:15 — one-hour lookback cap on Save existing recordings now.
9. runtime-profiles.md:126 — 8 KiB per endpoint CA bundle / 64 KiB aggregate.
10. identity-eligibility.md:70–71 — user/group picker stops at 20 results with no pagination.

---

<!-- part: ifx -->
## docs/interfaces (prose and non-schema values) and examples/**

JSON-Schema keywords inside these files are in the schema sections. Example values are instances of schema fields; the verdict below is about the *field as a required limit* shown to users. Where the same field appears in many examples it is one row.

### docs/interfaces/README.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
|---|---|---|---|---|---|
| 38 | default 20, max 100 items per page; cursors never expire | list page size | none ("Lists default to 20 items, maximum 100") | KEEP(a) | Per-request response size with cursor pagination; the total is unbounded. Fine as a page size. |
| 38 | MCP envelope 24 KiB default / 32 KiB structured / 64 KiB combined | MCP tool result size | none stated here | DERIVE | A real cost exists (LLM context window, the client's tool-result limits). Derive from published MCP client limits (e.g. Claude Code truncates tool output around 25k tokens ≈ 100 KiB) and keep pagination for the rest; 24/32/64 KiB is arbitrary. |
| 38 | console JSON 32 KiB hard response bound | browser response size | none | REMOVE | Pages are already bounded by page size; a byte cap on top creates truncation failures with no resource reason. Rely on page size + streaming (SSE). |
| 38 | configuration impact preview ≤ 1,000 targets and 256 KiB | preview size | "existing maximum" (agent ADR) | REMOVE | Paginate the target list (the text already says "bounded partial pages"); the 1,000/256 KiB totals add a failure mode for large namespaces. |
| 38 | editor-diff projection ≤ 64 KiB | diff output | none | REMOVE | Derive from the input instead: diff of a ≤ 1.5 MiB K8s object (b) is itself bounded. |
| 38 | `stage_editor_draft` ≤ 64 KiB YAML in ≤ 128 KiB request | editor draft size | none | DERIVE | The real bound is the Kubernetes object size (1.5 MiB etcd request limit, b). Set draft max = 1.5 MiB, request = draft + envelope. |
| 38 | 64 KiB transport ceiling for other JSON requests | request body | none | DERIVE | A body cap is good practice (DoS), but derive per operation from its largest legitimate field (K8s object 1.5 MiB for config; small for others). Keep one global server cap ~2 MiB. |
| 60 | Alertmanager max 1 MiB body / 100 alerts | webhook batch | "Reject oversized batches with 413" (behaviour, not reason) | RAISE | Alertmanager sends whole groups; it has no batch-size setting except `max_alerts` per receiver (default 0 = unlimited). 100 alerts will 413 real large groups. Keep a body cap as DoS protection (a), derive from the per-alert size × Alertmanager group size, e.g. 10 MiB, and drop the alert-count cap (trigger rate limits per policy already bound captures, ADR-335 D8). Document `max_alerts` as the Alertmanager-side knob. |
| 62 | "bounded retries/backoff" for outgoing webhooks | retry count | none | KEEP(a) | Unnumbered; retries need a bound because each costs network and a queue row. Number it in federation spec with exponential backoff up to the event's own deadline. |
| 70 | SSE `GET /api/v1/events` names up to 16 captures/grants/downloads | per-page subscription | none | REMOVE | One SSE stream filtered server-side costs per change, not per subscribed ID; a page showing 50 downloads would be silently partial. Replace with "the IDs the page shows" (bounded by page size 100) or subscribe by scope (case, user). |
| 70, 74, 45 (mcp-workflows) | MCP status `after_revision` / `watch_live` waits ≤ 30 s | long-poll wait | ADR-330 D1 "bounded, at most 30 s" | KEEP(c) | Maintainer-accepted ADR-330 D1; also typical HTTP intermediary idle timeout (b). |
| 70 | authorization reused ≤ 30 s | SSE auth reuse | ADR-311 | KEEP(c) | ADR-311 maintainer decision. |
| 76, 78 | live watch stays open while reads arrive ≤ 10 min apart; 10-minute idle window | idle live-watch lifetime | ADR-335 D9 | KEEP(c) | Maintainer decision ADR-335 D9. |
| 76 | "its delivery rate is bounded" | live row rate | none numeric | KEEP(a) | Rows cost network/CPU per viewer; leave as a rate limit derived from the source's events/s (schema `bytes_per_second`, see examples row). |
| 78 | "rows beyond the replay buffer" | replay buffer | maintainer "rows/replay remain bounded transient data" | KEEP(c) | AGENTS live-watch decision; size see examples row `replay_seconds`. |
| 88 | resumes unlimited until `AccessUntil` | download resumes | ADR-335 D9 | KEEP(c) | Already the maintainer position (no count cap). |

### docs/interfaces/mcp-workflows.md

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
|---|---|---|---|---|---|
| 17, 31 | live watch open while reads ≤ 10 min apart | idle window | ADR-335 D9 | KEEP(c) | Same as README 76. |
| 31, 45 | `wait_ms` ≤ 30000 | MCP long-poll | ADR-330 D1 | KEEP(c) | |
| 27 | "Save the last 20 seconds" / `before: 20s` | example only | n/a | KEEP | Example value, not a limit. |
| 45 | "every truncation includes a narrowing hint"; "do not return an unbounded list of related cases" | MCP list size | context-window cost | KEEP(a) | Pagination + page size; fine. |
| 57 | auth reused ≤ 30 s per cursor page | ADR-311 | KEEP(c) | |
| 57 | "bounded retry time" when quota unavailable | retry hint | n/a | KEEP | It reports Retry-After, not a cap. |

### docs/interfaces/browser-auth-openapi.yaml (descriptions)

| line(s) | value | bounds what | stated reason | verdict | justification / replacement |
|---|---|---|---|---|---|
| 27 | `max_age=0` for step-up | OIDC re-authentication | OIDC Core `max_age` semantics | REMOVE (feature default) | ADR-335 D5: step-up is optional and off by default; the forced `max_age=0` applies only when enabled. Not a limit to keep by default. |
| 123 | `Retry-After: 1` on 409 credential rotation; "CSRF and the following POST share the original attempt budget" | refresh/CSRF retry | none | REMOVE (budget) | The shared "attempt budget" is agent machinery; the 409 + Retry-After is enough. Keep Retry-After (b: HTTP semantics). |

### docs/interfaces/errors.yaml

| line(s) | value | verdict | note |
|---|---|---|---|
| 11, 18, 23 | 429 BudgetExceeded / RetryLater / SharingCapacityUnavailable | KEEP(c)/REMOVE | BudgetExceeded and RetryLater KEEP (D8 rate/concurrency limits). `SharingCapacityUnavailable` ("Bounded sharing capacity") REMOVE: there is no resource reason for a sharing-capacity cap (shares are rows; D7 removes the 7-day cap); handled by the share-cap agent too. |

### docs/interfaces/*-validation.json

Counters of test cases (32/152/10/19). Not limits. Skip.

### examples/** — fields that encode limits

| file(s) | field = value(s) | bounds what | stated reason | verdict | justification / replacement |
|---|---|---|---|---|---|
| helm/context-trial-profile.yaml (capacity.*, federation.connector.*, metadata.*, footprints.*, envelope.*, backup.*) | accounts 2, recordsPerAccount 8/16/96/128, admissionSeconds 86400, captureRetainedSeconds/retainedSeconds/stopRetainedSeconds 10000/4000, rowBytes/transitionWALBytes/fixedRowBytes/accountRowBytes/recordRowBytes/recordWALBytes, sqlBytes 512 MiB, backupBytes 1 GiB, walBytes 32 GiB, keyAttempts 16384, recordKeyAttempts 16, configurationTransitions 4096, purgeLeases 4/2, processing.maxRules 2, maxRootTransitions 512, backup.horizonSeconds/cleanupBudgetSeconds/proofWindowSeconds, sourceTransitions 8, validSeconds 3600, profiles 1 | SQL/WAL/backup prepayment and footprint arithmetic | agent capacity model | REMOVE | ADR-335 D2: "Byte, WAL, row and footprint figures are internal estimates, not values"; ADR-330 D7 removes WAL/backup prepayment and key slots. Replace with the D2 operator values (storage size, retention, per-workload share, concurrency). The whole file is installer-era (ADR-330 D13). |
| helm/context-trial-profile.yaml `identity`, browser-settings.json (+implemented/) | maxLogins 8/256, maxSessions 8/2000, maxLogoutEvents 8/4000 | concurrent login attempts, sessions, logout events | none | REMOVE | ADR-335 D8: "sessions unlimited (bounded by rate limits)". Pending logins and logout events are rows that expire; bound with a per-client login rate limit. |
| browser-settings.json, helm/context-trial-profile.yaml | maxLifetimeSeconds 28800 / 3600 | browser session absolute lifetime | none | KEEP(b)/DERIVE | An absolute session lifetime is standard (OWASP ASVS 3.3, NIST 800-63B reauth ≤ 12 h–30 d by AAL). Default it to the IdP's SSO session max (Keycloak `SSO Session Max`, default 10 h) instead of an Asservat number; 1 h in the trial profile contradicts D9 human timescales. |
| identity-settings.json, helm/context-trial-profile.yaml | groupMaxAgeSeconds 300 | staleness of token group claims | none | REMOVE | Groups come from the token (ADR-335 D4 uses the standard `groups` claim); the token's own `exp` and the 30 s authority reuse (ADR-311) bound staleness. A second 5-minute bound forces re-login. |
| fleet-settings.json, helm/context-trial-profile.yaml | maxActiveBootstraps 8/1, maxBootstrapHistory 1024/4, maxClusters 32/1 | cluster join bootstraps, history rows, clusters per installation | none | REMOVE | Bootstrap machinery replaced by connector workload identity (ADR-334/332, ADR-330 D3). Clusters are a handful of rows; "central multi-cluster management" (AGENTS) has no cluster cap. Join-token issuance can be rate-limited. |
| helm/context-trial-profile.yaml | captureHistory perSelector 16, perInstallation 32 | capture history entries | none | REMOVE | History rows are SQL rows paged by cursor; retention (D7) deletes them. Paginate instead. |
| helm/context-trial-profile.yaml | hub-api connections 4, concurrency 2 | SQL pool | ADR-335 D11 total ≤ 30 | KEEP(c) | Pool size the chart sets (D11). Concurrency 2 per process: DERIVE from pool size. |
| permission-source-*.yaml (4) | maxDecisionAgeSeconds 30 | permission decision reuse | ADR-311 30 s | REMOVE (field) / KEEP(c) (value) | 30 s is the maintainer's `AuthorityRecheckInterval`; a per-source knob duplicates it (D7 "configuration solely to tune its own machinery"). Drop the field, use the global 30 s. |
| permission-source-*.yaml (4) | maxNamespaces 200 / 50 | namespaces a permission source may cover | none | REMOVE | Watch-based (ADR-330 D1) evaluation costs per change, not per namespace; a cap silently denies access in large clusters. |
| budget-policy.yaml, helm profile | namespaceEnvelope.maxWorkloadAccounts 4/2, maxStoredBytes, maxObjects; workload.protected/hardLimit/contextReserve bytes+objects; pool capacity/safetyHeadroom/systemReserve/sharedBurst bytes+objects, protectedAllocations.workloadSlots | storage exhaustion protection | maintainer: "protection against cross-workload storage exhaustion" | KEEP(c) (concept) / REMOVE (most fields) | ADR-335 D2: "evidence storage size, retention, per-workload share and concurrency" are the operator values. Keep `capacity.bytes` and a per-workload share (percent of capacity); derive protected/hard/reserve/headroom/burst from them. Object counts: REMOVE unless the backend has an object limit (SeaweedFS/S3 have none practical). maxWorkloadAccounts REMOVE (workload count is not a resource). |
| budget-policy.yaml, helm profile | dump.burst 1, minimumIntervalSeconds 900, maxStartsPerRollingHour 1–2, maxInputBytesPerRollingHour 1 MiB/4 GiB | core-dump storm protection | maintainer D8 rate limits | KEEP(c) / DERIVE | Rate limits stay (D8). maxInputBytesPerRollingHour duplicates storage share + rate; REMOVE. 15-minute interval + 2/h for dumps are fine defaults but should derive from node size per D8 ("defaulting from cluster size"). |
| budget-policy.yaml, helm profile | maxConcurrentExpensive 1/2, maxQueuedExpensive 1/10, maxQueueAgeSeconds 30 | concurrent expensive actions per workload/node | D8 concurrency | KEEP(c) concurrency / REMOVE queue age | Concurrency stays (D8). A 30 s queue age contradicts D9 (human timescales): queued work should wait while its capture window is valid. maxQueued: DERIVE (rows; one per pending capture is cheap) or REMOVE. |
| budget-policy.yaml, storage-pool.yaml, helm profile | upload.bytesPerSecond 8–128 MiB/s, burstBytes, maxUploadRequestsPerSecond 10–100, maxSpoolBytes 16 MiB–4 GiB | upload bandwidth/spool | resource protection | KEEP(a)/DERIVE | Real network/disk cost. Derive defaults from node NIC/egress and the spool from the node collector's emptyDir/PVC size rather than four separate per-workload and per-node numbers; maxUploadRequestsPerSecond REMOVE (bytes/s already bounds it; S3 request rate limit 3,500 PUT/s per prefix is far above). |
| budget-policy.yaml | pressureTriggers stallMicroseconds 150000/300000 over 1 s, recoverySeconds 60; helm unhealthySamples 3, sampleIntervalSeconds 5 | node PSI back-off | node protection | KEEP(a) | PSI thresholds protect the node (kernel PSI semantics, b). Sampling interval: ADR-330 D1 allows sampling only for sources without events; PSI supports poll() triggers (kernel psi.rst) — use PSI trigger fds instead of 5 s sampling. |
| policy-*.yaml (13), implemented/policy-deployment.yaml | budgets.cooldown 5m, burst 1–2, maxOccurrencesPerHour 2–12, maxConcurrentActions 1–3 | per-policy trigger storm | maintainer D8 | KEEP(c) | Rate/concurrency stays (D8); should default (not be required in every example). |
| policy-*.yaml | target.maxPods 1 | pods per incident | maintainer "independently cap per-incident collection" | KEEP(c) | |
| policy-*.yaml | detectors.options.maxRecordBytes 16 KiB/64 KiB | log line size matched | memory per line | DERIVE | Kubernetes log lines are capped by the runtime (containerd/CRI-O split at 16 KiB, b). Use 16 KiB CRI line size, no field. |
| policy-*.yaml | sampleInterval 5s/30s/60s, window 30s/1m, duration 20s, minimumFailures | detector semantics | user-chosen | KEEP | User expression parameters, not caps. metrics.k8s.io sampled at its interval (ADR-330 D1). |
| policy-*.yaml | retention 72h / 3600s | requested retention | user choice under admin max D7 | KEEP(c) | |
| access-binding-automation.yaml, grant-policy.yaml | automation.maxLifetimeSeconds 2592000 (30 d), maxExecutions 100/12, maxBytes 1 TiB / 8 GiB, maxObservedBytes 1 TiB; grant limits.maxDuration 60s | team automation envelope | maintainer: "expiring policy grants for automatic intrusive actions", ADR-059 "bounded automation" | KEEP(c) lifetime / REMOVE run & byte counts | ADR-335 D6: expiring grants with admin-configured periods (default 90 days — this example's 30 d contradicts the default); "Non-intrusive policies do not expire and have no run count. Always-on recorders are bounded by rates and ring sizes, not lifetime byte budgets." So maxExecutions/maxBytes/maxObservedBytes lifetime totals REMOVE; rate limits (D8) and ring sizes replace them. |
| approval-policy.yaml, grant-policy.yaml approvalPolicyRef | policyGrants.defaultAgeSeconds 7776000 (90 d), maxAgeSeconds 15552000 (180 d), renewalNoticeSeconds 1209600 (14 d) | policy grant period | ADR-335 D6 default 90 d, admin-configured | KEEP(c) default / REMOVE max | Default 90 d is D6. A hard 180-day ceiling on what the administrator configures has no reason; the administrator is the ceiling. Renewal notice: KEEP as a derived default (e.g. 1/6 of period). |
| grant-*.yaml, capture-investigation.yaml, investigation-*.json | maxArtifacts 2, maxOperations 20, maxExecutions 1–4 | manual investigation approval scope | maintainer "one bounded independent approval… finite parent disclosure pool" | KEEP(c) concept / DERIVE numbers | The pool must be finite (maintainer); the numbers should derive from the preview (the artifacts actually selected) rather than a separate typed count. |
| sharing-intent.yaml, policy-with-sharing.yaml | maxCaptures 1/10, maxArtifactsPerCapture 64, notAfter +6 h | recurring/capture-time sharing | maintainer "explicitly bounded recurring-policy sharing" | KEEP(c) bound / REMOVE artifact cap, RAISE notAfter | Recurring sharing must be explicitly bounded (AGENTS) — one bound (time or capture count) suffices. maxArtifactsPerCapture 64 has no reason (a capture's artifacts are already bounded by its recipe) → REMOVE. Example `notAfter` 6 h contradicts D7 (shares until evidence retention ends). |
| grant-packet-observation.yaml | maxConcurrentSessions 1, maxSessionSeconds 30, maxBytesPerSecond 32 MiB, maxObservedBytes 1 GiB | packet observation grant | none | REMOVE session caps / KEEP rate | D8 "sessions unlimited (bounded by rate limits)"; a 30 s session contradicts D9. Keep bytes/s (a). Lifetime observed bytes REMOVE (D6). |
| retention-policy.yaml, helm profile | defaults/maxima evidenceSeconds 86400 (helm 300/3600), caseMetadataSeconds 604800, auditMetadataSeconds 7776000; rules maxAgeSeconds core/heap 21600 | retention | maintainer administrator-enforced maximum; D7 defaults 14 d | KEEP(c) / fix values | Concept KEEP(c). Example values contradict D7 (evidence 14 d, cores 14 d); the 6 h core rule and 1 d evidence should be 14 d. Separate case/audit metadata maxima: DERIVE from evidence retention (metadata ≥ evidence) unless a legal reason is cited. |
| retention-policy.yaml, assessment-*.json, helm profile (22 files) | deletionBudgetSeconds 300 | time allowed for deletion after deadline | none | REMOVE | ADR-330 D12: deletion runs from stored deadlines; a 5-minute deletion budget is a lag SLO, not a limit. Report overdue deletions (artifact-deletion-overdue.json) without a configured budget, or make it a monitoring threshold. |
| assessment-*.json, mcp-*preview*.json | maximumAgeSeconds, deleteAgeSeconds, accessAgeSeconds, requestedAgeSeconds, resolvedMaxAgeSeconds | displayed retention | output | KEEP | Output facts, not limits. |
| capture-profile-*.yaml (packets/http) | maxEndpoints 1/256, maxFlows 1024, maxHeaderBytes 32 KiB, maxReassemblyBytes 16 MiB, maxReassemblyBytesPerFlow 256 KiB | HTTP header extraction memory | memory in collector | KEEP(a)/DERIVE | Reassembly memory is a real per-node cost; derive per-flow × flows from a collector memory budget. maxHeaderBytes: derive from common server header limits (nginx 8 KiB per line/ 32 KiB large_client_header_buffers, b) — 32 KiB is defensible, cite it. maxEndpoints REMOVE (pcap/BPF filter size is the external bound, b). |
| capture-profile-*.yaml (23) | segmentBytes 1–4 MiB, maxSegments 4/9, maxFrozenBytes 4–64 MiB, maxConcurrentSnapshots 1, maxAge 10s/30s, idleTimeout 30s, maxStaleness 5s (implemented/) | ring buffer | maintainer "segmented rings"; D6 recorders bounded by ring sizes | KEEP(c) ring size / REMOVE maxStaleness | Ring size is the maintainer-accepted bound. maxStaleness 5 s is an agent freshness window (ADR-330 D5 removes 5 s windows) → REMOVE. idleTimeout 30 s for HTTP flow tracking: KEEP(a) (memory per idle flow), derive from TCP keepalive defaults. |
| capture-profile-syscall/io-arguments, recipe-syscall-arguments | maxEvents 100000, maxEventsPerSecond 10000, maxTrackedThreads 4096, maxBytesPerEvent 256 | syscall trace | maintainer "argument mode needs reviewed observation budgets" | KEEP(c) per-second, argument bytes / REMOVE maxEvents total | Rates and per-event argument bytes are the reviewed budget (c). A lifetime event total on an always-on recorder contradicts D6 (rings). maxTrackedThreads: KEEP(b) derive from the eBPF map size (BPF map max_entries memory). |
| recipe-*, mcp-recommend-* | maxProcesses 2, maxDepth 2, maxBytesPerProcess 256 MiB, maxStopPerProcess 10s, maxTotalStop 20s | process-tree dump selection | workload pause impact | KEEP(a)/DERIVE | Stop time is a real impact on the workload (a). maxDepth 2 / maxProcesses 2: REMOVE (dump all matching processes, bounded by total stop time and the bytes per capture). |
| capture-*.yaml, recipe-*.yaml, capture-profile-*.yaml, mcp preview results (≈50) | maxBytes / maxTotalBytes / max_bytes (4 KiB – 1 TiB), maxDuration 5s–30m, timeout 2s–90s, before/after 0–30s, finalizeTimeout 30s | per-capture size/duration | maintainer "manual requests finite", "independently cap per-incident collection", D8 post-trigger windows up to capture duration | KEEP(c) | Finite manual captures and per-incident caps are maintainer requirements. `after` ≤ 30 s in examples contradicts D8 ("post-trigger windows up to the capture's configured duration (minutes)"). Defaults should come from the recipe/profile, not be required in every example. |
| live-watch.json, mcp-live-open-result.json | bytes_per_second 64 KiB, max_rows_per_batch 100, max_buffer_bytes 1 MiB, max_output_bytes 16 MiB, replay_seconds 5, duration_seconds 600 | live view | maintainer "finite views", "bounded transient rows/replay" | KEEP(c) concept / REMOVE max_output_bytes, duration | Replay/buffer bounded (c). A 16 MiB lifetime output cap and a 600 s duration contradict D9 (watch open while connected or 10-minute idle). Rate (bytes/s) stays (a). |
| mcp-packet-query-*-input.json | max_packets 100, max_scan_bytes 8 MiB | packet query | context size / CPU per query | KEEP(a) page / REMOVE scan cap | max_packets is a page size (paginate). max_scan_bytes caps the work per query; replace with a query timeout or pagination over the artifact (offset cursor). |
| mcp-*-input.json (8) | limit 20 | page size | pagination | KEEP(a) | |
| implemented/mcp-context-*-pending.json | retry_after_seconds 1 | polling hint | none | REMOVE | ADR-330 D1: status tools wait server-side; no client poll hint. |
| download-*.json, manifest-*.json, framed-*.json | size_bytes, ciphertextBytes, plaintextBytes, nativeBytes, dataBytes 4352, indexBytes | artifact facts | output | KEEP (not limits) | 4096-byte context slice: see artifact-format rows (schema/arch sections). |
| helm/small-profile-values.yaml | size 8Gi/32Gi, dataSize 64Gi, backupSize 64Gi | PVC sizes | operator choice | KEEP(c) | D2 operator values. |
| helm/context-trial-profile.yaml | nodePorts 31446–31450 | exposure | K8s NodePort range 30000–32767 (b) | KEEP(b) | Five ports for owner/operation/key services are removed machinery (ADR-330 D2 one connection) — REMOVE the extra ports. |

COUNTS (this part, first verdict per row): KEEP=43 REMOVE=16 RAISE/DERIVE=5 (several KEEP rows also remove a sub-field)

---

<!-- part: schema0 -->
## Schema-limit audit — part 00 (schema-groups-part00, 536 groups)

Scope: every (property, keyword, value) group in `schema-groups-part00` (JSON-Schema limit keywords from specs/contracts/**, docs/interfaces/**, examples/** of /home/phil/Projekte/asservat-friction). Rows are grouped by rationale; each row lists every group it covers as `property keyword value ×occurrences`, and the files (`impl/` = specs/contracts/implemented/, `di/` = docs/interfaces/, other names = specs/contracts/*.schema.json; ×n = occurrences in that file).

Verdict counts at the end are per group (536 groups). The identifier/format row is counted separately as SKIP (brief: identifier/format validation is skipped, only counted).


## Identifier and external-format bounds (counted, not individually audited)

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| ID | `(def) maxLength 43` ×3; `(def) minLength 43` ×3; `(def) maxLength 256` ×163; `(def) maxLength 128` ×57; `(def) minLength 16` ×36; `(def) maxLength 2048` ×3; `(def) maxLength 4096` ×1; `(def) maxLength 180` ×1; `CSRF maxLength 43` ×1; `CSRF minLength 43` ×1; `csrf_token maxLength 43` ×1; `csrf_token minLength 43` ×1; `csrf_token maxLength 256` ×2; `Location maxLength 2048` ×1; `Origin maxLength 2048` ×1; `abi maxLength 32` ×2; `errno maxLength 32` ×2; `acquisitionRegion maxLength 63` ×1; `acquisition_region maxLength 63` ×1; `hubRegion maxLength 63` ×1; `hub_region maxLength 63` ×1; `connectorRegion maxLength 63` ×1; `connector_region maxLength 63` ×1; `acr maxLength 128` ×20; `acrValues maxLength 128` ×1; `actionID maxLength 63` ×41; `actionID maxLength 128` ×1; `actionID maxLength 64` ×1; `actionIDs maxLength 63` ×4; `actionIds maxLength 128` ×2; `action_id maxLength 128` ×2; `action_id maxLength 64` ×24; `action_id maxLength 63` ×10; `action_ids maxLength 64` ×8; `localActionID maxLength 63` ×1; `componentID maxLength 24` ×2; `dependsOn maxLength 63` ×14; `detector maxLength 63` ×2; `detectors maxLength 63` ×1; `endpointRef maxLength 63` ×1; `id maxLength 63` ×24; `adapterRef maxLength 63` ×1; `budgetPolicyRef maxLength 63` ×1; `identityMappingRef maxLength 63` ×1; `impactProfileRef maxLength 63` ×2; `address maxLength 32` ×8; `assessmentRef maxLength 128` ×3; `handlingPolicyRef maxLength 128` ×4; `keyRef maxLength 256` ×1; `captureUID maxLength 128` ×6; `basisUID maxLength 64` ×2; `basis_uid maxLength 64` ×12; `assignmentIDs maxLength 128` ×1; `environment_digest maxLength 64` ×2; `expected_selection_digest maxLength 64` ×2; `end_time maxLength 35` ×4; `base_resource_version maxLength 256` ×4; `expected_resource_version maxLength 256` ×2; `field_manager maxLength 128` ×2; `candidate_release maxLength 128` ×4; `configured_release maxLength 128` ×2; `clientID maxLength 256` ×4; `client_id maxLength 256` ×74; `client_ids maxLength 256` ×8; `clientIDs maxLength 128` ×2; `clients maxLength 256` ×1; `consoleClientID maxLength 128` ×1; `code maxLength 64` ×270; `code maxLength 80` ×2; `completeness maxLength 32` ×8; `kind maxLength 64` ×22; `format maxLength 64` ×1; `evidence_kinds maxLength 64` ×1; `blocker_codes maxLength 64` ×2; `blockers maxLength 64` ×4; `columns maxLength 64` ×4; `fields maxLength 64` ×8; `impact_codes maxLength 80` ×2; `action maxLength 80` ×2; `decision maxLength 80` ×2; `dimension maxLength 80` ×2; `container_name maxLength 63` ×2; `declared_port_name maxLength 63` ×8; `declaredPortName maxLength 15` ×1; `excludedNamespaces maxLength 63` ×1; `matchLabels maxLength 63` ×8; `labels maxLength 63` ×1; `key maxLength 253` ×1; `display_name maxLength 253` ×4; `containerID maxLength 256` ×1; `cidrs maxLength 64` ×2; `destination maxLength 128` ×4; `cursor maxLength 4096` ×76; `cursor maxLength 64` ×4; `diagnostic_handle maxLength 128` ×11; `flow_ref maxLength 128` ×1; `flow_refs maxLength 128` ×4; `id maxLength 256` ×12; `id maxLength 64` ×3; `id maxLength 128` ×2; `id maxLength 4096` ×1; `idempotencyKey maxLength 128` ×2; `idempotency_key maxLength 128` ×92; `issuer maxLength 2048` ×94; `event_id maxLength 180` ×1; `eligibleGroups maxLength 256` ×1; `groups maxLength 256` ×1; `buildIDs maxLength 128` ×2; `build_ids maxLength 128` ×1; `executableName maxLength 255` ×1; `executable_name maxLength 255` ×1; `executablePath maxLength 4096` ×1; `executable_path maxLength 4096` ×1; `logical_path maxLength 4096` ×4; `cron maxLength 128` ×1; `duration maxLength 16` ×10; `after maxLength 16` ×15; `before maxLength 16` ×11; `cooldown maxLength 16` ×3; `jitter maxLength 16` ×1; `maxDuration maxLength 16` ×2; `approval_navigation_uri maxLength 2048` ×24; `endpoint maxLength 2048` ×1; `image maxLength 512` ×2; `deliveryProfiles maxLength 64` ×1; `activities maxLength 128` ×2; `coverage_gaps maxLength 128` ×4; `etag maxLength 1024` ×1; `logout_token maxLength 32768` ×1; `material maxLength 44` ×1; `material minLength 44` ×1; `browserAudience maxLength 128` ×1; `hostname maxLength 2048` ×1 | SKIP (identifier/format; KEEP(b)) | Identifier/token/format lengths fixed by an external format or a bounded opaque token: base64url-32-byte CSRF/state (43), UUID (36), SHA-256 hex (64), DNS label/K8s label value/region (63), IANA port name (15), DNS subdomain / K8s object name or label-key (253), NAME_MAX (255), PATH_MAX (4096), OIDC subject (≤255 per OIDC Core), URL/issuer/return_to/Location/Origin (2048), OAuth code (4096), RFC 3339 date-time (35)/timestamps (32), Idempotency-Key header 16..128, ETag/If-*/Range headers 128, opaque server cursors/handles/SSE ids, machine-readable codes/enums (32–80), duration strings (16), resourceVersion (256), K8s/ref names (63). Inconsistencies to fix when touched: the same action ID is 63, 64 or 128 depending on file (use 63, DNS label); CSRF token is exactly 43 in browser-auth but maxLength 256 on every X-CSRF-Token header/Session.csrf_token (use 43); client IDs 128 vs 256 (use 255, OIDC/Keycloak); Keycloak `hostname` 2048 should be 253 (DNS). | 58 files (all browser/MCP copies plus most contracts) |

## Structural bounds (array size equals a closed enum/state machine/protocol shape; no limiting effect)

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| S1 | `dataClasses maxItems 3` ×3; `data_classes maxItems 3` ×4; `evidenceTypes maxItems 5` ×1; `evidenceTypes maxItems 10` ×1; `formats maxItems 5` ×1; `include maxItems 5` ×2; `include maxItems 8` ×1; `execution_modes maxItems 2` ×4; `action_kinds maxItems 2` ×1; `action_kinds maxItems 16` ×1; `allowedActions maxItems 14` ×1; `handlingCodes maxItems 6` ×4; `handlingCodes minItems 6` ×4; `gapReasons maxItems 11` ×1; `gaps maxItems 7` ×1; `detectedRuntimes maxItems 10` ×1; `effects maxItems 10` ×2; `effectiveRetention maxItems 1` ×1; `dependsOn maxItems 0` ×2; `argumentPrograms maxItems 1` ×1; `dependencies maxItems 2` ×2; `dependencies minItems 2` ×2; `headers maxItems 2` ×2; `detectors minItems 2` ×1; `maxSegments minimum 2` ×2; `arguments maxItems 6` ×1; `expected_revision maximum 3` ×4; `fraction maximum 1` ×4 | KEEP(b) | `maxItems` equals (or exceeds) the cardinality of a closed enum with `uniqueItems`, a then-branch shape, or a fixed protocol arity: Linux syscalls have ≤ 6 arguments; a sequence needs ≥ 2 detectors; a ring needs ≥ 2 segments to rotate; a grant has ≤ 3 revisions (requested→decided→revoked); recording-save dependencies are an exact pair. Not a product limit. `action_kinds maxItems 16` over a 14-value enum and `fields 32` over the 16-value pcap_query enum are dead weight but harmless. | action×5, capture-assessment×5, impl/capture-assessment×5, mcp-tools.json×4, impl/browser-openapi.yaml×4, impl/mcp-tools.json×4, di/browser-openapi.yaml×4, download-environment×2, trigger×2, capture-history×2, recording-save×2, impl/recording-save×2, event×1, share×1, retention-policy×1, policy-authority×1, action-lifecycle×1, log-record×1, profile×1, collection-scope×1, recorder-preview×1, live-watch×1, impl/live-watch×1, packet-capture×1, impl/packet-capture×1, syscall-results×1 |
| S2 | `exitCodes maximum 255` ×1; `exit_codes maximum 255` ×4; `errno maximum 4095` ×2; `hostPID maximum 4194304` ×2; `display_pid maximum 4194304` ×1; `mask maximum 511` ×4; `bytes maximum 65535` ×2 | KEEP(b) | Kernel/protocol value ranges: exit status 0–255; errno ≤ MAX_ERRNO 4095; PID ≤ PID_MAX_LIMIT 4194304; TCP flag mask 9 bits (511); pcap snaplen / IPv4 total length 65535 (libpcap's own default is 262144, but the hub compiles with snaplen 65535 per specs/packets.md). | mcp-tools.json×2, impl/browser-openapi.yaml×2, impl/mcp-tools.json×2, di/browser-openapi.yaml×2, trigger×1, live-watch×1, impl/live-watch×1, action×1, manifest×1, guidance×1, packet-capture×1, impl/packet-capture×1 |
| S3 | `available maximum 9007199254740991` ×2; `baseline maximum 9007199254740991` ×4; `charged_bytes maximum 9007199254740991` ×2; `committed maximum 9007199254740991` ×2; `copyGeneration maximum 9007199254740991` ×2; `count maximum 9007199254740991` ×1; `deliveryFence maximum 9007199254740991` ×2; `delta maximum 9007199254740991` ×4; `dropped_events maximum 9007199254740991` ×2; `dropped_packets maximum 9007199254740991` ×1; `errors maximum 9007199254740991` ×1; `faults maximum 9007199254740991` ×1; `filtered maximum 9007199254740991` ×1; `incident maximum 9007199254740991` ×4; `limit maximum 9007199254740991` ×2; `lost_samples maximum 9007199254740991` ×1; `lower maximum 9007199254740991` ×2; `malformed maximum 9007199254740991` ×1; `expected_revision maximum 9007199254740991` ×4; `duration_ns maximum 9007199254740991` ×2; `delivered_bytes maximum 9223372036854775807` ×1; `delivered_rows maximum 9223372036854775807` ×1; `dropped_rows maximum 9223372036854775807` ×1; `lost_events maximum 9223372036854775807` ×1; `activeVersion maximum 2147483647` ×1; `captured maximum 2147483647` ×4; `count maximum 2147483647` ×4; `executions_spent maximum 2147483647` ×4 | KEEP(b) | Integer-width bounds: 2^53−1 (JS safe integer, browser/MCP JSON), 2^63−1 (int64 internal metrics), 2^31−1 (SQL `integer`/int32 counters), 2^32−1 PostgreSQL OID. These are the replacement for every arbitrary decimal ceiling below. | impl/browser-openapi.yaml×12, di/browser-openapi.yaml×12, mcp-tools.json×6, impl/mcp-tools.json×6, syscall-results×6, syscall-arguments×4, impl/live-capacity×4, impl/internal-work×3, internal-work×1, guidance×1, capture-assessment×1, impl/capture-assessment×1, local-key-secret×1 |

## Obsolete machinery still present as current contracts

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| O1 | `attemptID maxLength 36` ×1; `auditDigest maxLength 64` ×1; `authorityDigest maxLength 64` ×1; `budgetDigest maxLength 64` ×1; `captureID maxLength 36` ×1; `clusterID maxLength 36` ×3; `collectorEpoch maxLength 36` ×1; `committedAt maxLength 32` ×1; `executorAccountUID maxLength 36` ×1; `executorPodUID maxLength 36` ×1; `issuerEpoch maxLength 36` ×3; `installationID maxLength 36` ×1; `id maxLength 36` ×1; `databaseOID maximum 4294967295` ×1; `databaseSchemaVersion maximum 1000000` ×1; `databaseStart maxLength 32` ×1; `authorityRootID maxLength 36` ×1; `controlNamespaceUID maxLength 64` ×1; `keys maxItems 32` ×1; `keys maxItems 8` ×1 | REMOVE | Whole schema files describe removed machinery and are referenced by no spec/architecture doc: local-start (CapacityReservation CRD per attempt, ADR-330 D8), installation-witness (installer witness, ADR-330 D13), retention-topology (topology pins, ADR-330 D12), work-trust (signed JWS work envelopes, ADR-330 D2), submission-trust (hub-signed submissions, ADR-330 D10), small-services-preparation / small-openbao (installer-era preparation plan, ADR-330 D13, ADR-335 D11 setup Job). Delete the files; their limits disappear with them. | local-start×11, installation-witness×6, retention-topology×3, work-trust×3, submission-trust×1 |
| O2 | `groups maxItems 256` ×1; `eligibleGroups maxItems 256` ×1; `eligibleSubjects maxItems 256` ×1; `maxClusters maximum 1024` ×1; `maxActiveBootstraps maximum 128` ×1; `maxBootstrapHistory maximum 65536` ×1; `deliveryProfiles maxItems 16` ×1 | REMOVE | ADR-335 D14 collapses `fleet.groups`, eligibility lists and parallel lists into AccessBindings; ADR-335 D3/ADR-332 removes connector counts/bootstrap slots. fleet-settings `groups`/`maxClusters`/`maxActiveBootstraps`/`maxBootstrapHistory`/`deliveryProfiles`, identity-settings `eligibleGroups`/`eligibleSubjects` are obsolete; if any survive, a ConfigMap (1 MiB) bounds them. | fleet-settings×5, identity-settings×2 |
| O3 | `groupMaxAgeSeconds maximum 300` ×1 | REMOVE | `groupMaxAgeSeconds ≤ 300`: group freshness is the standard OIDC `groups` claim refreshed with the token (ADR-330 D3/D11, ADR-335 D4); authority reuse is ADR-311's 30 s. No separate group-age knob or ceiling. | identity-settings×1 |
| O4 | `deletionBudgetSeconds maximum 86400` ×5 | REMOVE | `deletionBudgetSeconds ≤ 86400`: ADR-330 D12 — each artifact stores its deletion deadline and deletion runs from it; a separate per-artifact deletion budget (and `deleteBy = expiresAt + deletionBudget`) is retention-proof machinery. Document the deletion lag instead. | capture-assessment×1, collection-scope×1, privacy-common×1, retention-policy×1, impl/capture-assessment×1 |
| O5 | `clusterAcknowledgements maxItems 1024` ×1 | REMOVE | retention-policy `status.clusterAcknowledgements ≤ 1024`: per-cluster acknowledgement/watermark status is removed by ADR-330 D12 (one SQL update per policy event). | retention-policy×1 |
| O6 | `assignmentIDs maxItems 32` ×1 | REMOVE | `assignmentIDs ≤ 32` (management) – ADR-330 D11 removes assignment-ID continuity; audiences are group IDs/subjects. | management×1 |
| O7 | `guardRef maxLength 256` ×1 | REMOVE | permission-common `guardRef` — installer guard reference (ADR-330 D13 "no guard qualification"). | permission-common×1 |

## Pagination: page sizes with a cursor

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| P1 | `AuditPage maxItems 100` ×2; `CapabilityPage maxItems 100` ×2; `CapacityPage maxItems 100` ×2; `ClusterPage maxItems 100` ×2; `DeletionPage maxItems 100` ×2; `(def) maximum 100` ×2; `limit maximum 100` ×82; `cases maxItems 100` ×8; `diagnostics maxItems 100` ×4; `intents maxItems 100` ×4; `events maxItems 100` ×6; `entries maxItems 100` ×1; `history maxItems 100` ×1; `flows maxItems 100` ×1 | KEEP(a) | Per-request page size with cursor continuation (PageInput / `cursor` / `after` / `next_cursor`); response memory and SQL work grow with page size. 100 is the convention; keep. | impl/browser-openapi.yaml×32, di/browser-openapi.yaml×32, mcp-tools.json×25, impl/mcp-tools.json×25, syscall-results×2, log-results×1, capture-history×1, guidance×1 |
| P2 | `deltas maxItems 4096` ×4 | KEEP(a) | `deltas ≤ 4096` per preview_access_change page: description says result "bounded to 256 KiB and delivered in pages: repeat with next_cursor". Page bound with continuation — keep, but derive the count from the 256 KiB page budget rather than a separate 4096. | mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |
| P3 | `lines maxItems 200` ×4; `length maximum 16384` ×4; `bytes_returned maximum 16384` ×4 | KEEP(a) | Excerpt windows with explicit continuation: get_file_excerpt returns ≤ 200 lines from `line_start`; read_memory returns ≤ 16 KiB from a caller-chosen address. Per-request bound with offset paging. | mcp-tools.json×3, impl/browser-openapi.yaml×3, impl/mcp-tools.json×3, di/browser-openapi.yaml×3 |
| P4 | `candidates maxItems 12` ×1; `limit maximum 12` ×6 | KEEP(a) | processing-discovery `candidates ≤ 12` / search `limit ≤ 12` (default 12) — paginated (CaseCursor/WorkloadCursor). Keep as page size; consider aligning to 100. | processing-discovery×3, mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |
| P5 | `limit maximum 3` ×7 | RAISE | processing-report `Query.limit ≤ 3` (default 3): a page of 3 rows with "continue with the returned exact query" makes privacy operators page dozens of times for an inventory export. Page size is fine as a concept; raise to the 100 convention (derive from the response byte budget). | processing-report×7 |
| P6 | `artifacts maxItems 100` ×8 | KEEP(a) | `artifacts ≤ 100` in list_artifacts/find_similar_cases (cursor) — page size. The get_case copy has no cursor input: there it must either drop the embedded list (point to list_artifacts) or accept a cursor. | mcp-tools.json×2, impl/browser-openapi.yaml×2, impl/mcp-tools.json×2, di/browser-openapi.yaml×2 |
| P7 | `conversations maxItems 100` ×4 | KEEP(a) | get_pcap_summary `conversations` = top-100 aggregates with `conversations_truncated`; a summary is a deliberate top-N projection, full data is available through pcap_query / native download. | mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |
| P8 | `approvals maxItems 100` ×4; `ReviewPage maxItems 100` ×2 | REMOVE | list_reviews `approvals ≤ 100` and its `limit ≤ 100`: the tool has no `cursor` input (its outputs share the envelope `next_cursor` but it cannot be sent back) — an approver inbox with > 100 pending requests silently loses rows. Add cursor pagination (then the 100 becomes a KEEP(a) page size). `ReviewPage` (browser, maxItems 100) is referenced by no path: delete the dead schema. | impl/browser-openapi.yaml×2, di/browser-openapi.yaml×2, mcp-tools.json×1, impl/mcp-tools.json×1 |
| P9 | `assignments maxItems 32` ×5; `assignments_total maximum 256` ×4 | REMOVE | explain_access `assignments ≤ 32` with `assignments_total ≤ 256`: no cursor; a user with more contributing assignments gets a truncated explanation and >256 cannot even be counted. Paginate or return all (bounded by the AccessBinding objects themselves). | mcp-tools.json×2, impl/browser-openapi.yaml×2, impl/mcp-tools.json×2, di/browser-openapi.yaml×2, permission-common×1 |
| P10 | `affected maximum 10000` ×4; `affected_total maximum 10000` ×4; `artifacts_scanned maximum 10000` ×4; `deletion_due maximum 10000` ×4; `deletion_due_total maximum 10000` ×4; `groups maxItems 32` ×4; `groups_total maximum 20000` ×4; `incomplete_clusters maxItems 32` ×4; `incomplete_total maximum 20000` ×4 | REMOVE | preview_retention_change scans "at most 10,000 retained artifacts" and returns ≤ 32 groups / ≤ 32 incomplete clusters with totals capped at 10,000/20,000. Under ADR-330 D12 the deadlines are SQL columns, so the preview is one `GROUP BY` aggregate over all affected rows; paginate the groups. No 10,000-artifact ceiling (an installation with more evidence gets an incomplete preview). | mcp-tools.json×9, impl/browser-openapi.yaml×9, impl/mcp-tools.json×9, di/browser-openapi.yaml×9 |
| P11 | `before_basis maxItems 8` ×4; `after_basis maxItems 8` ×4 | REMOVE | preview_access_change `before_basis`/`after_basis ≤ 8` per delta: truncates the explanation inside an already paginated response; the 256 KiB page budget (P2) bounds it. | mcp-tools.json×2, impl/browser-openapi.yaml×2, impl/mcp-tools.json×2, di/browser-openapi.yaml×2 |
| P12 | `conversations_total maximum 16384` ×4 | REMOVE | get_pcap_summary `conversations_total ≤ 16384`: a count field cannot exceed 16384, i.e. the aggregation silently stops; count with 2^53−1 and bound aggregation memory by the summary's top-N (P7). | mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |
| P13 | `blockers maxItems 16` ×13; `blockers maxItems 32` ×8; `blocker_codes maxItems 16` ×2; `limitations maxItems 16` ×6; `coverage_gaps maxItems 32` ×4; `gaps maxItems 32` ×4; `gaps maxItems 16` ×2; `alternatives maxItems 8` ×2; `interactions maxItems 16` ×2; `combinedQuantities maxItems 16` ×2; `conditions maxItems 32` ×6; `conditions maxItems 16` ×2; `impact_codes maxItems 32` ×2; `answers maxItems 8` ×1; `evidence_kinds maxItems 16` ×1; `frames maxItems 128` ×4; `columns maxItems 16` ×4; `changes maxItems 100` ×2; `actionIDs maxItems 16` ×4; `buildIDs maxItems 128` ×1; `build_ids maxItems 16` ×1 | REMOVE | Server-generated output lists without pagination: blockers, limitations, coverage gaps, alternatives/interactions/combined quantities, conditions, impact codes, answers, evidence kinds, backtrace frames, debugger columns, ConfigurationPreview `changes`, live-watch batch gaps. The server controls these; a cap only risks rejecting its own valid output or truncating it. Bound by the response byte budget/page; for backtrace frames (deep stacks > 128 are common in Java/Go) add frame paging. | impl/browser-openapi.yaml×14, di/browser-openapi.yaml×14, mcp-tools.json×8, impl/mcp-tools.json×8, guidance×7, capture-assessment×5, impl/capture-assessment×5, recording-save×2, impl/recording-save×2, live-watch×2, impl/live-watch×2, manifest×2, syscall-results×2 |
| P14 | `index maximum 10000` ×4; `frame maximum 10000` ×4 | REMOVE | Frame `index ≤ 10000` (output) and debugger_command `frame ≤ 10000` (input): arbitrary; a recursion-heavy core can have deeper stacks. Use 2^31−1. | mcp-tools.json×2, impl/browser-openapi.yaml×2, impl/mcp-tools.json×2, di/browser-openapi.yaml×2 |

## Request/selection list caps (input lists; no pagination possible)

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| L1 | `artifact_digests maxItems 64` ×4; `artifacts maxItems 64` ×10; `maxArtifacts maximum 64` ×2; `artifactsRegistered maximum 64` ×1; `grantIDs maxItems 64` ×1; `artifactIDs maxItems 64` ×1; `max_artifacts maximum 64` ×8; `artifact_count maximum 64` ×8; `artifacts_used maximum 64` ×8; `actionIds maxItems 64` ×2; `action_ids maxItems 16` ×8 | REMOVE | Raw-access / grant / share artifact selection capped at 64 (request_raw_access `artifact_digests`, Grant/Share CRD `artifacts`, investigation-access `maxArtifacts`/`artifactsRegistered`/`grantIDs`, event `artifactIDs`, result-access `max_artifacts`/`artifact_count`/`artifacts_used`). The maintainer requirement is a *finite* disclosure pool and one bounded approval, which the explicit selection plus byte budget already gives; 64 has no derivation. A capture with > 64 artifacts (multi-pod, segmented rings) needs several approvals. Replace with the K8s object size (1.5 MiB ≈ thousands of 64-char digests) for CRDs and the HTTP request size for MCP/browser input. | mcp-tools.json×11, impl/browser-openapi.yaml×11, impl/mcp-tools.json×11, di/browser-openapi.yaml×11, investigation-access×6, grant×1, share×1, event×1 |
| L2 | `clientIDs maxItems 8` ×2; `client_ids maxItems 4` ×8; `clients maxItems 64` ×4 | REMOVE | Client selections: investigation-access `clientIDs ≤ 8`, result-access `client_ids ≤ 4`, download-environment/fleet `clients ≤ 64`. No resource cost; the set of OAuth clients is administrator-configured. Bounded by the ConfigMap/row it lives in. | investigation-access×2, mcp-tools.json×2, impl/browser-openapi.yaml×2, impl/mcp-tools.json×2, di/browser-openapi.yaml×2, download-environment×2, fleet-settings×1, identity-settings×1 |
| L3 | `managed_by maxItems 8` ×8 | REMOVE | Share managers `managed_by ≤ 8`: "multiple owner teams may manage shares" (maintainer); no resource reason. Bounded by the CRD/row size. (Recipient caps 8/32 are audited separately.) | mcp-tools.json×2, impl/browser-openapi.yaml×2, impl/mcp-tools.json×2, di/browser-openapi.yaml×2 |
| L4 | `actions maxItems 16` ×16; `dependsOn maxItems 16` ×14; `dependencies maxItems 64` ×1; `action_windows maxItems 16` ×2; `detectors maxItems 16` ×4; `all maxItems 16` ×3; `any maxItems 16` ×1; `endpointBindings maxItems 16` ×1; `buildIDs maxItems 16` ×1; `environmentNames maxItems 16` ×1; `argv maxItems 64` ×1; `exitCodes maxItems 16` ×1; `exit_codes maxItems 16` ×4; `clusterIDs maxItems 100` ×1; `excludedNamespaces maxItems 64` ×1; `(def) maxItems 8` ×1; `actionMap maxItems 128` ×1; `editableFields maxItems 32` ×1; `effectiveRetention maxItems 16` ×1; `filters maxItems 16` ×1 | REMOVE | Spec-authored lists inside Kubernetes objects (Recipe/Capture/Policy/Trigger/CaptureProfile/PermissionSource/RetentionPolicy CRDs): actions per plan, `dependsOn`, collection-scope `dependencies`, action windows, policy detectors, trigger `all`/`any` width, endpoint bindings, process-selector build IDs, env names, argv entries, exit codes, retention `clusterIDs`, permission-source `excludedNamespaces`, capture-composition components/actionMap/editableFields, resolved effectiveRetention, recorder filters, live display-filter `all`. ADR-335 D8: policies are bounded by Kubernetes object limits; the same reasoning applies to their contents. "Finite typed edits" for capture profiles means a closed set of typed fields, not a count. Replace with the etcd 1.5 MiB object limit (and the BPF instruction limit for filters, see F3). | action×17, mcp-tools.json×4, impl/browser-openapi.yaml×4, impl/mcp-tools.json×4, di/browser-openapi.yaml×4, trigger×4, collection-scope×3, recipe×2, policy×2, capture-composition×2, action-lifecycle×1, capture-assessment×1, impl/capture-assessment×1, recording-save×1, impl/recording-save×1, live-watch×1, impl/live-watch×1, retention-policy×1, permission-source×1, capture-profile×1, recorder-preview×1 |
| L5 | `labels maxProperties 16` ×1; `annotations maxProperties 16` ×1; `annotations maxLength 1024` ×1; `binding maxProperties 32` ×1; `canonicalScope maxProperties 64` ×1 | REMOVE | Kubernetes metadata maps in the illustrative Namespace and manifest provenance: `labels ≤ 16`, `annotations ≤ 16` (values ≤ 1024), manifest `binding ≤ 32`/`canonicalScope ≤ 64` properties. Kubernetes has no label-count limit; annotations are limited to 256 KiB total (KEEP(b) at that value); manifest maps are bounded by the manifest byte bound (F7). | namespace-permission-example×3, manifest×2 |
| L6 | `discovery_capture_ids maxItems 4` ×4; `flow_refs maxItems 16` ×4; `changes maxItems 16` ×8; `fields maxItems 32` ×16; `artifact_ids maxItems 100` ×2; `(def) maxItems 16` ×3 | REMOVE | Tool inputs: recommend_diagnostics `discovery_capture_ids ≤ 4`, `flow_refs ≤ 16`; preview tools `changes ≤ 16`; get_zeek_log `fields ≤ 32`; browser `PrivacyInput.artifact_ids ≤ 100`; `/api/v1/events` `capture_id/download_id/grant_id ≤ 16` each. No cost grows meaningfully; the request/URL size bounds them (8 KiB URL ≈ 200 UUIDs). | di/browser-openapi.yaml×12, impl/browser-openapi.yaml×9, mcp-tools.json×8, impl/mcp-tools.json×8 |
| L7 | `activities maxItems 8` ×2 | REMOVE | download-environment / processing-report `activities ≤ 8` (operator-declared processing organization activities): no reason; ConfigMap/report row bounds it. | download-environment×1, processing-report×1 |
| L8 | `acrValues maxItems 8` ×1 | REMOVE | identity-settings step-up `acrValues ≤ 8`: step-up is optional/off by default (ADR-335 D5); no cost. ConfigMap bounds it. | identity-settings×1 |
| L9 | `keys maxItems 16` ×1 | REMOVE | local-key-secret `keys ≤ 16`: rotations retain old versions (ADR-067); a 17th rotation would be refused. The Secret's 1 MiB limit bounds it (each entry < 200 B). | local-key-secret×1 |
| L10 | `ceilings maxItems 128` ×1 | REMOVE | download-environment `liveRead.ceilings ≤ 128` entries: admin policy list in a ConfigMap; ConfigMap size bounds it. | download-environment×1 |

## Free-text lengths

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| T1 | `explanation maxLength 256` ×2; `explanation maxLength 1024` ×1; `benefit maxLength 192` ×2; `coverageLoss maxLength 192` ×2; `coverage maxLength 256` ×2; `limitations maxLength 256` ×2; `limitations maxLength 512` ×4; `gaps maxLength 256` ×4; `answers maxLength 256` ×1; `handling_notice maxLength 1024` ×1; `coverage_notice maxLength 1024` ×1; `description maxLength 512` ×9 | REMOVE | Server-written explanatory text in outputs (explanations, benefits, coverage notes, limitations, gap texts, handling/coverage notices, diagnostic/profile descriptions): the server controls the text; the cap only rejects or truncates its own output. Bound by response size. | guidance×5, capture-assessment×4, impl/capture-assessment×4, mcp-tools.json×3, impl/browser-openapi.yaml×3, impl/mcp-tools.json×3, di/browser-openapi.yaml×3, syscall-results×2, artifact-download×2, manifest×1, capture-profile×1 |
| T2 | `description maxLength 1024` ×2; `displayName maxLength 128` ×1; `display_name maxLength 128` ×8; `label maxLength 128` ×1 | REMOVE | User/admin-authored text stored in Kubernetes objects or SQL (CaptureProfile/Recipe `description`, `displayName`, editable-field `label`, ClusterView/EnrollmentInput/profile `display_name`): ADR-330 D8 small metadata in SQL; K8s object size bounds CRD text. If a cluster display name feeds the generated cluster ID (ADR-335 D4) derive it from DNS-1123 (63/253) instead. | capture-profile×3, impl/browser-openapi.yaml×3, di/browser-openapi.yaml×3, recipe×1, mcp-tools.json×1, impl/mcp-tools.json×1 |
| T3 | `jsonField maxLength 128` ×1; `matchLabels maxLength 256` ×1; `environmentNames maxLength 128` ×1 | REMOVE | Trigger detector free-form fields: `jsonField ≤ 128` (JSON path into log records), alert `matchLabels` values ≤ 256 (Alertmanager labels have no length limit), action `environmentNames` entries ≤ 128 (Linux env names: only MAX_ARG_STRLEN 128 KiB). Bounded by the CRD object size. | trigger×2, action×1 |
| T4 | `function maxLength 512` ×12; `file maxLength 1024` ×4; `lines maxLength 4096` ×4; `argv maxLength 4096` ×1 | RAISE | Evidence-derived strings truncated by arbitrary caps: backtrace `function ≤ 512` (demangled C++/Rust/Go generic symbols routinely exceed 512), frame `file ≤ 1024` (debug-info paths: PATH_MAX 4096), file-excerpt `lines ≤ 4096` per line, action `argv` element ≤ 4096. Derive: file → PATH_MAX 4096 (KEEP(b)); argv element → MAX_ARG_STRLEN 131072; function/lines → no per-string cap, bounded by the response byte budget (truncate with a flag, never reject). | mcp-tools.json×5, impl/browser-openapi.yaml×5, impl/mcp-tools.json×5, di/browser-openapi.yaml×5, action×1 |
| T5 | `manifest_yaml maxLength 65536` ×2 | RAISE | Browser `StageDraftInput.manifest_yaml ≤ 65536`: the staged object is a Kubernetes manifest; derive the bound from the API server limit (1.5 MiB request / etcd object), otherwise valid large AccessBindings/Policies cannot be staged. | impl/browser-openapi.yaml×1, di/browser-openapi.yaml×1 |

## Fixed-size binary/base64 payloads

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| B1 | `data maxLength 5464` ×1; `data minLength 4` ×1; `bytes_base64 maxLength 1368` ×1; `bytes_base64 minLength 4` ×1 | KEEP(a) | Log storage framing: a JSONL fragment carries ≤ 4096 raw bytes (`data` 5464 = base64(4096)) and a log-results entry ≤ 1024 bytes (`bytes_base64` 1368); long lines are split into fragments, not truncated (`fragment`, `line_offset`). The fragment size bounds per-record memory; min 4 = one base64 quantum. Keep. | log-record×2, log-results×2 |
| B2 | `binding maxLength 2732` ×1; `binding minLength 4` ×1; `input maxLength 21848` ×1; `input maxLength 5464` ×1; `input minLength 4` ×2; `ciphertext maxLength 16384` ×1; `ciphertext maxLength 8192` ×1; `ciphertext minLength 4` ×1 | KEEP(b) | Key-service RPC payloads carry fixed-size key material/AEAD outputs: `binding` ≤ 2732 (base64 of 2048 B AAD), `input` ≤ 21848/5464 (base64 of 16 KiB/4 KiB), sealed `ciphertext` ≤ 8192, framed-storage sealed key `ciphertext` ≤ 16384; min 4 = one base64 quantum. Bounded by the wrapped 32-byte keys plus AEAD overhead — generous but derived; fine. (If ADR-335 D11's static-key Secret makes the separate key-service role obsolete, delete local-key-service with it.) | local-key-service×8, framed-storage×1 |

## Artifact format (framed-storage / manifest)

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| F1 | `dataBytes maximum 8454144` ×1; `dataBytes maximum 2164260864` ×1; `frameCount maximum 256` ×1; `frames maxItems 256` ×1; `indexBytes maximum 327680` ×1; `ciphertextBytes maximum 1114112` ×1 | KEEP(a) | Framed-storage frame and page geometry: a frame holds ≤ 8 MiB+64 KiB plaintext (`dataBytes` 8454144), an index page ≤ 256 frames (`frameCount`, `frames`, page `dataBytes` 2164260864, page `indexBytes` 327680), manifest commit ciphertext ≤ 1114112 B. These bound the reader's per-frame/per-page buffer memory (ADR-048); keep as format constants. | framed-storage×6 |
| F2 | `firstFrame maximum 131071` ×1; `dataBytes maximum 1108101562368` ×1; `dataOffset maximum 1108101562368` ×2; `ciphertextBytes maximum 1108101562368` ×1; `indexBytes maximum 167772160` ×1; `indexOffset maximum 167772160` ×1 | REMOVE | Whole-artifact size ceiling ≈ 1 TiB derived only from index addressing (`firstFrame ≤ 131071` = 2^17 frames × 8 MiB, layout `dataBytes`/`dataOffset`/manifest `ciphertextBytes` ≤ 1108101562368, `indexBytes`/`indexOffset` ≤ 160 MiB). No resource reason; the real bound is the administrator's evidence storage/quota (ADR-335 D2). Widen offsets to 2^53−1 (uint64 on disk). Large cores of big JVM/DB processes and long rings can exceed 1 TiB only rarely, but there is no reason to fail them. | framed-storage×6, manifest×1 |

## Arbitrary decimal/byte ceilings on counters and reported values

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| C1 | `after_revision maximum 1000000000` ×8; `expected_revision maximum 1000000000` ×24; `filter_generation maximum 1000000000` ×8; `count maximum 1000000000` ×2; `generation maximum 1000000000` ×1; `line_start maximum 1000000000` ×8; `line maximum 100000000` ×4; `line maximum 67108864` ×2; `lines maximum 67108864` ×2; `line_offset maximum 67108864` ×2; `fragment maximum 67108864` ×1; `fragments maximum 67108864` ×2; `dropped_flows maximum 1000000000000` ×4; `drops maximum 1000000000000` ×4; `incomplete_flows maximum 1000000000000` ×4; `lostSamples maximum 1000000000000` ×1; `duration_ns maximum 1000000000000` ×2; `duration_ms maximum 60000` ×2; `clock_uncertainty_ms maximum 3600000` ×8; `clock_uncertainty_ms maximum 5000` ×6; `active_viewers maximum 65536` ×1; `cohorts maximum 80000` ×1; `expectedRevision maximum 15` ×1 | REMOVE | Reported counters/revisions capped at 1e9/1e12 or 2^26 instead of the integer width: MCP `after_revision`/`expected_revision` 1e9, live-watch `filter_generation`/gap `count` 1e9, sharing-intent `generation` 1e9, excerpt `line_start` 1e9, frame `line` 1e8, log `line`/`lines`/`line_offset`/`fragment(s)` 2^26 (64 Mi lines per artifact), `dropped_flows`/`drops`/`incomplete_flows`/`lostSamples` 1e12, live `duration_ns` 1e12 (rejects any syscall row lasting > 16.7 min) and `duration_ms` 60000 (rejects > 1 min), timeline `clock_uncertainty_ms` 3.6e6 and live `clock_uncertainty_ms` 5000 (a node with > 5 s skew makes rows invalid instead of flagged), live-capacity `active_viewers` 65536 / `cohorts` 80000, processing `expectedRevision ≤ 15` (a restriction rule can be toggled only ~8 times). Replace with 2^53−1 (S3). | mcp-tools.json×18, di/browser-openapi.yaml×18, impl/browser-openapi.yaml×14, impl/mcp-tools.json×14, live-watch×10, impl/live-watch×10, log-record×6, log-results×3, impl/live-capacity×2, sharing-intent×1, profile×1, processing×1 |
| C2 | `generation maximum 2147483647` ×9 | DERIVE | Kubernetes `generation` fields (collection-scope policyRefs, download-environment revision, MCP outputs) capped at 2^31−1: `metadata.generation` is int64 in Kubernetes. Use 2^53−1 (S3). | collection-scope×1, download-environment×1, mcp-tools.json×1, policy-authority×1, privacy-common×1, processing-report×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |
| C3 | `bytes_used maximum 1099511627776` ×8; `bytes_used maximum 274877906944` ×8; `collected_bytes_spent maximum 1099511627776` ×4; `collected_bytes_used maximum 1099511627776` ×12; `bytesReserved maximum 1099511627776` ×1; `bytesSpent maximum 1099511627776` ×1; `emitted_bytes maximum 1099511627776` ×1; `emitted_bytes maximum 1152921504606846976` ×1 | REMOVE | Byte counters/charges capped at 1 TiB or 256 GiB (raw/result access `bytes_used`, policy `collected_bytes_used/spent`, investigation-access `bytesReserved`/`bytesSpent`, artifact-download `emitted_bytes`) and 2^60 (processing-report `emitted_bytes`). A counter is not a limit; use 2^53−1 (S3). The limit itself lives in the configured budget (C4). | mcp-tools.json×8, impl/browser-openapi.yaml×8, impl/mcp-tools.json×8, di/browser-openapi.yaml×8, investigation-access×2, artifact-download×1, processing-report×1 |
| C4 | `maxBytes maximum 1099511627776` ×7; `maxObservedBytes maximum 1099511627776` ×5; `maxTotalBytes maximum 1099511627776` ×2; `bytes maximum 1125899906842624` ×11; `burstBytes maximum 1125899906842624` ×5; `bytesPerSecond maximum 1125899906842624` ×5; `maxSpoolBytes maximum 1125899906842624` ×4; `maxStoredBytes maximum 1125899906842624` ×2; `maxInputBytesPerRollingHour maximum 1125899906842624` ×2; `inputBurstBytes maximum 10737418240` ×4; `inputBytesPerSecond maximum 10737418240` ×4 | REMOVE | Hard-coded ceilings on configurable byte budgets: `maxBytes` (common limits, Grant limits, investigation-access request) 1 TiB, `maxObservedBytes` 1 TiB, recipe/composition `maxTotalBytes` 1 TiB, budget-policy/storage-pool `bytes`/`burstBytes`/`bytesPerSecond`/`maxSpoolBytes`/`maxStoredBytes`/`maxInputBytesPerRollingHour` 1 PiB, `inputBurstBytes`/`inputBytesPerSecond` 10 GiB. The *existence* of an explicit finite budget is a maintainer decision (finite disclosure pool, storm/storage-exhaustion protection, reviewed observation budgets) — KEEP(c) for the field — but the schema ceiling on the administrator's/requester's value has no reason. Use 2^53−1. Note ADR-335 D2: most budget-policy byte figures should stop being operator values at all. | budget-policy×15, impl/budget-policy×15, storage-pool×7, policy-authority×6, grant×2, investigation-access×2, common×1, recorder-preview×1, capture-composition×1, recipe×1 |
| C5 | `maxExecutions maximum 10000` ×4; `executionsReserved maximum 10000` ×1; `executionsSpent maximum 10000` ×1; `executions_used maximum 10000` ×12; `maxOperations maximum 10000` ×2 | REMOVE | Execution/operation counts: Grant `maxExecutions`/status `executionsReserved`/`executionsSpent` ≤ 10000, policy `executions_used` ≤ 10000, policy-authority envelope `maxExecutions`, investigation-access `maxOperations` ≤ 10000 ("fixed 10000-operation ceiling" in request_raw_access). ADR-335 D6: non-intrusive policies have no run count; automatic intrusive grants are bounded by their expiry and the rate limits. ADR-335 D9: downloads have no request-count cap. Replace with expiry + rate limits; drop the field where it only counts. | grant×3, policy-authority×3, mcp-tools.json×3, impl/browser-openapi.yaml×3, impl/mcp-tools.json×3, di/browser-openapi.yaml×3, investigation-access×2 |
| C6 | `maxObservedEvents maximum 1000000000` ×5; `maxEvents maximum 1000000` ×1 | REMOVE | `maxObservedEvents ≤ 1e9` (Grant/policy-authority observation limits) and syscall-trace `maxEvents ≤ 1e6`: syscall argument mode needs a reviewed observation *budget* (maintainer) — keep the configurable value KEEP(c) — but ADR-335 D6 bounds always-on recorders by rate and ring size, not lifetime totals, and the hard-coded ceilings have no derivation. Bound by `maxEventsPerSecond` × duration and the ring. | policy-authority×3, grant×1, recorder-preview×1, syscall-trace×1 |

## Durations, TTLs and lifetimes

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| D1 | `evidenceSeconds maximum 315360000` ×2; `caseMetadataSeconds maximum 315360000` ×2; `auditMetadataSeconds maximum 315360000` ×2; `maxAgeSeconds maximum 315360000` ×1; `accessAgeSeconds maximum 315360000` ×2; `deleteAgeSeconds maximum 315360000` ×2 | REMOVE | Retention values capped at 10 years (`evidenceSeconds`, `caseMetadataSeconds`, `auditMetadataSeconds` defaults+maxima, rule `maxAgeSeconds`, assessment `accessAgeSeconds`/`deleteAgeSeconds`). The administrator-enforced maximum is a maintainer decision (KEEP(c) for the field, defaults 14 d per ADR-335 D7); a hard-coded ceiling on what the administrator may configure has no reason. Use 2^53−1 seconds (or omit `maximum`). | retention-policy×7, capture-assessment×2, impl/capture-assessment×2 |
| D2 | `defaultAgeSeconds maximum 31536000` ×1; `maxAgeSeconds maximum 31536000` ×2; `maxLifetimeSeconds maximum 31536000` ×1; `lifetime_seconds maximum 31536000` ×24 | REMOVE | Policy-grant period ceilings at 1 year: approval-policy `defaultAgeSeconds`/`maxAgeSeconds`, Grant `approvalPolicyRef.maxAgeSeconds`, policy-authority `maxLifetimeSeconds`, MCP `lifetime_seconds` outputs. ADR-335 D6: administrator-configured periods (default 90 days) with renewal in place — keep the admin value KEEP(c); the 1-year cap on it is unexplained. | mcp-tools.json×6, impl/browser-openapi.yaml×6, impl/mcp-tools.json×6, di/browser-openapi.yaml×6, approval-policy×2, grant×1, policy-authority×1 |
| D3 | `lifetime_seconds maximum 28800` ×12 | RAISE | Manual approval window `lifetime_seconds ≤ 28800` (adHocCapture grants). Manual requests must be finite (maintainer) and the approval covers its stated window (ADR-335 D5), but human timescales are minutes to days (D9): an 8-hour ceiling blocks "capture during tomorrow's batch run". Make it an administrator-configured maximum (default e.g. 7 days) instead of a schema constant. | mcp-tools.json×3, impl/browser-openapi.yaml×3, impl/mcp-tools.json×3, di/browser-openapi.yaml×3 |
| D4 | `expires_in_seconds maximum 28800` ×4 | REMOVE | request_raw_access `expires_in_seconds ≤ 28800`: ADR-335 D9 — result handles last as long as the evidence; downloads run to their original bounds. The evidence's access end (retention/AccessUntil) bounds the grant; no 8-hour cap. | mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |
| D5 | `lifetime_seconds minimum 60` ×12; `maxLifetimeSeconds minimum 60` ×2; `maxAgeSeconds minimum 30` ×1 | REMOVE | Floors `lifetime_seconds ≥ 60`, browser `maxLifetimeSeconds ≥ 60`, step-up `maxAgeSeconds ≥ 30`: no stated reason; any positive value works. | mcp-tools.json×3, impl/browser-openapi.yaml×3, impl/mcp-tools.json×3, di/browser-openapi.yaml×3, browser-settings×1, impl/browser-settings×1, identity-settings×1 |
| D6 | `maxLifetimeSeconds maximum 86400` ×2 | REMOVE | Browser session `maxLifetimeSeconds ≤ 86400`: administrator value; ADR-335 D9 (human timescales up to days) and ADR-312 (downloads session-bound) make a 24 h hard ceiling friction. The IdP's SSO session/refresh lifetime bounds it. | browser-settings×1, impl/browser-settings×1 |
| D7 | `maxAgeSeconds maximum 3600` ×1 | REMOVE | Step-up `maxAgeSeconds ≤ 3600`: step-up is optional and off by default (ADR-335 D5); the administrator chooses the auth_time age. No ceiling. | identity-settings×1 |
| D8 | `maxSessionSeconds maximum 3600` ×2; `duration_seconds maximum 3600` ×6; `durationSeconds maximum 3600` ×1 | REMOVE | Live observation durations: Grant/recorder-preview `maxSessionSeconds ≤ 3600`, live-watch `duration_seconds ≤ 3600` (open_live_watch input, live-watch limits), download-environment liveRead `durationSeconds ≤ 3600`. ADR-335 D9: live watches stay open while the client is connected or within a 10-minute idle window — replace the fixed 1 h lifetime by the 10-minute idle timeout (KEEP(c)). | grant×1, recorder-preview×1, live-watch×1, mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/live-watch×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1, download-environment×1 |
| D9 | `available_before_seconds maximum 3600` ×2; `lookbackMillis maximum 3600000` ×2; `history_seconds maximum 3600` ×5 | REMOVE | Ring look-back windows capped at 1 hour: recording-save `available_before_seconds`, internal-work `lookbackMillis`, guidance/recommend_diagnostics `history_seconds`. ADR-335 D6: recorders are bounded by ring sizes; how much history is available is whatever the ring holds. The ring byte size is the bound. | recording-save×1, impl/recording-save×1, internal-work×1, impl/internal-work×1, guidance×1, mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |
| D10 | `duration_seconds maximum 86400` ×16; `durationNanoseconds maximum 86400000000000` ×1 | REMOVE | Profile/capture durations ≤ 1 day (`duration_seconds ≤ 86400` in profile/baseline/incident outputs, profile `durationNanoseconds ≤ 86400e9`): manual requests are finite (maintainer) and post-trigger windows run up to the capture's configured duration (ADR-335 D8); the configured duration/approval window bounds it, not a schema constant. | mcp-tools.json×4, impl/browser-openapi.yaml×4, impl/mcp-tools.json×4, di/browser-openapi.yaml×4, profile×1 |
| D11 | `maxQueueAgeSeconds maximum 300` ×2 | REMOVE | budget-policy `maxQueueAgeSeconds ≤ 300`: queued expensive work is part of storm protection (concurrency limits stay, KEEP(c)), but capping how long an administrator lets work queue at 5 minutes contradicts human timescales (ADR-335 D9). Admin value without ceiling. | budget-policy×1, impl/budget-policy×1 |
| D12 | `maxDecisionAgeSeconds maximum 60` ×1 | KEEP(c) | permission-source `maxDecisionAgeSeconds ≤ 60`: ADR-311 — authority reused ≤ 30 s, ≤ 60 s for the shared policy observation. Keep the 60 s ceiling, but under ADR-330 D1 (informer caches stay valid until invalidated) consider making it a fixed constant rather than a per-source field. | permission-source×1 |
| D13 | `managed_row_max_age_seconds maximum 30` ×1 | KEEP(c) | implemented live-watch `managed_row_max_age_seconds ≤ 30`: live rows are bounded transient data (maintainer: "bounded transient rows/replay"); 30 s matches ADR-311's reuse window. This bounds data age, not a human wait. | impl/live-watch×1 |

## Storm protection, concurrency and rate ceilings

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| R1 | `burst maximum 10` ×3; `maxConcurrentActions maximum 10` ×3; `maxOccurrencesPerHour maximum 1000` ×3 | REMOVE | Policy budgets with hard-coded ceilings: `burst ≤ 10`, `maxConcurrentActions ≤ 10`, `maxOccurrencesPerHour ≤ 1000` (collection-scope/policy). Rate and concurrency limits stay (ADR-335 D8, KEEP(c) for the fields); the ceiling should be the administrator's cluster-size-derived limit (D8: concurrent captures per cluster ≥ 8), not a schema constant. | policy×6, collection-scope×3 |
| R2 | `maxActiveSources maximum 1024` ×4; `maxConcurrentExpensive maximum 100` ×4; `maxQueuedExpensive maximum 100` ×2; `maxQueuedExpensive maximum 1000` ×2; `maxUploadRequestsPerSecond maximum 100000` ×3; `maxStartsPerRollingHour maximum 1000` ×2; `maxProcessesPerEpisode maximum 64` ×2; `maxWorkloadAccounts maximum 10000` ×2; `maxObjects maximum 1000000000` ×2 | REMOVE | Budget-policy/storage-pool concurrency and rate ceilings: `maxActiveSources ≤ 1024`, `maxConcurrentExpensive ≤ 100`, `maxQueuedExpensive ≤ 100/1000`, `maxUploadRequestsPerSecond ≤ 100000`, `maxStartsPerRollingHour ≤ 1000`, `maxProcessesPerEpisode ≤ 64`, `maxWorkloadAccounts ≤ 10000`, `maxObjects ≤ 1e9`. The administrator values are storm protection (KEEP(c)); the ceilings on them have no derivation (D8: defaults from cluster size). | budget-policy×11, impl/budget-policy×11, storage-pool×1 |
| R3 | `maxPods maximum 100` ×3; `maxPods maximum 1000` ×3; `incidentPods maximum 100` ×2; `incidentPodLimit maximum 100` ×2; `incident_pod_cap maximum 16` ×4; `covered_pods maximum 100` ×1; `available_pods maximum 1000` ×4 | REMOVE | Pod-count ceilings: target `maxPods ≤ 100` per occurrence (preset-input, target), observation `maxPods ≤ 1000`, assessment `incidentPods ≤ 100`, recording-save `incidentPodLimit ≤ 100` and `incident_pod_cap ≤ 16` (inconsistent with 100), guidance `covered_pods ≤ 100`, list_targets `available_pods ≤ 1000` (an output count — a Deployment with 1001 Pods breaks the schema). Maintainer: monitor all authorized replicas within administrator ceilings and independently cap per-incident collection — the per-incident cap and the admin ceiling are KEEP(c) values, but these schema constants are neither. | recording-save×3, impl/recording-save×3, preset-input×2, policy×2, target×1, collection-scope×1, capture-assessment×1, impl/capture-assessment×1, guidance×1, mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |
| R4 | `maxProcesses maximum 64` ×1; `maxBytesPerProcess maximum 8589934592` ×1 | REMOVE | Dump batch `maxProcesses ≤ 64`, `maxBytesPerProcess ≤ 8 GiB`: per-incident collection is capped by the administrator budget (`maxProcessesPerEpisode`, byte budget); 8 GiB per process rejects cores of large JVM/database processes outright. Bound by the configured byte budget. | action×2 |
| R5 | `maxConcurrentSessions maximum 1000` ×2; `maxWatches maximum 4096` ×1; `maxWatchesPerPrincipal maximum 4096` ×1; `maxWatchesPerWorkload maximum 4096` ×1 | REMOVE | Observation-session ceilings: Grant/recorder-preview `maxConcurrentSessions ≤ 1000`; download-environment `maxWatches`/`maxWatchesPerPrincipal`/`maxWatchesPerWorkload ≤ 4096`. ADR-335 D8: sessions unlimited, bounded by rate limits. | download-environment×3, grant×1, recorder-preview×1 |
| R6 | `maxSessions maximum 100000` ×2; `maxLogins maximum 10000` ×2; `maxLogoutEvents maximum 100000` ×2 | REMOVE | Browser-settings `maxSessions ≤ 100000`, `maxLogins ≤ 10000`, `maxLogoutEvents ≤ 100000`: ADR-335 D8 sessions unlimited (bounded by rate limits); login/logout floods are bounded by the ingress/IdP rate limit. | browser-settings×3, impl/browser-settings×3 |
| R7 | `maxNamespaces maximum 1000` ×1 | REMOVE | permission-source `maxNamespaces ≤ 1000`: no resource reason; the informer holds all namespaces anyway (ADR-330 D1). | permission-source×1 |
| R8 | `atLeast maximum 100000` ×1 | REMOVE | Trigger `count.atLeast ≤ 100000`: a threshold, not a resource; any int works (S3). | trigger×1 |
| R9 | `maxCaptures maximum 100` ×2; `maxArtifactsPerCapture maximum 64` ×3; `materializedArtifacts maximum 6400` ×1 | DERIVE | Sharing-intent bounds `maxCaptures ≤ 100`, `maxArtifactsPerCapture ≤ 64`, `materializedArtifacts ≤ 6400` (=100×64). "Explicitly bounded recurring-policy sharing" is a maintainer decision (KEEP(c) that a bound is stated) and ADR-335 D7 makes recurring sharing run without weekly renewal, until the evidence's retention ends. The bound the user states (or the policy/retention end) is the limit; remove the schema constants and derive `materializedArtifacts` from the stated values. | sharing-intent×3, sharing-request×3 |
| R10 | `bytes_per_second maximum 262144` ×2; `bytesPerSecond maximum 262144` ×1; `bytesPerSecond maximum 268435456` ×1; `burstBytes maximum 1073741824` ×1; `maxBufferBytes maximum 1048576` ×1; `maxOutputBytes maximum 67108864` ×1; `maxRowsPerBatch maximum 100` ×1 | DERIVE | Live-watch per-watch rate `bytes_per_second ≤ 256 KiB/s` (live-watch limits, liveRead ceilings) and liveRead root `bytesPerSecond ≤ 256 MiB/s`, `burstBytes ≤ 1 GiB`, ceilings `maxBufferBytes ≤ 1 MiB`, `maxOutputBytes ≤ 64 MiB`, `maxRowsPerBatch ≤ 100`. Bounded transient live rows are a maintainer decision (KEEP(c) for rate/buffer bounds), but the numbers are unexplained: derive per-watch rate and buffer from the hub-api memory request ÷ expected concurrent watches and the connector link bandwidth; keep a default, drop the schema ceilings. `burstBytes ≥ 24576` is KEEP(a) (must hold one maximal row/page). | download-environment×6, live-watch×1, impl/live-watch×1 |
| R11 | `burstBytes minimum 24576` ×1 | KEEP(a) | liveRead `burstBytes ≥ 24576`: a burst must fit at least one maximal page (24 KiB page charge, request_raw_access description). Derived floor. | download-environment×1 |
| R12 | `maxBytesPerSecond maximum 1073741824` ×2; `maxEventsPerSecond maximum 100000` ×1 | DERIVE | Observation `maxBytesPerSecond ≤ 1 GiB/s` (Grant/recorder-preview) and syscall-trace `maxEventsPerSecond ≤ 100000`: rate limits are KEEP(c) (reviewed observation budgets, storm protection); the ceilings should derive from what a collector can sustain (measured per-node event throughput / connector bandwidth), published as the default, not a schema constant. | grant×1, recorder-preview×1, syscall-trace×1 |

## Packet / syscall / profile mechanism bounds

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| F3 | `filter_instructions maximum 256` ×8 | RAISE | Compiled filter `filter_instructions ≤ 256` (specs/packets.md "256 compiled instructions"): classic BPF's own limit is BPF_MAXINSNS 4096 and CIDR peers are compiled into the same program — 128 CIDRs alone exceed 256 instructions, so the peer caps (F4) are unreachable. Raise to 4096 (KEEP(b)). | mcp-tools.json×2, impl/browser-openapi.yaml×2, impl/mcp-tools.json×2, di/browser-openapi.yaml×2 |
| F4 | `entries maxItems 16` ×2; `cidrs maxItems 128` ×2 | REMOVE | Peer query caps: `entries ≤ 16`, `cidrs ≤ 128` per entry. Peers are compiled into the BPF program (CIDRs) or an eBPF map (dynamic members); the real bounds are the instruction limit (F3) and the map capacity (F5). Reject at compile time with the actual limit instead of separate count caps. | packet-capture×2, impl/packet-capture×2 |
| F5 | `maxEndpoints maximum 4096` ×2 | DERIVE | Dynamic peer `maxEndpoints ≤ 4096` ("map capacity", specs/packets.md): reason exists (eBPF map memory), number arbitrary. Derive from the map's memory budget (entry ≈ 24–40 B; 64 Ki entries ≈ 2.5 MiB) or the collector memory request; Services with > 4096 endpoints exist in large clusters. | packet-capture×1, impl/packet-capture×1 |
| F6 | `filter maxLength 4096` ×10; `expression maxLength 4096` ×1 | KEEP(c) | `filter ≤ 4096` bytes (packet-capture, MCP action outputs) and recorder-preview filter `expression ≤ 4096`: "bounded pcap filters" is a maintainer decision; 4096 also equals PATH_MAX-scale text and is screened before libpcap. | mcp-tools.json×2, impl/browser-openapi.yaml×2, impl/mcp-tools.json×2, di/browser-openapi.yaml×2, packet-capture×1, impl/packet-capture×1, recorder-preview×1 |
| F7 | `maxHeaderBytes maximum 32768` ×2; `maxReassemblyBytesPerFlow maximum 262144` ×2; `maxReassemblyBytes maximum 16777216` ×2; `maxFlows maximum 1024` ×2 | DERIVE | HTTP-header extraction: `maxHeaderBytes ≤ 32 KiB`, `maxReassemblyBytesPerFlow ≤ 256 KiB`, `maxReassemblyBytes ≤ 16 MiB`, `maxFlows ≤ 1024`. Reason exists (reassembly memory) but values are unrelated: 16 MiB ÷ 256 KiB = 64 flows, yet maxFlows allows 1024. Derive maxFlows = maxReassemblyBytes ÷ maxReassemblyBytesPerFlow and maxReassemblyBytes from the collector memory request; header bytes ≥ common server limits (8–64 KiB; Go defaults to 1 MiB). | packet-capture×4, impl/packet-capture×4 |
| F8 | `maxBytes maximum 268435456` ×6; `maxFrozenBytes maximum 268435456` ×3; `maxFrozenBytes maximum 4294967296` ×2; `maxRingBytes maximum 4294967296` ×2; `maxConcurrentSnapshots maximum 4` ×3; `maxSegments maximum 64` ×2 | DERIVE | Ring/freeze sizes: packet ring `maxBytes ≤ 256 MiB` (also recording-save source `maxBytes`), `maxFrozenBytes ≤ 256 MiB` (packet/syscall), node `maxFrozenBytes`/`maxRingBytes ≤ 4 GiB`, `maxConcurrentSnapshots ≤ 4`, `maxSegments ≤ 64`. Rings are the maintainer's chosen bound (ADR-335 D6, segmented rings), so their size must exist, but the constants are not derived: ring and frozen bytes should derive from the node collector's memory/scratch allocation (node `maxRingBytes`), snapshots = node maxFrozenBytes ÷ ring maxBytes, segments = ring bytes ÷ minimum segment size. | packet-capture×4, impl/packet-capture×4, recording-save×2, impl/recording-save×2, syscall-trace×2, budget-policy×2, impl/budget-policy×2 |
| F9 | `maxBytesPerEvent maximum 4096` ×2 | KEEP(b) | syscall argument `maxBytesPerEvent ≤ 4096` (recorder-preview, syscall-trace): equals PATH_MAX and the practical per-event eBPF copy size (ring-buffer record/stack constraints); reviewed observation budget for argument mode (maintainer). | recorder-preview×1, syscall-trace×1 |
| F10 | `maxTrackedThreads maximum 16384` ×1 | DERIVE | syscall-trace `maxTrackedThreads ≤ 16384`: eBPF map sizing (memory per tracked thread); derive from map memory budget — a single JVM Pod can exceed 16 Ki threads rarely, PID_MAX_LIMIT is 4194304. | syscall-trace×1 |
| F11 | `frequencyHz maximum 999` ×1 | DERIVE | Profile `frequencyHz ≤ 999`: the real bound is the node's `kernel.perf_event_max_sample_rate` (default 100000, auto-lowered by the kernel); report the node value instead of a constant. 999 is a habit (avoid lockstep with 1000 Hz timers), not a limit. | action×1 |
| F12 | `maxDepth maximum 32` ×1 | REMOVE | process-selector `maxDepth ≤ 32`: walking a process ancestry is O(depth) and bounded by the process tree itself; no reason. | action×1 |
| F13 | `length maximum 64` ×4 | RAISE | pcap_query `frame_prefix.length ≤ 64` bytes: an IPv6 + TCP-options header is up to 14+40+60 = 114 bytes, so 64 cuts headers. Derive from the per-page budget (24 KiB) or allow up to the snaplen for approved raw queries. | mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |
| F14 | `burst_factor maximum 8` ×1 | REMOVE | Guidance ring sizing `burst_factor ≤ 8`: an advisory multiplier in a recommendation output; no cost. | guidance×1 |
| F15 | `headers maxItems 32` ×4 | REMOVE | get_http_headers record `headers ≤ 32`: approved header fields per record are already bounded by `maxHeaderBytes` (F7); the count cap silently drops fields. | mcp-tools.json×1, impl/browser-openapi.yaml×1, impl/mcp-tools.json×1, di/browser-openapi.yaml×1 |

## Remaining selector / log-detector bounds

| id | groups covered (property keyword value ×occ) | verdict | justification / replacement | files |
|---|---|---|---|---|
| M1 | `matchLabels maxProperties 16` ×9 | REMOVE | `matchLabels ≤ 16` properties (budget-policy namespaceSelector, packet podSelector, permission-common selector, trigger): Kubernetes LabelSelector has no entry-count limit; the CRD object size bounds it. | retention-policy×2, budget-policy×1, packet-capture×1, permission-common×1, target×1, trigger×1, impl/budget-policy×1, impl/packet-capture×1 |
| M2 | `complete_origins maximum 128` ×1; `gapped_origins maximum 128` ×1 | REMOVE | log-results page coverage counters `complete_origins`/`gapped_origins ≤ 128`: counts of origins (containers/Pods) in a page; a workload with > 128 Pods makes the page invalid. Use 2^53−1 (S3). | log-results×2 |
| M3 | `maxRecordBytes maximum 65536` ×1 | DERIVE | Log detector `maxRecordBytes ≤ 65536`: reason exists (per-stream buffer memory in the detector) but the ceiling is arbitrary. Derive from the connector memory request ÷ followed streams; CRI already splits lines into 16 KiB partial records, so the default can stay 64 KiB as long as the admin may raise it. | trigger×1 |


## Duplication between browser-openapi, mcp-tools and the implemented/ copies

- Every MCP tool limit exists **four times**: `specs/contracts/mcp-tools.json` (988 limit keywords), `specs/contracts/implemented/mcp-tools.json` (972), and as `McpInput_*`/`McpOutput_*` component copies inside `docs/interfaces/browser-openapi.yaml` (1,873 of its 2,145 limits) and `specs/contracts/implemented/browser-openapi.yaml` (1,786 of 2,055). Nearly all `×4`/`×8` occurrence counts in the tables above are this duplication, not distinct limits. Recommendation: generate the browser `Mcp*` components from mcp-tools.json so each limit is fixed once.
- Value drift spec vs implemented at the snapshot: `revision maximum` (1e9 vs 3) in MCP outputs, `provenance maxItems` (2 vs 0), and `read_live_watch.wait_ms maximum` 30000 (spec, ADR-330 D1) vs **5000 in implemented/** — the code still waits only 5 s, which is the I/O-timeout value ADR-330 D5 reserves, not the 30 s status wait (part01 owns `wait_ms`; flagged here because it is a spec/implemented divergence).
- Spec-only vs implemented-only paths: mcp-tools 18 spec-only / 2 impl-only; browser-openapi 114 / 24; budget-policy 10 / 6; live-watch 8 / 6; internal-work 0 / 4; browser-settings 0 / 2; `implemented/live-capacity.schema.json` (36 limits) has no spec counterpart. capture-assessment, packet-capture and recording-save copies are value-identical.

## Drift: repository HEAD moved after the extraction

`schema-limits.tsv` was extracted at 10:08; `docs/friction-audit` HEAD `9fce7bf8b` (10:21, "Align contracts, examples and checkers with ADR-335") already changed many of these limits, mostly by rewriting the spec copy and leaving the old value in a new `specs/contracts/implemented/` copy (which describes the current code). Re-extraction at HEAD, for every non-KEEP group above (`old->new` occurrence count):

- **gone** = already removed everywhere; **impl-only** = spec copy fixed, old value now only in `implemented/` (code still enforces it); **partial** = some spec copies still carry it; **unchanged** = still in spec.

### gone 6
filters maxItems 16 [L4] 1->0; executionsReserved maximum 10000 [C5] 1->0; executionsSpent maximum 10000 [C5] 1->0; maxSessionSeconds maximum 3600 [D8] 2->0; maxConcurrentSessions maximum 1000 [R5] 2->0; maxBytesPerSecond maximum 1073741824 [R12] 2->0
### impl-only 73
groups maxItems 256 [O2] 1->1; eligibleGroups maxItems 256 [O2] 1->1; eligibleSubjects maxItems 256 [O2] 1->1; maxClusters maximum 1024 [O2] 1->1; maxActiveBootstraps maximum 128 [O2] 1->1; maxBootstrapHistory maximum 65536 [O2] 1->1; deliveryProfiles maxItems 16 [O2] 1->1; groupMaxAgeSeconds maximum 300 [O3] 1->1; guardRef maxLength 256 [O7] 1->1; blocker_codes maxItems 16 [P13] 2->1; alternatives maxItems 8 [P13] 2->1; interactions maxItems 16 [P13] 2->1; combinedQuantities maxItems 16 [P13] 2->1; actionIDs maxItems 16 [P13] 4->2; clientIDs maxItems 8 [L2] 2->2; client_ids maxItems 4 [L2] 8->4; dependsOn maxItems 16 [L4] 14->14; dependencies maxItems 64 [L4] 1->1; detectors maxItems 16 [L4] 4->4; any maxItems 16 [L4] 1->1; endpointBindings maxItems 16 [L4] 1->1; buildIDs maxItems 16 [L4] 1->1; environmentNames maxItems 16 [L4] 1->1; argv maxItems 64 [L4] 1->1; exitCodes maxItems 16 [L4] 1->1; excludedNamespaces maxItems 64 [L4] 1->1; (def) maxItems 8 [L4] 1->1; actionMap maxItems 128 [L4] 1->1; editableFields maxItems 32 [L4] 1->1; effectiveRetention maxItems 16 [L4] 1->1; acrValues maxItems 8 [L8] 1->1; argv maxLength 4096 [T4] 1->1; lostSamples maximum 1000000000000 [C1] 1->1; active_viewers maximum 65536 [C1] 1->1; cohorts maximum 80000 [C1] 1->1; maxObservedBytes maximum 1099511627776 [C4] 5->3; maxTotalBytes maximum 1099511627776 [C4] 2->2; bytes maximum 1125899906842624 [C4] 11->8; maxSpoolBytes maximum 1125899906842624 [C4] 4->2; maxStoredBytes maximum 1125899906842624 [C4] 2->1; maxInputBytesPerRollingHour maximum 1125899906842624 [C4] 2->1; maxExecutions maximum 10000 [C5] 4->3; maxObservedEvents maximum 1000000000 [C6] 5->3; accessAgeSeconds maximum 315360000 [D1] 2->1; deleteAgeSeconds maximum 315360000 [D1] 2->1; defaultAgeSeconds maximum 31536000 [D2] 1->1; maxAgeSeconds maximum 31536000 [D2] 2->1; maxLifetimeSeconds maximum 31536000 [D2] 1->1; expires_in_seconds maximum 28800 [D4] 4->2; maxLifetimeSeconds minimum 60 [D5] 2->1; maxAgeSeconds minimum 30 [D5] 1->1; maxLifetimeSeconds maximum 86400 [D6] 2->1; maxAgeSeconds maximum 3600 [D7] 1->1; duration_seconds maximum 3600 [D8] 6->3; durationNanoseconds maximum 86400000000000 [D10] 1->1; maxWorkloadAccounts maximum 10000 [R2] 2->1; maxObjects maximum 1000000000 [R2] 2->1; maxPods maximum 100 [R3] 3->3; maxPods maximum 1000 [R3] 3->3; incidentPods maximum 100 [R3] 2->1; maxProcesses maximum 64 [R4] 1->1; maxBytesPerProcess maximum 8589934592 [R4] 1->1; maxSessions maximum 100000 [R6] 2->1; maxLogins maximum 10000 [R6] 2->1; maxLogoutEvents maximum 100000 [R6] 2->1; maxNamespaces maximum 1000 [R7] 1->1; atLeast maximum 100000 [R8] 1->1; maxCaptures maximum 100 [R9] 2->1; entries maxItems 16 [F4] 2->1; cidrs maxItems 128 [F4] 2->1; maxEndpoints maximum 4096 [F5] 2->1; frequencyHz maximum 999 [F11] 1->1; maxDepth maximum 32 [F12] 1->1
### partial 17
deletionBudgetSeconds maximum 86400 [O4] 5->4; blockers maxItems 16 [P13] 13->11; artifacts maxItems 64 [L1] 10->9; max_artifacts maximum 64 [L1] 8->6; artifacts_used maximum 64 [L1] 8->6; action_ids maxItems 16 [L1] 8->6; actions maxItems 16 [L4] 16->13; description maxLength 512 [T1] 9->8; bytes_used maximum 274877906944 [C3] 8->6; collected_bytes_used maximum 1099511627776 [C3] 12->10; executions_used maximum 10000 [C5] 12->10; lifetime_seconds maximum 31536000 [D2] 24->20; lifetime_seconds maximum 28800 [D3] 12->10; lifetime_seconds minimum 60 [D5] 12->10; filter_instructions maximum 256 [F3] 8->6; maxBytes maximum 268435456 [F8] 6->5; matchLabels maxProperties 16 [M1] 9->7
### unchanged 198
attemptID maxLength 36 [O1] 1->1; auditDigest maxLength 64 [O1] 1->1; authorityDigest maxLength 64 [O1] 1->1; budgetDigest maxLength 64 [O1] 1->1; captureID maxLength 36 [O1] 1->1; clusterID maxLength 36 [O1] 3->3; collectorEpoch maxLength 36 [O1] 1->1; committedAt maxLength 32 [O1] 1->1; executorAccountUID maxLength 36 [O1] 1->1; executorPodUID maxLength 36 [O1] 1->1; issuerEpoch maxLength 36 [O1] 3->3; installationID maxLength 36 [O1] 1->1; id maxLength 36 [O1] 1->1; databaseOID maximum 4294967295 [O1] 1->1; databaseSchemaVersion maximum 1000000 [O1] 1->1; databaseStart maxLength 32 [O1] 1->1; authorityRootID maxLength 36 [O1] 1->1; controlNamespaceUID maxLength 64 [O1] 1->1; keys maxItems 32 [O1] 1->1; keys maxItems 8 [O1] 1->1; clusterAcknowledgements maxItems 1024 [O5] 1->1; assignmentIDs maxItems 32 [O6] 1->1; limit maximum 3 [P5] 7->7; approvals maxItems 100 [P8] 4->4; ReviewPage maxItems 100 [P8] 2->2; assignments maxItems 32 [P9] 5->5; assignments_total maximum 256 [P9] 4->4; affected maximum 10000 [P10] 4->4; affected_total maximum 10000 [P10] 4->4; artifacts_scanned maximum 10000 [P10] 4->4; deletion_due maximum 10000 [P10] 4->4; deletion_due_total maximum 10000 [P10] 4->4; groups maxItems 32 [P10] 4->4; groups_total maximum 20000 [P10] 4->4; incomplete_clusters maxItems 32 [P10] 4->4; incomplete_total maximum 20000 [P10] 4->4; before_basis maxItems 8 [P11] 4->4; after_basis maxItems 8 [P11] 4->4; conversations_total maximum 16384 [P12] 4->4; blockers maxItems 32 [P13] 8->8; limitations maxItems 16 [P13] 6->6; coverage_gaps maxItems 32 [P13] 4->4; gaps maxItems 32 [P13] 4->4; gaps maxItems 16 [P13] 2->2; conditions maxItems 32 [P13] 6->6; conditions maxItems 16 [P13] 2->2; impact_codes maxItems 32 [P13] 2->2; answers maxItems 8 [P13] 1->1; evidence_kinds maxItems 16 [P13] 1->1; frames maxItems 128 [P13] 4->4; columns maxItems 16 [P13] 4->4; changes maxItems 100 [P13] 2->2; buildIDs maxItems 128 [P13] 1->1; build_ids maxItems 16 [P13] 1->1; index maximum 10000 [P14] 4->4; frame maximum 10000 [P14] 4->6; artifact_digests maxItems 64 [L1] 4->4; maxArtifacts maximum 64 [L1] 2->4; artifactsRegistered maximum 64 [L1] 1->2; grantIDs maxItems 64 [L1] 1->2; artifactIDs maxItems 64 [L1] 1->1; artifact_count maximum 64 [L1] 8->8; actionIds maxItems 64 [L1] 2->4; clients maxItems 64 [L2] 4->4; managed_by maxItems 8 [L3] 8->8; action_windows maxItems 16 [L4] 2->2; all maxItems 16 [L4] 3->3; exit_codes maxItems 16 [L4] 4->4; clusterIDs maxItems 100 [L4] 1->1; labels maxProperties 16 [L5] 1->1; annotations maxProperties 16 [L5] 1->1; annotations maxLength 1024 [L5] 1->1; binding maxProperties 32 [L5] 1->1; canonicalScope maxProperties 64 [L5] 1->1; discovery_capture_ids maxItems 4 [L6] 4->4; flow_refs maxItems 16 [L6] 4->4; changes maxItems 16 [L6] 8->8; fields maxItems 32 [L6] 16->20; artifact_ids maxItems 100 [L6] 2->2; (def) maxItems 16 [L6] 3->3; activities maxItems 8 [L7] 2->2; keys maxItems 16 [L9] 1->1; ceilings maxItems 128 [L10] 1->1; explanation maxLength 256 [T1] 2->2; explanation maxLength 1024 [T1] 1->1; benefit maxLength 192 [T1] 2->2; coverageLoss maxLength 192 [T1] 2->2; coverage maxLength 256 [T1] 2->2; limitations maxLength 256 [T1] 2->2; limitations maxLength 512 [T1] 4->4; gaps maxLength 256 [T1] 4->4; answers maxLength 256 [T1] 1->1; handling_notice maxLength 1024 [T1] 1->2; coverage_notice maxLength 1024 [T1] 1->2; description maxLength 1024 [T2] 2->4; displayName maxLength 128 [T2] 1->2; display_name maxLength 128 [T2] 8->8; label maxLength 128 [T2] 1->2; jsonField maxLength 128 [T3] 1->2; matchLabels maxLength 256 [T3] 1->2; environmentNames maxLength 128 [T3] 1->2; function maxLength 512 [T4] 12->12; file maxLength 1024 [T4] 4->4; lines maxLength 4096 [T4] 4->4; manifest_yaml maxLength 65536 [T5] 2->2; firstFrame maximum 131071 [F2] 1->1; dataBytes maximum 1108101562368 [F2] 1->1; dataOffset maximum 1108101562368 [F2] 2->2; ciphertextBytes maximum 1108101562368 [F2] 1->1; indexBytes maximum 167772160 [F2] 1->1; indexOffset maximum 167772160 [F2] 1->1; after_revision maximum 1000000000 [C1] 8->10; expected_revision maximum 1000000000 [C1] 24->26; filter_generation maximum 1000000000 [C1] 8->8; count maximum 1000000000 [C1] 2->2; generation maximum 1000000000 [C1] 1->1; line_start maximum 1000000000 [C1] 8->10; line maximum 100000000 [C1] 4->4; line maximum 67108864 [C1] 2->2; lines maximum 67108864 [C1] 2->2; line_offset maximum 67108864 [C1] 2->2; fragment maximum 67108864 [C1] 1->1; fragments maximum 67108864 [C1] 2->2; dropped_flows maximum 1000000000000 [C1] 4->4; drops maximum 1000000000000 [C1] 4->4; incomplete_flows maximum 1000000000000 [C1] 4->4; duration_ns maximum 1000000000000 [C1] 2->2; duration_ms maximum 60000 [C1] 2->2; clock_uncertainty_ms maximum 3600000 [C1] 8->8; clock_uncertainty_ms maximum 5000 [C1] 6->6; expectedRevision maximum 15 [C1] 1->1; generation maximum 2147483647 [C2] 9->10; bytes_used maximum 1099511627776 [C3] 8->8; collected_bytes_spent maximum 1099511627776 [C3] 4->4; bytesReserved maximum 1099511627776 [C3] 1->2; bytesSpent maximum 1099511627776 [C3] 1->2; emitted_bytes maximum 1099511627776 [C3] 1->2; emitted_bytes maximum 1152921504606846976 [C3] 1->1; maxBytes maximum 1099511627776 [C4] 7->8; burstBytes maximum 1125899906842624 [C4] 5->6; bytesPerSecond maximum 1125899906842624 [C4] 5->6; inputBurstBytes maximum 10737418240 [C4] 4->4; inputBytesPerSecond maximum 10737418240 [C4] 4->4; maxOperations maximum 10000 [C5] 2->4; maxEvents maximum 1000000 [C6] 1->2; evidenceSeconds maximum 315360000 [D1] 2->2; caseMetadataSeconds maximum 315360000 [D1] 2->2; auditMetadataSeconds maximum 315360000 [D1] 2->2; maxAgeSeconds maximum 315360000 [D1] 1->1; durationSeconds maximum 3600 [D8] 1->1; available_before_seconds maximum 3600 [D9] 2->2; lookbackMillis maximum 3600000 [D9] 2->2; history_seconds maximum 3600 [D9] 5->5; duration_seconds maximum 86400 [D10] 16->16; maxQueueAgeSeconds maximum 300 [D11] 2->2; burst maximum 10 [R1] 3->6; maxConcurrentActions maximum 10 [R1] 3->6; maxOccurrencesPerHour maximum 1000 [R1] 3->6; maxActiveSources maximum 1024 [R2] 4->4; maxConcurrentExpensive maximum 100 [R2] 4->4; maxQueuedExpensive maximum 100 [R2] 2->2; maxQueuedExpensive maximum 1000 [R2] 2->2; maxUploadRequestsPerSecond maximum 100000 [R2] 3->4; maxStartsPerRollingHour maximum 1000 [R2] 2->2; maxProcessesPerEpisode maximum 64 [R2] 2->2; incidentPodLimit maximum 100 [R3] 2->2; incident_pod_cap maximum 16 [R3] 4->4; covered_pods maximum 100 [R3] 1->1; available_pods maximum 1000 [R3] 4->4; maxWatches maximum 4096 [R5] 1->1; maxWatchesPerPrincipal maximum 4096 [R5] 1->1; maxWatchesPerWorkload maximum 4096 [R5] 1->1; maxArtifactsPerCapture maximum 64 [R9] 3->3; materializedArtifacts maximum 6400 [R9] 1->1; bytes_per_second maximum 262144 [R10] 2->2; bytesPerSecond maximum 262144 [R10] 1->1; bytesPerSecond maximum 268435456 [R10] 1->1; burstBytes maximum 1073741824 [R10] 1->1; maxBufferBytes maximum 1048576 [R10] 1->1; maxOutputBytes maximum 67108864 [R10] 1->1; maxRowsPerBatch maximum 100 [R10] 1->1; maxEventsPerSecond maximum 100000 [R12] 1->2; maxHeaderBytes maximum 32768 [F7] 2->2; maxReassemblyBytesPerFlow maximum 262144 [F7] 2->2; maxReassemblyBytes maximum 16777216 [F7] 2->2; maxFlows maximum 1024 [F7] 2->2; maxFrozenBytes maximum 268435456 [F8] 3->4; maxFrozenBytes maximum 4294967296 [F8] 2->2; maxRingBytes maximum 4294967296 [F8] 2->2; maxConcurrentSnapshots maximum 4 [F8] 3->4; maxSegments maximum 64 [F8] 2->2; maxTrackedThreads maximum 16384 [F10] 1->2; length maximum 64 [F13] 4->6; burst_factor maximum 8 [F14] 1->1; headers maxItems 32 [F15] 4->4; complete_origins maximum 128 [M2] 1->1; gapped_origins maximum 128 [M2] 1->1; maxRecordBytes maximum 65536 [M3] 1->2


New groups at HEAD inside this half of the alphabet (not in the snapshot):

| group | verdict | justification |
|---|---|---|
| `expires_in_seconds maximum 315360000` (mcp-tools, di/browser-openapi) | REMOVE | replaced the 8 h cap by 10 years "capped by the administrator maximum"; the bound is the artifacts' AccessUntil (ADR-335 D9) — use 2^53−1 like the other fixed fields. |
| `argv maxLength 131072` (action) | KEEP(b) | MAX_ARG_STRLEN — matches T4. |
| `maxCaptures maximum 1000000` (sharing-intent), `maxCaptures maximum 100` (sharing-request, still) | REMOVE | arbitrary; see R9 (the user's explicit bound is the limit). |
| `filename maxLength 200` (artifact-download) | DERIVE | download file names (ADR-335 D17 `<workload>-<pod>-<time>.core`): derive from NAME_MAX 255 minus suffix, not 200. |
| `artifact_ids maxItems 64` (mcp-tools, browser) | REMOVE | same as L1. |
| `live_projections maxItems 3` (recording-save) | KEEP(b) | closed set (structural, S1). |
| `cluster maxLength 63`, `clusters maxLength 63` | SKIP | cluster names as DNS labels (ADR-335 D4). |
| many `maximum 9007199254740991` replacements (maxPods, maxBytes, maxExecutions, maxDepth, frequencyHz, …) | KEEP(b) | JS safe integer; these are the fixes recommended above. |


COUNTS: KEEP=109 (KEEP(a) 33, KEEP(b) 72, KEEP(c) 4) REMOVE=258 RAISE/DERIVE=36 (RAISE 9, DERIVE 27) — plus 133 identifier/format groups counted as SKIP; total 536 groups (per group, snapshot state).

### Most user-visible REMOVE items

1. list_reviews has `limit`/`approvals ≤ 100` but no `cursor` input — approver inbox silently drops requests beyond 100 (specs/contracts/mcp-tools.json:5655).
2. preview_retention_change scans at most 10,000 artifacts and returns ≤ 32 groups — retention previews are incomplete on any real installation (specs/contracts/mcp-tools.json:16198).
3. Raw-access/grant/share artifact selection capped at 64 (`artifact_digests`, `artifacts`, `maxArtifacts`) — a multi-pod or segmented capture needs several approvals (specs/contracts/mcp-tools.json:3712).
4. Dump `maxBytesPerProcess ≤ 8 GiB` — cores of large JVM/database processes are refused outright (specs/contracts/implemented/action.schema.json:1509).
5. request_raw_access `expires_in_seconds ≤ 28800` in the implemented code (spec now 10 y) — raw access expires after 8 h although ADR-335 D9 says handles last as long as the evidence (specs/contracts/implemented/mcp-tools.json:4055).
6. Investigation-access `maxOperations ≤ 10000` / grant `maxExecutions ≤ 10000` — request-count caps that ADR-335 D6/D9 abolish (specs/contracts/investigation-access.schema.json:48).
7. Live-watch row fields `duration_ms ≤ 60000`, `duration_ns ≤ 1e12`, `clock_uncertainty_ms ≤ 5000` — long syscalls or a skewed node make rows schema-invalid instead of flagged (specs/contracts/live-watch.schema.json:703).
8. Recording-save `incident_pod_cap ≤ 16` (vs `incidentPodLimit ≤ 100` in the same file) and list_targets `available_pods ≤ 1000` — larger workloads break or get capped below the admin ceiling (specs/contracts/recording-save.schema.json:150).
9. explain_access `assignments ≤ 32`, `assignments_total ≤ 256` with no paging — truncated access explanations (specs/contracts/mcp-tools.json:15139).
10. Processing restriction `expectedRevision ≤ 15` — a restriction rule can be restricted/released only ~8 times, then never again (specs/contracts/processing.schema.json:200).

Also user-visible but RAISE/DERIVE: manual approval window `lifetime_seconds ≤ 28800` (D3), compiled pcap filter ≤ 256 instructions while 128 CIDR peers alone need more (F3), `manifest_yaml ≤ 64 KiB` for staged Kubernetes manifests (T5), processing-report pages of 3 rows (P5).

---

<!-- part: schema1 -->
## Schema keywords, second half (properties `max_buffer_bytes` … `x-www-form-urlencoded`)

Source: every `maxItems/maxLength/maximum/…` in specs/contracts/**, docs/interfaces/** and examples/** (grouped by property, keyword, value). `browser-openapi.yaml` (docs/interfaces and specs/contracts/implemented) embeds the MCP schemas, so almost every MCP row appears 2–4× (mcp-tools.json, implemented/mcp-tools.json, both browser-openapi copies); one verdict covers all copies. "occ" = occurrences.

### S1 Identifier/format lengths (skipped, counted only)

| properties | keyword = value | occ | verdict |
|---|---|---|---|
| namespace, sourceName, source_name, source_ref, sourceRef, poolRef, profileRef, templateRef, receiverRef, storageProfileRef, permittedRegions, storageRegion, storage_region, name (63) | maxLength 63 | ≈130 | skip — DNS label (b) |
| name, name_prefix, pod_name, policy_name, workload_name, secretName, propertyNames (253) | maxLength 253 | ≈130 | skip — DNS subdomain (b) |
| *UID / *_uid (namespaceUID, nodeUID, podUID, policyUID, resourceUID, sourceUID, workloadUID, uid, peer_uid, pod_uid, policy_uid, workload_uid, namespace_uid) 64/36/128 | maxLength | ≈330 | skip — Kubernetes UID is a 36-char UUID; 64/128 are loose but harmless |
| planDigest, scopeDigest, scope_digest, sourceDigest | maxLength 64 | 6 | skip — sha256 hex |
| nodeBootID, operationID, writerAccountUID, targetClusterID (36) | maxLength 36 | 5 | skip — UUID |
| portName 15 | maxLength 15 | 1 | skip — IANA_SVC_NAME (b) |
| port, peer_port, remote_port, minimum_port, maximum_port, snaplen, ports, value 65535 | maximum 65535 | ≈35 | KEEP(b) — TCP/UDP port and pcap snaplen max |
| status 100–599 | min/max | ≈18 | KEEP(b) — HTTP status range |
| pid, value 4194304 | maximum | 4 | KEEP(b) — Linux PID_MAX_LIMIT 2^22 |
| program (cBPF code 65535, jt/jf 255, k 2^32−1, ≥ 4 items) | max/min | 5 | KEEP(b) — classic BPF instruction encoding |
| origin_id 127, number 511, sequence 131071 | maximum | 4 | KEEP(b) — fixed binary field widths in the framed/log record formats |
| start_time 35, notAfter/notBefore 32/40 | maxLength | 8 | skip — RFC 3339 timestamp |
| *_ns, *Ticks, sequence, revision, generation, total, observed_*, unmatched_events, paired_count, output_full, truncated, retained, uncertain, reserved, part, viewRevision, stageGeneration, transferGeneration, value 9007199254740991 / 2147483647 / 4294967295 / 9223372036854775807 / 1152921504606846976 | maximum | ≈170 | KEEP(b) — integer width (JS safe integer, int32, uint32, int64); counters, not limits |

### S2 Page sizes and result lists

| property, keyword = value | files | stated reason | verdict | justification / replacement |
|---|---|---|---|---|
| records, rows, shares, targets, timeline, top, profiles, metrics, selected_pods, sources(live-watch 100), processes, recordings, max_items, max_packets, top_n maxItems/maximum 100 | mcp-tools.json, browser-openapi.yaml, guidance, live-watch, recording-save | "at most limit (default 20, maximum 100)" (mcp-tools description) | KEEP(a) where a cursor exists; REMOVE where not | KEEP for paginated lists (records, rows, shares, targets, timeline, profiles). `selected_pods` 100 is not a page: it is the pods a capture selects — REMOVE, bounded by maintainer per-incident cap (maxPods) and the admin ceiling. `recordings` 100 in recording-save preview: REMOVE → paginate. `top`/`top_n` 100: KEEP(a) (ranked summary, user can narrow). |
| rows 32 / 16, rows maxLength 128 | mcp-tools.json, browser-openapi.yaml | none | REMOVE | Inline summary tables with no cursor; paginate or derive from the 100 page size. |
| next_cursor, query_handle, protected_draft_handle, poll_handle, scope_handle, target_handle (4096), step_up_reference 4096 | browser-openapi.yaml, mcp-tools.json, mcp-result | none | KEEP(b) | Opaque tokens that travel in URLs/headers; 4 KiB fits common URL/header limits (8 KiB). `poll_handle`/`poll_operation` REMOVE as fields (ADR-330 D1 no polling). `protected_draft_handle`, `query_handle` with expiry: handles last as long as evidence (D9). |
| navigation_uri, sharing_navigation_uri 2048 | 281 occ | none | KEEP(b) | Practical URL length (RFC 9110 recommends ≥ 8000; browsers/proxies 2 KiB safe). |
| recent 8, recommendations 8, suppressions 6, not_evaluated 16, unmatched 16, missing_observations 16, peer_candidates 16, process_refs 16, source_artifact_ids 16, source_capture_ids 4, result_access_actions 16, required_roles 4, sensitive 4, quantities 4 | guidance, mcp-tools, browser-openapi, capture-assessment | none | REMOVE (or derive from enum) | Small advisory lists. Where the list is an enum projection (sensitive 4, quantities 4, required_roles 4, retainedPossible/mayContain/transientOnly 7) the cap equals the enum size — KEEP(b) as `uniqueItems` + enum, the number is redundant. The rest have no cost reason: paginate or let the result be what it is (`recent` 8: page). |
| warnings 32, reason_codes/reasons/reasonCodes 16 (also 3, 4), validation_codes 32 | many | none | REMOVE | Bounded by the number of distinct codes in the enum (b-derived); a separate cap can hide the cause of a failure. `uniqueItems` + enum is the bound. |
| unavailable 1000, unavailable_total 1000, targets_evaluated 1000, scanned_targets 1000 | mcp-tools, browser-openapi | description: "affected namespaces (at most 1,000)" | REMOVE | Configuration impact preview capped at 1,000 targets/namespaces; replace with pagination (the result already has partial pages). Large clusters exceed 1,000 workloads. |
| provenance 64 / 2 / 0 | mcp-result, mcp-tools | none | REMOVE (64) / KEEP (2,0 structural) | 64 has no reason; provenance lists are per-result and small. |
| threads 64, max_threads 64, max_frames 128 | mcp-tools (get_backtrace) | context size | KEEP(a)/RAISE | Backtrace output goes into an MCP response; page sizes are fine, but derive from the MCP envelope (see `max_lines`) and offer a cursor; 64 threads hides threads in a 500-thread Go/Java process. |
| max_lines 200 | mcp-tools get_file_excerpt | context size | KEEP(a) | Page size; continuation by line offset. |
| offset 1499 (mcp-tools) | mcp-tools | none | REMOVE | Offset cap on a paginated query; use opaque cursor instead of capped offsets. |
| shared_captures 100, read_closed/read_closed_total 10000, unknown/unknown_total 10000, scanned 10000 | mcp-tools | none | REMOVE | Counter maxima on outputs; use integer width. |
| watched_pods 2147483647 | mcp-tools | int32 | KEEP(b) | |

### S3 Free-text and descriptive strings

| property, keyword = value | files | stated reason | verdict | justification / replacement |
|---|---|---|---|---|
| reason 512 (70 occ), reason 80, summary 512, message 256/1024 (285 occ), text 256/1024, title 80/120/128/256, narrowing_hint 1024, warnings 256/1024, missing_observations 256, reasons 256, values 256, value 1024 | access-binding, capture, browser-openapi, mcp-tools, mcp-result, guidance, log-results, permission-common | reason: "Optional 1–512 Unicode scalars, preserved verbatim" | DERIVE | A bound protects logs/audit rows/UI (a), but six different numbers for prose is arbitrary. Use one: user reason ≤ 4 KiB (fits a K8s annotation and a log line), server messages ≤ 1 KiB. `reason` 80 (code-like) is an identifier: skip. |
| packet_filter 512 | mcp-tools, browser-openapi | "Supported tcpdump/libpcap packet-filter subset" | DERIVE | Maintainer: bounded pcap filters (c). The real bound is the compiled cBPF program (≤ 4096 instructions, BPF_MAXINSNS, b); the recorder-preview already caps `program` (see `program maxItems 256`). Cap the compiled size, not the source text, and raise text to e.g. 4 KiB. |
| program maxItems 256 / 4 | recorder-preview | "Classic BPF instructions … emitted by libpcap" | RAISE | Kernel cBPF limit is BPF_MAXINSNS 4096 (b); 256 rejects ordinary multi-port/peer filters. Use 4096. |
| pattern 1024 (trigger log regexp) | trigger | none | KEEP(a)/DERIVE | RE2 compile cost grows with pattern size; derive from RE2 program-size limit (default max program size 1000 instructions → ~1 KiB source fits). Cite RE2. |
| path 4096 / 1024, workingDirectory 4096 | action, trigger | none | KEEP(b) | Linux PATH_MAX 4096. Raise the 1024 instance to 4096. |
| value 32768 (preset input / editor value) | mcp-tools, browser-openapi | none | DERIVE | Derive from the K8s object size it ends up in (1.5 MiB, b). |
| value 4096 / 179 / 16 / 128 / 256 (capture-composition typed edit values, syscall-arguments value 179, live-watch values) | capture-composition, syscall-arguments, live-watch | maintainer "finite typed edits"; argument bytes | KEEP(c)/DERIVE | Typed edits finite (c). syscall-arguments `value` 179 = base64 of 128 argument bytes — derived from the reviewed per-event argument budget (c). live-watch value 128/256: derive from the projection field definitions. |
| valueSchema 4096/16/64 items | capture-composition | finite typed edits | KEEP(c) | |
| rootsPEM 32768, roots 4 / 21848, output 5464, wrappedKeyset 16384, versionID 1024, reference 256 | small-services-preparation, small-openbao, local-key-service, manifest, framed-storage | none | REMOVE (machinery) / KEEP(b) | `roots`/`rootsPEM` CA bundles: ADR-335 D12 system trust store, bundles optional — keep as Secret size (1 MiB, b), drop the 4-root cap. local-key-service `output`/`reference` describe removed key-service machinery (ADR-330 D3) → REMOVE. wrappedKeyset 16 KiB: KEEP(a) (keyset size known, Tink). versionID 1024: KEEP(b) (S3 version IDs ≤ 1024 bytes). |
| mcpRedirectURIs 32 × 2048, origin 2048, mcpClientID 128 | small-services-preparation, browser-settings | none | REMOVE count / KEEP(b) length | Redirect URIs are a handful; no cost reason for 32. Length: URL practice (b). |
| x-www-form-urlencoded maxProperties 128 | browser-auth-openapi | none | KEEP(b) | Form parameter DoS bound — standard (Go `http.MaxBytesReader`, Tomcat maxParameterCount 10000). Prefer a byte cap; 128 is fine for OIDC callback forms. |
| media/format/type/unit/phase/status/runtime/operation/tool_name/thread_id/syscall/method/version/pack_version/native_format/native_type/sample_type/mechanism/observation_point/transform/region/source/requested/runtime_id/owner_id/row_id/source_handle/recording_handle/process_ref/thread_ref/parent_ref/protected_*_ref/reason_reference/reviewRef/secret_delivery_reference/purposeRef/purpose_ref/subject/subject_id/recipient_id/signature/resource_version/resourceVersion/source_time/timeZone/acr/abi (16–256) | many | none | skip / KEEP(b) | Enum-like or identifier strings; bounded by their own format (OIDC `sub` ≤ 255 ASCII per OIDC Core, K8s resourceVersion opaque). `resourceVersion` 128 vs `resource_version` 256: unify at 256. |
| recipient_issuer 2048 | processing-report | URL | KEEP(b) | |

### S4 Counts in configuration objects (CRDs, settings)

| property, keyword = value | files | stated reason | verdict | justification / replacement |
|---|---|---|---|---|
| subjects maxItems 32 (AccessBinding) | access-binding | none | REMOVE | RoleBinding has no subject cap; the K8s object size (1.5 MiB, b) bounds it. |
| roles maxItems 4 (AccessBinding), roles 16 × 80 (Session) | access-binding, browser-openapi | none | REMOVE | Equals the number of built-in roles; use `uniqueItems` + enum. |
| workloads maxItems 64 (AccessBinding) | access-binding | none | REMOVE | Object size bounds it (b); ADR-335 D4 names workloads. |
| subjects maxItems 256 (fleet-settings) | fleet-settings | none | REMOVE | ADR-335 D14 collapses `fleet.groups` lists into one admin group; field goes. |
| ownerAssignments 8, ownerTeams 8, teams 8 | policy-authority, management | none | REMOVE | "Multiple owner teams may manage evidence shares" (AGENTS) — no number given; object size bounds it. |
| rules maxItems 64 (retention-policy), 100 (processing inventory) | retention-policy, processing | none | REMOVE | Bounded by object size (b); evaluation is per artifact × rules, cheap. |
| privacyClasses maxItems 5 / 1 | retention-policy, download-environment | enum size | KEEP(b) | Equals the enum size; `uniqueItems`. The `1` in download-environment: structural. |
| policyRefs 64, policyDigests 64 | collection-scope, privacy-common, capture-assessment | none | REMOVE | Number of policies applying to one artifact; ADR-335 D8 "policies unlimited". |
| podBindings 100 / 1 | collection-scope | maxPods | REMOVE (100) / KEEP(c) (1) | 1 = per-incident cap (c); 100 is arbitrary — use the admin ceiling. |
| origins maxItems 8 (capture-profile), origins/partial_origins/unavailable_origins/unknown_timestamp_origins maximum 128 (log-record) | capture-profile, log-record, log-results | none | REMOVE / KEEP(b) | Log origins = containers per pod; derive from the record format's `origin_id` width (127, b) and drop the separate 8. |
| overrides 32, resolvedProfiles 8, value maxItems 64 | capture-composition | finite typed edits (c) | KEEP(c) concept / RAISE | Finite edits required (c); the numbers have no derivation — derive from K8s object size or the number of typed fields in the profile. |
| resolvedSelections 32, selectionApprovals 32, outputs 16 | sharing-intent, sharing-request | none | REMOVE | Bounded by the recipe's actions/outputs; share cap agent covers recipients. |
| operations maxItems 16/5/4/32/2 | grant, investigation-access, share, mcp-tools | maintainer finite disclosure pool | KEEP(b) | Each equals the operation enum for that grant kind; use enum + `uniqueItems`. |
| pressureTriggers maxItems 6 | budget-policy | "Linux PSI triggers" | KEEP(b) | 3 resources × some/full = 6 PSI files (kernel psi.rst). |
| protectedAllocations 64, workloadSlots 10000 | storage-pool | none | REMOVE | ADR-335 D2 removes the slot/allocation arithmetic; per-workload share replaces it. |
| objects maximum 1000000000 | budget-policy, storage-pool | none | REMOVE | Object counts are not a resource on SeaweedFS/S3 (D2). |
| priority maximum 1000 | budget-policy | "highest priority applies" | KEEP(b)-ish | Ordinal range; harmless. Could be int32. |
| permittedRegions 64, regions 16, purposes 32, operators 32, processors 16, paths/pathIDs 32, projections 3, requiredCapabilities 32 | download-environment, processing-report, internal-work, live-watch | processors: "Optional operator declarations for inventory reporting only" | REMOVE | Configuration lists bounded by object size (b). `projections` 3 = enum size (KEEP b). `requiredCapabilities` internal-work describes per-request work envelopes removed by ADR-330 D2/D4 → REMOVE. |
| names maxItems 128, syscall_names 64 × 64 | recorder-preview, syscall-trace, mcp-tools | none | DERIVE | Syscall name list: derive from the architecture syscall table size (~450 on x86-64, b), or drop the cap. |
| signals maxItems 16, signals maximum 64 | trigger | none | KEEP(b) | Linux has 64 signals (SIGRTMAX). maxItems 16: REMOVE (uniqueItems). |
| toolDigests 32, parentArtifacts 16/0, parents 16/0, pages 512/32, sampleTypes 16 | manifest, processing-*, framed-storage, profile | none | DERIVE/REMOVE | `pages` 512 × 8 MiB frame layout = 4 GiB index-page bound: DERIVE from the artifact size cap. parentArtifacts 16: REMOVE (lineage graph, paginate). sampleTypes 16: KEEP(b) (pprof profiles have few sample types). toolDigests 32: REMOVE. |
| values maxItems 16 × 256, maxProperties 128 (permission-common label selector) | permission-common | none | KEEP(b)-derive | Mirrors K8s label selector; K8s has no per-selector cap — REMOVE caps, keep label value 63 (b). |
| subjects (event) 128 | event | CloudEvents `subject` | skip | |

### S5 Durations, deadlines, intervals

| property, keyword = value | files | stated reason | verdict | justification / replacement |
|---|---|---|---|---|
| wait_ms maximum 30000 | mcp-tools watch_live, after_revision | ADR-330 D1 | KEEP(c) | |
| wait_ms maximum 5000 | mcp-tools (second variant) | none | RAISE | Use the same 30 s (ADR-330 D1); 5 s forces client loops. |
| max_session_seconds maximum 3600 | mcp-tools observation_limits | none | REMOVE | ADR-335 D8/D9: sessions unlimited, bounded by rate limits; a live session runs while connected. |
| max_concurrent_sessions maximum 1000 | mcp-tools observation_limits | none | REMOVE | D8 sessions unlimited. Concurrency for collectors stays via capture concurrency. |
| requested_duration_ms 1000–60000 (CPU profile), 15000 (trace) | mcp-tools, browser-openapi | profiles.md: "maximum 60 seconds under the administrator ceiling; trace maximum 15 seconds" | RAISE | The admin ceiling (c) is the bound; a hardcoded 60 s/15 s on top contradicts D8 ("post-trigger windows up to the capture's configured duration (minutes)"). Max = administrator ceiling (default 60 s is fine as a default). |
| window_seconds 30–300, sample_interval_seconds 30–300 (policy detector status) | mcp-tools get_policy_status | none | REMOVE max / KEEP(b) min | Minimum: metrics.k8s.io resolution (metrics-server default 15 s; resource metrics window 30 s, b). Max 300: no reason — users may want hour windows. |
| sampleIntervalSeconds maximum 60, unhealthySamples 60, recoveryHealthySeconds 3600, recoverySeconds 3600, stallMicroseconds 10000000, windowMicroseconds 500000–10000000, minimumIntervalSeconds 86400 | budget-policy | recoverySeconds: "The breaker closes after this long without a new trip event" | KEEP(b) PSI / REMOVE others | PSI window 500 ms–10 s is the kernel's accepted trigger window (psi.rst, b). Sampling interval: ADR-330 D1 → use PSI trigger fds, drop sampling fields. recoverySeconds/minimumIntervalSeconds caps (1 h / 1 d): no reason for the maximum; admin choice. |
| replaySeconds maximum 5, replay_seconds 5 | download-environment liveRead, live-watch | maintainer "bounded transient rows/replay" | KEEP(c)/DERIVE | Replay is bounded (c); derive the bound from the buffer (`max_buffer_bytes` 1 MiB) rather than time. |
| rowMaxAgeSeconds 30, row_max_age_seconds 30 | download-environment, live-watch | none | REMOVE | A row's age is not a resource; buffer bytes already bound memory. |
| retry_after_seconds maximum 60 (355 occ), 1000000 | mcp-tools, browser-openapi, processing-report | none | REMOVE max | Retry-After (RFC 9110) has no maximum; quota retry hints can be hours (D8 rate limits per hour). Cap at int32. Also ADR-330 D1: pending-status retry hints go away for status tools. |
| retry_after_ms 100–5000 | live-watch | none | REMOVE max | Same. |
| maximumOutstandingLeaseSeconds 60 | retention-policy status | none | REMOVE | Deletion-lease machinery removed (ADR-330 D12). |
| renewalNoticeSeconds maximum 31536000 | approval-policy | none | REMOVE | No reason to cap the admin's notice; keep int. |
| requested_retention_seconds, requestedAgeSeconds, resolvedMaxAgeSeconds, maximumAgeSeconds maximum 315360000 (10 y), retention_seconds 31536000 (1 y) | mcp-tools, collection-scope, privacy-common, capture-assessment, guidance | "Omission uses the administrator default" | KEEP(c) / REMOVE hard max | The administrator maximum (c) is the real bound; a 10-year schema ceiling is a harmless sanity bound (KEEP as integer guard). `retention_seconds` 1 y in guidance: REMOVE (admin may allow longer). |
| sample_interval / sampleInterval / pollInterval / window / within / settleFor / timeout / retention / ring_max_age / requestedBefore maxLength 16 | trigger, action, common, collection-scope, policy | duration string length | skip / REMOVE pollInterval | Duration-string length (format). `pollInterval` field: ADR-330 D1 — detectors use watches/streams; remove unless the source is metrics.k8s.io. |
| notAfter description "apiContextStart/v1 is at most identity.AuthorityRecheckInterval (30 seconds, ADR-311) after notBefore; the historical node profile is at most sixty seconds" | local-start | ADR-311 | KEEP(c) 30 s / REMOVE 60 s | 30 s is ADR-311. The local-start "historical node profile" is installer/start-journal machinery (ADR-330 D7/D13). |

### S6 Byte sizes and collection budgets

| property, keyword = value | files | stated reason | verdict | justification / replacement |
|---|---|---|---|---|
| plaintextBytes 8388608 for pcapng (metadata and raw), http-response-headers, syscall events/arguments (manifest); description "at most 8 MiB" (ADR-248/273/279/282); syscalls.md "argument source limit is 8 MiB" | manifest, framed-storage frame nativeBytes 8 MiB | ADR-048 frame size; "delivered through the connector" | REMOVE (artifact cap) / KEEP(a) (frame) | The 8 MiB frame is a streaming unit (a: per-frame memory). Capping whole packet/syscall artifacts at one frame is a leftover of the single-frame context slice; artifacts are framed and streamed (ADR-330 D2/D4). Bound by the capture's maxBytes and ring size (c). Very user-visible: an 8 MiB pcap is seconds of traffic. |
| plaintextBytes 67108864 / 134217728, nativeBytes 64 MiB/128 MiB (local-start), max_output_bytes 64 MiB, max_bytes 64 MiB | manifest, local-start, live-watch, mcp-tools | profiles.md: "Default profile output cap 16 MiB, maximum 64 MiB; default trace output cap 32 MiB, maximum 128 MiB" | RAISE | Per-capture output must be finite (c), but the max is the administrator ceiling; the hardcoded 64/128 MiB maxima have no derivation. Live-watch `max_output_bytes` lifetime cap: REMOVE (D9, watch open while connected). |
| plaintextBytes 4096 (pod status), context slice 4096 | manifest | ADR-066 "4096-byte context slice" | DERIVE | Pod status JSON can exceed 4 KiB (many containers, long messages). Derive from the K8s object it projects (Pod object ≤ 1.5 MiB, b) or stream in frames. |
| nativeBytes/plaintextBytes/size_bytes/sizeBytes/native_bytes/verified_native_bytes/nativeOffset/max_bytes/max_collected_bytes/remaining_bytes/reservedBytes/spentBytes maximum 1 TiB (1099511627776) | framed-storage, manifest, artifact-download, trigger, mcp-tools | none | KEEP(a)-ish / DERIVE | A global artifact ceiling guards integer/format math; 1 TiB is arbitrary but larger than any configured budget. Derive from the frame index (pages × frames × 8 MiB) and say so. |
| max_bytes 100 TiB, 256 GiB, 1 GiB; rss_bytes 100 TiB; max_ring_bytes 25 GiB; ring_max_bytes/ring_bytes 256 MiB; segment_bytes/segmentBytes 64 MiB; segments 2–64; max_buffer_bytes 1 MiB; wire_bytes 1 MiB; source_bytes 64 MiB; offset 64 MiB (log); total_fragments 64 Mi | guidance, mcp-tools, packet-capture, live-watch, log-record | maintainer: segmented rings, live buffers bounded | KEEP(c) ring concept / DERIVE numbers | Ring size bounds always-on recorders (D6). The maxima (256 MiB ring, 64 segments) should derive from node memory/emptyDir the collector is given; 25 GiB `max_ring_bytes` vs 256 MiB `ring_max_bytes` are inconsistent. log `source_bytes`/`offset` 64 MiB: derive from kubelet `containerLogMaxSize` (default 10 MiB, b) × rotated files. |
| max_bytes_per_second 1 GiB/s, retained_bytes_per_second 1 GiB/s | mcp-tools, guidance | rate | KEEP(a) | Rates are the D8 storm bound; maximum is a sanity value. |
| max_observed_bytes / observed_bytes_* / observedBytesReserved/Spent 1 TiB; max_observed_events / observed_events_* / observedEvents* 1e9; description "Original accepted cumulative pre-filter observation ceiling"; max_collected_bytes "cumulative native-output ceiling, shared across grants" | grant, mcp-tools | maintainer: syscall argument mode reviewed observation budgets | KEEP(c) for manual/argument mode / REMOVE for always-on | ADR-335 D6: "Always-on recorders are bounded by rates and ring sizes, not lifetime byte budgets." Lifetime observed totals stay only for intrusive manual grants/argument mode. Reserved/Spent counters: ADR-330 D7 → per-workload counters with release; drop "reserved". |
| max_executions 10000, remaining_executions 10000, max_grant_starts 10000 ("Server-derived ceiling in action-start units"), max_process_starts 10000, max_operations/operations_used/operationsReserved/Spent 10000, max_captures 100, registered_captures/registeredCaptures 100 | mcp-tools, grant, investigation-access, sharing-intent | maintainer finite approval; D6 | KEEP(c) intrusive grants / REMOVE non-intrusive | D6: non-intrusive policies have no run count. Intrusive automatic grants expire by time (90 d); a run count on top is a second bound without a resource reason → REMOVE max_executions/grant_starts; keep rates (D8). Manual investigation operations pool: KEEP(c) (finite disclosure pool). max_captures for recurring sharing: KEEP(c) only if chosen as the "explicit bound" instead of time; one bound suffices. |
| max_scan_bytes 1 GiB, scanned_bytes 1 GiB ("Logical scan budget") | mcp-tools packet query | CPU per query | REPLACE → KEEP(a) as timeout | Replace byte budget with a query deadline/cursor over the artifact. |
| scan_bytes/scan_cpu_nanos/scan_events/refused_admissions int64, pending_rows 80000000, nodes 5000, rates_unavailable 5000 | live-capacity | none | REMOVE (nodes 5000, pending_rows) | live-capacity status counters; `nodes` ≤ 5000 equals the documented K8s scalability limit (b) — KEEP(b) as a sanity bound. pending_rows 80 M: derive or drop. |
| observationPods 1000, requested_pods 100, pod_count 100, runningInstances/running/terminated/waiting 64, restarts, restartCount 100000 | capture-assessment, guidance, pod-status | none | REMOVE / KEEP(b) | Pod-status container counts: no K8s cap on containers per pod (practical object size) → REMOVE 64. observationPods 1000 / pod_count 100: maintainer "monitor all authorized replicas within administrator ceilings" — the admin ceiling is the bound, not a schema 100/1000 → REMOVE. restartCount int32 (b). |
| threshold maximum 1e18 / 1 | trigger, mcp-tools | ratio | KEEP(b) | Ratio ≤ 1 is semantic. |
| minimumFailures / minimum_failures maximum 1000 | trigger, mcp-tools | none | REMOVE | Probe failure count; no cost; int32. |
| ordinal 8/100, ordinals 100 × 100000 | processing-report, target | none | REMOVE | Replica ordinals: StatefulSets can exceed 100 replicas; use int32. |
| occurrences int32, occurrenceCount 1 TiB | mcp-tools, event | counters | KEEP(b) | |
| record_count 1000000, unfinished_events/unknown_events 1000000 | syscall-results | none | REMOVE | Output counters; JS safe integer. |
| resolvedLocations/totalLocations/unattributedSamples 1e12, packets/unclassified_packets 1e12 | profile, mcp-tools | counters | KEEP(b) | Integer sanity. |
| description "fixed server-owned 160 KiB response budget" (browser) | mcp-tools | none | DERIVE | Same as MCP envelope row (ifx): derive from client limits; inconsistent with "32 KiB console JSON" in interfaces/README. |
| description "over at most 10,000 retained artifacts whose deletion is not yet due" (retention preview) | mcp-tools | none | REMOVE | Paginate the preview; the update itself is one SQL statement (ADR-330 D12). |
| description small-openbao "Public preparation plan, at most 96 KiB" | small-openbao | none | REMOVE | Installer-era plan (ADR-330 D13); OpenBao optional (D11). |
| `revision` maximum 3 / 16 / minimum 2 | mcp-tools, processing | schema version | skip | Versions, not limits. |
| revision maximum 1000000 (grant, share), observed_generation 1000000 | grant, share, browser-openapi | none | RAISE | Generations are int64 in Kubernetes; 1e6 is an arbitrary wrap point. Use int53. |

COUNTS (this part, rows): KEEP=38 REMOVE=39 RAISE/DERIVE=12, skip=11 (identifier groups)
