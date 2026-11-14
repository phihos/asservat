# Limit audit — docs/architecture part A

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
