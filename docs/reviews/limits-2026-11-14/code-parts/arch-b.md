# Limit audit — docs/architecture (part B)

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
