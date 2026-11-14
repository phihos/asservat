# MCP interface

## REQ-MCP-001 — Transport and protocol

Serve `/mcp` using official Go SDK, candidate `v1.8.0`, over Streamable HTTP with TLS terminated at an operator-controlled gateway or the service. Explicitly configure supported revisions `2026-07-28` and `2025-11-25`, with stateless HTTP handling. Do not require a load-balancer sticky session. Use the SDK's protocol-specific discovery/initialization behavior; do not manually imitate new wire fields on old clients.

Every tool MUST have strict `inputSchema` and `outputSchema`, return structured content, and provide a bounded text mirror for older clients. Set per-identity/private caching and `Cache-Control: no-store` for evidence. Do not accept anonymous origin/cross-site requests; validate Host/Origin and supported content types. Reject excess request bytes, nesting, tool concurrency and inconsistent method/name headers.

No Sampling, Roots, Logging, DCR dependency, server-side LLM, agent harness or automatic approval through elicitation. Resource links are optional authenticated mirrors, not bearer capabilities. [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic), [Go transport documentation](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/docs/protocol.md).

### SC-MCP-001

Given representative clients for both revisions, when they call discovery/list/tools across two replicas, then both work without transport-held authorization state. Forged header/body routing disagreements and oversized frames are rejected.

## Tool catalogue

The machine-readable catalog is [mcp-tools.json](contracts/mcp-tools.json). A UI uses the same authorization/query services; it does not bypass tool-equivalent checks.

| Tool | Purpose | Access and bounds |
| --- | --- | --- |
| `list_cases` | Filter by cluster, workload, time, status, signature, shared-with-me | Authorized projections only; default 20, max 100 cases |
| `get_case` | Minimal case timeline, available artifacts/classes, capture gaps | Shared callers see only the shared projection |
| `find_similar_cases` | Exact signature and structured similarity, optional bounded text | Authorization-filtered results/counts; deterministic ranking |
| `list_artifacts` | Authorized artifact descriptors and provenance | No storage paths, wrapped keys or credentials |
| `get_timeline` | Time-ordered incident and collection events | Stable cursor; source-clock uncertainty included |
| `get_backtrace` | Bounded threads/frames, symbols and source locations | Extract; no arbitrary local variable values |
| `get_runtime_summary` | Typed heap/thread/GC/profile aggregates | Extract; runtime pack version and omissions included |
| `get_profile_summary` | Profile totals, units and bounded flat/cumulative hotspots | Extract; sample type and symbol coverage explicit |
| `compare_profiles` | Baseline/incident deltas or normalized rates | Authorize both artifacts; reject incompatible sample types/units |
| `get_syscall_summary` | Syscall counts, errors and paired duration totals | Approved metadata projection; loss and incomplete pairs explicit |
| `get_syscall_events` | Bounded recorded syscall metadata timeline | No argument option; source authorization and expiry |
| `syscall_query` | Typed recorded argument query | Raw scope, artifact/share permission, matching grant and cumulative limits |
| `get_pcap_summary` | Traffic counters, peers, handshake/error summaries where present | Extract; distinguish header-only from payload-derived findings |
| `get_http_headers` | Approved plain HTTP/1 method/status/header fields and coverage gaps | Structured extract only; no bodies or arbitrary header selection |
| `get_zeek_log` | Allowed log stream, fields and time window | Extract projection only; fields may be absent for headers-only input |
| `get_file_excerpt` | Approved text/structured projection of a collected file | Extracts only by default; no live file reads |
| `get_logs` | Redacted incident log extract with context bounds | No direct cluster log tailing through this tool |
| `request_raw_access` | Request artifact-operation grant | Creates pending grant; does not collect or disclose evidence |
| `get_grant` | Own grant state and remaining quota; optional bounded wait for the next change | Requester/approver-specific views; anyone else sees the same reply as for an unknown ID (ADR-249). The approval inbox `list_reviews`, `decide_review` and `revoke_grant` are browser-only console operations |
| `read_memory` | Bounded core-memory view at an address | Raw scope + share/ACL + grant; max 16 KiB/call, cumulative quota |
| `debugger_command` | Structured enum operation with typed arguments | Raw grant; no text command language, shell or code evaluation |
| `pcap_query` | Bounded saved-packet fields, tcpdump/libpcap packet filter and typed time/flag selectors | Ordinary rights for metadata-only; exact pcap_query grant for any raw source/fields; scan/packet/output caps |
| `get_query_result` | Retrieve result of an explicit analysis job | Authorization under REQ-INT-003; optional bounded wait; never charged |
| `list_shares` | View owned/received concrete shares; optionally the sharing instructions of owned captures and policy acceptances; administrators: every share management-only (view administration) | Current personal/team-manager-only instructions; bounded origins and combined pagination; administration view without recipients, ≤ 100 per cursor page |
| `create_share` | Request an explicit user/group evidence share | Sharing authority; raw-sharing may be pending approval |
| `revoke_share` | Revoke one share or an owned/admin-managed sharing instruction (by capture or acceptance ID) and its dependent shares | Exactly one target ID; expected revision and idempotency required; current managers and installation administrators |
| `transfer_share` | Replace the managing owner teams of one share (audited transfer or administrator recovery) | Current manager with teams they hold, or installation administrator with current owner teams (also for a Suspended share); expected revision and idempotency required; creator, recipients and expiry unchanged |
| `stop_future_sharing` | Stop the future sharing of a recurring policy sharing (ADR-239); already selected captures still publish, existing shares stay | `sharing_intent_id` = the policy acceptance ID, expected revision 1 and idempotency required; creator, current owner-team member or installation administrator; changes no collection authority |
| `explain_access` | Explain the caller's own Allow/Deny/Indeterminate decision for one workload and operation | Caller only; real evaluator; uniform reply without own allow; no evidence lookup |
| `list_capture_history` | Previous accepted captures for one workload/selector | Default manual origin; retained/current history rights; bounded pages |
| `get_capture_settings` | Retained collection parameters for review/editing | Protected immutable projection; no credentials, grants or sharing; ordinary byte limit |
| `list_targets` | Discover authorized pods/workloads | Whole-pod collection eligibility; no share-based inventory |
| `get_target_discovery` | Read approved process/flow/coverage projections from a discovery capture | Extracts; source artifact access and live-target eligibility; no acquisition |
| `recommend_diagnostics` | Rank diagnostics for a goal and produce previewable handles | Passive; at most four discovery inputs/eight choices; current scope, stateless plans |
| `list_capture_profiles` | Target-aware builtin/organization/namespace catalog | Bounded summary only; no collection or publication authority |
| `get_capture_profile` | Versioned definition and exposed editable fields | Target/configuration-authorized extract; no secret material |
| `list_diagnostics` | Discover usable presets/recipes for a target | Bounded capability-aware handles; no manual digest entry |
| `preview_capture` | Resolve scope, impact, retention and missing approval | Side-effect-free dry run returning the resolved plan and `plan_digest`; nothing stored |
| `list_live_sources` | Inventory of existing policy/manual sources and live projection capabilities | Metadata only; current maintainer and source audience rights |
| `open_live_watch` | Open a finite approved view from now | Viewer mutation only; no new capture, grant transfer or raw content |
| `read_live_watch` | Bounded transient rows and explicit gaps | Bounded wait (≤ 30 s), continuation cursor and no durable replay |
| `update_live_watch` | Pause/resume or replace typed display filter | Revision/idempotency; no lifetime, budget or acquisition change |
| `close_live_watch` | Close own viewer and release subscriber resources | Source recording continues independently |
| `list_recordings` | Discover eligible existing packet/syscall recordings and history coverage | Passive, current whole-pod collection rights; bounded selection references |
| `preview_recording_save` | Preview a snapshot-only save and incremental handling/impact | Existing-source selection only; submits via request_capture |
| `get_capture` | Collection, approval and partial outcomes; optional bounded wait for the next change | Current requester/maintainer view; case/approval navigation |
| `cancel_capture` | Stop remaining collection | Disabled by default; revision/idempotency and cancellation authority |
| `request_capture` | Submit a recipe-bound capture with optional result-sharing instruction | Disabled by default; collection scope/rights plus evidence:share and owner authority if sharing is requested |

Collection-time sharing follows [REQ-SHR-004–008](authorization.md#req-shr-004--share-results-when-requesting-collection). request_capture returns capture status; when sharing is requested, `sharing_intent_id` is the capture ID (or, for a policy, its acceptance ID) and `get_capture` reports `sharing.state` (`Pending`, `Shared`, `SharingUnavailable`) separately from collection. create_share still requires a concrete existing snapshot. list_shares(include_intents=true) is valid only for the owned view; limit/cursor bounds cover the combined shares/instructions count, and recipients never discover an empty pending case. Returned child origin fields are opaque provenance, not authority to inspect the parent instruction or other recipients. revoke_share accepts exactly one of share_id or sharing_intent_id and never approves an action or raw query. Parent revocation reaches delivery under REQ-INT-003. Missing sharing authority refuses the request with `SharingNotPermitted`; raw outputs need raw-sharing review (REQ-SHR-006).

## REQ-MCP-002 — Bounded result contract

Every tool result MUST carry `schema_version`, `request_id`, `data_class`, `status`, `data`, `truncated`, `next_cursor`, `narrowing_hint`, `warnings` and provenance references where available. `data_class` is the maximum sensitivity represented in the result, including mixed fields. The default serialized structured result budget is 24 KiB, with a 32 KiB specification ceiling for ordinary results; runtime subsets may enforce a smaller bound. Every MCP response, including structured/text representations and protocol overhead, stays within 64 KiB; there is no caller-selected response budget. `preview_recording_save` returns one aggregate effective-retention summary per source plus authenticated navigation to the per-policy details.

Token counts are estimates, not enforceable universal units. Default output aims at roughly 5,000–8,000 tokens where practical; the actual safety bound is bytes/items. `truncated=true` requires a useful narrowing hint, and a cursor only if further authorized data exists. The explicit live-watch continuation contract below is the exception: an empty active batch can return a cursor for future rows. Cursor tokens are opaque, HMAC-authenticated and bind query parameters, principal/client and budgets. They do not expire and do not bind grant or share revisions; each page is authorized under REQ-INT-003, so a revoked share fails within 30 s. Cursors carry no raw secrets.

Long work returns `status=pending` with a server-minted query handle and a `revision` in `data`. Status tools (`get_capture`, `get_grant`, `get_query_result`, `get_artifact_download`) accept an optional `after_revision`; the server holds the call until the revision changes or at most 30 s, woken by PostgreSQL `LISTEN/NOTIFY`, and then returns current state. Status reads are never charged and carry no not-before advice. Store only bounded current job state, not transport session state. Default query wall time 10 seconds, administrator maximum 60 seconds; input scan default 256 MiB, max 1 GiB without an explicit larger profile. A 100 GiB core may require a separately budgeted acquisition/staging job before a bounded memory query can run.

For `get_query_result`, validate the nested result against the original tool's output schema, identified by the server-owned handle. The caller cannot choose a weaker schema through `tool_name`. Byte ceilings apply to the entire wrapped response.

The [approved pod-status read profile](../docs/architecture/context-projection.md)
uses the existing `get_file_excerpt` input and a fixed `pod-status.txt` projection.
A long-running regional reader serves the read ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D4);
no Job, worker certificate or key slot is created per query. The query is
authorized once at creation and that decision is reused under REQ-INT-003; the
query lifetime is bounded by the original evidence/access deadlines. A pending
handle binds the original tool, principal/client, committed source version, line
selection and budgets. `get_query_result` never starts another query, capture or
analyzer. Fixed ordinary reads need no caller idempotency key (SC-AUT-005); the
saved-packet query keeps its idempotency key under REQ-MCP-003.

For these two query operations, successful and pending `data` includes
`query_observed_at` and `query_expires_at`. The first timestamps the prepared
server snapshot; the second is the total query cutoff from the original
evidence/access deadlines. Neither field extends authority. A repeated status
read returns the same timing and request ID in its original-tool result. Browser and MCP use the same contract;
errors carry no query timing. Managed views clear on that cutoff, scope loss,
closure or suspension. Already delivered external copies cannot be recalled.

### SC-MCP-002

Given a query with more output than the byte cap, when it completes, then truncation is explicit and the result remains valid JSON. Reusing its cursor under another principal, a revoked share or modified filter is rejected.

### SC-MCP-006

Given an authorized browser or MCP reader and a committed pod-status artifact,
when `get_file_excerpt` reads the selected lines, then both return the same fixed
approved projection without download scope, new collection or extra consent.
Given a known query handle and a lost outward reply, a later `get_query_result`
returns the same result without starting another read; a reader whose access was
revoked is refused within 30 s. Disclosure and its audit row commit in one
PostgreSQL transaction; when the audit row cannot be written nothing is disclosed.

## REQ-MCP-003 — Typed raw operations

`syscall_query` selects names/errors in an existing saved argument recording,
with a required idempotency key and optional approval-discovery `grant_id`.
An admitted read always requires the exact current `syscall_query` grant for
the artifact and requesting client. No supplied grant returns the existing
raw-approval remedy before admission, not argument data. The canonical and
browser contracts share raw event fields, native encoded values, provenance,
query observation/expiry timestamps and the 24 KiB result bound. A retry with
the same key returns the original query; pages use the authenticated cursor
under the same key.
See [the saved-argument contract](syscalls.md#req-sys-003--evidence-projections-and-mcp).

`debugger_command` MUST accept an enum such as `backtrace`, `threads`, `registers`, `frame_variables`, `managed_stack`, or `heap_statistics`, plus validated numeric/frame/thread selectors and projection limits. The implementation constructs fixed debugger scripts or MI calls itself. Do not accept shell, Python, debugger expressions, `source`, output redirection, extension loading or arbitrary `print` expressions. A command-name allowlist applied to free text is insufficient.

`pcap_query` MUST validate a bounded **tcpdump/libpcap packet-filter** subset,
closed packet fields and typed numeric/time/address/flag selections. The
`packet_filter` input is capture-filter syntax, not Wireshark display-filter
syntax ([ADR-305](../docs/decisions/305-bounded-saved-packet-queries.md)). The
same pinned hub compiler and supported Go BPF evaluator used for acquisition are
reused, without reconfiguring capture. Keep the public filter cap at 512 bytes, the existing token/instruction bounds,
no DNS/service-name resolution and exact evaluator compatibility checks. The
initial query subset refuses bracket/raw-byte predicates before compilation or
spend; this is a bounded first-release choice, not full libpcap support.
Typed packet-time bounds and TCP flag mask/value selectors preserve those
outcomes separately from expressions. The closed field catalog and selector
limits MUST be identical across canonical input, browser/MCP, scope and reader.

Metadata-only source/fields use current ordinary and retained rights without a
raw grant. Any raw original needs an exact `pcap_query` grant even for header-only
fields; the raw-summary aggregate right, collection grant, raw share or download
operation does not replace it. A raw captured-frame prefix may be returned as
bounded hex only from a raw original under that grant. It is a prefix of saved
frame bytes, not inferred application payload. Missing/truncated headers remain
null or explicitly unavailable. Authorization follows REQ-INT-003; Stop and
retention cut-offs end a running query as events.

Return one transient page of at most 100 saved-record rows, 32 selected fields and
24 KiB encoded structured output including required wrapping. Keep input/native,
parser/evaluator work and elapsed-time bounds separate. The declared 1 GiB scan
ceiling does not qualify sources larger than the 8 MiB published packet bound.
Logical `scanned_bytes` sums captured frame lengths visited in original order,
including nonmatches; do not visit a record that would cross `max_scan_bytes`.
Stop logical matching/projection at its row or scan cap, report visited work and
limit/truncation state with a useful narrowing hint, then authenticate and check
the complete original/canonical EOF before publishing a result. Full-authentication
drain is bounded independently and is not reported as logical scanned bytes.
Cancellation, source error, corrupt tail or lost authority overrides any page.

The `idempotency_key` binds the exact normalized source/selection and grant for
the original human/client. A retry with the same key and input returns the stored
outcome or the still-running query; changed input conflicts. One `grant_use` row
per (grant, idempotency key) records the charged operation and bytes. Returned
bytes are debited at delivery in the same transaction as the audit row; when the
outcome is known and nothing was disclosed, the reservation is released. Each
invocation has its own audit request ID.

Query-only raw grant pools fund returned disclosure rather than require coverage
of the whole native file; retain verified native size as an exact source fact and
the existing 1 GiB query-only request ceiling. A scope also selecting download keeps
whole-file coverage and its existing download ceiling. Both operations spend the
same parent pool across artifacts/clients. Reuse covering standalone or combined
result-access grants under REQ-INV-001–003; an unlisted client needs its own review.
Store bounded normalized filter/program, numeric/enum selectors, exact source and
keyed control identity, never rows, frame bytes or arbitrary payload/string
literals in SQL/audit/logs. Numeric addresses still have finite user-data retention.
No new capture, native download, stored derivative or capture-history entry is
implicit in a query. `read_memory` likewise requires a collected core, validated
address range and artifact digest; it never reads a live process. Returned byte
views are bounded raw query results, not artifact downloads.

### SC-MCP-003

Given a malicious debugger command or packet filter containing file access,
shell syntax, unbounded regex, unsupported functions or an excluded raw-byte
predicate, validation rejects it before any query or grant spend. A permitted
backtrace cannot load target-provided Python pretty-printers. A supported packet
filter uses the pinned program, typed time/flag bounds and exact saved fields;
truncation cannot manufacture a missing field. A metadata-only query needs no
raw grant, while header-only selection from a raw original still needs its exact
pcap_query grant. A logical scan/row stop followed by a corrupt authenticated tail
returns no page. Retrying an uncertain query with its original key does not
create another query or disclosure charge; a changed selection conflicts.

## REQ-MCP-004 — OAuth and untrusted evidence

Publish RFC 9728 resource metadata, validate audience strictly, and use configured issuers and preregistered clients. Advertise only `evidence:read` as the minimal scope; additional `evidence:raw`, `evidence:share`, and `evidence:capture` are requested through precise insufficient-scope challenges when necessary. An IdP adapter must pass discovery, resource/audience mapping and step-up tests. Separate workload token exchange is preferred to direct projected-token acceptance.

Treat all evidence text as untrusted data. Tool descriptions and result schemas MUST state that logs/files/source excerpts may contain attacker instructions. Keep provenance, user content and system-generated summaries separate; never convert content into tool instructions or automatically follow embedded URLs. This reduces ambiguity for a client agent but cannot guarantee the behavior of external models. No tool automatically remediates a workload or executes a suggestion found in evidence.

### SC-MCP-004

Given a log containing instructions to disclose another case, when retrieved, then it remains labeled evidence text and causes no server-side tool execution, credential access or URL fetch. An insufficient scope response does not approve a grant.

## Errors

Use stable application codes in the result envelope: `NotAuthorized`, `GrantRequired`, `ShareExpired`, `EvidenceExpired`, `CapabilityUnavailable`, `TargetGone`, `BudgetExceeded`, `IndexRebuilding`, `AnalysisUnavailable`, `ArtifactIncomplete`, `InvalidCursor`, `AuditUnavailable`, `ClusterOffline`, `RetryLater`. Before access is established, use a uniform not-found/not-authorized projection to avoid existence oracles. Transport authentication errors use OAuth HTTP semantics; malformed MCP calls use protocol errors. Error text never contains raw evidence or credentials.

## Team management and HTTP-header evidence

`create_share` accepts optional management selection under REQ-SHR-008; the service derives the creator and the managing groups from current allows. `request_capture.sharing` uses the same resolver. `list_shares(view=owned)` means currently manageable through personal/team authority; received views stay concrete-artifact-only. `revoke_share` can be used by any valid manager, but does not approve raw access or transfer grant ownership.

`get_http_headers(case_id, artifact_id, cursor?, limit?)` reads an already approved HTTP/1 projection, with at most 100 bounded records, inherited privacy deadlines, provenance and reported gaps. It has no body, decryption or arbitrary header-selection option. `get_pcap_summary.capture_mode` is networkHeaders or rawPackets; it does not confuse L3/L4 and HTTP headers. [ADR-304](../docs/decisions/304-transient-raw-packet-summary.md) permits the fixed transient Go summary of a raw original with dedicated ordinary aggregate rights and independently checked numeric output. Raw results require `unclassified_packets`; metadata results omit it. The original stays raw and broader queries/downloads retain separate grants. Native/subprocess analyzers retain qualified encrypted scratch and separate Jobs. All result/output/client/audit limits continue to apply.

## REQ-MCP-005 — Complete capture workflow

An enabled collection client can use list_targets → list_diagnostics → preview_capture → request_capture → get_capture, then ordinary case tools. list_targets lists only currently collectable pod/workload scope; a shared-evidence reader gains no workload inventory. list_diagnostics accepts exactly one target_handle or explicit target_ref and returns applicable immutable preset references or recipe handles, capability gaps and approval requirements for one target. Each row contains exactly one preset_ref or diagnostic_handle; a stable preset reference is not a scoped handle or evidence authority. Default pages are 20, maximum 100, with existing byte/cursor ceilings and current authorization.

preview_capture also supports the exclusive history_capture_id restore branch in [REQ-HIS-004](capture-history.md); this creates a fresh passive preview with current checks. For a new plan, preview_capture accepts either a discovered target_handle or an explicit cluster/namespace/kind/name, and exactly one of a diagnostic_handle, versioned preset or profile_composition. It resolves pod-wide scope, runtime capabilities, budgets, retention, owner/sharing eligibility and approval requirements without acquiring application evidence, arming sensors, executing a command or reserving execution capacity. Preview is a dry run ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D9): it returns the resolved plan and a `plan_digest` over immutable target UIDs, dependencies and the normalized request, and stores nothing. Target and diagnostic handles are opaque, stateless encodings of the listed target or recipe reference, bound to principal/client; the server stores nothing for them and resolves them again with current checks on use. They are not bearer permissions.

The fixed `pod-status/v1` preset resolves only `builtin-pod-status-v1`; it is not an alias for the broader `incident-context/v1` preset or a CaptureProfile. Its successful preview echoes `preset_ref` and `target_ref`, returns one `selected_pods` row with actual owning workload identity, and states `pod_selection=explicitPod|lexicalEligiblePod`. The selected UID and owner are independently resolved, never accepted as input. `pod_count=1`, `max_bytes=4096`, `max_process_starts=0` and the single on-trigger pod-status lifecycle remain exact. An unchanged preset/handle/composition/history branch retains its schema; an unimplemented runtime branch returns a bounded explicit error rather than substituting this preset. [Paired synthetic example](../examples/mcp-pod-status-preview-result.json) demonstrates the contract, not an enabled collector.

Normal `preview_capture` inputs may include `requested_retention_seconds`, an integer from 1 through 315360000. Omission selects the administrator default (the internal zero sentinel is never a valid explicit wire value). It requests evidence-access lifetime, not permission to exceed current managed-copy retention/deletion bounds; the assessment shows actual access and deletion ages. A `history_capture_id` restore preserves its original retention and rejects this override. Editing retention uses normal preview with optional `repeated_from_capture_id`; submission by preview cannot change it.

For `pod-status/v1`, each assessment action reports `retention.anchorRule: submissionPreparation`. Access and deletion ages run from the first admitted submission preparation; waiting for collection counts, and accepted retries do not restart the clock. Agents must not describe these ages as beginning at acquisition. The generic `firstAcquisitionOrEarlierSource` rule remains available to other mechanisms.

The assessment carries a digest and no validity period. Submission recomputes the plan and assessment; when the digest differs from `expected_plan_digest` it returns ReviewChanged with the differences and never silently changes reviewed scope. All pre-eligibility target lookup errors remain nondisclosing.

request_capture accepts either the explicit shape or the previewed request with `expected_plan_digest`, always with an `idempotency_key` (browser: `Idempotency-Key`). A retry with the same key returns the original operation rather than recapturing; a changed request under the same key is Conflict. A lost reply is resolved by retrying with the same key. Stale scope requires a fresh preview, without silently widening it. The service creates any pending ad hoc action-grant request using the frozen capture UID/scope; browser review stays mandatory. Sharing checks remain independent. The accepted response always includes a capture navigation URI. The connector resumes accepted work by operation ID after an interruption; status reads, reload and session refresh never start or repeat collection, and a new investigation requires a deliberate fresh review.

get_capture returns authorized revision/phase, bounded per-action progress, available case reference, gaps, `revision` and existing approval navigation where eligible; it supports the bounded `after_revision` wait. It does not return evidence bytes, commands or hidden recipients. Read access is requester/current scoped maintainer or administrator; mere receipt of one shared artifact does not expose the entire collection plan. Requests across clients by the same user still require current scope; idempotency keys and raw-query grants remain client-bound. Errors name the remedy/role only after access is established. Navigation links are same-installation authenticated URLs and contain no tokens.

Capture status is one phase plus the Conditions Accepted, Collected, Verified and Published ([state machines](apis.md#state-machines)). Succeeded requires Published for every required output. Wall-clock passage alone never changes the phase. Case navigation requires its own current authorization.

cancel_capture is disabled by default alongside request_capture; when enabled it needs evidence:capture and current requester/workload cancellation authority, expected revision and idempotency key. It stops remaining collection, does not erase artifacts or retract shares, and never reruns/resumes work. Return cancellation_requested and current phase; a sent cancellation is not proof a profiler or kernel operation stopped. All capture-workflow tools retain strict schemas, audit, privacy, request/output limits and no automatic approval.

### SC-MCP-005

Given an authorized agent with collection enabled but no hashes, when it discovers a workload, previews incident-context and submits the previewed request with its plan digest, then it can follow the same capture with get_capture and reach the resulting case. An intrusive preview leads to browser approval; context can progress independently. A replayed submission with the same key returns the same capture; a changed plan is reported as ReviewChanged; a foreign handle, changed parameters under the same key or a received share cannot authorize collection. Cancellation cannot delete evidence or revoke shares implicitly.

## Guided selection

REQ-GDE-001–006 in [guidance](guidance.md) add `get_target_discovery` and `recommend_diagnostics`, with strict [projection contracts](contracts/guidance.schema.json). Both are read-only tools using `evidence:read` plus current target collection eligibility; read-only annotations never authorize live process/packet collection. The existing `evidence:capture`/disabled-by-default submission gate controls every new survey. Recommendation focus may name up to 16 process references and/or 16 flow references from supplied discovery captures, so agents can refine plans without copying PIDs or peer addresses. Resolve all references against caller/client and current source rights; they constrain the recommendation, not execution authority. If a durable selector also matches other processes or peers, show the expanded set and require the ordinary explicit plan selection; never silently discard a focus constraint. Unsupported or conflicting focus yields a useful blocker.

`preferences.max_bytes` caps aggregate acquired output across selected pods; `max_ring_bytes` separately caps their total live ring allocation. Show frozen/parser/scratch reservations alongside these values; neither field overrides administrator resource accounts.

Recommendation preferences constrain proposed plans; an impossible history/byte/impact combination returns explicitly blocked choices and alternatives, not an automatically relaxed preference. Source captures must belong to the same pinned workload/pod scope; mixed incarnations are stale-context errors. With no source capture, only capability/catalog-based suggestions are possible and missing observations are explicit. User-supplied strings and evidence-derived names remain untrusted data.

## Repeating from history

The strict [history projections](contracts/capture-history.schema.json) back list_capture_history and get_capture_settings. Agents can list by target_handle (or explicit cluster/target selector), then call preview_capture(history_capture_id) and request_capture with the previewed request, `expected_plan_digest` and an idempotency key. No new mutation tool is needed. Optional repeated_from_capture_id in preview/submission/status is provenance only and does not authorize reading that source. History selection cannot be combined with a target, diagnostic or preset override; edit a draft through the existing normal authoring path with a new preview and optional repeated_from_capture_id provenance. The provenance requires source access, restores nothing implicitly and is mutually exclusive with history_capture_id. Expired parameters, stale exact identities and disabled dependencies produce specific blockers. SettingsTooLarge returns authenticated navigation; large parameter snapshots never bypass tool output ceilings and need not be fetched to repeat by reference.

## Capture-profile composition and syscall projections

[Capture profiles](capture-profiles.md) reuse preview_capture → request_capture → get_capture. Full composition provenance in a preview is an extract and subject to the ordinary byte bound. If it cannot fit, return a bounded error with authenticated browser navigation; do not silently drop component settings or approval-relevant differences. List/detail are passive and require current target eligibility plus the relevant catalog visibility. Save/publish remains Kubernetes configuration, not a new MCP mutation or permission CRUD API.

[Syscall evidence](syscalls.md) adds two approved extract tools and syscall_query to the typed raw-operation set. The latter has no live tracing, pointer dereference or code-execution operation. Bound scan work as well as returned rows; shared views select only permitted artifacts/projections. get_query_result authorizes the same scope/grant under REQ-INT-003. Argument-bearing results, tool strings and catalog descriptions are untrusted data.

## Lifecycle-aware planning

list_capture_profiles rows include execution_modes; preview_capture always includes lifecycle_plan (action-lifecycle/v1), resolving per-action mode, policyArming versus manualSession and requested history/post-window. These fields contain configuration/metadata only and do not arm anything. get_capture reports incident progress; policy source readiness is separate. Recommendations and history repeat pass through this same compiler and cannot treat a ten-second live profiler as prior history or a delayed newly started ring as pre-trigger evidence. No new tool can bypass source approval or start an unbounded recorder.

## Impact assessment and handling notices

preview_capture success requires capture_assessment under the [assessment contract](contracts/capture-assessment.schema.json). It binds execution_digest and action modes, separates known effects from uncertainty, labels limits/estimates/measurements and describes data exposure and effective retention. A blocker still disables collection; the assessment grants no authority. Browser and GitOps use the same evaluator under [REQ-ASM-001–005](capture-assessment.md).

get_case/list_artifacts descriptors require handling_notice with possible contents, expiresAt/deleteBy, current deletion state/asOf and managed-copy/external-copy boundaries. Derive this only for authorized descriptors; sharing one extract cannot expose its hidden raw parent. Direct evidence queries retain a concise handling reminder in the ordinary warnings array so opening the case is not a prerequisite. The server returns notices in structured/text views but cannot force an external agent to display them. These fields add no tool or approval mutation and remain inside existing result limits.

## Saving existing recordings

[Recording saves](recording-saves.md) add two passive tools: list_recordings for authorized ongoing-source inventory, and preview_recording_save for a bounded selection/lookback and incremental impact/privacy assessment; like preview_capture it is a dry run that returns the resolved save plan and its `plan_digest` and stores nothing. They use existing metadata result limits and principal/client-bound selection references, and do not freeze/read buffers. Submit with request_capture, the preview's `expected_plan_digest` and an idempotency key; get_capture and cancel_capture handle the resulting operation=recordingSave. The existing mutation enable switch, OAuth scope and current workload permissions apply. No tool accepts a policy trigger event, arbitrary source ID, post-window, core/command or filter override.

get_capture_settings returns either ordinary captureSettings or recordingSaveSettings. A saved-recording history entry has origin=manual, operation=recordingSave and repeat_state=requiresSelection while usable; ordinary preview_capture redirects it to fresh inventory. A schema-valid handle alone never authorizes access, and partial/expired sources are never silently replaced. A raw-result share still confers no inventory/capture rights.

## Live watching of existing sources

[REQ-LIV-001–006](live-watch.md) add five typed tools and the [live contract](contracts/live-watch.schema.json). `list_live_sources` is separate from policy-save inventory because finite manual sessions may be watched without gaining the policy-only save capability. Open/update/close are enabled viewer-state operations under evidence:read plus current source eligibility; they do not enable request_capture/cancel_capture or require evidence:capture. Opening a watch is explicit user/agent intent and never acquisition. Source selection/projection are immutable for that watch; only a typed approved display filter and pause state can change.

MCP uses `read_live_watch`, which waits server-side up to `wait_ms` (at most 30 s, [REQ-LIV-003](live-watch.md)) for rows and returns bounded rows and explicit gaps. Its next_cursor continues an active stream, including when the current batch is empty; it does not promise unread historical rows. Timeout/connection loss does not close the watch or extend its original deadline. Reads are not charged and are authorized under REQ-INT-003; stale view revisions or an aged-out resume position yield a gap/fresh position rather than an unbounded backlog. No tool creates a raw live grant, subscribes to hidden sources, invokes arbitrary expressions or returns an infinite stream. Both supported MCP protocol profiles use these bounded tools; notifications are not required. Live row references identify transient source observations, not durable artifact citations.

Stateless HTTP remains a transport property. LiveWatch is domain state (slot accounting and view settings), not a connection-bound MCP session. The browser receives rows over one Server-Sent Events stream per watch, bounded by the watch lifetime and byte budget; the replica serving the stream subscribes to the source over the connector connection for the stream's lifetime and resumes from `Last-Event-ID` = (source session, sequence) within the resume window, otherwise it sends a gap event. Any replica serves an MCP read from the source's bounded buffer over the connector connection. No client affinity, hub projection owner or owner fencing is required.

## Native-file handoff

`prepare_artifact_download`, `get_artifact_download` and `cancel_artifact_download` share browser contracts. Preparation requires explicit user intent plus evidence:download and current artifact access; raw files additionally require evidence:raw and an existing grant covering download_artifact. Results contain status and, when available and currently authorized, the complete verified native filename/size/format/checksum group. Ready/Streaming/Interrupted require that group and an authenticated application content path; terminal states expose neither content path nor resume. Completed may return status without native metadata after the regional result cache is gone, including after the original transfer deadline while current evidence metadata authority still permits disclosure. Do not infer local file persistence or checksum verification from Completed. Status reads never re-prepare evidence. Results never contain file bodies, base64, credentials or presigned URLs. An OAuth-capable client uses the separate streaming HTTP endpoint outside the model context; browser handoff rebinds to that browser principal/client. Existing bounded raw-query tools remain useful and unchanged. See [downloads](artifact-downloads.md).

The native download resource has its own protected-resource metadata at `/.well-known/oauth-protected-resource/downloads`, pinned to the installed origin and issuer. Clients obtain authorization for that exact resource and original client identity; an MCP audience alone does not authorize the content endpoint. The fixed HTTP preflight audit is not advertised as a tool. Native bytes remain outside all model responses and transcripts.

Advertise evidence:download as an optional file-transfer scope alongside evidence:read; it is not raw eligibility. Raw native transfers still use the existing evidence:raw challenge and explicit artifact grant. File content is excluded from ordinary MCP response-byte/token budgets because it travels on the separate fully accounted HTTP transfer, not because those budgets are bypassed.

## One review for collection and investigation

preview_capture and expanded request_capture accept result_access as a finite instruction, not a grant. It selects output action IDs, operations, registered clients for the same human and aggregate limits/deadline; the planner resolves friendly UI selections. Submit-by-preview forbids overriding it. preview_capture returns the resolved result_access scope; get_capture returns current result_access state and authorized child grant IDs. Use [investigation-access.schema.json](contracts/investigation-access.schema.json) and [REQ-INV-001–003](investigation-approval.md). Selecting an agent client is explicit. Artifact tools reuse exact current child grants automatically; unrelated clients/principals need their own review. A pending access materialization never asks the agent to recollect evidence.
