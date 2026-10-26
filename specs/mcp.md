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
| `get_grant` | Poll own grant state and remaining quota | Requester/approver/admin-specific views |
| `read_memory` | Bounded core-memory view at an address | Raw scope + share/ACL + grant; max 16 KiB/call, cumulative quota |
| `debugger_command` | Structured enum operation with typed arguments | Raw grant; no text command language, shell or code evaluation |
| `pcap_query` | Bounded packet projection and typed display predicates | Raw grant if any raw artifact/fields; scan/packet/output caps |
| `get_query_result` | Retrieve result of an explicit analysis job | Recheck current authorization at every poll/delivery |
| `list_shares` | View owned/received concrete shares; optionally owned SharingIntents | Current personal/team-manager-only pending intents; bounded origins and combined pagination |
| `create_share` | Request an explicit user/group evidence share | Sharing authority; raw-sharing may be pending approval |
| `revoke_share` | Revoke one share or an owned/admin-managed SharingIntent and its dependent shares | Exactly one target ID; expected revision and idempotency required |
| `explain_access` | Explain the caller's own Allow/Deny/Indeterminate decision for one workload and operation | Caller only; real evaluator; uniform reply without own assignment; no evidence lookup |
| `list_capture_history` | Previous accepted captures for one workload/selector | Default manual origin; retained/current history rights; bounded pages |
| `get_capture_settings` | Retained collection parameters for review/editing | Protected immutable projection; no credentials, grants or sharing; ordinary byte limit |
| `list_targets` | Discover authorized pods/workloads | Whole-pod collection eligibility; no share-based inventory |
| `get_target_discovery` | Read approved process/flow/coverage projections from a discovery capture | Extracts; source artifact access and live-target eligibility; no acquisition |
| `recommend_diagnostics` | Rank diagnostics for a goal and produce previewable handles | Passive; at most four discovery inputs/eight choices; current scope, expiring drafts |
| `list_capture_profiles` | Target-aware builtin/organization/namespace catalog | Bounded summary only; no collection or publication authority |
| `get_capture_profile` | Versioned definition and exposed editable fields | Target/configuration-authorized extract; no secret material |
| `list_diagnostics` | Discover usable presets/recipes for a target | Bounded capability-aware handles; no manual digest entry |
| `preview_capture` | Resolve scope, impact, retention and missing approval | Side-effect-free planning; expiring principal/client-bound handle |
| `list_live_sources` | Inventory of existing policy/manual sources and live projection capabilities | Metadata only; current maintainer and source audience rights |
| `open_live_watch` | Open a finite approved view from now | Viewer mutation only; no new capture, grant transfer or raw content |
| `read_live_watch` | Bounded transient rows and explicit gaps | Current checks, continuation cursor, short row expiry and no durable replay |
| `update_live_watch` | Pause/resume or replace typed display filter | Revision/idempotency; no lifetime, budget or acquisition change |
| `close_live_watch` | Close own viewer and release subscriber resources | Source recording continues independently |
| `list_recordings` | Discover eligible existing packet/syscall recordings and history coverage | Passive, current whole-pod collection rights; bounded short-lived handles |
| `preview_recording_save` | Preview a snapshot-only save and incremental handling/impact | Existing-source selection only; submits via request_capture |
| `get_capture` | Poll collection, approval and partial outcomes | Current requester/maintainer view; case/approval navigation |
| `cancel_capture` | Stop remaining collection | Disabled by default; revision/idempotency and cancellation authority |
| `resolve_capture_request` | Recover an uncertain own request before editing | evidence:read; closes unaccepted preview or returns accepted receipt; never starts/cancels collection |
| `request_capture` | Submit a recipe-bound capture with optional result-sharing instruction | Disabled by default; collection scope/rights plus evidence:share and owner authority if sharing is requested |

Collection-time sharing follows [REQ-SHR-004–008](authorization.md#req-shr-004--share-results-when-requesting-collection). request_capture returns capture status plus a sharing-intent ID/authenticated navigation URI when requested; the intent page explains pending/partial/blocked sharing independently. create_share still requires a concrete existing snapshot. list_shares(include_intents=true) is valid only for the owned view; limit/cursor bounds cover the combined shares/intents count, and recipients never discover an empty pending case. Returned child origin fields are opaque provenance, not authority to inspect the parent instruction or other recipients. revoke_share accepts exactly one of share_id or sharing_intent_id and never approves an action or raw query. Parent revisions participate in cursor and delivery checks. SharingApprovalRequired and SharingCapacityUnavailable distinguish missing review from unavailable bounded control capacity.

## REQ-MCP-002 — Bounded result contract

Every tool result MUST carry `schema_version`, `request_id`, `data_class`, `status`, `data`, `truncated`, `next_cursor`, `narrowing_hint`, `warnings` and provenance references where available. `data_class` is the maximum sensitivity represented in the result, including mixed fields. Default serialized structured result budget is 24 KiB; hard limit 32 KiB per result unless an administrator approves a narrower dedicated contract. Combined structured/text representations and protocol overhead MUST stay within a 64 KiB response ceiling.

Token counts are estimates, not enforceable universal units. Default output aims at roughly 5,000–8,000 tokens where practical; the actual safety bound is bytes/items. `truncated=true` requires a useful narrowing hint, and a cursor only if further authorized data exists. The explicit live-watch continuation contract below is the exception: an empty active batch can return a cursor for future rows. Cursor tokens are opaque, authenticated, expire within 15 minutes, and bind query parameters, principal/client, grant/share revisions, dataset generation and budgets. Cursors carry no raw secrets.

Long work returns `status=pending` with a server-minted query handle in `data`. Store only bounded current job state, not transport session state. Default query wall time 10 seconds, administrator maximum 60 seconds; input scan default 256 MiB, max 1 GiB without an explicit larger profile. A 100 GiB core may require a separately budgeted acquisition/staging job before a bounded memory query can run.

For `get_query_result`, validate the nested result against the original tool's output schema, identified by the server-owned handle. The caller cannot choose a weaker schema through `tool_name`. Byte ceilings apply to the entire wrapped response.

The initial [approved pod-status read profile](../docs/architecture/context-projection.md)
uses the existing `get_file_excerpt` input and a fixed `pod-status.txt` projection.
The installed shared-acquisition profile explicitly selects a finite 60-second
query lifetime for cold Job startup and independent worker enrollment (ADR-219
and ADR-221), shortened by original evidence/access/backing limits. This is a
configured bound, not a measured startup guarantee. Each public request retains
its own original at-most-five-second authority interval; polls reconstruct that
request authority and never renew the query. Four paid polls and two paid read
batches remain the profile ceilings. Clients honor the returned not-before
interval and original expiry rather than immediately spending all polls.
Ordinary reads require no extra caller idempotency key (SC-AUT-005). A pending
handle binds the original tool, principal/client, exact committed source/display
version, line selection, finite budgets and query deadline. `get_query_result`
MUST NOT start another query, capture, analyzer or replacement worker. Delivering
the already bound result may consume a fresh separately charged source-read batch
under current ordinary read authority; a pending poll cannot dispatch work.
Prior spend and uncertainty remain charged. All operations preserve the original
query lifetime and each request's original at-most-five-second identity and
authority bounds. This profile is specified, not yet runtime-qualified.

For these two query operations, successful and pending `data` includes
`query_observed_at` and `query_expires_at`. The first timestamps the prepared
server snapshot; the second is the original total query cutoff, irreversibly
shortened by effective evidence access. Neither field extends the current
request's disclosure authority. A successful poll repeats the same timing and
request ID in its original-tool result. Browser and MCP use the same contract;
errors carry no query timing. Managed views clear on that cutoff, scope loss,
closure or suspension. Already delivered external copies cannot be recalled.

### SC-MCP-002

Given a query with more output than the byte cap, when it completes, then truncation is explicit and the result remains valid JSON. Reusing its cursor under another principal, a revoked share or modified filter is rejected.

### SC-MCP-006

Given an authorized browser or MCP reader and a committed pod-status artifact,
when `get_file_excerpt` reads the selected lines, then both return the same fixed
approved projection without download scope, new collection or extra consent.
Given a known query handle and an outward reply lost after a positively joined
private read, a later `get_query_result` may use only a new paid batch within the
same source, selection, budget and original deadline. Unknown private closure,
changed actor/client, current denial, expiry or exhaustion cannot cause reuse,
replacement, refund or automatic successor admission. Audit failure before
outcome acknowledgement prevents disclosure.
Given a late or repeated read-start acknowledgement, no second private read
starts. The previous batch remains active through its exact outcome audit,
outward write and positively joined cleanup; neither a pending poll nor expiry
proves remote quiescence or releases uncertain worker, key or provider spend.

## REQ-MCP-003 — Typed raw operations

`debugger_command` MUST accept an enum such as `backtrace`, `threads`, `registers`, `frame_variables`, `managed_stack`, or `heap_statistics`, plus validated numeric/frame/thread selectors and projection limits. The implementation constructs fixed debugger scripts or MI calls itself. Do not accept shell, Python, debugger expressions, `source`, output redirection, extension loading or arbitrary `print` expressions. A command-name allowlist applied to free text is insufficient.

`pcap_query` MUST validate a bounded subset of display-filter grammar, numeric/time/address ranges and field projections. Limit filter length, parse complexity, packets scanned/returned and CPU. Disable network name resolution. `read_memory` requires a collected core, validated address range and artifact digest; it is never a live process memory read. Returned byte views are bounded raw query results, not artifact downloads.

### SC-MCP-003

Given a malicious debugger command or packet filter containing file access, shell syntax, unbounded regex or unsupported functions, when submitted, then input validation rejects it before starting a sandbox. A permitted backtrace cannot load target-provided Python pretty-printers.

## REQ-MCP-004 — OAuth and untrusted evidence

Publish RFC 9728 resource metadata, validate audience strictly, and use configured issuers and preregistered clients. Advertise only `evidence:read` as the minimal scope; additional `evidence:raw`, `evidence:share`, and `evidence:capture` are requested through precise insufficient-scope challenges when necessary. An IdP adapter must pass discovery, resource/audience mapping and step-up tests. Separate workload token exchange is preferred to direct projected-token acceptance.

Treat all evidence text as untrusted data. Tool descriptions and result schemas MUST state that logs/files/source excerpts may contain attacker instructions. Keep provenance, user content and system-generated summaries separate; never convert content into tool instructions or automatically follow embedded URLs. This reduces ambiguity for a client agent but cannot guarantee the behavior of external models. No tool automatically remediates a workload or executes a suggestion found in evidence.

### SC-MCP-004

Given a log containing instructions to disclose another case, when retrieved, then it remains labeled evidence text and causes no server-side tool execution, credential access or URL fetch. An insufficient scope response does not approve a grant.

## Errors

Use stable application codes in the result envelope: `NotAuthorized`, `GrantRequired`, `ShareExpired`, `EvidenceExpired`, `CapabilityUnavailable`, `TargetGone`, `BudgetExceeded`, `IndexRebuilding`, `AnalysisUnavailable`, `ArtifactIncomplete`, `InvalidCursor`, `AuditUnavailable`, `ClusterOffline`, `RetryLater`. Before access is established, use a uniform not-found/not-authorized projection to avoid existence oracles. Transport authentication errors use OAuth HTTP semantics; malformed MCP calls use protocol errors. Error text never contains raw evidence or credentials.

## Team management and HTTP-header evidence

`create_share` accepts optional management selection under REQ-SHR-008; the service derives creator and assignment proof. `request_capture.sharing` uses the same resolver. `list_shares(view=owned)` means currently manageable through personal/team authority; received views stay concrete-artifact-only. `revoke_share` can be used by any valid manager, but does not approve raw access or transfer grant ownership.

`get_http_headers(case_id, artifact_id, cursor?, limit?)` reads an already approved HTTP/1 projection, with at most 100 bounded records, inherited privacy deadlines, provenance and reported gaps. It has no body, decryption or arbitrary header-selection option. Raw packet analysis first runs in the offline sandbox and creates a reviewed extract. `get_pcap_summary.capture_mode` is networkHeaders or rawPackets; it does not confuse L3/L4 and HTTP headers. All result/output/client/audit limits continue to apply.

## REQ-MCP-005 — Complete capture workflow

An enabled collection client can use list_targets → list_diagnostics → preview_capture → request_capture → get_capture, then ordinary case tools. list_targets lists only currently collectable pod/workload scope; a shared-evidence reader gains no workload inventory. list_diagnostics accepts exactly one target_handle or explicit target_ref and returns applicable immutable preset references or recipe handles, capability gaps and approval requirements for one target. Each row contains exactly one preset_ref or diagnostic_handle; a stable preset reference is not a scoped handle or evidence authority. Default pages are 20, maximum 100, with existing byte/cursor ceilings and current authorization.

preview_capture also supports the exclusive history_capture_id restore branch in [REQ-HIS-004](capture-history.md); this creates a fresh passive preview with current checks. For a new plan, preview_capture accepts either a discovered target_handle or an explicit cluster/namespace/kind/name, and exactly one of a diagnostic_handle, versioned preset or profile_composition. It resolves pod-wide scope, runtime capabilities, budgets, retention, owner/sharing eligibility and approval requirements without acquiring application evidence, arming sensors, executing a command or reserving execution capacity. A service-owned preview handle expires within five minutes and binds principal/client, immutable target UIDs, dependencies and the normalized request. Bound preview storage to 10 per principal and 1,000 per installation; expiry/eviction requires a new preview. Target/diagnostic handles have the same identity/freshness binding. These handles are navigation/planning references, not bearer permissions.

The fixed `pod-status/v1` preset resolves only `builtin-pod-status-v1`; it is not an alias for the broader `incident-context/v1` preset or a CaptureProfile. Its successful preview echoes `preset_ref` and `target_ref`, returns one `selected_pods` row with actual owning workload identity, and states `pod_selection=explicitPod|lexicalEligiblePod`. The selected UID and owner are independently resolved, never accepted as input. `pod_count=1`, `max_bytes=4096`, `max_process_starts=0` and the single on-trigger pod-status lifecycle remain exact. An unchanged old preset/handle/composition/history branch retains its schema; an unimplemented runtime branch returns a bounded explicit error rather than substituting this preset. [Paired synthetic example](../examples/mcp-pod-status-preview-result.json) demonstrates the contract, not an enabled collector.

Normal `preview_capture` inputs may include `requested_retention_seconds`, an integer from 1 through 315360000. Omission selects the administrator default (the internal zero sentinel is never a valid explicit wire value). It requests evidence-access lifetime, not permission to exceed current managed-copy retention/deletion bounds; the assessment shows actual access and deletion ages. A `history_capture_id` restore preserves its original retention and rejects this override. Editing retention uses normal preview with optional `repeated_from_capture_id`; submission by preview cannot change it.

For `pod-status/v1`, each assessment action reports `retention.anchorRule: submissionPreparation`. Access and deletion ages run from the first admitted submission preparation; waiting for collection counts, and accepted retries do not restart the clock. Agents must not describe these ages as beginning at acquisition. The generic `firstAcquisitionOrEarlierSource` rule remains available to other mechanisms.

The assessment's original five-second validity and the passive preview's at-most-five-minute expiry are distinct. Reading the review must not generate a replacement preview every five seconds. Submission rechecks current facts without silently changing reviewed scope. An uncertain request response retains the original preview ID and idempotency key; retry resolves its accepted operation before preview expiry checks. It does not automatically make a fresh preview or new capture. All pre-eligibility target lookup errors remain nondisclosing; a previously owned preview alone does not establish current rights.

`resolve_capture_request(preview_id, idempotency_key)` is an explicit recovery mutation for the caller's original reviewed request. It stays discoverable/enabled when new collection is disabled and requires `evidence:read` and the original actor/client binding; accepted metadata additionally requires current original-target read eligibility, while own unaccepted closure discloses no target metadata and does not require target rights; it does not require `evidence:capture`, a live pod or acquisition capability. Browser requests require the same original key in `Idempotency-Key`. It checks accepted admission and permanently closes an unaccepted reviewed request under the same transactional serialization boundary as admission. An accepted preview wins even when found through another original-key lookup; closure cannot cancel or refund accepted work. A successful response is exactly one of `state=accepted` with the original capture ID, `phase=Accepted`, authenticated navigation and operation, or `state=closed` with no target/effect metadata. Neither result creates a new capture.

Only an acknowledged `closed` result permits editing and obtaining a fresh preview/key. An accepted result opens existing progress. PreviewExpired, ReviewChanged, Conflict, CollectionDisabled, an unavailable/unauthorized response or missing read result never proves closure or non-admission. An uncertain resolution reply retains the original pair for explicit retry; it must not mint a new key or silently restart. Server closure must prevent later admission by an already-running submitter using that preview. No ordinary failure discloses foreign preview existence. Resolution uses normal metadata bounds and final current-identity/authorization deadlines; it is not a bypass for a revoked identity.

request_capture accepts either the existing explicit shape or preview_id + idempotency_key, never both. A fresh request checks handle ownership/expiry and all current authority/dependencies. Resolve an already accepted idempotency key before checking preview expiry; retries return the original operation rather than recapturing. Changed request under the same key is Conflict. Stale scope requires a fresh preview, without silently widening it. The service creates any pending ad hoc action-grant request using the frozen capture UID/scope; browser review stays mandatory. Sharing checks remain independent. The accepted response always includes a capture navigation URI. For the qualified pod-status preview/key path, `continue_acquisition: true` is an explicit fresh-current attempt to continue an already accepted acquisition. Omission preserves passive accepted replay. A missing original key is never admitted by this branch. The same original actor/client, capture, attempt and immutable start interval remain binding; no replacement target or repeated key preparation is allowed. After uncertain preparation, check progress; a new investigation requires deliberate fresh review and cannot cancel or erase the original. Polling, resolution, reload and session refresh never perform this action.

get_capture returns authorized revision/phase, bounded per-action progress, available case reference, gaps, retry interval and existing approval navigation where eligible. It does not return evidence bytes, commands or hidden recipients. Read access is requester/current scoped maintainer or administrator; mere receipt of one shared artifact does not expose the entire collection plan. Requests across clients by the same user still require current scope; preview/idempotency and raw-query grants remain client-bound. Errors name the remedy/role only after access is established. Navigation links are same-installation authenticated URLs and contain no tokens.

The initial bounded pod-status implementation follows [ADR-105](../docs/decisions/105-durable-context-progress.md): persistent revisions track durable intent, custody, verification, audit and publication changes. Accepted or audited admission remains Pending until there is a stored outcome; verified outcomes awaiting audit/publication are Finalizing. Only audited verified catalog publication is Succeeded. A separately persisted elapsed-deadline observation without publication is Indeterminate and never refunds uncertain spend. Wall-clock passage alone does not fabricate a revision. Case navigation requires its own current authorization, and this slice exposes no cancellation capability or inferred Running state.

cancel_capture is disabled by default alongside request_capture; when enabled it needs evidence:capture and current requester/workload cancellation authority, expected revision and idempotency key. It stops remaining collection, does not erase artifacts or retract shares, and never reruns/resumes work. Return cancellation_requested and current phase; a sent cancellation is not proof a profiler or kernel operation stopped. All capture-workflow tools retain strict schemas, audit, privacy, request/output limits and no automatic approval.

### SC-MCP-005

Given an authorized agent with collection enabled but no hashes, when it discovers a workload, previews incident-context and submits the handle, then it can poll the same capture and reach the resulting case. An intrusive preview leads to browser approval; context can progress independently. Replayed submission after preview expiry returns the same capture; a foreign handle, changed parameters or a received share cannot authorize collection. Cancellation cannot delete evidence or revoke shares implicitly.

## Guided selection

REQ-GDE-001–006 in [guidance](guidance.md) add `get_target_discovery` and `recommend_diagnostics`, with strict [projection contracts](contracts/guidance.schema.json). Both are read-only tools using `evidence:read` plus current target collection eligibility; read-only annotations never authorize live process/packet collection. The existing `evidence:capture`/disabled-by-default submission gate controls every new survey. Recommendation focus may name up to 16 process references and/or 16 flow references from supplied discovery captures, so agents can refine plans without copying PIDs or peer addresses. Resolve all references against caller/client and current source rights; they constrain the recommendation, not execution authority. If a durable selector also matches other processes or peers, show the expanded set and require the ordinary explicit plan selection; never silently discard a focus constraint. Unsupported or conflicting focus yields a useful blocker.

`preferences.max_bytes` caps aggregate acquired output across selected pods; `max_ring_bytes` separately caps their total live ring allocation. Show frozen/parser/scratch reservations alongside these values; neither field overrides administrator resource accounts.

Recommendation preferences constrain proposed plans; an impossible history/byte/impact combination returns explicitly blocked choices and alternatives, not an automatically relaxed preference. Source captures must belong to the same pinned workload/pod scope; mixed incarnations are stale-context errors. With no source capture, only capability/catalog-based suggestions are possible and missing observations are explicit. All result-group handles count together against the existing planning cache limit. User-supplied strings and evidence-derived names remain untrusted data.

## Repeating from history

The strict [history projections](contracts/capture-history.schema.json) back list_capture_history and get_capture_settings. Agents can list by target_handle (or explicit cluster/target selector), then call preview_capture(history_capture_id) and request_capture(preview_id, idempotency_key). No new mutation tool is needed. Optional repeated_from_capture_id in preview/submission/status is provenance only and does not authorize reading that source. History selection cannot be combined with a target, diagnostic or preset override; edit a draft through the existing normal authoring path with a new preview and optional repeated_from_capture_id provenance. The provenance requires source access, restores nothing implicitly and is mutually exclusive with history_capture_id. Expired parameters, stale exact identities and disabled dependencies produce specific blockers. SettingsTooLarge returns authenticated navigation; large parameter snapshots never bypass tool output ceilings and need not be fetched to repeat by reference.

## Capture-profile composition and syscall projections

[Capture profiles](capture-profiles.md) reuse preview_capture → request_capture → get_capture. Full composition provenance in a preview is an extract and subject to the ordinary byte bound. If it cannot fit, return a bounded error with authenticated browser navigation; do not silently drop component settings or approval-relevant differences. List/detail are passive and require current target eligibility plus the relevant catalog visibility. Save/publish remains Kubernetes configuration, not a new MCP mutation or permission CRUD API.

[Syscall evidence](syscalls.md) adds two approved extract tools and syscall_query to the typed raw-operation set. The latter has no live tracing, pointer dereference or code-execution operation. Bound scan work as well as returned rows; shared views select only permitted artifacts/projections. get_query_result rechecks the same scope/grant at delivery. Argument-bearing results, tool strings and catalog descriptions are untrusted data.

## Lifecycle-aware planning

list_capture_profiles rows include execution_modes; preview_capture always includes lifecycle_plan (action-lifecycle/v1), resolving per-action mode, policyArming versus manualSession and requested history/post-window. These fields contain configuration/metadata only and do not arm anything. get_capture reports incident progress; policy source readiness is separate. Recommendations and history repeat pass through this same compiler and cannot treat a ten-second live profiler as prior history or a delayed newly started ring as pre-trigger evidence. No new tool can bypass source approval or start an unbounded recorder.

## Impact assessment and handling notices

preview_capture success requires capture_assessment under the [assessment contract](contracts/capture-assessment.schema.json). It binds execution_digest and action modes, separates known effects from uncertainty, labels limits/estimates/measurements and describes data exposure and effective retention. A blocker still disables collection; the assessment grants no authority. Browser and GitOps use the same evaluator under [REQ-ASM-001–005](capture-assessment.md).

get_case/list_artifacts descriptors require handling_notice with possible contents, expiresAt/deleteBy, current deletion state/asOf and managed-copy/external-copy boundaries. Derive this only for authorized descriptors; sharing one extract cannot expose its hidden raw parent. Direct evidence queries retain a concise handling reminder in the ordinary warnings array so opening the case is not a prerequisite. The server returns notices in structured/text views but cannot force an external agent to display them. These fields add no tool or approval mutation and remain inside existing result limits.

## Saving existing recordings

[Recording saves](recording-saves.md) add two passive tools: list_recordings for authorized ongoing-source inventory, and preview_recording_save for a bounded selection/lookback and incremental impact/privacy assessment. They use existing metadata result limits and principal/client-bound handles, and do not freeze/read buffers. Submit with request_capture(preview_id, idempotency_key); get_capture and cancel_capture handle the resulting operation=recordingSave. The existing mutation enable switch, OAuth scope and current workload permissions apply. No tool accepts a policy trigger event, arbitrary source ID, post-window, core/command or filter override.

get_capture_settings returns either ordinary captureSettings or recordingSaveSettings. A saved-recording history entry has origin=manual, operation=recordingSave and repeat_state=requiresSelection while usable; ordinary preview_capture redirects it to fresh inventory. A schema-valid handle alone never authorizes access, and partial/expired sources are never silently replaced. A raw-result share still confers no inventory/capture rights.

## Live watching of existing sources

[REQ-LIV-001–006](live-watch.md) add five typed tools and the [live contract](contracts/live-watch.schema.json). The catalog also includes request recovery without new collection authority. `list_live_sources` is separate from policy-save inventory because finite manual sessions may be watched without gaining the policy-only save capability. Open/update/close are enabled viewer-state operations under evidence:read plus current source eligibility; they do not enable request_capture/cancel_capture or require evidence:capture. Opening a watch is explicit user/agent intent and never acquisition. Source selection/projection are immutable for that watch; only a typed approved display filter and pause state can change.

Use `read_live_watch` with bounded wait/rows and server retry advice. Its next_cursor continues an active stream, including when the current batch is empty; it does not promise unread historical rows. Timeout/connection loss does not close the watch or extend its original deadline. Retry is bounded, reauthorized and charged; stale view revisions or expired replay yield a gap/fresh position rather than an unbounded backlog. No tool creates a raw live grant, subscribes to hidden sources, invokes arbitrary expressions or returns an infinite stream. Both supported MCP protocol profiles use these bounded tools; notifications are not required. Live row references identify transient source observations, not durable artifact citations.

Stateless HTTP remains a transport property. LiveWatch is domain query state, like an analysis handle, not a connection-bound MCP session. Any authenticated hub replica can resolve its SQL control record and dispatch a bounded read to the current fenced projection owner through internal service routing; no client/load-balancer affinity is required. A lost owner yields an explicit replay gap or terminal view, never an invisible renewal or resurrected buffer. Old owners lose delivery authority when their fence/lease is invalidated.

## Native-file handoff

`prepare_artifact_download`, `get_artifact_download` and `cancel_artifact_download` share browser contracts. Preparation requires explicit user intent plus evidence:download and current artifact access; raw files additionally require evidence:raw and an existing grant covering download_artifact. Results contain status and, when available and currently authorized, the complete verified native filename/size/format/checksum group. Ready/Streaming/Interrupted require that group and an authenticated application content path; terminal states expose neither content path nor resume. Completed may return status without native metadata after the regional result cache is gone, including after the original transfer deadline while current evidence metadata authority still permits disclosure. Do not infer local file persistence or checksum verification from Completed. Status reads never re-prepare evidence. Results never contain file bodies, base64, credentials or presigned URLs. An OAuth-capable client uses the separate streaming HTTP endpoint outside the model context; browser handoff rebinds to that browser principal/client. Existing bounded raw-query tools remain useful and unchanged. See [downloads](artifact-downloads.md).

The native download resource has its own protected-resource metadata at `/.well-known/oauth-protected-resource/downloads`, pinned to the installed origin and issuer. Clients obtain authorization for that exact resource and original client identity; an MCP audience alone does not authorize the content endpoint. The fixed HTTP preflight audit is not advertised as a tool. Native bytes remain outside all model responses and transcripts.

Advertise evidence:download as an optional file-transfer scope alongside evidence:read; it is not raw eligibility. Raw native transfers still use the existing evidence:raw challenge and explicit artifact grant. File content is excluded from ordinary MCP response-byte/token budgets because it travels on the separate fully accounted HTTP transfer, not because those budgets are bypassed.

## One review for collection and investigation

preview_capture and expanded request_capture accept result_access as a finite instruction, not a grant. It selects output action IDs, operations, registered clients for the same human and aggregate limits/deadline; the planner resolves friendly UI selections. Submit-by-preview forbids overriding it. preview_capture returns the resolved result_access scope; get_capture returns current result_access state and authorized child grant IDs. Use [investigation-access.schema.json](contracts/investigation-access.schema.json) and [REQ-INV-001–003](investigation-approval.md). Selecting an agent client is explicit. Artifact tools reuse exact current child grants automatically; unrelated clients/principals need their own review. A pending access materialization never asks the agent to recollect evidence.
