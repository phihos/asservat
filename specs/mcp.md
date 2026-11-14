# MCP interface

## REQ-MCP-001 — Transport and protocol

Serve `/mcp` with the official Go SDK (candidate `v1.8.0`) over Streamable HTTP, stateless, for protocol revisions `2026-07-28` and `2025-11-25`. No sticky session is required. Use the SDK's discovery/initialization per revision; do not imitate new wire fields on old clients.

Every tool has strict `inputSchema` and `outputSchema`, returns structured content and a text mirror for older clients. Evidence responses carry `Cache-Control: no-store`. Validate Host/Origin and content type; reject anonymous cross-site requests, bodies larger than the called tool's largest valid input, JSON nested deeper than its schema and method/name header mismatches. Concurrent tool calls need no separate cap: running queries are bounded by query concurrency ([REQ-AUT-004](authorization.md#req-aut-004--budgets-reservations-and-revocation)).

No Sampling, Roots, Logging, DCR dependency, server-side LLM, agent harness or approval through elicitation. Resource links are optional authenticated mirrors, not bearer capabilities. [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic), [Go transport documentation](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/docs/protocol.md).

### SC-MCP-001

Given representative clients for both revisions, when they call discovery/list/tools across two replicas, then both work without transport-held authorization state. Forged header/body routing disagreements and oversized frames are rejected.

## Tool catalogue

The machine-readable catalog is [mcp-tools.json](contracts/mcp-tools.json); this table lists every MCP tool. The browser calls the same services with the same contracts. Tools that differ only by evidence kind or by workflow step are one tool with a typed discriminator ([ADR-335](../docs/decisions/335-usable-by-default.md)). Every tool is enabled by default; OAuth scopes and current rights decide what a caller can do.

| Tool | Purpose | Access and bounds |
| --- | --- | --- |
| `list_cases` | Filter by cluster, workload, time, signature, shared-with-me; optional `text` ranks similar cases | Authorized cases only; deterministic ranking |
| `get_case` | Case, artifacts, capture gaps and the time-ordered timeline (cursor pages) | Shared callers see only the shared projection; source-clock uncertainty included |
| `list_artifacts` | Authorized artifact descriptors, provenance and the extract views each supports | No storage paths, wrapped keys or credentials |
| `get_extract` | Approved extract of one artifact; `view` = `backtrace`, `runtimeSummary`, `profileSummary`, `syscallSummary`, `syscallEvents`, `pcapSummary`, `httpHeaders`, `zeekLog`, `fileExcerpt` or `logs` | View must match the artifact kind; ordinary read rights; no live reads, bodies, local variables or argument data |
| `compare_profiles` | Baseline/incident deltas or normalized rates | Authorize both artifacts; reject incompatible sample types/units |
| `query_artifact` | Typed query of saved evidence; `operation` = `packets`, `syscalls`, `memory` or `debugger` | Raw operations need the equivalent Kubernetes right or a covering grant (REQ-MCP-003) |
| `get_query_result` | Result of a pending query | Optional server-side wait; never charged |
| `request_raw_access` | Request a grant for raw queries or downloads the caller cannot already perform | Creates a pending grant; collects and discloses nothing; reason required for the reviewer |
| `get_grant` | Own grant state and remaining quota; optional server-side wait | Requester/approver views; others get the unknown-ID reply (ADR-249). The approval inbox is browser-only |
| `download_artifact` | `action` = `prepare`, `status` or `cancel` a native download or core bundle | `evidence:download`; metadata, `content_path` and `browser_url`, never bytes ([downloads](artifact-downloads.md)) |
| `list_shares` | Owned/received shares; optionally the sharing instructions of owned captures and policies | Administrators get a management view without recipients |
| `create_share` | Share evidence with users or groups by name | Sharing authority; raw sharing may need approval |
| `revoke_share` | Revoke one share or a sharing instruction and its dependent shares | Current managers and administrators; expected revision and idempotency |
| `transfer_share` | Replace the managing owner teams of one share | Current manager or administrator; creator, recipients and expiry unchanged |
| `stop_future_sharing` | Stop future sharing of a policy; existing shares stay | Creator, owner-team member or administrator; changes no collection authority |
| `explain_access` | Explain the caller's own Allow/Deny/Indeterminate decision for one workload and operation | Caller only; real evaluator; no evidence lookup |
| `list_targets` | Search authorized clusters, namespaces, workloads and pods by name | Collectable whole-pod scope only; no share-based inventory |
| `list_diagnostics` | Presets, recipes, capture profiles and discovery diagnostics for a target, with execution modes | Stateless handles; no digest entry |
| `get_capture_profile` | Versioned capture-profile definition and editable fields | Target/catalog visibility; no secret material |
| `get_target_discovery` | Approved process/flow/coverage projections of a discovery capture | Source artifact access and target eligibility; no acquisition |
| `recommend_diagnostics` | Ranked diagnostics for a goal, as previewable handles | Passive ([guidance](guidance.md)) |
| `list_recordings` | Running and stopped packet/syscall sources with history, save eligibility and live projections | Evidence-read on the source audience; save rows need collection rights |
| `preview_capture` | Dry run of a new capture, a repeat from history or a save of existing recordings | Returns the resolved plan and `plan_digest`; stores nothing |
| `request_capture` | Submit a previewed capture or save, with optional result sharing and result access | `evidence:capture`; an approval, when required, starts it |
| `get_capture` | Collection, approval and partial outcomes; optional server-side wait | Requester, workload maintainer or administrator |
| `cancel_capture` | Stop remaining collection | `evidence:capture`; revision and idempotency |
| `list_capture_history` | Previous accepted captures for one workload | Current history rights |
| `get_capture_settings` | Retained parameters of one capture for review/editing | No credentials, grants or sharing |
| `watch_live` | `action` = `open`, `read`, `update` (pause/resume/filter) or `close` a live view | Viewer state only ([live watch](live-watch.md)) |
| `deactivate_policy` | Stop an accepted policy | Sponsoring-group maintainer; idempotent |
| `get_policy_status` | Policy acceptance, counters, sharing state and grant | No content |

Sharing semantics, including collection-time and recurring sharing, are owned by [REQ-SHR-004–008](authorization.md#req-shr-004--share-results-when-requesting-collection). `create_share` resolves recipient names against installation principals and groups ([ADR-335](../docs/decisions/335-usable-by-default.md) D4); an ambiguous or unknown name returns candidates instead of a share. Reasons are optional except for `request_raw_access`.

## REQ-MCP-002 — Bounded result contract

One result pattern applies to every tool:

- **Envelope.** `schema_version`, `request_id`, `data_class` (the most sensitive class in the result), `status` (`ok`, `pending` or `error`), `data`, `truncated`, `next_cursor`, `narrowing_hint`, `warnings` and provenance references.
- **Size.** The whole MCP response is at most 96 KiB, derived from the common client tool-output limit (Claude Code `MAX_MCP_OUTPUT_TOKENS` 25,000 tokens ≈ 100 KB; the MCP specification sets none), and aims at 24 KiB to leave room in the model context. There is no caller-selected byte budget.
- **Pages.** List-shaped results take an optional `limit` (rows) and `cursor` and end a page at the row limit or the size target, whichever comes first. `truncated=true` comes with a narrowing hint, and a cursor only when more authorized data exists. Cursors are opaque, HMAC-authenticated, bind query parameters and principal/client, carry no secrets and do not expire; each page is authorized under REQ-INT-003, so a revoked share fails within the 30 s reuse ([ADR-311](../docs/decisions/311-operation-authority-recheck.md)).
- **Pending work.** Long work returns `status=pending` with a server-minted `query_handle` and a `revision`. Status tools (`get_capture`, `get_grant`, `get_query_result`, `download_artifact(action=status)`) accept `after_revision` and hold the call until the revision changes or at most 30 s ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1), woken by PostgreSQL `LISTEN/NOTIFY`. Status reads are never charged. A handle stays valid as long as its source evidence is readable (ADR-335 D9). `get_query_result` validates its nested result against the original tool's output schema, never starts another query, and returns the same result after a lost reply.

Queries over saved evidence run in the long-running regional reader ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D4). A query's input scan is bounded because reader CPU and decryption grow with it: by default the artifact size when it is at most the configured capture or ring size, otherwise reader throughput × query wall time; administrators may set a maximum. 5 s is only an I/O timeout (ADR-330 D5). Query results carry `query_observed_at` and `query_expires_at` (the cutoff from the original evidence/access deadlines); neither extends authority. A disclosure and its audit row commit in one transaction; without the audit row nothing is disclosed.

### SC-MCP-002

Given a query with more output than the byte bound, when it completes, then truncation is explicit and the result remains valid JSON. Reusing its cursor under another principal, a revoked share or modified filter is rejected.

### SC-MCP-006

Given an authorized browser or MCP reader and a committed pod-status artifact, when `get_extract(view=fileExcerpt)` reads the selected lines, then both return the same fixed `pod-status.txt` projection ([context projection](../docs/architecture/context-projection.md)) without download scope, new collection or extra consent. Given a known query handle and a lost reply, a later `get_query_result` returns the same result without another read; a reader whose access was revoked is refused within 30 s. When the audit row cannot be written nothing is disclosed.

## REQ-MCP-003 — Typed raw operations

A `query_artifact` operation that returns raw content (`syscalls`, `memory`, `debugger`, and `packets` over a raw original) is admitted when the caller holds the equivalent Kubernetes right on the recorded workload's namespace (`pods/exec`, [ADR-335](../docs/decisions/335-usable-by-default.md) D5) or a covering grant for that artifact and operation; otherwise it returns the prefilled `request_raw_access` remedy, not data. Metadata-only packet queries need ordinary read rights.

Every operation takes an `idempotency_key` bound to the normalized selection and the original human/client: a retry returns the stored outcome or the running query; a changed selection conflicts. A grant is charged the delivered bytes and one operation in the same transaction as the audit row; an operation that delivers nothing is charged nothing (ADR-330 D7). Grant pools are owned by [investigation approval](investigation-approval.md). SQL, audit rows and logs keep only the bounded selection and identity, never rows, frame bytes or argument values. A query creates no capture, derivative, native download or history entry, and never reads a live process.

- `debugger` accepts an enum command (`backtrace`, `threads`, `registers`, `frame_variables`, `managed_stack`, `heap_statistics`) plus validated thread/frame selectors. The server builds fixed debugger scripts or MI calls. No shell, Python, debugger expressions, `source`, redirection, extension loading or `print` expressions; an allowlist applied to free text is not enough.
- `memory` needs a collected core, a validated address range and the artifact digest; it returns at most 32 KiB per call, default 8 KiB (hex doubles the size, so it fits the 96 KiB bound and the 24 KiB target).
- `packets` uses the packet-filter, field catalog and scan rules of [saved packet queries](packets.md#req-net-005--provenance-mcp-and-qualification).
- `syscalls` selects names/errors in a saved argument recording ([REQ-SYS-003](syscalls.md#req-sys-003--evidence-projections-and-mcp)).

### SC-MCP-003

Given a malicious debugger command or packet filter containing file access, shell syntax, unbounded regex or unsupported functions, validation rejects it before any query or grant spend. A permitted backtrace cannot load target-provided Python pretty-printers. A metadata-only packet query needs no raw grant, while header-only selection from a raw original still needs raw authority. A frame that fails authentication returns no page. Retrying an uncertain query with its original key creates no second query or charge; a changed selection conflicts.

## REQ-MCP-004 — OAuth and untrusted evidence

Asservat is one OAuth protected resource identified by the installation origin (`https://<host>`). Its RFC 9728 metadata is at `/.well-known/oauth-protected-resource`, and every 401/403 from `/mcp` and from `/api/v1/downloads/{download_id}/content` names it in `resource_metadata`. A token for that audience is valid at both endpoints; the hub is the resource server for both, so this is not token passthrough. Validate issuer, audience and client strictly against configured issuers and preregistered clients. This follows the MCP authorization specification ([2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)), which accepts an origin without path as the canonical URI and defines no file transfer.

`scopes_supported` and the first 401 challenge are `evidence:read evidence:download evidence:capture`. `evidence:share` is requested through one insufficient-scope challenge that names every scope the operation needs. There is no raw scope: raw content is gated by the Kubernetes right or a grant. Scopes never grant workload entitlement. Step-up re-authentication is optional and off by default (ADR-335 D5).

Evidence text is untrusted data. Tool descriptions and result schemas state that logs, files and source excerpts may contain attacker instructions. Keep provenance, user content and system summaries separate; never turn content into tool instructions or follow embedded URLs. No tool remediates a workload or executes a suggestion found in evidence.

### SC-MCP-004

Given a log containing instructions to disclose another case, when retrieved, then it remains labeled evidence text and causes no server-side tool execution, credential access or URL fetch. An insufficient scope response does not approve a grant.

## Errors

Stable application codes in the result envelope: `NotAuthorized`, `GrantRequired`, `ShareExpired`, `EvidenceExpired`, `CapabilityUnavailable`, `TargetGone`, `BudgetExceeded`, `IndexRebuilding`, `AnalysisUnavailable`, `ArtifactIncomplete`, `InvalidCursor`, `AuditUnavailable`, `ClusterOffline`, `RetryLater`. Before access is established, not-found and not-authorized look the same. Transport authentication errors use OAuth HTTP semantics; malformed calls use protocol errors. Error text never contains evidence or credentials.

## REQ-MCP-005 — Complete capture workflow

A client with `evidence:capture` uses list_targets → list_diagnostics → preview_capture → request_capture → get_capture, then the case tools. A shared-evidence reader gains no workload inventory. Target and diagnostic handles are stateless, opaque encodings of the listed reference bound to principal/client; they are resolved again with current checks on use and are not bearer permissions.

`preview_capture` takes a target (handle or cluster/namespace/kind/name) and exactly one of a diagnostic handle, a preset, a `profile_composition`, a `history_capture_id` ([REQ-HIS-004](capture-history.md)) or `recording_handles` ([REQ-SAV-004](recording-saves.md)). It is a dry run ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D9): it resolves pod scope, capabilities, limits, retention, sharing and approval requirements, returns the plan, the `lifecycle_plan` ([action lifecycles](action-lifecycle.md)), the `capture_assessment` ([assessment](capture-assessment.md)) and a `plan_digest`, and acquires, arms and reserves nothing. Optional `requested_retention_seconds` is clamped by the administrator maximum (ADR-335 D7). A composition that does not fit the result bound returns an error with browser navigation, never a silently shortened plan. The fixed `pod-status/v1` preset resolves one pod and one on-trigger action ([paired synthetic example](../examples/mcp-pod-status-preview-result.json)).

`request_capture` takes the previewed request with `expected_plan_digest` and an `idempotency_key` (browser: `Idempotency-Key`). A retry with the same key returns the original operation; a changed request under the same key is Conflict; a changed plan returns ReviewChanged with the differences. When the plan needs an independent approval, the approval itself starts the capture ([ADR-335](../docs/decisions/335-usable-by-default.md) D5). Optional `result_access` is a finite instruction for the same human's later inspection/download ([REQ-INV-001–003](investigation-approval.md)), not a grant. Status reads, reloads and session refresh never start or repeat collection.

`get_capture` returns the phase, the Conditions Accepted, Collected, Verified and Published ([state machines](apis.md#state-machines)), per-action progress, gaps, sharing and result-access state, case navigation and `revision`. Wall-clock passage alone never changes the phase. `cancel_capture` stops remaining collection; it does not erase artifacts or retract shares, and a sent cancellation is not proof that a profiler or kernel operation stopped.

### SC-MCP-005

Given an authorized agent with `evidence:capture` but no hashes, when it discovers a workload, previews incident-context and submits the previewed request with its plan digest, then it can follow the capture with get_capture and reach the resulting case. An intrusive preview leads to browser approval, after which the capture starts without another submission. A replayed submission with the same key returns the same capture; a changed plan is reported as ReviewChanged; a foreign handle or a received share cannot authorize collection. Cancellation deletes no evidence and revokes no shares.

## Native-file handoff

`download_artifact(action=prepare|status|cancel)` shares the browser contract ([REQ-DLD-002](artifact-downloads.md#req-dld-002--reuse-authority-review-only-where-required)). Status returns the verified native filename, size, format and SHA-256 while the caller may read the metadata; ready and interrupted sessions also return `content_path` and `browser_url`. A client that can stream an authenticated HTTP resource to disk GETs `content_path` with its existing token; any other client gives the user `browser_url`, which the same human's signed-in browser opens without another consent. File bytes never enter MCP results, which hold no base64, credentials or presigned URLs. Completed does not prove the file was stored locally.
