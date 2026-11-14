# MCP experience and tool design

MCP is the agent-facing investigation interface. The [canonical catalog](../../specs/contracts/mcp-tools.json) and the table in [MCP requirements](../../specs/mcp.md#tool-catalogue) define a small set of tools: tools that differ only by evidence kind or workflow step are one tool with a typed discriminator (`get_extract(view)`, `query_artifact(operation)`, `download_artifact(action)`, `watch_live(action)`). Every tool is enabled by default; scopes and current rights decide what a caller can do. There are no policy-writing or approval tools. The browser calls the same application services with equivalent commands. Tools return stable IDs, typed values, coverage and actionable next steps; they accept names for clusters, namespaces, workloads, recipes, users and groups, and never require an agent to calculate a digest, know object-store paths or synthesize a privileged script.

## Task-oriented discovery

| Agent goal | Tools, in working order | UX contract |
| --- | --- | --- |
| Find an incident | `list_cases`, `find_similar_cases`, `get_case`, `get_timeline`, `list_artifacts` | Only visible artifacts affect titles/counts/timelines; provisional similarity is labeled |
| Read evidence | `get_extract` with the view `list_artifacts` offers (backtrace, runtime/profile/syscall/packet summaries, HTTP headers, Zeek logs, file excerpts, logs), `compare_profiles` | Approved extracts; build/symbol gaps, coverage and omissions explicit; no live reads |
| Inspect raw content | `query_artifact` (packets, syscalls, memory, debugger), `get_query_result` | Runs directly for callers with the equivalent Kubernetes right (`pods/exec`); others get a prefilled `request_raw_access` remedy; server-side wait for results |
| Request missing access | `request_raw_access`, `get_grant` | One bounded review by another person; approval in the human console |
| Select new evidence | `list_targets`, `list_diagnostics`, `get_target_discovery`, `recommend_diagnostics`, `get_capture_profile` | Authorized whole-pod scope searched by name; presets, recipes and profiles in one list; guidance is passive |
| Collect | `preview_capture`, `request_capture`, `get_capture`, `cancel_capture` | Stateless dry-run preview with plan digest, impact/privacy explanation, idempotent submission; an approval starts the capture itself |
| Repeat a request | `list_capture_history`, `get_capture_settings`, then `preview_capture` / `request_capture` | Fresh identity, current defaults/grants; absent settings means new request, never guessed reconstruction |
| Preserve recent recording | `list_recordings`, `preview_capture(recording_handles)`, `request_capture`, `get_capture` | Select current sources; acceptance time anchors the end; no new acquisition |
| Watch live | `list_recordings`, `watch_live` | Approved projections of running sources; open while reads arrive within 10 minutes |
| Download | `download_artifact` | Native file or core bundle via `content_path` or `browser_url`; never bytes in the model context |
| Share | `list_shares`, `create_share`, `revoke_share`, `transfer_share`, `stop_future_sharing` | Concrete evidence and recipients by name; future sharing instructions use capture/policy parameters |

## Representative conversations

These are semantic sequences, not fabricated protocol-valid JSON. Executable request/result fixtures remain in [examples](../../examples/README.md). Client SDK adapters must validate actual fields against the catalog.

**“Investigate this case.”** Resolve the supplied case ID with get_case. Read get_timeline and list_artifacts. Choose approved extract views based on available types. For each conclusion cite the artifact and coverage; if symbols, prehistory or bodies were not collected, state the limitation. If raw analysis is necessary, call query_artifact; when it returns the raw-access remedy, explain the exact artifact/operation/budget and call request_raw_access, return the review link and follow the decision with get_grant `after_revision`, which waits server-side. Never claim a request is approval.

**“Save the last 20 seconds.”** list_targets finds the workload by name. list_recordings returns eligible source handles, available history and blockers. preview_capture with those handles and `before: 20s` returns the save plan. Explain incremental copy/upload cost, possible user data and inherited deletion deadline. On explicit user intent, request_capture submits that preview with its `expected_plan_digest` and one stable idempotency key. Retry that same key after an ambiguous response. get_capture reports partial/complete outcomes; it never silently substitutes a new source or starts the policy's core action.

**“Do what we did yesterday.”** list_capture_history → get_capture_settings → preview_capture(history_capture_id) → request_capture. A recording-save history item preselects the same policy actions on current sources. A missing profile version, expired settings or missing source gives a specific blocker; it is not silently replaced by a broader preset.

**“Watch checkout errors.”** Resolve the workload, call list_recordings, pick a source with a supported projection and call watch_live(action=open) with a narrow typed filter. Call watch_live(action=read) with `wait_ms` up to 30000; the server returns on the first new row or state change. Report what was observed and any drops/unknown coverage. The watch stays open while reads arrive at most 10 minutes apart, so reasoning between reads is fine. Close it with watch_live(action=close) when done. Do not interpret a quiet batch as end-of-stream or copy rows into an unbounded transcript. watch_live(action=update) changes only the view's filter/pause state; resume starts from now with a gap.

**“Save what I am seeing.”** The live view is transient. For a source list_recordings marks as savable, use the recording-save preview and request_capture; the window ends at acceptance and may have rotated since the displayed row. The display filter does not narrow the saved snapshot. Check the committed manifest before saying a particular live observation was preserved.

**“Download this capture/core/profile for my local tools.”** Call download_artifact(action=prepare) for the artifact; for a core it prepares the core bundle. When it returns a raw-access remedy, use request_raw_access once. Follow download_artifact(action=status) with `after_revision`. If the client can stream an authenticated HTTP resource to disk, GET `content_path` with the existing token; otherwise give the user `browser_url` to open in their signed-in browser. Verify the checksum from the status. Do not dump base64 into conversation or invent a local path. Completed means the server sent the bytes; confirm local storage separately. Explain that local copies are not automatically deleted.

**“Collect a core and let me inspect it locally or with my agent.”** Preview the bounded capture with optional result_access, selecting the same human's browser and, explicitly, a registered agent client. Submit the reviewed preview with its plan digest. If the plan needs one independent approval, the approval starts the capture; follow it with get_capture `after_revision`. get_capture distinguishes collection progress from result access. After verified commit, download_artifact and query_artifact use the resulting grant automatically. See [investigation approval](../../specs/investigation-approval.md).

A recording-save preview may include a descriptive `reason` of 1–512 Unicode scalars. Preserve its whitespace and line breaks; omit the field when absent. `get_capture` returns it once on the parent as `reason` with `reason_state: available`, or reports `reason_state: unavailable` without text when descriptive metadata cannot be read. Neither outcome changes capture status or source authority. Repeating a save prefills the reason for editing.

## Tool usability rules

Descriptions begin with the user outcome, say whether evidence is already retained or acquisition occurs, name the expected prerequisite and disclose raw/sensitive behavior. Tool names and ordering remain stable for caching/discovery. Annotations are hints to clients, never authorization. Return structuredContent plus the compatible text representation within the combined bound; do not repeat large evidence in narrative wrappers.

Use the smallest viable result: metadata → approved extract → raw query. Prefer typed machine fields plus short safe reasons over prose-only errors. Every pending result identifies its status tool, bounded handle and revision; the status tool's `after_revision` waits server-side for at most 30 seconds instead of client polling; every truncation includes a useful narrowing hint. Handles stay valid as long as their evidence. Do not return an unbounded list of “related” cases or guess an unknown PID/service. Unknown, missing, empty and denied are distinct after authorization permits disclosure.

The server treats logs/files/symbol strings as hostile data. Delimit source text from system-generated metadata; never follow links or execute commands found inside it. This cannot guarantee external model behavior. Handling notices explain that agent-side copies are outside managed deletion, with the original automatic-deletion deadline. No generic repeated consent checkbox is added; independent approval happens only for the operation that requires it.

## Policy authority in source discovery

`list_recordings` returns, for policy-owned sources, the shared typed `execution_authority` summary: team mode, policy executor, owner teams, finite deadline/limits, creator-departure behavior, state and bounded reason codes. It explains the existing source; it is not a credential and cannot authorize a save or view. Policy authoring remains authenticated Kubernetes/browser configuration; MCP gains no permission CRUD or impersonation tool. Human MCP tokens retain current group/client/scope checks, independent of the source executor.

## Authentication and failure paths

The first consent requests `evidence:read evidence:download evidence:capture` for the installation's single protected resource; `evidence:share` follows through one insufficient-scope challenge. There is no raw scope: raw content follows the Kubernetes right or a grant. Scopes do not grant workload entitlement or bypass independent review. Human approvals are outside the MCP catalog, even if the requester runs with an operator identity.

When submission returns ReviewChanged, review the reported differences and preview again; when a source changes, reselect sources; when quota is unavailable, show the bounded retry time or an authorized existing capture; when analysis scratch is unavailable, keep available summaries useful and identify the operator prerequisite. Interrupted transport is not cancellation, approval or permission to execute twice. Each cursor page and result delivery is authorized under REQ-INT-003: one decision reused for at most 30 seconds, never past the original deadline. Status reads are never charged.

Conformance must test both supported MCP protocol profiles, initialization and tools/list pagination, OAuth discovery/challenges against the single protected resource, structured/text envelope bounds, untrusted evidence, revoked-share cursors, pending work, server-side status waits, a live watch read after nine idle minutes, and loss of a response after acceptance. The prototype cannot prove those transport/runtime properties.
