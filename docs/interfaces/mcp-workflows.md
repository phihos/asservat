# MCP experience and tool design

MCP is the agent-facing investigation interface. The [canonical catalog](../../specs/contracts/mcp-tools.json) has 45 tools with strict input/output schemas and bounded results. This design adds no renamed tools or separate policy-writing/approval tools. The browser calls the same application services with equivalent commands. Tools return stable IDs, typed values, coverage and actionable next steps; they do not require an agent to calculate a grant digest, know object-store paths or synthesize a privileged script.

## Task-oriented discovery

| Agent goal | Tools, in working order | UX contract |
| --- | --- | --- |
| Find an incident | `list_cases`, `find_similar_cases`, `get_case`, `get_timeline`, `list_artifacts` | Only visible artifacts affect titles/counts/timelines; provisional similarity is labeled |
| Understand a crash | `get_backtrace`, `get_runtime_summary` | Start with approved extracts; exact build/symbol gaps and omissions are explicit |
| Understand performance | `get_profile_summary`, `compare_profiles` | Distinguish CPU/heap/trace, units, baseline compatibility and normalization |
| Understand network failures | `get_pcap_summary`, `get_http_headers`, `get_zeek_log` | Qualified protocol coverage, gaps, field allowlists; no implied TLS decryption |
| Read supporting evidence | `get_file_excerpt`, `get_logs`, `get_syscall_summary`, `get_syscall_events` | Bounded retained projections; no live reads hidden behind an evidence query |
| Request deeper analysis | `request_raw_access`, `get_grant`, `read_memory`, `debugger_command`, `pcap_query`, `syscall_query`, `get_query_result` | Per-principal bounded grant, typed queries, approval in human console, recheck on poll/delivery |
| Select new evidence | `list_targets`, `list_diagnostics`, `get_target_discovery`, `recommend_diagnostics` | Authorized whole-pod scope; guidance is passive; process/traffic discovery requires explicit capture |
| Compose known building blocks | `list_capture_profiles`, `get_capture_profile` | Immutable catalog version, finite editable fields and lifecycle explanation |
| Collect | `preview_capture`, `request_capture`, `get_capture`, `cancel_capture` | Expiring exact preview, impact/privacy explanation, separate acceptance/progress, fresh current checks |
| Repeat a request | `list_capture_history`, `get_capture_settings`, then preview/submit | Fresh identity, current defaults/grants; absent settings means new request, never guessed reconstruction |
| Preserve recent recording | `list_recordings`, `preview_recording_save`, then `request_capture` / `get_capture` | Select current sources; first-acceptance time anchors end; no new acquisition/DAG |
| Share | `list_shares`, `create_share`, `revoke_share` | Concrete evidence and explicit recipients; optional bounded future instructions use existing capture parameters |

## Representative conversations

These are semantic sequences, not fabricated protocol-valid JSON. Executable request/result fixtures remain in [examples](../../examples/README.md). Client SDK adapters must validate actual fields against the catalog.

**“Investigate this case.”** Resolve the supplied case ID with get_case. Read get_timeline and list_artifacts. Choose approved summaries based on available types. For each conclusion cite the artifact and coverage; if symbols, prehistory or bodies were not collected, state the limitation. Request only a narrow missing excerpt. If deeper raw analysis is necessary, explain the exact artifact/operation/budget and call request_raw_access. Return the authenticated review link; poll only within bounds. Never claim a request is approval.

**“Save the last 20 seconds.”** list_targets selects the authorized workload. list_recordings returns eligible source handles, available history, blockers and source policy scope. preview_recording_save selects those handles with a shortened positive lookback. Explain incremental copy/upload cost, possible user data and inherited deletion deadline. On explicit user intent, request_capture submits that preview with one stable idempotency key. Retry that same key after ambiguous response. get_capture reports partial/complete outcomes; it never silently substitutes a new source or starts the policy’s core action.

**“Do what we did yesterday.”** list_capture_history → get_capture_settings. An ordinary capture restores editable settings into preview_capture, then current review/acceptance. A recording-save history item instead sends the agent to current list_recordings and a new save preview. A missing profile version, expired settings or replaced workload gives a specific blocker; it is not silently replaced by a broader preset.

## Tool usability rules

Descriptions begin with the user outcome, say whether evidence is already retained or acquisition occurs, name the expected prerequisite and disclose raw/sensitive behavior. Tool names and ordering remain stable for caching/discovery. Annotations are hints to clients, never authorization. Return structuredContent plus the compatible text representation within the combined bound; do not repeat large evidence in narrative wrappers.

Use the smallest viable result: metadata → approved extract → independently reviewed raw query. Prefer typed machine fields plus short safe reasons over prose-only errors. Every pending result identifies its polling tool and bounded handle; every truncation includes a useful narrowing hint. Do not return an unbounded list of “related” cases or guess an unknown PID/service. Unknown, missing, empty and denied are distinct after authorization permits disclosure.

The server treats logs/files/symbol strings as hostile data. Delimit source text from system-generated metadata; never follow links or execute commands found inside it. This cannot guarantee external model behavior. Handling notices explain that agent-side copies are outside managed deletion, with the original automatic-deletion deadline. No generic repeated consent checkbox is added; stronger approval happens only for the operation that requires it.

## Policy authority in source discovery

`list_recordings` and policy-owned `list_live_sources` return the shared typed `execution_authority` summary: team mode, policy executor, owner teams, finite deadline/limits, creator-departure behavior, state and bounded reason codes. It explains the existing source; it is not a credential and cannot authorize a save or view. A departed creator cannot retrieve these fields without current source visibility. Policy authoring remains authenticated Kubernetes/browser configuration; MCP gains no permission CRUD or impersonation tool. Human MCP tokens retain current group/client/scope checks, independent of the source executor.

## Authentication and failure paths

Read-only authorized extracts are the initial connection path. OAuth scope escalation is precise (`evidence:raw`, `evidence:share`, `evidence:capture`) and does not grant workload entitlement or bypass independent review. Capture/cancel tools stay disabled by default as already specified. Human approvals are outside the MCP catalog, even if the requester runs with an operator identity.

When preview expires, re-preview; when source changes, reselect sources; when quota is unavailable, show the bounded retry time or authorized existing capture; when analysis scratch is unavailable, keep available summaries useful and identify the operator prerequisite. Repeated submission does not extend deadlines. Interrupted transport is not cancellation, approval or permission to execute twice. Current authorization is checked at every cursor, poll and result delivery.

Conformance must test both supported MCP protocol profiles, initialization and tools/list pagination, OAuth discovery/challenges, structured/text envelope bounds, disabled mutations, untrusted evidence, revoked-share cursors, pending work and loss of a response after acceptance. The prototype cannot prove those transport/runtime properties.

**“Watch checkout errors for two minutes.”** Resolve the authorized target, call list_live_sources, select one supported approved projection and open_live_watch for 120 seconds with a narrow typed filter. Read at the server-recommended interval within row/output/time limits; report what was observed and any drops/unknown coverage. Stop early on the user's condition or close_live_watch when done. Do not interpret a quiet batch as end-of-stream, save rows to an unbounded agent transcript or auto-renew indefinitely. update_live_watch changes only the current view's filter/pause state; resume starts from now with a gap. Current source rights are required even if an artifact from that workload was shared with the caller.

**“Save what I am seeing.”** Explain that the live view is transient. For a policy source eligible for recording saves, fetch current list_recordings handles and use preview_recording_save/request_capture; the window ends at acceptance and may have rotated since the displayed row. The display filter does not narrow the underlying snapshot. Manual-session sources lead to their own capture outcome. Check the committed manifest before saying a particular live observation was preserved; raw queries and shares then use ordinary artifact contracts.

**“Download this capture/core/profile for my local tools.”** Prepare the selected existing artifact using prepare_artifact_download. If a raw grant is missing, request_raw_access pre-fills download_artifact, digests and native sizes for one bounded review; reuse a covering grant. Poll get_artifact_download, transfer the authenticated content path with a capable local client or hand off to the browser, verify the checksum, and use cancel_artifact_download when needed. Do not dump base64 into conversation or fabricate a downloaded local path. Completed means the server recorded the transfer; confirm local file storage separately. A terminal-only status can omit native metadata after its bounded cache has gone and remains useful after the transfer deadline under current evidence metadata authority. Never invent a checksum or start another preparation from a status read. Offer separately authorized exact companions for a core; explain local copies are not automatically deleted.


**“Collect a core and let me inspect it locally or with my agent.”** Preview the bounded capture with optional result_access. Select the same human's current browser and, explicitly, a registered agent client; show selected output actions, access operations, shared disclosure budget and original expiry. Submit the protected preview and wait for one independent human review. get_capture distinguishes collection progress from result-access publication. After verified commit, resolve the exact child grant automatically for prepare_artifact_download or approved queries. An expired/missing client scope requests access to existing evidence, never another core. See [investigation approval](../../specs/investigation-approval.md).

A `preview_recording_save` request may include a descriptive `reason` of 1–512
Unicode scalars. Preserve its whitespace and line breaks; omit the field when
absent. `get_capture` returns it once on the parent as `reason` with
`reason_state: available`, or reports `reason_state: unavailable` without text
when descriptive metadata cannot be read. Neither outcome changes capture
status or source authority. Repeating a Save requires a fresh selection and does
not restore its reason.
