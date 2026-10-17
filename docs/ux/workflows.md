# Workflows and interaction contracts

The [surface catalog](surfaces.yaml) maps every screen to its persona and principal domain concept. Screen names use the user’s task. Operations and storage names stay out of ordinary product copy. There is one console; different identities see different authorized navigation and data projections. Organization/tenant selection and container configuration are absent.

## Information architecture

| Navigation | Primary question | Views |
| --- | --- | --- |
| Overview | What needs attention and what is available? | Own cases, capture progress, actionable blockers; counts use authorized rows |
| Workloads | What can I inspect or monitor? | Cluster/namespace/workload identity, all-replica coverage, capabilities, history |
| Cases | What happened? | Occurrences, evidence timeline, bounded viewers, analysis and agent handoff |
| Captures | Did my request finish, and what can I inspect now? | Contextual Requests, Recordings, Watch live and History views; independent action progress, partial artifacts, cancellation and approval links |
| Monitoring policies | What will trigger collection? | Trigger builder, ongoing/on-trigger evidence, readiness, grants and suppressions |
| Capture profiles (Tools) / History (Captures) | Can I reuse a known plan? | Immutable building blocks, typed adaptations, previous request settings |
| Approvals / Sharing | Who may do or read this? | Own requests versus reviewer queue; concrete shares versus future instructions |
| Connect agent / Your access | How can I investigate with my tools? | Authenticated reference, least-scope connection, current access explanations |
| Administration | Is the installation ready and bounded? | Fleet, permission sources, retention, capacity, integrations, audit, deletion |

The [design system](design-system.md) specifies section hierarchy and disclosure. The header contains an authorized parent breadcrumb; technical screen IDs stay in the prototype inspector. The sidebar highlights a detail view’s section. Avoid adding each subview as another permanent global destination.

A share recipient starts at Shared with me, not an empty workload dashboard. An approver starts at available approval requests; requesters can view their request without seeing approval controls. Operator and maintainer roles are independent in production. A reviewer sees only the scope needed for an eligible review, not blanket evidence-reader rights.

## Collection and guidance

| Step | Inputs / defaults | Validation and behavior |
| --- | --- | --- |
| Target | Current cluster/namespace/workload from navigation; pod scope | Resolve enrolled cluster and immutable namespace/workload identities; show selected and eligible counts; no container selector |
| Goal | Latency, memory growth, network failure, exits, custom | Deterministic goal-to-profile suggestions with capability/uncertainty reasons; no trial capture during suggestion |
| Compose | Pinned builtin/admin/team profiles; finite fields | Separate ongoing recording from on-trigger actions; unsupported profiles show a reason and supported alternatives |
| Processes (optional, applicable profiles) | Stable executable/runtime/descendant rule; explicit process cap | Show last discovery timestamp and source; PID is an advanced temporary choice; matching multiple processes is explicit |
| Network (optional, packet profiles) | Representation, site, peers, pcap filter, before/after, segmented ring | Validate grammar and bounds before preview; resolve Service/Deployment/StatefulSet peers; explain TLS/protocol qualification and uncertain PID attribution |
| Advanced | Files, runtime-profile endpoint reference, bounded argv, dependencies | Typed finite options; configured endpoint references, no arbitrary remote URLs; approved command semantics |
| Review | Exact target, action lifecycles, costs, data, default audience, expiry, optional recipients | No duplicate form entry, opaque digests or generic consent checkbox; concrete blockers link to their fix; preview expiry is visible |
| Submit | One explicit Collect evidence action | Stable idempotency key, current checks; do not reset key after timeout; separate accepted from acquired |
| Progress | Per-action readiness/state, evidence already available | Partial is useful; await review without implying execution; cancel only remaining work with truthful acknowledgement |

Low-impact context is the suggested baseline. Selecting intrusive or sensitive actions updates the existing review panel with the specific effect and approval prerequisite. Expected effects are categorical unless measured qualification supports a numeric estimate. Configured limits remain labeled limits. Manual ongoing recording is a finite session; configuring a history duration does not conjure prehistory. Discovery and protocol surveys are visible new requests with their own bounds, authorization and retention.

Process selection shows executable/runtime, present PID, confidence and timestamp; avoid argv/environment contents by default. Accepting a suggested filter does not freeze a stale process inventory. The planner shows how many processes currently match and the cap; execution records final identity and omissions. Network suggestions show observed protocol, peer mapping, possible site, ring/output estimate inputs and limitations. Missing TLS plaintext, one-sided traffic or unowned sockets remain unknown, not guessed.

## Save and repeat

Save existing recordings starts from the policy/workload inventory. Select at most the permitted sources from one policy/workload, show readiness and available history, optionally shorten lookback, then review incremental cost and inherited privacy. The end is first acceptance; there is no future window. The form cannot add a command, runtime profile, core, new filter or recorder. No policy recurring share is inherited; optional per-save sharing is a distinct visible choice.

A rotating/warming/stopped source can yield a partial window, never a silently replaced source. Quota/cooldown refusal gives a reason and known retry bound; it does not queue a fresh future snapshot. Repeating this history entry opens current recording selection. Ordinary history restores retained settings into a new editable capture; current profile availability, workload UID, permissions and limits are rechecked. Explain missing/expired settings and offer a new request rather than fabricating them.

## Policy and profile authoring

Policy editor groups **When**, **Observe**, **Save / run**, **Limits**, and optional **Sharing**. Basic forms use all authorized replicas under administrator limits and show a separate expensive incident pod cap. Trigger builder has typed any/all/sequence groups, windows, threshold units, event/level semantics and rearm/Unknown behavior. Complexity limits disable adding more leaves with a concrete explanation. Schedules show timezone and missed-slot behavior. External alerts reference configured receivers and target mapping, never arbitrary webhook URLs.

Policy authoring also shows **Runs for Payments**, the effective automation binding, finite approval/authority deadline and budgets. Explain once: “Continues if the creator leaves; only current authorized members can manage it or read evidence.” Resolve a sole eligible delegation automatically; multiple eligible bindings require an explicit choice and none produces an actionable administrator/GitOps suggestion without losing the draft. No credential provisioning or extra consent screen. Show creator separately in details. Revoked/expired/replaced delegation shows its reason and current remedy; no stale identity fallback. Recurring sharing retains its own team/personal management rules, so capture may continue while personal sharing is suspended.

Show detector health and each source’s readiness separately, with last accepted generation versus current authored generation. Suppression explanations include cooldown, coalesced event count, rate/output cap, budget or missing authority; never persist each noisy match as a separate incident. Suspend shows expected acknowledgements and the latest remaining offline lease, not instant global cessation.

Profile browser shows goal, lifecycle, publisher/catalog/version, capability prerequisites, exposed editable fields, possible data and impact. “Use and adapt” changes a local composition; “Publish a version” validates a new immutable definition under publisher authority. Policies keep their pins until explicitly edited. Flat composition displays deduplication, aggregate caps and conflicts; never silently overwrites one profile’s bounds.

## Evidence and collaboration

| Viewer | Primary controls | Required context |
| --- | --- | --- |
| Timeline | Occurrence/time/type; available artifact links | Provisional signatures, source/clock gaps; no hidden-artifact placeholders |
| Logs | Retained interval, bounded search/context | Rotation/truncation/redaction; hostile strings rendered as text |
| Files / pod context | Collected item and approved projection | Internal process/runtime provenance, missing paths, byte bounds |
| Stacks / core | Thread/frame selection, private symbols | Exact build match, missing symbols, raw-memory approval separately |
| Packets / HTTP / Zeek | Approved representation, peers, interval | Capture site/filter generations, drops, truncation, TLS and parser qualification |
| Syscalls | Counts/errors, metadata events, bounded filters | Matched pairs, lost events, process coverage; arguments separately authorized |
| Runtime profiles | Sample type, flat/cumulative hotspots, baseline | Units, totals, duration, symbol identity, compatible normalization |
| Raw query | Typed operation + smallest needed region/fields | Exact artifact/grant/budget; no arbitrary debugger command language |

Every artifact view places provenance and handling notice beside the result: possible sensitive content, read cutoff, deletion due/state and external-copy limitation. Exact tool/runtime metadata can be expanded. Do not label a partial capture simply “Failed” when useful artifacts exist. Do not claim absence of activity from missing recording coverage.

Sharing starts from concrete evidence, resolves user/group identity in this organization and previews the recipient’s projection. Multiple owner teams are explicit manager assignments. Show creator separately. “Share results when ready” on a capture is bounded to that capture; recurring policy sharing needs finite publication count/time and reviewed selection. Recipients see only materialized allowed artifacts, not a pending empty case or hidden selection counts. Removing one access path may not remove another independent entitlement; explain that without exposing others’ private shares.

Raw selection approval and raw-query approval are separate. Reviewer page shows requester, exact scope, action purpose, cost/data, expiry and independent step-up. The requester cannot approve their own request. Approval expiration during a long open tab requires fresh review; page presence never authorizes the next command.

## Operator workflows

Installation is a capability checklist with configured, inspected and actively qualified columns. Supply normal Kubernetes/Helm config and secret references once. Default grants/namespace inheritance reduce repetitive administration; guard qualification proves workload writers cannot modify trusted ownership metadata. Preview a user’s effective access and proposed namespace mapping before applying through Kubernetes. Explain unsupported exec-rights inheritance rather than assuming it is universal.

Capacity view separates protected allocations, shared burst, reserved, committed and uncertain charges, source rings versus saved evidence, and upload/action limits. Filter by scope only when authorized. Do not offer eviction of another workload’s protected evidence to make an incident succeed. Retention preview identifies shortened read/deletion deadlines, derived children, object versions, scratch, backups/WAL and incompatible storage locks. Privacy actions return tracked work, not a “deleted” toast.

Enrollment exposes no bootstrap secret in HTML, clipboard or command line; provide the approved secret-channel handoff. Upgrade accepts an operator-selected pinned release, checks compatibility, schema/profile consequences, private images and recovery prerequisites. There is no unsolicited update check. Audit shows minimized actor/decision/reference, not evidence text.

## State, validation and recovery copy

| State | Behavior | Primary next step |
| --- | --- | --- |
| Loading | Preserve structure and focus; aria-busy, no duplicate submit | Wait; bounded timeout gives a retry with original identity |
| Empty | Say whether filters returned no authorized items or collection has never run | Clear filters or choose a permitted first action |
| Unauthorized / unknown identity | Uniform unavailable view before visibility is established | Your access; no title/count/ID leakage |
| Expired preview | Retain permitted draft fields, invalidate the plan handle | Re-preview with current checks |
| Expired evidence/share | Deny reads; preserve only authorized lifecycle explanation | Return to available items; no expiry extension |
| Disconnected cluster | Stored reads continue; no new dispatch; local leases explained | Inspect connectivity or available evidence |
| Quota/cooldown | No extra queued acquisition; show scoped blocker/known retry time | Open an already readable capture or wait |
| Conflict | Show changed revision and a fresh diff | Review/apply; no automatic force overwrite |
| Partial / truncated | Show actual coverage and useful artifacts | Narrow query, choose another authorized artifact or fresh capture |
| Deletion overdue | Reads denied; copy remains charged | Operator repair and verified retry |

Errors attach to the relevant field and a focusable summary; preserve valid input. Every action has a pending state and is protected from accidental duplicate clicks. Never use elapsed UI time as approval. Form defaults and entered values survive Back within the production flow; sensitive drafts expire and are not persisted in browser storage. Prototype fields outside the documented interactive set are intentionally illustrative.

## Usability verification before release

Use maintainers, an occasional share recipient and an operator unfamiliar with the design. Measure active user effort separately from collection/approval waiting. Targets: first supported low-impact capture without YAML in under two minutes after sign-in; repeat in 30 seconds; save an existing recorder in three decisions (select, window, submit); explain default audience, possible sensitive data, deletion and workload effect after review without assistance. Targets are hypotheses, not measured outcomes.

Test stale tabs, failed submissions, mobile/zoom, keyboard-only review, screen-reader announcement of partial evidence, loss of rights mid-query, namespace replacement, selection of multiple owner teams and a raw share recipient without workload rights. Record confusion and task failures; do not replace participant testing with a click-count claim or automated accessibility scan.

## Live packet and syscall observation

UI-061 **Live sources** discovers authorized existing sources without arming them. Show policy versus finite manual capture, ready projection, exact selected pod/action, recording-save eligibility and source blockers. UI-062 **Watch live** opens only on an explicit Start action, with a visible projection and finite duration/output allowance. Use the same per-view logic and source eligibility as the five MCP tools. Source selection is immutable; changing projection/scope requires a fresh view, not an invisible subscription expansion.

Display filters are fixed approved-field controls, applied directly on change, with click-to-filter shortcuts where qualified; they affect only this viewer. Keep the capture's BPF/peer/ring settings read-only and separately linked to policy authoring. Pause view retains only still-valid visible rows and releases row delivery, while bounded status reads check continued eligibility. Resume from now gives a gap instead of replaying an unbounded backlog. The UI keeps finite status, received freshness, delivery gaps and unknown coverage visible. Exact source/filter generations and clock limits are available under View limits, source details & access. Detailed counts distinguish dropped from filtered rows when known; do not infer them. Follow-tail does not move keyboard focus or scroll a selected row out of inspection. Rows and selected details expire on schedule.

Save current recordings opens the existing fresh policy-save review, with explicit notice that its acceptance time and underlying representation govern preservation; a displayed old row is not guaranteed. Manual capture sources open their own capture result. Raw fields are unavailable live; no body/argument inspection button pretends an approved projection includes them. Recipient navigation excludes Live sources and direct routes are nondisclosing. Losing access clears managed rows; reconnect never auto-renews a view or attaches a replacement pod. Capacity view shows active viewers and incremental limits separately from recording/save budgets.

The synthetic prototype includes state-specific Start, Pause, Resume and Close controls, projection choice before starting, direct Errors-only display filtering and automatic bounded row expiry. The simulated dropped-batch control is in Prototype controls → Live-view simulation. The inspector is separate from product interaction. It demonstrates data flow locally, with no actual network capture or live transport. A new goal for usability tests: recognize what Pause and Save preserve, and distinguish a quiet interval from data loss without assistance.

## Visual-review acceptance

Use the [web-design research](web-design-research.md) and REQ-UI-007 when reviewing changes. An entry page emphasizes one next step. A table has readable sentence-case columns and enough width; its secondary details do not become a second dashboard. Review forms expose impact, audience and deadlines before submission, even when optional sharing is collapsed. Recipient and operator views use the same components without borrowing maintainer authority. Mobile stacks the content in task order and keeps necessary table scrolling local.

Participant checks must specifically test the consolidated Captures navigation, profile discoverability, optional sharing disclosure, Pause versus Save, and retention comprehension. The narrower navigation is a design hypothesis, not evidence that these tasks became faster.

## Download and investigate locally

Artifact lists and every viewer offer Download, including approved projections and raw evidence. The common download view shows native format/size, coverage, checksum, existing grant or a prefilled missing-permission review, progress/resume/cancel and a short external-copy notice. No recurring consent checkbox or review when authority already covers the operation. Companion selection for cores lists only available authorized exact files, and does not block the core when symbols are missing. Prototype actions remain synthetic; production saves a native file usable by the relevant local tool. All evidence kinds participate, including new collector types. Label tool guidance “Inspect with”; cores use “Your preferred compatible debugger”. Named tools are optional format/runtime-aware examples. Download neither selects a debugger nor restricts users to one.

## Corrections from complete user tasks

[User-task findings](../reviews/user-task-review.md) distinguish applied design changes from open capabilities. The capture journey is representative: the current prototype already permits direct review, and optional process/network links now appear only for relevant selected profiles. Neither is a required step for a context capture. Production compilation discards inactive settings.

For a core request, offer “Include my inspection and downloads in this review,” showing the browser and explicitly selected registered agent, output limits/expiry and local-copy implications. The approver sees collection and result access together, with one decision. After commit, progress distinguishes saved evidence/access preparing from acquisition failure; retry access publication, not capture. Collection-only and later raw requests remain supported.

Recordings offers immediate save with visible already-reviewed defaults and optional Customize. No second human page on the unchanged path. Label the approver queue “Available approval requests” until actual assignment/routing exists. Do not promise that a reviewer was notified. Prototype interactions remain synthetic.
