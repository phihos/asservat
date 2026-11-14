# Reusable capture profiles

A capture profile is a versioned, named preset of ordinary evidence actions with a few typed, editable fields. Users pick one or more profiles, adjust exposed settings, preview the combined plan, and collect or enable a policy. It is distinct from a CPU/heap **profile artifact** and from named endpoints. Presets such as `pod-status/v1` are builtin profiles: `presetRef: {name, version}` (MCP `preset_ref`) is shorthand for one builtin component without edits.

## REQ-CPR-001 — Three catalogs, immutable versions

A profile is a `CaptureProfile` object: name, version, display name, description, a complete expanded recipe and its list of editable fields. It is data only: no scripts, BPF, templates, plugins or includes.

| Catalog | Where it lives | Who publishes |
| --- | --- | --- |
| `builtin` | Embedded in the release ([ADR-243](../docs/decisions/243-packet-syscall-plans-in-preview.md)) | The release; nothing can edit or impersonate it |
| `organization` | The hub's catalog namespace | Administrators, through Kubernetes/GitOps |
| `namespace` | The workload's namespace | Its maintainers, under Kubernetes RBAC |

A reference is `(catalog, name, version)`; there is no shadowing between catalogs, and namespace lookup stays within the target's namespace. The hub reads organization profiles through an informer and namespace profiles from connector pushes (ADR-330 D1). A resolved profile is identified by its definition digest: SHA-256 over RFC 8785 JSON of `{name, version, definition}`. Versions are immutable; editing publishes a new version. `availability.enabled: false` disables a version for new starts, including earlier previews and history repeats; `deprecated: true` only discourages it. Nothing switches to a newer version automatically. Status uses `observedGeneration` and an `Accepted` condition.

**Save as profile** writes a new namespace profile through the caller's Kubernetes rights: the expanded recipe plus chosen editable fields, with no nested profile references. Publishing a profile grants no collection, approval or secret access. Definitions hold no credentials or evidence; discovery-derived values pass the normal privacy admission before they can be saved.

### SC-CPR-001

Given a builtin and a namespace profile with the same display name, when a maintainer selects the builtin reference, then the namespace object cannot replace it. A maintainer can save a namespace version but cannot publish organization-wide or change a published version. Disabling a pinned version blocks new captures instead of selecting a newer one.

## REQ-CPR-002 — Finite typed edits

Each editable field names an action ID and a field from the finite registry in [the composition contract](contracts/capture-composition.schema.json): packet peers, filter, window, ring and mode; process selector and batch; profile duration; syscall filter, mode, window and limits; file path; command argv; action timeout and output cap. Values are literal typed data; no JSONPath, patches, interpolation or expressions.

The profile supplies defaults; users enter only changes. After edits the whole plan is validated again against administrator ceilings, and impact is recomputed. Unexposed, unknown or duplicate edits fail with a field path. A type-correct edit can still make the plan infeasible (a longer packet window may need a longer timeout); the UI offers the related change and never applies it silently. An edit cannot lower an action's impact or change its engine. **Customize as a new profile** edits other fields and is validated as new configuration, without reusing any approval.

### SC-CPR-002

Given a profile exposing packet peers, after-duration and timeout, when a user narrows peers and extends duration, then the values are type-checked and the preview shows cost and approval. An unexposed field, duplicate edit, `$(...)` or impact change is refused; command argv stays literal.

### SC-CPR-006

Given `builtin/network-connections/v1` with a packetFilter and an onTrigger mode edit, when previewed in browser or MCP, then both compile the same definition digest, action IDs, lifecycle plan and execution digest, and `before` resolves to 0 s. An unexposed or duplicate edit, onTrigger with a positive `before`, or output above `maxTotalBytes` is refused with its field path.

## REQ-CPR-003 — Compose into one recipe

`profileComposition` lists uniquely named components, each with a profile reference and edits, plus optional aggregate `maxTotalBytes` and `maxDuration` (default: the sum of outputs and the longest duration; users may lower them). It replaces `recipeRef` in a `DebugCapture` or `DebugPolicy`; target, triggers, sharing and execution identity are unchanged. Composition compiles to one ordinary recipe and uses the existing execution, approval and capacity path.

Action and endpoint IDs are namespaced per component: `a` plus the first 24 hex characters of SHA-256(`componentID` NUL `localActionID`), `e` for endpoints; collisions are rejected and dependencies rewritten. The plan keeps a `component/action` alias map for preview and provenance; clients never compute IDs. Identical independent `kubernetesSnapshot`, `processSnapshot` and `networkSnapshot` actions are acquired once under all their aliases. Identical expensive actions (dumps, profilers, recorders, commands) are a conflict; other actions are never merged.

Action modes resolve as in [action lifecycles](action-lifecycle.md). The plan has no action-count cap; capacity admission bounds the compiled cost, with ongoing rings reserved over observation pods and saves over incident pods. Operations that stop the same process run serially; exclusive profilers must fit a serial schedule or conflict. The [assessment](capture-assessment.md) runs on the compiled plan, so a friendly name cannot hide the combined impact.

### SC-CPR-003

Given HTTP headers, syscall metadata and process context, when composed, then one recipe and one execution scope hold every action. Duplicate process snapshots are acquired once with both aliases. Duplicate core dumps, incompatible profilers or a ring budget over the node limit are rejected before collection.

## REQ-CPR-004 — Shipped profiles

| Reference | Purpose | Mode | Defaults and limits |
| --- | --- | --- | --- |
| `builtin/process-context/v1` | Process and socket context | On trigger | Identity, status, cgroups, sockets; no argv, environment or attach |
| `builtin/network-connections/v1` | Transport traffic, both directions | Ongoing; save on trigger | 30 s before, 10 s after; network headers of all approved peers; no payload |
| `builtin/http-headers/v1` | HTTP/1 headers, both directions | Ongoing; save on trigger | Plain HTTP/1 projection, all TCP ports, 30 s before and after; sensitive-observation approval |
| `builtin/go-cpu/v1` | Short Go CPU profile | On trigger | Named endpoint, 10 s; `observe` (no approval) |
| `builtin/go-profile/v1` | Go profile of a chosen type | On trigger | Named endpoint; cpu, heap, allocs, goroutine, block or mutex; no forced GC, `observe` |
| `builtin/syscall-activity/v1` | System calls of all pod processes | Ongoing; save on trigger | Metadata only, all syscalls, 30 s before, 10 s after; no user buffers |

All windows are editable defaults; ring cost grows with history. Recorder profiles expose the mode field, and in a manual capture they record forward for `duration` without edits (REQ-LIF-005). "All" means all eligible sources within visible loss limits, never lossless. The HTTP projection keeps method, status and validated Content-Type/Content-Length and omits URL, Host and credential headers; HTTPS plaintext, HTTP/2 and HTTP/3 are not acquired. Syscall argument mode ([syscalls](syscalls.md)) is available only in reviewed administrator profiles.

### SC-CPR-004

Given a maintainer asks for all HTTP traffic, when offered the shipped profile, then the UI explains the HTTP/1 header projection and the encrypted gaps. Syscall activity follows new workers without a PID picker and shows loss. Unavailable pprof does not fall back to a command.

## REQ-CPR-005 — Browser and MCP

The browser shows a searchable catalog with catalog, version, purpose, defaults, editable fields, impact and approval needs. Users add and remove profile cards, adjust fields and preview the combined plan grouped by mode, with merged and conflicting actions and a diff against the previous plan.

MCP has `list_capture_profiles(target_handle, catalog?, cursor?, limit?)` and `get_capture_profile(target_handle, profile_ref)`, scoped to the target and the MCP result bound; an oversized definition returns an error with a browser link and can still be referenced. `preview_capture` takes exactly one of diagnostic handle, preset or `profile_composition` and returns the plan, alias map, conflicts, aggregate cost and `plan_digest`; it stores nothing. Submission is the usual `request_capture`.

Policies and history snapshots keep the authored components and edits, definition digests, expanded recipe and alias map; `captureProfile` is an execution dependency role, so the collection digest binds profile versions. Availability is checked at start. A repeat uses the recorded versions; a newer version never changes a saved policy or history entry.

### SC-CPR-005

Given the same target and profiles in browser and MCP, when previewed, then both produce the same recipe, aliases and limits, and the agent submits without computing hashes. Disablement, revoked namespace access and expired inferred values cannot be bypassed through earlier previews or history.
