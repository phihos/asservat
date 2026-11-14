# When evidence actions run

Actions have two execution modes, independent of impact and sensitivity. An ongoing action records continuously into a bounded ring and saves a window when an occurrence is admitted; it does not upload continuously. The resolved mode appears in profiles, previews, accepted plans, history and artifact provenance. Every save, whether from a detector, a manual [recording save](recording-saves.md) or a natural crash, follows one path: occurrence at t0 → window [t0 − before, t0 + after] from the existing source → capture.

## REQ-LIF-001 — Two execution modes

| Mode | User label | Behavior | Actions |
| --- | --- | --- | --- |
| `onTrigger` | On trigger | One bounded action per admitted occurrence or manual capture | Dumps, commands, file reads, snapshots, endpoint calls, runtime diagnostics, profiles, log retrieval, artifact collection |
| `ongoing` | Ongoing; save on trigger | A recorder armed before incidents; each occurrence saves its own window while recording continues | Packet captures and syscall traces (default) |

`action.executionMode` may be omitted; the [action contract](contracts/action.schema.json) fixes each kind's default and allowed modes, and the compiler records the resolved mode in the plan. Changing mode changes collection scope and needs fresh acceptance and any applicable approval; it never lowers sensitivity or waives approval.

Only packetCapture and syscallTrace support both modes. Their onTrigger variant records forward only: selecting it resolves an omitted `before` to 0 s, and an explicit positive `before` with onTrigger is refused with its field path. A zero `before` alone does not change the mode. Commands, dumps and snapshots cannot run as ongoing loops.

`kernelCore` is onTrigger with a natural-crash origin. Interception, a cached data key and a local admission budget are prepared in advance (REQ-ACT-005); the crash itself is admitted locally at once or refused as a missed core. A crash artifact notification for an already saved core does not acquire it again, and other triggers cannot produce a natural core (use an approved liveCore). Log retrieval and pprof counter reads are onTrigger reads of history the runtime keeps; detectors are not evidence actions. A finite `logs` plan records `requestedBefore` and `after` (at least one positive); history is bounded by kubelet log rotation and the preview reports the resulting byte ceiling.

### SC-LIF-001

Given a recipe with a live core, packets, syscalls and logs, when previewed, then the core and logs appear under On trigger and packets and syscalls under Ongoing; save on trigger. Switching packets to onTrigger resolves `before` to 0 s and the preview states the lost history. An ordinary health trigger cannot claim a natural kernel core.

## REQ-LIF-002 — Arm recorders before incidents

Applying a policy arms its ongoing actions on every authorized observation pod within administrator ceilings, independent of the smaller per-incident `target.maxPods`, and follows new replicas under the same scope. Arming reserves ring, parser and CPU capacity before the first read.

A source is one recording session bound to its pod UID, node boot, action and filter digests and execution authority. Its states are `Unavailable` (waiting for approval or capacity, with the blocker), `Warming` (ring not yet covering the requested lookback), `Ready`, `Degraded` (coverage shortened by eviction, loss or restart) and `Stopped`. Status shows eligible, armed, warming, blocked and lost counts. Detector readiness never implies recorder history.

Rings rotate and erase expired segments without creating captures. An occurrence references the existing source; it never attaches another recorder. Sources are not shared between policies. A missing optional recorder does not block detectors or other actions; missing required history makes the capture Partial.

### SC-LIF-002

Given 20 replicas, a one-pod incident cap and an approved ongoing packet action, when the policy applies, then all 20 replicas record within admin ceilings. A trigger from replica 17 saves that replica's ring; it starts no recorder. A new replica shows `Warming` and an exhausted source `Degraded` while other detectors keep working.

## REQ-LIF-003 — Incident windows

Each admitted occurrence fixes t0, the detector's observed time, with its clock uncertainty. The window is [t0 − before, t0 + after], limited to bytes actually observed under valid authority and before retention cut-offs. Delays and late approvals never move t0 or invent history. The node pins the pre-trigger segments on receipt and records the remaining post-trigger interval; source loss makes the result Partial. A slow upload never extends recording.

A recorder has session limits (rates, ring size and, for a manual session, its duration); each saved window has its action timeout and output cap. The post-trigger window may last up to the capture's configured duration (ADR-335 D8); window bytes are encrypted as they leave memory, so the output cap, not ring memory, bounds a long window.

Saves and onTrigger actions start independently at admission; a ring save never waits for a dump or an approval. Ongoing actions have no `dependsOn`; an onTrigger action may depend on an ongoing one, which waits for this occurrence's saved window. Concurrent occurrences get separate windows while the source continues; an occurrence beyond the rate or concurrency limit is suppressed (REQ-TRG-004). A sustained condition cannot extend a window; Stop and revocation can only shorten it.

### SC-LIF-003

Given an armed ring and a live dump awaiting approval, when an occurrence at t0 is admitted, then the ring window is saved without waiting for the dump. A further occurrence beyond the limits is suppressed and attaches no recorder. A crash during the post-window yields truthful partial timing.

## REQ-LIF-004 — Recorder cost, authority and stop

Ongoing costs (ring, parser, CPU, observation rates) scale with the observation pod set and are reserved at arming; save costs (frozen segments, output, encryption, upload) are reserved per admitted occurrence ([capacity](capacity.md)). Metadata recorders (sanitized network headers, syscall metadata) need collection rights and are bounded by rates and ring sizes, never by a cumulative byte total (ADR-335 D6). HTTP, raw packet and syscall-argument recorders need their reviewed grant before the first sensitive read, even if nothing ever triggers; a policy recorder is bounded by the grant's expiry, rates and ring, a manual sensitive session by rate × duration.

A source is authorized once when armed. A policy source runs as one session while the policy applies and its grant (if any) is unexpired; there is no session ceiling or periodic re-arm. Policy pause or deletion, AccessBinding or deny changes, grant expiry and retention tightening reach the hub as events, and the hub pushes `stop(sourceSessionID)` over the connector connection; the connector also stops sources itself on its own AccessBinding watch events ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1, D5). While disconnected, a source runs to its hard end unless a local event stops it. Rates are counted locally, reported in batches and charged by actual use. Segment content expiry is separate from the source's end; a saved window inherits the earliest expiry of its segments.

After a stop, nothing new is observed or saved under the expired authority. Already admitted windows finalize under their own authority; unsaved rings are erased once references settle. Stopping one save never stops the policy's recorder. A restarted source is a new session with a reported gap.

### SC-LIF-004

Given a manual sensitive recording with no saves, when it reaches its observation limit, then it stops and nothing replenishes the limit. Given a sanitized policy recorder on 20 busy replicas, when it runs for a week, then it remains one session within its rate and ring ceilings. Pausing the policy stops its sources; cancelling one saved capture leaves the recorder running.

## REQ-LIF-005 — Manual captures and provenance

A manual capture has no trigger, so an ongoing action requested manually records forward as a **manual session** of the action's `duration` (default 60 s; always finite; administrator maximum default 1 hour), bounded by its limits and stoppable at any time ([ADR-313](../docs/decisions/313-manual-recording-stop.md)). Shipped recorder profiles need no edit for this. The session streams its recording encrypted to storage and has no prehistory, which the preview states. A manual capture never fires a policy or borrows its source or grant; saving a policy's existing ring is the separate [recording save](recording-saves.md).

The UI and MCP show two groups, **Runs on trigger** and **Records while armed; saves on trigger**, each with its own scope, cost and approval, and show actual source readiness and history. `preview_capture` includes the `action-lifecycle/v1` plan with per-action mode, activation (`policyArming` or `manualSession`), requested window and observation scope; no extra arming or approval tool exists. Repeat creates fresh sessions; it never reuses old rings.

Every saved window's artifact carries `actionLifecycle` provenance ([contract](contracts/action-lifecycle.schema.json)): mode, trigger kind and time, `sourceSessionID`, source start, snapshot ID, requested window, `historyCoverage`, `windowCoverage` and gap reasons, plus `sourceStoppedAt` (the target ended) or `sourceClosedAt` (the session ended) when known ([ADR-244](../docs/decisions/244-native-artifact-types.md) verifies these). Full history does not imply full window coverage. A quiet, fully covered interval can contain zero records. Artifact `startedAt`/`completedAt` describe the actual acquisition.

### SC-LIF-005

Given a user selects the shipped syscall profile for five minutes, when they collect, then one finite five-minute session records all pod processes and stores the recording, with no mode or window edit. Repeating a recorder profile manually explains the missing prehistory. Cancelling stores nothing unless storage had already started (ADR-313). A history entry cannot revive an old recording or grant.

## REQ-LIF-006 — Stopped sources serve late exit events

When a source's pod or runtime ends, the source stops reading but keeps its ring, so a late exit, crash or alert occurrence can still save it. Exit of one process or sidecar does not stop a whole-pod recorder. The stopped ring stays until ring-budget eviction, content expiry or the end of its authority, whichever comes first; there is no separate timer. It never renews a grant or resumes observation, and a new pod gets a new source. Under memory pressure the oldest unreferenced stopped ring is evicted first (`historyEvicted`). Explicit suspension, deletion, revocation and grant expiry end the stopped ring at once. Node loss loses volatile history. If a source stops between t0 and t0 + after, history may be full while the window is partial.

### SC-LIF-006

Given recording before a probe occurrence at t0 and pod exit at t0 + 2 s, when the matching exit arrives while the stopped ring is held, then it saves full history and two seconds of the ten-second post-window, reported as partial with `targetGone`. A replacement pod, an evicted ring or a revoked policy cannot reuse the source; rapid exits stay within the ring budget.

## Live readers

[Live watching](live-watch.md) attaches finite, separately budgeted readers to running ongoing sources, including manual sessions. It is not a third mode, a detector or an arming operation, and viewer actions never change the source or its windows.
