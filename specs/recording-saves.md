# Save existing recordings now

A recording save is a manual occurrence on a policy's running packet or syscall recorders: it saves the window [t0 − before, t0] of selected sources, exactly as an admitted trigger would, with `after: 0`. It runs none of the policy's onTrigger actions, starts no recorder and changes no filter. The result is an ordinary capture with `operation: recordingSave` that uses the capture service, the rate and concurrency limits, history and publication of every other capture ([action lifecycles](action-lifecycle.md), [ADR-330](../docs/decisions/330-event-driven-system-design.md)). The [recording-save contract](contracts/recording-save.schema.json) defines its inventory, plan and settings.

## REQ-SAV-001 — Who may save which recordings

`DebugPolicy.spec.recordingSaves.enabled` lets workload maintainers save the policy's recordings. It defaults to true for a policy with ongoing actions and is invalid without one. The grant review shows it. It is not part of the execution digest, because a save only keeps bytes the reviewed policy already observes; changing it neither restarts the recorder nor invalidates the grant, and `false` stops new saves at once.

The caller needs current collection entitlement for every selected pod. The policy's executor must still hold its acquisition authority and any sensitive-observation grant (ADR-059: the team policy identity, not its creator). The save runs as the policy's snapshot operation and records the caller as initiator; the policy's authority is never transferred to the caller. A share, reader role or handle confers no collection right. Disabling saves, suspension, grant expiry or revocation, or an execution-digest change stops new saves, including accepted but unstarted ones.

`list_recordings` shows only permitted policy/pod/action rows with source state, available history, maximum lookback and eligibility or blocker; no packet contents, arguments or hidden-source counts. A recording handle is an opaque, caller-bound reference to an exact source session; it does not expire and is checked when used, so it never reaches a replacement pod's recorder. Reading inventory or a preview reads no payload, pins nothing and reserves nothing. Pages default to 20 rows.

### SC-SAV-001

Given a maintainer and a share-only recipient, when they open one workload, then only the maintainer sees and can save recordings. Setting `recordingSaves.enabled: false` stops new saves without restarting the recorder. A replaced pod's source cannot be saved through an old handle.

## REQ-SAV-002 — Window and execution

One save selects distinct source handles of one policy and workload, at most the policy's incident pod cap × its ongoing actions; any authorized observed pod may be chosen. The UI preselects the current pod. Unauthorized selections are refused, not dropped; sources of different policies are never combined. A source with zero configured history shows `NoHistoryConfigured` and offers a separate forward capture.

Lookback defaults to each source's policy `before`; an optional common `before` can only shorten it. Representation, filters, audience, limits and privacy ceiling stay exactly as recorded. No dumps, commands, profiles, context actions or new parameters are accepted.

The preview is a stateless dry run (ADR-330 D9) returning the `recording-save/v1` plan, its digest and the [capture assessment](capture-assessment.md). Submitting the digest with an idempotency key accepts that plan or reports what changed. Acceptance sets t0 to the acceptance time; the caller cannot choose t0 or a future window, and retries never change it. Acceptance authorizes once (ADR-311) and commits the parent capture, one child per source and their audit rows in one transaction; the hub then pushes each child to its node, which pins the retained segments before t0 on receipt. Each child reports its actual coverage: Partial if history was evicted or the source ended, Failed if nothing remained. A fully observed quiet interval is a valid empty artifact. Cancelling releases only this save; the recorder continues.

### SC-SAV-002

Given a policy with packets, syscalls and a live core, when the user saves two sources with 20 s lookback, then only the two windows are saved and no core or recorder starts. A source that ended after the preview is refused at submission or reported lost. A retry with the same idempotency key returns the original capture and t0.

## REQ-SAV-003 — Limits, retention and sharing

A save is an occurrence: it is charged to the same workload rate limit and concurrency limit as automatic occurrences (REQ-TRG-004), plus storage and upload capacity, reserved at acceptance and settled when each child's outcome is known (ADR-330 D7). It has no run count and draws on no grant budget (ADR-335 D6). It does not reset a detector's hold or re-arm state. A save that does not fit is refused with the blocker and retry time; it is never queued. When an admitted capture of the same window exists and the caller may read it, the UI offers it instead. No per-save approval is needed; a missing policy approval blocks the save and links to the review.

Retention starts at the original acquisition of the saved segments, not at the click. The saved window keeps the earliest deadlines and the recorded source audience; the initiator gains no audience membership or raw-read right. Recurring policy sharing does not apply; the caller may attach a capture-time `sharing` instruction under the normal rules.

### SC-SAV-003

Given two maintainers repeatedly saving a sensitive ring during an automatic incident, when the workload rate limit is exhausted, then later saves are refused without another ring, dump or reservation. An admitted save keeps the source deadlines and audience, a new team member gains no old evidence through the click, and the policy's recurring sharing publishes nothing from it.

## REQ-SAV-004 — Browser, MCP, history and provenance

One action, **Save last N seconds** (N = the policy's `before`, default 30), appears wherever an eligible source is shown: recording inventory, [live view](live-watch.md) and capture history. A click previews and submits at once when the plan is unchanged; **Customize** opens the selector. A display filter in a live view is not a capture filter; the saved window is the source's own representation, and t0 is the acceptance time, so rows already rotated out are reported missing.

MCP uses `list_recordings(target_ref, policy?, cursor?, limit?)`, `preview_capture(recording_handles, before?, reason?, sharing?)` and `request_capture` with the plan digest and an idempotency key; `request_capture` needs `evidence:capture`. `get_capture` and `cancel_capture` work unchanged; the capture has one parent `capture_id` and one action row per source with its `action_instance_id`, pod and `action_id`. Recipe previews never accept recording handles.

History lists the save with origin `manual` and operation `recordingSave`. Its settings are the target, policy name, action IDs, lookback and reason. Repeat opens a new save preview for the same policy and actions on the workload's current sources, or reports `NoCurrentSource`; it never becomes a recorder capture or runs the policy's other actions. The optional reason is descriptive text kept with the capture row, never authority.

Artifacts carry lifecycle provenance with trigger kind `recordingSave`, t0, source session, snapshot ID and coverage; `recordingSaveOrigin` binds the policy UID and execution digest, and the plan digest is the save's own. Initiator and policy executor are recorded separately.

### SC-SAV-004

Given an MCP client, when it saves an eligible ring and retries after an ambiguous response, then it gets one capture it can follow and cancel. History labels it a recording save, and repeat cannot invoke the policy's liveCore. A request with a dump parameter, mixed-policy handles, `after > 0`, a forged executor or an ended source fails before acquisition.
