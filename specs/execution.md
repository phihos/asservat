# Accepted execution identities and digest scopes

A digest identifies a scope; it does not authorize executing it. The [collection-scope contract](contracts/collection-scope.schema.json) is a resolved record written by the hub, never a user-writable resource. Mechanisms follow [ADR-330](../docs/decisions/330-event-driven-system-design.md).

## REQ-EXE-001 — Separate immutable scopes

Two digests are stored:

1. **Collection execution digest:** the resolved collection-scope/v1 record: source cluster, namespace and workload by name (the workload UID only under `adoption: pinUID`), the capture or policy UID, executor, resolved team policy authority, pod selection, detectors, action/recipe digests, budgets, effective retention and ceilings, and resolved dependencies. Policy generation is provenance, so approval survives a label, pause, sharing or grant-reference change. Ad hoc scope binds one capture UID and its durations, so another request cannot reuse its approval. For approval-required plans (`timing: approvedAcceptance/v1`) the capture deadline (recording duration plus finalization margin) starts when the approval is decided, because approval submits the request ([ADR-335](../docs/decisions/335-usable-by-default.md) D5).
2. **Sharing scope digest:** the resolved sharing instruction with its collection execution digest, creator, management, recipients, outputs, limits and expiry. It never authorizes collection. Changing only sharing needs no new collection approval; captures already admitted keep their instruction.

What was submitted is the browser/MCP request (with the authenticated session) or the Kubernetes object at its `metadata.generation`; Kubernetes audit attributes the writer ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D10). No submission digest or signed envelope exists. Re-applying an identical spec is a no-op.

For a DebugPolicy, `policyAuthority` is mandatory; DebugCapture forbids it. It records the installation, the delegating AccessBinding by namespace and name, and the digest of the binding's resolved automation scope (groups, allowed actions, ceilings). A binding change that keeps that digest keeps acceptance; a narrowing or removal stops new and running sources (REQ-LIF-004); any other change needs fresh acceptance and applicable review ([team policy automation](policy-automation.md)).

Sharing, resultAccess, suspend, reason and idempotencyKey are excluded from the collection digest. An approval attaches to the policy or capture whose current digest it covers and cannot change the frozen plan. Pausing stops future starts; resuming checks current authority, capacity and approval without a new approval or budget reset. Changing target, executor, recipe, trigger, runtime pack, image restriction, observation scope, limits or privacy ceiling needs a newly accepted scope and applicable review; "narrower" edits are not assumed safe. Pause, deny and retention tightening take effect when their event arrives: the hub refuses new starts and pushes a stop. Policy lifetime and renewal follow [team policy automation](policy-automation.md#approval-of-automatic-intrusive-actions).

Recipes, capture profiles and endpoints are referenced by name with an optional version ([ADR-335](../docs/decisions/335-usable-by-default.md) D4); the hub resolves them, records the digest in status and in the scope, and an approval binds that digest. Digests are computed by one Go implementation over normalized values (integer bytes and counts, canonical durations, UTC timestamps, ordered lists kept, sets sorted with duplicates rejected, integers within ±2^53−1 for RFC 8785), serialized with RFC 8785 and hashed with SHA-256. Clients never compute hashes. `collectionProvenance.planDigest` and `SharingIntent.source.planDigest` mean the collection execution digest; `collector.policyDigest` is authored-policy provenance only.

The hub reconciles CRDs on watch events and reports `status.observedGeneration` with conditions. Observing a generation never by itself accepts execution or revives an approval.

Compilers emit `effectiveRetention` per action (purpose, privacy class and type, requested and maximum age, deletion budget); it is part of the execution digest. The collector image is provenance, so a collector upgrade keeps approvals; runtime packs and gadget digests are pinned dependencies.

### SC-EXE-001

Given an approved policy, when its grant is renewed in place or only recipients change, then the collection execution digest stays fixed while the sharing identity changes. Re-applying the unchanged policy YAML changes nothing. Adding a core, another target or a broader ceiling changes collection scope and invalidates its approval. A manual capture with no policy can request approval for its own immutable capture identity, which cannot authorize another capture.

## REQ-EXE-002 — Acceptance, deadlines and progress

The hub authorizes an operation once (identity, permission, deny, retention, capacity) and reuses the decision under [REQ-INT-003](interfaces.md#req-int-003--bounded-errors-retries-and-asynchronous-work). SQL constraints and conditional updates enforce capacity, retention deadlines and idempotency.

An interactive request's deadline is its HTTP request context. Stored capture and grant deadlines are never extended by a retry.

A DebugCapture written through Kubernetes uses its UID and generation as operation identity and computes its deadline at acceptance, so a late GitOps sync never runs an expired request. Browser and MCP requests follow the idempotency rule of REQ-INT-003. Each execution has an operation ID (capture UID, action ID, attempt), inserted with `INSERT … ON CONFLICT DO NOTHING`. The hub sends the start over the connector's single connection (ADR-330 D2) and the connector starts the work idempotently under that ID. A retry, lost reply or restart looks the ID up and never starts work twice. A start with an unknown outcome follows [REQ-FED-002](federation.md#req-fed-002--durable-outbound-work-and-compatibility).

Connectors and in-cluster executors authenticate with projected ServiceAccount tokens ([ADR-334](../docs/decisions/334-connector-workload-identity.md), ADR-330 D3); the region trusts its Kubernetes RBAC. Before each attach the executor checks the target identity locally under REQ-TGT-002 (pod UID, container ID, host PID and start time, node boot ID).

Target resolution reads cluster state the connector pushes (ADR-330 D1) and confers no authority. Progress reaches browsers and MCP as events. Failures are logged with the failing stage, without identities, credentials or payloads.

Acceptance allocates the capture identity and freezes the plan, pod set, per-action fanout, privacy and deadline. A manual capture's deadline is its longest requested action duration (a recording's `duration`, default 60 s; administrator maximum default 1 h) plus the finalization margin. A pending approval stays decidable as in [REQ-AUT-003](authorization.md#req-aut-003--individual-and-policy-grants).

For DebugCapture, `podBindings` is a non-empty list sorted and unique by podUID and bounded by `target.maxPods`. The node class requires podUID, nodeUID and nodeBootID; a replacement Pod, rescheduling or node reboot invalidates the start. The kubernetesAPI class serves only builtin-pod-status-v1, binds podUID and permits an unscheduled Pod. The class is part of execution identity. DebugPolicy has no fixed podBindings: each incident pins its concrete pods. A matchedProcesses plan re-resolves processes within pinned pods before dispatch (REQ-ACT-008); selectedPID binds one process.

Context that needs no approval runs at acceptance; expensive capacity is reserved close to dispatch, not during a review. Each process-affecting start has its own operation ID and reservation within the parent's bounds. If the pinned process is gone or the deadline passed, nothing starts against a replacement; the user can start a fresh capture. Cancellation is idempotent. Deleting a CRD neither deletes evidence nor revokes sharing.

The capture phase ([APIs](apis.md)) projects action states: AwaitingApproval while no runnable action is active and some await review, Running until every output is published or has failed, then Succeeded, Partial or Failed; Cancelled and Indeterminate are explicit.

### SC-EXE-002

Given an accepted API context capture whose start reply is lost, when the hub retries with the same operation ID, then the connector returns the existing execution and no second start occurs. A retry after the capture deadline returns the recorded outcome and starts nothing.

Given cheap context and a required intrusive action, when the approver decides after 40 minutes, then context ran once at acceptance and was visible immediately, and the intrusive action starts at approval with its full requested duration. When the requester-set `notAfter` passes undecided, the intrusive start never occurs and the terminal result explains partial evidence. A refreshed page or repeated MCP request returns the same capture without resetting its clock or counters.

## Related identities

- **Repeat.** [REQ-HIS-001–004](capture-history.md) restore settings from the immutable snapshot written at acceptance. A repeat binds its own capture UID, requester, deadlines and digest; no grant, sharing instruction or reservation is copied.
- **Composition.** A composed capture records its components, edits, resolved definitions, expanded recipe and alias map ([capture profiles](capture-profiles.md)). Each CaptureProfile is a dependency identified by catalog, name, version and definition digest; the expanded recipe digest identifies the actual actions under a service-owned `composition-<24 digest characters>` recipe name. A disabled or deleted version cannot be started from an old preview or history.
- **Source sessions.** Resolved execution modes ([action lifecycles](action-lifecycle.md)) are part of the digest. A `sourceSessionID` identifies one recorder; each incident has its own snapshot ID and t0-anchored window. Cancelling a manual capture stops its session; cancelling a policy incident stops only that save.
- **Assessment.** [Capture assessments](capture-assessment.md) reference the execution digest; changing metrics are never hashed into it, and a report is not a permit.
- **Recording saves.** [REQ-SAV-001–004](recording-saves.md) use a separate recording-save/v1 scope binding exact sources, audiences, lookbacks, requester and policy executor; its digest is the save's `planDigest`. `recordingSaves.enabled` (default true for a policy with an ongoing action) is not part of the policy's execution digest. A save group is authorized once and its children dispatch concurrently within the concurrency limits.
- **Result access.** [Investigation approval](investigation-approval.md) adds a result-access digest over `{captureUID, executionDigest, resultAccess}`; the review covers both digests, and changing result access needs a new approval without changing the collection digest.
