# User experience

The [UX package](../docs/ux/README.md) and [surface inventory](../docs/ux/surfaces.yaml) are the reviewed-design interface baseline. Mockups demonstrate behavior and layout using synthetic data. The [production console](../docs/architecture/console-runtime.md) now implements the initial session boundary; full investigation authorization, workflows and deployment remain incomplete.

## REQ-UI-001 — One role-aware workspace

Provide the inventoried maintainer, recipient, approver and administrator surfaces in one console. Landing page and navigation use current effective roles. Authorize before rendering resource titles, counts, breadcrumbs, related items or cached content. Keep workload identity and effective access clear. Explain whole-pod scope and Kubernetes configuration handoff at the relevant decision; do not repeat architecture statements in every heading. Use section-level navigation and contextual capture views as specified in the UX package. Operators do not implicitly gain evidence-read or reviewer authority.

### SC-UI-001

Given an evidence-only recipient following a maintainer’s case/workload URL, when the view loads, then no hidden title/count/collection navigation appears; Shared with me exposes only their authorized concrete selection.

## REQ-UI-002 — Low-effort bounded authoring

Provide target/goal, typed profile composition and one final review. Show process/network guidance provenance and freshness; a discovery or survey is explicit collection. Preserve valid entered values through Back and field errors. Separate observation count, incident pod cap, ongoing recording and on-trigger actions. Preview includes combined effects, uncertainty, possible sensitive data, default audience and inherited deadlines. Do not add generic consent or repeated confirmation to an already reviewed ordinary submission.

### SC-UI-002

Given a maintainer composing context, HTTP evidence and a live core, when they review, then the UI explains recording history, process pause and approval independently; changing the selection refreshes the assessment, and one submit cannot start an unapproved core.

## REQ-UI-003 — Truthful progress and recovery

All surfaces implement relevant loading, empty, denied, stale/expired, disconnected, capacity-blocked and partial states with an actionable next step. Acceptance is not acquisition, configured is not qualified, access expiry is not verified deletion, and cancellation is not instantaneous offline completion. Preserve idempotency after a lost response; distinguish old accepted state from edited drafts. Stored authorized evidence remains usable when new collection/analysis is unavailable.

Session expiry, revocation and unavailable current checks clear protected views.
Sign-out clears the local view immediately, but an unconfirmed server response
must retain an explicit retry path and cannot be presented as successful logout.
Returning to that tab must not silently reopen the workspace. Background and
page-cache restoration recheck the session before redisplaying protected data;
current server authorization remains mandatory for every operation.

### SC-UI-003

Given partial packets and an awaiting-approval core, when a cluster disconnects or a cancellation is requested, then already committed evidence remains accessible as authorized, missing coverage stays explicit, and no success or refund is inferred from a timeout.

## REQ-UI-004 — Sharing, review and administration

Make concrete sharing, per-capture future sharing, bounded recurring instructions, manager teams and immutable creator distinct. Preview the recipient’s projection. Differentiate stopping future publication from revoking child shares. Human review binds exact scope, current revision, independence and verified step-up. Configuration previews hand administrator writes back to Kubernetes/GitOps. Privacy/capacity views show managed-copy deadlines, uncertain charges and verification gaps.

### SC-UI-004

Given a bounded recurring share with multiple owner teams, when an owner stops future sharing, then the UI states that existing concrete shares remain active; revocation is a separate explicit action, and a namespace permission edit cannot be submitted to a second hub configuration store.

## REQ-UI-005 — Accessible responsive interaction

Target WCAG 2.2 AA. Provide keyboard operation, meaningful focus order/return, labels, accessible errors/status, non-color state cues, chart text equivalents, reflow and accessible authentication. Keep primary actions usable on small screens and zoom; confine necessary table scrolling to tables. No third-party font/script or motion dependency. Use labeled keyboard-scrollable regions for wide tables; state-specific live controls must preserve sensible focus when replaced. Incoming observations must not rebuild focused rows or announce every row count. Automated scans supplement manual assistive-technology and participant tests.

### SC-UI-005

Given keyboard-only and narrow-screen users, when they compose, review, dismiss a dialog and inspect partial evidence, then focus remains visible and returns sensibly, no principal action is clipped, and status/coverage/deadline information is available without color or pointer-only interaction.

## REQ-UI-006 — Reviewable interface coverage

Maintain machine-readable screen/role/state/journey inventory, navigable local mockups, domain mappings and operation contracts together. Shared browser/MCP functions use the same application services and bounded projections. Label synthetic, static and interactive behavior. Verify representative journeys and role-negative views; do not claim a prototype proves runtime security, collector performance or usability targets.

### SC-UI-006

Given a new user-visible capability, when its design is accepted, then its screen, domain entity, public operation and failure behavior are traceable; prototype validation reports actual checks separately from pending runtime and participant testing.

## REQ-UI-007 — Minimal visual hierarchy without hidden consequences

Use the [design system](../docs/ux/design-system.md) across all cataloged screens. Prefer plain aligned sections and comparable tables to nested cards. Show one emphasized next action per decision context, sentence-case labels and concise task descriptions; stable screen IDs and synthetic test controls do not occupy the normal product workspace. Put prototype controls in an explicit inspector.

Keep target, relevant lifecycle, audience, combined workload effects and uncertainty, possible user data, effective retention/deletion bounds, coverage gaps and blocking prerequisites visible at the decision point. Optional sharing fields, advanced provenance and detailed accounting may be disclosed on demand. Do not hide a consequential condition to make a screenshot simpler, reduce target sizes to fit more controls, or add another confirmation to compensate for poor hierarchy. The source research records which choices are design judgments; automated checks are not a usability result.

### SC-UI-007

Given a maintainer reviewing a capture or watching approved live evidence, when the screen is used at desktop or narrow width, then audience, effects, handling and applicable gaps remain readable without opening advanced details; optional sharing can be expanded; only applicable live playback controls appear; and a single ordinary submission proceeds without a second generic consent step. The prototype inspector is closed by default and returns focus on dismissal.
