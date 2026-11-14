# User experience

The [UX package](../docs/ux/README.md), [surface inventory](../docs/ux/surfaces.yaml) and [design system](../docs/ux/design-system.md) are the design baseline; mockups use synthetic data. Task outcomes and acceptance measures are in [ergonomics](ergonomics.md).

## REQ-UI-001 — One role-aware workspace

One console serves maintainers, recipients, approvers and administrators. Navigation follows current effective roles. Authorize before rendering titles, counts, breadcrumbs, related items or cached content. Operators do not gain evidence-read or reviewer authority by operating the console.

### SC-UI-001

Given an evidence-only recipient following a maintainer’s case/workload URL, when the view loads, then no hidden title/count/collection navigation appears; Shared with me exposes only their authorized concrete selection.

## REQ-UI-002 — Low-effort bounded authoring

Authoring is target/goal, profile composition and one final review. Every cluster, namespace, workload, recipe, user and group is chosen by name from a search picker; no form asks for a UUID, UID, digest or grant ID ([ADR-335](../docs/decisions/335-usable-by-default.md) D4). Values survive Back and field errors. The review separates ongoing recording from on-trigger actions and shows combined effects, possible user data, audience and deadlines. An already reviewed submission gets no extra consent step.

### SC-UI-002

Given a maintainer composing context, HTTP evidence and a live core, when they review, then the UI explains recording history, process pause and approval independently; changing the selection refreshes the assessment, and one submit cannot start an unapproved core. Every target, recipient and recipe is selected by name without copying an identifier.

## REQ-UI-003 — Truthful progress and recovery

Every surface implements loading, empty, denied, expired, disconnected, capacity-blocked and partial states with a next step (reasons and remedies: [REQ-UX-004](ergonomics.md)). Accepted is not acquired, configured is not qualified, access expiry is not verified deletion. Stored evidence stays usable when new collection is unavailable.

Each open page receives progress, status and live rows over Server-Sent Events ([REQ-INT-003](interfaces.md#req-int-003--bounded-errors-retries-and-asynchronous-work)) and does not poll; on reconnect it resynchronizes once. Session expiry or revocation clears protected views. Sign-out clears the view at once; an unconfirmed server logout keeps a retry path and is not shown as successful. Restored or cached pages recheck the session before showing protected data.

### SC-UI-003

Given partial packets and an awaiting-approval core, when a cluster disconnects or a cancellation is requested, then already committed evidence remains accessible as authorized, missing coverage stays explicit, and no success or refund is inferred from a timeout.

## REQ-UI-004 — Sharing, review and administration

Concrete shares, capture-time sharing, recurring policy sharing, manager teams and the immutable creator are visibly distinct; Stop and Revoke have distinct effects ([authorization](authorization.md)). The sender previews the recipient's view. An approval starts the approved work; the requester never submits again. Configuration previews hand administrator writes back to Kubernetes/GitOps.

### SC-UI-004

Given a bounded recurring share with multiple owner teams, when an owner stops future sharing, then the UI states that existing concrete shares remain active; revocation is a separate explicit action, and a namespace permission edit cannot be submitted to a second hub configuration store.

## REQ-UI-005 — Accessible responsive interaction

Target WCAG 2.2 AA: keyboard operation, focus order and return, labels, accessible errors and status, non-color state cues, chart text equivalents, reflow. Primary actions stay usable on small screens and at zoom; only wide tables scroll. No third-party fonts or scripts. Live rows must not steal focus or announce every row. Automated scans supplement manual assistive-technology and participant tests.

### SC-UI-005

Given keyboard-only and narrow-screen users, when they compose, review, dismiss a dialog and inspect partial evidence, then focus remains visible and returns sensibly, no principal action is clipped, and status/coverage/deadline information is available without color or pointer-only interaction.

## REQ-UI-007 — Minimal visual hierarchy without hidden consequences

Use plain aligned sections and tables, one emphasized next action per decision, sentence-case labels. Target, lifecycle, audience, workload effects, possible user data, retention and deletion bounds, coverage gaps and blocking prerequisites stay visible at the decision point; optional sharing, provenance and accounting expand on demand. Never hide a consequence to simplify a screen or add a confirmation to compensate for poor hierarchy. Prototype controls live in a closed inspector, not the product workspace.

### SC-UI-007

Given a maintainer reviewing a capture or watching approved live evidence, when the screen is used at desktop or narrow width, then audience, effects, handling and applicable gaps remain readable without opening advanced details; optional sharing can be expanded; only applicable live playback controls appear; and a single ordinary submission proceeds without a second generic consent step. The prototype inspector is closed by default and returns focus on dismissal.
