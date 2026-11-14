# One review for a bounded investigation

The maintainer selected one independent human approval for a one-off capture and the same developer's subsequent inspection and download. This refines [authorization](authorization.md) and [downloads](artifact-downloads.md) under [ADR-335](../docs/decisions/335-usable-by-default.md) D5/D9. It confers no workload eligibility and no general future-artifact grant.

## REQ-INV-001 — Review the intended outcome once

A manual capture that needs review may request `resultAccess` with its plan. The UI offers **Collect and investigate** and a collection-only choice. The one review shows the acquisition, the exact capture/Pod scope, the selected output actions, the follow-up operations, the requester and the limits. Result access belongs to the requesting human (same issuer and subject) on every client that authenticates as that human, including the user's MCP agents. Another person needs their own approval. A requester holding the equivalent Kubernetes right needs no result access ([REQ-AUT-002](authorization.md#req-aut-002--authorization-composition)).

The request names action IDs, operations, `maxArtifacts`, `maxBytes`, `maxOperations` and an optional `notAfter`: the finite disclosure pool of the approval (maintainer decision). The UI fills them from the selected outputs and never asks for hashes or IDs; the review shows whether `maxBytes` covers the requested full downloads. A download is full-file disclosure.

The service binds a result-access digest to the capture UID and execution digest and includes it in the single review. Result access lasts until `notAfter`, defaulting to the access end of the collected evidence (ADR-335 D9). Acquisition and disclosure have separate budgets.

### SC-INV-001

Given a developer requesting a core and local inspection, when an independent reviewer approves the combined plan, then capture and the subsequent core download and queries from the console, and from the developer's MCP agent need no second review. Another human, a changed output selection or another capture cannot use the approval. A context-only request adds no approval step. Approval hours after the preview, approval against the exact original target, revocation racing admission and a replay without new timing are covered; a missing or replaced Pod or a material scope change needs a new preview and review.

## REQ-INV-002 — Result access applies to exact published artifacts

The approved `adHocCapture` grant itself carries the result access. A raw operation or download uses it only on a published artifact whose recorded capture UID, execution digest and action ID match the approved result access, while the grant is Approved and unexpired and the requester is still entitled. No per-artifact grants are created and no unknown artifact is ever an executable target. Policies, other captures, recording saves and later derivatives are not covered.

All uses spend the grant's one pool: `maxArtifacts` counts distinct artifacts used, and every operation and byte is charged across all clients. Each use reserves under an idempotency key and settles to actual usage ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D7). A started transfer runs to its original bounds ([REQ-DLD-002](artifact-downloads.md#req-dld-002--reuse-authority-review-only-where-required)). Revoking, denying or expiring the grant refuses later uses; exhausting the capture-start counter does not. Artifact expiry, restriction and current entitlement still win.

### SC-INV-002

Given duplicate publications, a console and an MCP client of the same human and a bounded pool, when artifacts are used from both clients, then each artifact counts once and every use spends the same pool. A forged action, capture or digest, broadened operations, another principal, an expired or revoked grant or an exceeded count or byte limit refuses delivery. Capture-budget exhaustion does not consume the result budget. A transfer interrupted after 10 MiB of a 100 MiB reservation leaves 10 MiB charged once its outcome is reported.

## REQ-INV-003 — One browser/MCP journey with truthful progress

`preview_capture` returns the plan, its digest and `result_access_actions` (compiled action IDs with supported operations); it stores nothing. `request_capture` accepts `result_access` and binds it before the review is created ([ADR-249](../docs/decisions/249-sensitive-acquisition-grants.md)). The result-access digest covers `{captureUID, executionDigest, resultAccess}`; changing it needs a fresh preview and review. Supported operations are `download_artifact`, `query_artifact(operation=packets)` and `query_artifact(operation=syscalls)` ([ADR-305](../docs/decisions/305-bounded-saved-packet-queries.md), [ADR-306](../docs/decisions/306-bounded-saved-syscall-queries.md)). Result access is refused on a plan that needs no review. DebugCapture carries the same `resultAccess`.

The reviewer approves or denies collection and follow-up access once ([REQ-AUT-003](authorization.md#req-aut-003--individual-and-policy-grants)). Approval submits the stored request ([ADR-252](../docs/decisions/252-approved-capture-acceptance.md)) and the capture starts at once; a gone Pod ends it `TargetChanged`. Capture status shows the result-access state (NotRequested, AwaitingReview, WaitingForArtifacts, Ready, Partial, Expired, Revoked) separately from collection. Repeating a capture may offer the previous preferences but never copies approval or counters.

### SC-INV-003

Given a combined request approved at 02:00 while the developer is away, when the capture completes and the developer opens the download at 09:00 or the developer's agent queries it, then the capture started at 02:00 and its approved result access covers the published artifacts. Refresh and retry need no duplicate form and never recollect. The UI shows both capture readiness and evidence access.
