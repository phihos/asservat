# One review for a bounded investigation

The maintainer selected one independent human approval for a one-off capture and the same developer's subsequent inspection/download. This refines [authorization](authorization.md) and [downloads](artifact-downloads.md). It does not remove review, confer workload eligibility or create a general future-artifact grant.

## REQ-INV-001 — Review the intended outcome once

A manual `operation=collect` capture may request `resultAccess` alongside its collection plan. The normal UI offers **Collect and investigate** when raw follow-up access is needed, and a collection-only choice. The one review shows acquisition effects, exact accepted capture/pod scope, selected output actions, allowed follow-up operations, same requesting human, explicitly selected registered client IDs, artifact/count/byte/query ceilings and absolute expiry. The current browser client is the default; including an agent client is explicit and visible to the reviewer. An unlisted client or another person needs its own approval. Ordinary approved extracts/downloads still use existing rights without inventing review.

The authored request has action IDs, finite operations, selected client IDs, maxArtifacts, maxBytes, maxOperations and notAfter. UI/planner fill these from selected mechanisms and a practical query/transfer allowance, never require manual hashes. Validate the output selection against the compiled action aliases and requester/client policy. Show whether the disclosure budget covers the maximum requested full downloads and any query/retry allowance; do not advertise a full-file workflow with an insufficient byte cap. Each count is installation-bounded. Download is full-file disclosure; local tools cannot be restricted to particular debugger commands after the file is delivered.

The service binds a canonical resultAccess digest to the accepted capture UID and collection execution digest and includes it in the single human review. The adHocCapture grant carries the resolved resultAccess scope; user input cannot assign requester/approver or write a pre-approved scope. Same-human identity is issuer/subject, not a display name. The combined grant's existing finite lifetime and narrower raw/artifact limits bound follow-up access; no deadline starts again when an artifact arrives. The original capture start deadline and frozen pod identities remain unchanged. Short-lived execution permits are unchanged. Expensive acquisition and disclosure have separate budgets, both visible on this review.

### SC-INV-001

Given a non-lead developer requesting a core and local inspection, when an independent authorized reviewer approves the combined plan, then capture and subsequent authorized core download/queries need no second review. Selecting the developer's registered agent client includes it in that review. Another human/client, changed output selection or another capture cannot use the approval. A context-only request adds no approval step.

## REQ-INV-002 — Materialize exact grants after verified commit

Only C-03 materializes a child rawQuery grant after C-14 verifies an eligible artifact. It checks current parent decision, requester eligibility, client policy, accepted capture UID/execution digest, trusted collectionProvenance action ID and selected output identity. The child names **existing exact artifact digests**, original requesting human plus one approved client, matching operations, inherited reviewer/decision provenance, original expiry and parent shared disclosure pool. No unknown artifact ID is placed in an executable raw grant. Team automation has its own executor and cannot reuse the human requester's combined result-access approval. Automatic policies, unrelated captures, recording-save sources, another person's artifacts and arbitrary later derivatives are not covered. Approved ordinary extracts need no raw child. A separately selected newly collected companion can qualify; an unrelated preexisting symbol artifact still needs its own entitlement.

Unique parent/capture/artifact/client registration makes repeated commit delivery idempotent. One SQL transaction checks parent/revisions, registers the artifact once, creates/reuses the child, records audit and reserves relevant shared counters in the canonical lock order. MaxArtifacts counts distinct admitted outputs across clients; each delivered byte/query is charged across **all** children/clients. Child creation never copies a fresh full allowance per artifact/client. Parent disclosure budget and local transfer/query limits both apply; maxBytes includes retransmission and uncertain spend. Resolve child transfer duration under its own operation/administrator ceiling (30-minute default, never beyond the original access deadline), not the collection action timeout. Queries still obey their shorter per-tool limits. Child grants expose resultOrigin (parentGrantID, captureUID, executionDigest, resultAccessDigest, actionID), not caller-supplied authority.

Recheck the parent's current expiry after acquiring any blocking artifact/publication locks, following REQ-DB-003. Holding the parent row does not stop wall-clock expiry. A child must not become published merely because its parent was valid before waiting for another transaction.

Revoking/denying/expiring the parent denies new child publication and subsequent child reads before cleanup. Exhausting the parent's collection-start counter is not revocation of its separately budgeted result access; show these two states separately. Cancelling remaining capture work does not revoke authorized results already collected. Source artifact expiry/restriction/current entitlement still wins. If a grant/materialization dependency is unavailable, encrypted evidence remains saved and the UI shows pending access with a retry of materialization, never another collection. Artifact arrival after original access expiry requires a fresh existing-artifact review, without recollection.

### SC-INV-002

Given duplicate artifact commits, two approved clients and a bounded parent disclosure pool, when children are published/queried, then each exact output is registered once and every child spends the same finite pool. A forged action/capture/parent digest, broadened operations, different principal/client, expired/revoked parent or exceeded count/bytes prevents publication/delivery. Capture-budget exhaustion does not consume the result budget. Existing evidence is retained if access publication is delayed.

## REQ-INV-003 — One browser/MCP journey with truthful progress

`preview_capture` accepts optional `result_access`; its protected preview binds that instruction for submit-by-preview. Direct expanded manual requests and DebugCapture may carry the equivalent resultAccess; canonical submission provenance protects it separately from the acquisition execution digest. Immutable scope changes need a fresh review; attaching a grant handle does not mutate the accepted plan. Browser/MCP preview returns the accepted result-access summary and whether one combined review is required. Capture status exposes selected result-access state and relevant current-principal child handles/navigation; automatic resolution reuses those grants for queries/downloads.

The reviewer sees collection and follow-up access together and performs one authenticated approve/deny action with ordinary independent step-up. One review does not mean one undifferentiated counter or permission. Result states distinguish NotRequested, AwaitingReview, WaitingForArtifacts, Ready, Partial, Expired, Revoked and Unavailable. A saved artifact with pending access is not mislabeled collection failure. Repeating a capture may offer the previous access **preferences** but never copies approval, issuedAt, existing child grants, prior clients without confirmation, or spent counters. Existing separate artifact requests remain available for later needs.

[ADR-249](../docs/decisions/249-sensitive-acquisition-grants.md) refinement: the runtime binds `result_access` on submission (`request_capture` with `preview_id`) rather than on `preview_capture`, whose descriptor is at the 32 KiB result limit; it is still protected by its own digest over `{captureUID, executionDigest, resultAccess}`, never the execution digest, and changing it needs a fresh preview and review. The runtime subset allows `download_artifact` only, at most four client IDs and 16 actions, a pool of at most 256 GiB and `notAfter` within eight hours. It is refused on a plan that needs no review. Result states other than the grant phase are not exposed yet: no raw output exists before S-04 increment 14.

### SC-INV-003

Given an approved combined request submitted through the console, when the capture completes and the developer opens the download or a selected agent queries it, then the same review is resolved automatically into exact current artifact rights. Refresh/retry requires no duplicate form and never recollects evidence. An unlisted agent gets an actionable missing-client review rather than token copying or an unexplained denial. The UI shows both capture readiness and evidence access; automated fixtures do not establish real usability.

### Approved-plan acceptance timing (ADR-252)

The passive preview's expiry bounds opening a new review; it does not consume an
approved capture's execution window. For explicitly versioned
`approvedAcceptance/v1` recorder plans, retain the exact original blueprint under
the existing quotas through the original grant review/expiry bounds. Approval
never renews those bounds. Same-human/client acceptance fixes one finite capture
deadline (at most five minutes and never beyond the original grant expiry) while
preserving original IDs, exact Pod, frozen composition/filter, audience, storage,
relative retention and approved digest. Recheck current ordinary entitlement,
recovery, retention and current approved/unrevoked grant at admission and new
execution effects; serialize grant use with revocation. An accepted retry returns
the original deadline and never recollects. Legacy plans with an absolute preview
deadline require a new review; they cannot silently gain the new timing contract.

SC-INV-001 includes approval after preview expiry, exact original-target submission,
revocation racing admission, and replay without renewed timing. Missing/replaced
Pods and material scope changes require new selection and review.

The approval view reports passive `preview_deadline`, `capture_deadline_rule`
and the marked plan's `capture_window_seconds` separately; it must not label an
expired preview as the new capture's start deadline. A change to the protected
recording-approval requirement in either direction requires a new preview/review
at submission, preserving exact reviewed scope rather than silently weakening
or strengthening it.
