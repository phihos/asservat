# Shared manual context investigation

C-09 has one `ContextInvestigation` service used by browser and MCP under
ADR-103, I-09, S-01/S-02 and TASK-02/03/05/07/11. It takes the request's
[current identity](current-request-identity.md) and delegates policy evaluation
to C-03, target resolution to C-05, compilation and explanation to C-06,
retention to C-15 and atomic admission to C-21. Mechanisms follow
[ADR-330](../decisions/330-event-driven-system-design.md) (D5, D7, D8, D9).

The supported diagnostic is the exact `builtin-pod-status-v1` recipe: one
whole-pod Kubernetes status projection, bounded by the 2 MiB API response cap
(etcd's 1.5 MiB object limit plus JSON overhead).
Unsupported recipes (`incident-context/v1`, logs, process lists, network
counters) return a typed unavailable error before target resolution.

## Preview

`Preview(ctx, CurrentIdentity, ContextIntent)` is a dry run. It returns the
resolved plan, its digest and a transient `ContextAssessment`; it stores
nothing. The intent names the workload, the diagnostic, requested retention
seconds and an optional reason.

- Ordinary eligibility is checked before any target metadata is returned. Before
  entitlement is established, resolver errors do not reveal whether another
  team's workload exists.
- Target resolution reads the [pushed cluster state](cluster-observations.md)
  and pins one Pod by UID, with its owner and, for the node class, its node.
- The plan binds the canonical scope, the complete default audience (distinct
  from the requester's contributing assignments), the workload's storage
  binding, the retention policy provenance, the reported capability and the
  assessment rule digest.
- Preview fails with a typed reason when a required fact is unavailable (no
  binding, capability mismatch, account full, resource type unavailable). It
  does not wait for a refresh.

Fixed private stage labels identify which step refused a preview for operator
diagnostics; dependency error text is not logged.

## Request

`Request(ctx, CurrentIdentity, plan digest, intent, idempotencyKey)`:

1. Looks up the idempotency key for the actor and client. A stored capture is
   returned unchanged, even after the Pod or workload is gone; a different
   digest under the same key is `Conflict`.
2. Otherwise authorizes once for the operation
   ([ADR-311](../decisions/311-operation-authority-recheck.md)), re-resolves the
   plan from current state and compares its digest with the submitted one. A
   different digest returns the new plan and what changed; the user reviews
   again. The pinned Pod is never replaced by another replica.
3. Admits atomically ([context admission](context-admission.md)).

Evidence retention starts when the request is admitted, not at preview, so a
user may review for two minutes and still get the full requested retention.
Concurrent requests with different keys create different captures; a
deliberate repeat needs a new key.

Acceptance is not execution, a committed artifact or a completed case.
Dispatch, verification, publication, case presentation and download follow
separately.

## Recording-save reasons

A recording-save reason is a plain SQL column on the capture under the
capture's authorization (D8). Scope, grants and repeat selection do not include
the reason.

## Approved recorder acceptance

Recorders that need approval follow [ADR-252](../decisions/252-approved-capture-acceptance.md).

- The approval stores the reviewed plan and digest. The plan binds action
  durations, not an absolute preview deadline.
- Submission by the same requester fixes one capture deadline within the
  approved window and the grant's expiry (ADR-335 D5), checks current target, eligibility, storage,
  retention and assessment against the approved digest and admits. Admission
  checks the grant and its revocation in the same SQL transaction.
- The administrator's approval-required setting is read once per submission; a
  change in either direction invalidates the review.
- Packet submission checks the pinned Pod and recorder availability from pushed
  cluster state. An unknown or unsupported recorder is a plan blocker; a
  transient unavailability is a retryable `NotAvailable`.

The browser submits an approval-required composition and receives the
`ApprovalRequired` link; the idempotency key stays stable across pending review,
page reload and lost replies. `get_grant` tells the original requester and
client whether resubmission is possible; the server emits
`resume_requires_original_client` for the same human on another client. No
grant is transferred.

Manual recorder assessment rules are `recorder-assessment/v2`: retention starts
at submission. The page renders the supplied actions, categories and output
limits; unknown overhead stays unknown.

The idempotency key is public correlation. Actor and OAuth client scope its
lookup; knowing the key confers no authority.
