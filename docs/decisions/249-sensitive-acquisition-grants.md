# ADR-249 — Sensitive acquisition grants (S-04 increment 12)

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-AUT-003 (SC-AUT-003), REQ-AUT-004, REQ-AUT-005, REQ-AUT-006 (limits bound, spend
pending), REQ-INV-001–003, REQ-SYS-002 ("unless an administrator requires more"). Plan:
[S-04 plan](../reviews/s04-plan-2026-10-27.md) §2 P14, §4 row 12 (split: this is 12a, individual
approval; 12b, policy grants, is open) and §4.1. Migration 00098.

## Problem

HTTP headers, raw packets, syscall arguments and raw-byte filter predicates are specified as
sensitive acquisitions that need an approved grant before the first observed byte, and an
administrator may require approval for metadata recordings too (REQ-SYS-002). Until now the
compiler refused all of them with `ApprovalRequired` because no grant system existed (ADR-243
§2/§3). The `action-approver` role existed only in the AccessBinding schema. Without a grant system
increments 13–15 (HTTP headers, raw packets, syscall arguments) cannot start, and S-08 would have to
build it first.

## Decision

1. **One adHocCapture AccessGrant per reviewed plan.** A grant binds the preview's capture UID and
   its execution digest (SHA-256 of the canonical `recorder-preview/v1` plan, which already binds
   target pod, recipe/profile composition, filter bytecode digests, windows, rings, retention and
   deadline), the data class, the sensitive reasons, the requesting human (issuer, subject, client)
   and a finite lifetime. A review digest over all of these (plus the result-access digest and the
   stored review summary) is what the reviewer approves; every use recomputes it from the stored row.
   The frozen plan itself is stored with the grant (≤ 64 KiB), so a later recorder can start
   exactly the approved plan. One capture identity has at most one request (a second key is a
   conflict); a retry with the same key and content replays it.
2. **Which plans need a grant.** The compiler no longer refuses a `proto[offset]` predicate: it
   screens it like any filter (inside brackets an `offset:size` with size 1, 2 or 4 is allowed; names
   are still never resolved), compiles it with libpcap and records reason `rawBytePredicate` with
   REQ-AUT-006 observation limits (session seconds = action timeout capped at one hour, 1 GiB
   observed bytes, 16 MiB/s, one concurrent session) in a new optional `approval` block of the plan.
   The protected identity settings gain `approvals.requireRecordingApproval`; when true every
   packet/syscall plan gets reason `recordingApprovalRequired` (no observation limits: no payload
   reaches a predicate). Both are part of the execution digest. Metadata plans without the switch
   are unchanged byte for byte (the block is omitted). HTTP headers, raw packets and syscall
   arguments remain refused at compile time with `ApprovalRequired` because no builtin profile or
   edit can select them yet; increments 13–15 add them as further reasons.
3. **Journey.** `preview_capture` reports `approval_required: true` and the blocker
   `ApprovalRequired` (responsible role approver) before `RecorderUnavailable`. `request_capture`
   on such a preview opens the review request while the preview is current and returns
   `ApprovalRequired` with `navigation_uri` = the approval page `/approvals/<grant>` and
   `responsible_role: approver`; while pending it returns the same request; denied, revoked or
   expired grants return `ApprovalDenied`/`ApprovalRevoked`/`ApprovalExpired`. When an approved,
   current grant covers the exact plan for the calling requester (same issuer, subject and
   client) and the requester still has current undenied collection eligibility, the next refusal is
   `RecorderUnavailable` (no recorder exists yet). Nothing is armed, reserved or charged on any
   path. `request_capture` with `preview_id` may carry `result_access` (canonical contract relaxed:
   it is bound by its own digest, never the execution digest); the runtime subset allows only
   `download_artifact`, at most four client IDs and 16 actions, a pool ≤ 256 GiB and `notAfter`
   within eight hours. It is invalid on a plan that needs no review (a context-only request adds no
   approval step, SC-INV-001).
4. **Independent approval with IdP step-up.** `decide_review` (browser only) records one decision.
   The reviewer must be a human with a current, undenied `action-approver` assignment for the exact
   target (new evaluator operation `approveAction`, the ordinary allow/deny/freshness rules) and must
   not be the requesting human, compared by issuer and subject whatever the client; the database
   also refuses a self-approval with a CHECK constraint. Approval additionally needs a current
   step-up: the access token's signed `acr` must be one of the protected
   `approvals.stepUp.acrValues` and its `auth_time` at most `maxAgeSeconds` (30–3600) old; the
   verifier parses both (a malformed value means no assurance, never a rejected token; `auth_time`
   is used only together with `acr`) and identity
   admission derives `StepUpUntil`. Without configured step-up no approval can be decided (fail
   closed). Denial only restricts and needs no step-up. The decision records approver, reason,
   `acr` and `auth_time`; an approved grant expires one hour after the decision, never after the
   result-access `notAfter`. Only one decision and one revocation are ever written (trigger).
5. **Revocation and visibility.** `revoke_grant` (browser only): the requester (withdraw, any
   client) or a current approver of the target; no step-up because it only restricts; expected
   revision and idempotency key. `get_grant` (browser and MCP) shows the full review to the
   requester or a current approver and answers anyone else exactly like an unknown ID.
   `list_reviews` (browser only): view `pending` is the approver inbox (others' reviewable
   requests where the caller is an approver now; at most 100 candidates read, filtered per target),
   view `requested` the caller's own requests.
6. **Result access: exact children after verified commit (REQ-INV-002).** C-03 `Materialize`
   registers one existing published artifact of exactly the approved capture and target (the
   `context_case_locator` row must exist) for one approved client: unique per parent, artifact and
   client, so repeated commit delivery is idempotent; `maxArtifacts` counts distinct artifacts
   across clients. `Use` reserves bytes/operations of one finite parent pool before delivery for
   the requesting human through the child's client with current ordinary download eligibility;
   a use ID makes retries idempotent; spend is never refunded; the SQL UPDATE holds the parent row
   lock, so revocation and concurrent uses are serialized and the pool cannot be exceeded.
   Revocation, denial or expiry of the parent stops new children and every child use. No production
   caller exists yet: the first raw output (increment 14) wires `Materialize` at publication and
   `Use` into download authorization.
7. **Audit and storage.** Migration 00098 adds `access_grant` (one row per plan; immutable apart
   from one decision, one revocation and monotonic pool counters, enforced by a trigger),
   `access_grant_child` and `access_grant_use` (append-only), and the four operation names on the
   normal audit lane (`operation_audit_lane`, `operation_audit_human_input_valid`, copied from
   00093). The ledger shares the hub's existing `evidence-share` authorization duty credential (no
   new role or pool). All four operations and `request_capture` go through the existing audited
   operation path; `decide_review` and `revoke_grant` are recorded as possible effects.
8. **Console.** `/approvals` lists the approver inbox and the caller's requests; `/approvals/<id>`
   shows the exact plan (target, actions, filters and bytecode digests, windows, rings, data class,
   reasons, observation limits, result access and pool), requester, review window and decision,
   with Approve/Deny (reason) and Revoke. A step-up refusal tells the reviewer to sign in again
   with step-up.

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | No sensitive recording exists yet (not observed). Every HTTP-header, raw-packet, syscall-argument and raw-predicate capture (increments 13–15, S-08 dumps) needs it; without it those features cannot start, and an administrator cannot require approval for recordings. Harm of a missing gate: payload observation without review. |
| 2 | Risk accepted | Yes: the maintainer selected one bounded independent approval with same-human result access (REQ-INV-001–003, AGENTS.md); plan §2 P14 and §6.1 point 1 move it into S-04. |
| 3 | Typical deployments | Yes for HTTP headers (accepted feature); approval of metadata recordings is an optional administrator setting. |
| 4 | Precedent | GitLab/GitHub protected-environment approvals (distinct reviewer, no self-approval); OIDC `acr`/`auth_time` with `max_age` are the standard step-up claims (OpenID Connect Core §2, RFC 9470). |
| 5 | Privileges added | No new role, credential, network access or Kubernetes permission. The existing hub `evidence-share` SQL duty gains SELECT/INSERT on the three tables and UPDATE on the decision/revocation/spend columns only. Collectors and workers are unchanged. |
| 6 | Failure/degraded states | Grant phases Pending, Approved, Denied, Revoked, Expired (derived, none is a degraded runtime state). One new failure: `StepUpRequired` when step-up is not configured or not current (fail closed). |
| 7 | Self-configuration | No knob for Asservat's own machinery: lifetimes (1 h, ≤ 8 h with result access), review window (1 h) and pool bounds are constants. The two settings (`stepUp` acr values/max age, `requireRecordingApproval`) are IdP- and administrator-policy facts the specification requires. |
| 8 | External dependencies | The IdP must emit `acr` and `auth_time` in access tokens (Keycloak does with its default `acr` and `basic` client scopes; LoA step-up flows are a realm configuration). |
| 9 | Cost at scale | Per preview: one cached identity-settings read (30 s observation, already read for identity). Per approval request: one SQL row ≤ ~110 KiB (plan ≤ 64 KiB, review ≤ 32 KiB). Per covering check: one indexed row read and one projection read. Inbox: ≤ 100 rows plus one projection read per distinct target. No background work, watch or polling; nothing per node or cluster. |
| 10 | Upgrade/rollback | Additive migration (floor stays 81); older binaries never read the tables. Unsetting `requireRecordingApproval` and leaving `stepUp` unset restores the previous behavior except that raw-byte predicates now produce a plan that cannot be approved instead of a compile refusal. |
| 11 | Smaller fix | Keeping the compile refusal would leave increments 13–15 and REQ-SYS-002 unimplementable. A grant without stored plan, pool or children would have to be redone for increment 14 (raw downloads) and S-08. |

Benefit established, cost small: proceed.

## Remaining limits (open points)

- **Policy grants (12b)** with `policyExecutor`/`policyAuthority`, the default seven-day and
  configured maximum period and prepaid observation slices are not implemented: no policy can arm a
  packet/syscall recorder before increment 6, and the policy compiler still refuses compositions
  with their field path.
- **Observation spend** (REQ-AUT-006 bytes/events charged before processing) needs the recorder
  (increments 4, 13–15); the limits are bound into the plan and grant now.
- **Browser step-up login:** the console has no "sign in with step-up" button that adds
  `acr_values`/`max_age=0` to the authorization request; a reviewer must already hold a
  step-up-level session (for example a realm or client whose sign-in always performs the step-up
  flow) and sign in again when `auth_time` is older than the maximum age. Keycloak LoA step-up
  qualification in the identity fixture (plan open item 10) is pending.
- **Preview lifetime:** a review request can only be opened while its preview is current (≤ 5
  minutes); approval may come later, but the plan's own deadline is the preview's. Increment 13
  must start an approved plan through acceptance with its own capture deadline (or extend the
  pending-review model); until then every approved plan is still refused with
  `RecorderUnavailable`.
- **Children** have no production caller until the first raw output (increment 14); requester
  eligibility at materialization is not re-evaluated (the requester is not present), only at every
  use.
- The migration number 00098 requires 00097 (S-04 increment 4) to merge first (00096 has
  merged and does not redefine the audit-lane functions); if 00097 adds operation names, the two
  functions in 00098 must include them.
- **Keycloak:** a realm client needs the `acr` client scope for the claim to appear in access
  tokens (measured below); `auth_time` comes with the `basic` scope.

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-04-increment-12-sensitive-acquisition-grants-adr-249-2026-10-27).
