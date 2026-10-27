# ADR-239 — Bounded recurring-policy sharing (S-06 increment 8)

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-SHR-005 and REQ-SHR-007 (narrowed below), S-06 (TASK-07). Plan:
`docs/reviews/s06-plan-2026-10-26.md`, §2.3 row "Recurring sharing via SharingIntent registration
before dispatch", §2.4 (every spec feature ships in the first release) and §3 increment 8 (F6).

## Problem

A restart-, probe- or alert-trigger policy (ADR-228/230/231) collects automatically. A team that
wants another team (an incident-response group, an on-call user) to see those captures today has
to share every published artifact by hand ([ADR-232](232-concrete-evidence-share.md)). The
maintainer accepted "explicitly bounded recurring-policy sharing". The canonical design (a
`SharingIntent` runtime record with registrations, child shares per output selection, publication
slots and Draining/Completed states) has nothing to select for a policy whose every capture
publishes exactly one pod-status artifact.

## Decision

1. **Policy field.** A DebugPolicy may carry the canonical `spec.sharing` policy declaration,
   narrowed to `recipients` (1–8 User/Group stable IDs of one issuer), `futureCaptures:
   {enabled: true, maxCaptures: 1–100}` and an absolute `notAfter`. `outputSelection`,
   `maxArtifactsPerCapture`, `reason` and `management` are rejected with their field path (one
   output; management is the policy's owner teams). The compiler checks the shape only, so a
   running policy's poll never fails because the end passed. The CRD
   (`charts/asservat/crds/debugpolicies.yaml`) gains the structural `sharing` block so the API
   server keeps the field (rejected fields are kept too, so they are refused, never silently
   pruned). `sharing` stays outside the collection-intent digest (ADR-059), so editing it never
   advances the intent version or interrupts collection.
2. **Authority at activation.** `activate_policy` resolves the block with the activating human's
   current rights, on the projection it already reads: the human needs the `evidence:share` scope,
   no deny, and at least one evidence-owner Group assignment of the policy's sole automation
   AccessBinding for one of the sponsoring groups (`authorization.PolicyShareManagement`). The
   automation binding must therefore already hold `evidence-owner`; no schema field is added.
   Those assignments (≤ 8) are the pinned management — the policy's owner teams (default
   management, REQ-SHR-008). `notAfter` must be in the future and at most seven days after
   activation — the spec's installation maximum for every sharing intent (REQ-SHR-004: "an
   installation maximum of 7 days that administrators may tighten; an explicit notAfter must be
   future and within that bound"), which REQ-SHR-005's "same sharing declaration" inherits — and
   the recipients must be of the human's issuer. Otherwise
   the activation is refused (`SharingNotPermitted`, or `PolicyRejected` with the field path) and
   no acceptance exists. The SQL acceptance transaction re-derives the management after its locks
   and refuses a difference. The instruction (creator, management, recipients, `maxCaptures`,
   `notAfter`) is stored in the immutable acceptance record, so it is part of the acceptance's
   record digest and its encrypted acceptance audit.
3. **One counter per acceptance (migration 00092, schema 92, floor stays 81).**
   `policy_acceptance.shares_spent` only rises and never exceeds `maxCaptures`. An
   owner-privileged BEFORE INSERT trigger on `context_capture` (`claim_policy_capture_share`)
   runs inside every capture admission: for a policy executor's capture it increments the counter
   of the policy's current acceptance while under both limits — `shares_spent < maxCaptures` and
   `notAfter` not reached — and only while the observed DebugPolicy generation equals the
   accepted generation and the sharing is not revoked; then it copies an ADR-235 capture
   instruction (new share ID, the pinned creator/management/recipients, `notAfter`, the
   acceptance ID) into `context_capture.share_instruction`. A replayed admission inserts nothing,
   so it never spends twice; a restarted hub continues the stored counter. A failed or empty
   capture keeps its slot (REQ-SHR-005: conservatively consumed). Admission needs no new grant.
4. **Publication.** ADR-235's `materialize_capture_share` is replaced (same trigger) so a policy
   instruction's share names its acceptance (`evidence_share.policy_acceptance_id`, immutable
   with the row) and nothing is materialized once that acceptance's sharing is revoked. Share
   expiry is `min(notAfter, publication + 7 d, the artifact's access end)`; a capture published
   at or after `notAfter` is not shared. The share is an ordinary ADR-232 share afterwards.
5. **Stop future sharing (REQ-SHR-007).** The new shared browser/MCP operation
   `stop_future_sharing(sharing_intent_id = acceptance ID, expected_revision 1)` sets the
   acceptance's terminal `sharing_stopped_at` (once, idempotent by key): no further capture claims
   a slot, while captures that already claimed one still publish their shares before `notAfter`
   (the spec's Draining outcome, derived, no state machine) and existing shares stay until they
   expire or are revoked. It replaces the spec's console-only `/api/v1/console/stop_future_sharing`
   route with `/api/v1/operations/stop_future_sharing` (MCP parity). Editing the DebugPolicy
   (a later generation) also stops claims for the old acceptance; activating the new revision is a
   new acceptance with its own counter and end, earlier captures are never backfilled and the old
   counter never resets. Deactivation (ADR-229) stops collection and so sharing.
6. **Revoke-all by acceptance ID.** `revoke_share` accepts the canonical `sharing_intent_id`
   (the policy's `acceptance_id`) with `expected_revision` = the sharing's revision (1, or 2 after
   a Stop): under the acceptance row lock it marks the sharing revoked (terminal, once, idempotent
   by key) and revokes every still-unrevoked share with that `policy_acceptance_id` — exactly that
   acceptance's shares (each share's revision +1, ADR-238). Pending captures are never shared
   afterwards and no further slot is claimed. Stop and revoke-all are for the creator, any current
   manager (a current holder of a pinned owner-team assignment,
   `authorization.PolicySharingManagedBy`) or an installation administrator (ADR-238); others get
   NotAvailable.
7. **Review before activation (REQ-SHR-005).** `activate_policy` gains `sharing_reviewed`.
   Without it, a policy with sharing runs every activation check and then returns
   `SharingReviewRequired` with the review — "Repeated collections will be shared with" every
   recipient (or their count when too long), the capture limit, the end and the seven-day share
   bound — and nothing is accepted; with it, the policy is accepted. The activation reply carries
   `sharing` (statement, recipient count, `max_captures`, `not_after`) and a warning;
   `get_policy_status` reports `sharing.state` — `active`, `limitReached`, `expired`, `stopped`,
   `policyChanged` or `revoked` — with `revision`, the recipient count, `shared_captures`, the
   limit, the end and the stop/revoke times. Console: the review with "Activate and share", the
   sharing line, "Stop future sharing" and "Revoke all shares".

### Spec narrowing (agent-authored, recorded in specs/authorization.md)

- No SharingIntent record, registrations, selections, publication slots or stored
  PendingApproval/Draining/Completed states: one instruction in the acceptance, one counter and
  two terminal markers beside it (plan §2.3, accepted as outcome-preserving). Draining is the
  derived outcome of Stop (claimed captures still publish); the acceptance ID is the intent ID.
- No output selection or projection catalog: a pod-status capture has one metadata output.
  No independent sharing approval: raw selections do not exist and owner approval of metadata
  suffices where the installation permits it (REQ-SHR-005).
- Spec-required, not narrowings: the review before activation (decision 7), an explicit Stop
  (decision 5) and the seven-day `notAfter` bound (decision 2, REQ-SHR-004 installation maximum).

## Complexity gate (AGENTS.md)

1. **Frequency/harm:** every automatic capture meant for another team needs a manual share today;
   frequency unmeasured; not hypothetical (policies capture automatically, ADR-228).
2. **Risk accepted:** yes — "explicitly bounded recurring-policy sharing" is an accepted decision,
   and §2.4 schedules it for the first release.
3. **Typical:** optional; helps installations where a platform team's policies serve another team.
4. **Precedent:** scheduled report/alert sharing to a fixed recipient list with an end date
   (e.g. Grafana report schedules); general product knowledge, not a verified research baseline.
5. **Privileges added:** 1 owner-privileged trigger function (admission claim) and 1 replaced
   (publication); runtime grants: `evidence-share` gains SELECT and UPDATE(`sharing_stopped_at`,
   `sharing_stop_key`, `sharing_revoked_at`, `sharing_revoke_key`) on `policy_acceptance` for Stop
   and revoke-all. One new audited operation name, `stop_future_sharing` (the operation-name
   functions are redefined with every name of migrations 00086–00091). No Kubernetes, network, collector
   or worker change. Recipients gain what an ADR-232 share grants.
6. **Failure/degraded states:** 0 new phases; `limitReached`, `expired` and `policyChanged` are
   derived from stored facts; `stopped` and `revoked` are the stored terminal markers; one refusal
   (`SharingReviewRequired`) before acceptance. A capture without a claimed slot is
   simply unshared (ADR-235's SharingUnavailable when a claimed one cannot be materialized).
7. **Configuration for its own machinery:** no (constants: 100 captures, 8 recipients, 7 days).
8. **Outside Asservat's control:** IdP stable user/group IDs (as ADR-232).
9. **Cost:** policies without sharing: 1 indexed `policy_source` read per policy capture
   admission. With sharing: 1 counter UPDATE per admitted occurrence, 1 KEY SHARE read per
   publication, ≤ 100 share rows per acceptance; revoke-all: 1 transaction updating ≤ 100 rows
   through an index. No watches or polling added.
10. **Upgrade/rollback/disable:** additive migration, floor 81; an older binary ignores the record
    field and the columns, and its policy captures are claimed by the same triggers. Disable by
    removing `spec.sharing` (edit stops it), revoke-all, or withholding `evidence:share` /
    `evidence-owner`. As for ADR-232, an in-place `installer-upgrade` applies no new runtime
    grants (ADR-227): Stop and revoke-all are unavailable on an upgraded installation until role
    re-production exists; claiming, materialization, status and single-share revocation are not
    affected. Rollback leaves claimed instructions materializing (the trigger is in the schema);
    Stop and revoke-all need this binary.
11. **Smaller fix:** documenting "share each capture by hand" leaves the accepted requirement
    unmet; this is the plan's smallest form (one counter, one trigger, one reused instruction).

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-06-increment-8-recurring-policy-sharing-adr-239-2026-10-27).
