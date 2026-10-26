# ADR-238 — Explicit share management, transfer and administrator revocation (S-06 increment 9)

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-SHR-008 (narrowed below), REQ-SHR-001 to REQ-SHR-003 (administrator revocation),
S-06 (TASK-07). Plan: `docs/reviews/s06-plan-2026-10-26.md`, §2.4 (maintainer decision
2026-10-26: every spec feature ships in the first release), §3 row 9 and §3.1 gate row 9.

## Problem

[ADR-232 increment 4](232-concrete-evidence-share.md#increment-4-team-management) pins the
creator's owner teams as a share's managers and offers no choice, no transfer and no administrator
revocation; the S-06 plan §2.3 had replaced the canonical `management` selection with that default,
transfer with "revoke and share again", and the administrator API with an explicit Deny
AccessBinding. The maintainer's §2.4 decision restores these spec features for the first release:
REQ-SHR-008 asks for an optional `management: {mode: creator | teams}`, an audited replacement of
the pinned manager set, and REQ-SHR-008/SC-SHR-008 and the revocation rule ("currently authorized
personal/team managers and authorized administrators MUST be able to revoke immediately") for an
administrator who can revoke any share.

## Decision

1. **Explicit management at creation.** `create_share` accepts the canonical optional
   `management` (`specs/contracts/management.schema.json#/$defs/request`). `mode: teams` names one to
   eight stable group IDs of the creator's issuer; the share pins the creator's contributing
   `evidence-owner` assignments of exactly those groups (ordinary `ReadApproved` of the artifact,
   retained audience included, `evidence:share`). `mode: creator` pins only the creator's individual
   `evidence-owner` assignment. Omitted, the ADR-232 increment 4 default applies unchanged (also for
   capture-time sharing, ADR-235). A named team the creator does not hold now for the artifact, or
   `mode: creator` without an individual assignment, is refused with `ManagementNotHeld`; nothing is
   silently dropped or added. The selection is part of the create request digest (a default request
   keeps the increment 1 digest).
2. **Delegation check.** REQ-SHR-008 lets a scoped delegation (normally an evidence administrator)
   select owner teams the submitter does not belong to. There is no Kubernetes-configured "assign
   management" delegation in the permission model (AccessBinding roles are `evidence-reader`,
   `workload-maintainer`, `evidence-owner`, `action-approver`), so the delegation check always
   finds none and such a selection is refused. This follows the plan row ("≤8 of the creator's
   current owner Groups, delegation-checked") and fails closed; adding the delegation needs a new
   role and its own review.
3. **Audited transfer.** New shared browser/MCP operation `transfer_share(share_id,
   expected_revision, idempotency_key, management)` on the normal operation-audit lane (the audit
   records the acting principal, the input and the outcome). The caller must be a current manager
   (ADR-232 `ManagedBy`: holds a pinned assignment that is still exactly a current allow, no deny,
   `evidence:share`) — checked before any catalog read. The new set is computed exactly as in
   decision 1 from the caller's own current assignments, so "a current manager replaces the pinned
   set with groups they currently hold"; `mode: creator` is allowed only for the creator, so
   management never names another person. The store requires every held assignment to be pinned by
   the locked row, replaces only `management`, records the transfer's idempotency key and request
   digest, and adds one revision. Creator, recipients, artifact, version and expiry never change,
   so a transfer cannot extend or widen access (REQ-SHR-008: replacement carries original deadlines
   and cannot reset budgets). A revoked, expired or Suspended share cannot be transferred (nobody
   manages a Suspended share; resumption stays "revoke and share again").
4. **Revision.** Each transfer and the one revocation add one revision (migration 00091 replaces the
   increment 1 rule "1 unrevoked, 2 revoked" with `1..10^9`, revoked ≥ 2). `list_shares(view=owned)`
   already returns `revision`; `revoke_share` and `transfer_share` compare it (`Conflict` when
   stale). The latest transfer key replays the same request; the same key for another request is
   `Conflict`.
5. **Administrator revocation.** An installation administrator may `revoke_share` any share. The
   administrator is an operator of the protected fleet administration (`fleet.Administration`:
   configured issuer, clients, subjects or groups, not suspended; the Kubernetes-protected
   installation projection that already authorizes cluster enrollment). This is the same
   installation-wide administrator check ADR-237 (permission impact preview, increment 10) uses, and
   the `Operator` method is shared verbatim. No new role type or Kubernetes object is added. The
   check runs only after the caller is neither creator nor current manager, and an unavailable
   permission projection does not block it (revocation only restricts). It grants no read: the
   administrator still needs ordinary rights or a share to read the artifact, cannot transfer,
   cannot list other teams' shares and revokes by share ID (with its revision). The operation audit
   records the administrator principal. Without a configured fleet administration, administrator
   revocation is off; the explicit Deny AccessBinding remains available.
6. **Console.** The case Share panel has a collapsed "Managed by (optional)" team list; `/shares`
   shows "Created by" and "Managed by" per owned row, a "Transfer management" form on Active rows,
   uses the listed revision for revoke, and a collapsed "Revoke any share (installation
   administrators)" form (share ID and revision). The server decides every case.
7. **Interfaces.** `transfer_share` is added to `specs/contracts/mcp-tools.json` (canonical; the
   runtime subset excludes sharing intents), `docs/interfaces/operations.yaml` and the browser
   OpenAPI. It implements the earlier design-only console operation `replace_share_managers`, which
   is removed. Migration 00091 adds the operation name to `operation_audit_lane` and
   `operation_audit_human_input_valid`, copying the latest definitions including the names of the
   parallel migrations 00089 (`list_capture_history`, `get_capture_settings`) and 00090
   (`preview_access_change`), so their merge order drops no name. The `evidence-share` duty gains
   column UPDATE on `management`, `transfer_key`, `transfer_digest`; the table trigger allows a
   revocation or a management transfer of a live share only.

### Spec narrowing (agent-authored, recorded in specs/authorization.md)

- No delegated selection of owner teams the submitter does not belong to (decision 2).
- No "Manage existing sharing"/"Read existing evidence" preview step: a transfer of a concrete
  metadata share hands over management only and never reading; the console and tool text state
  that managing grants no read. Raw sharing (which needs independent review for widened transfers)
  does not exist yet.
- No administrator authority recovery (resuming a Suspended share or transferring as an
  administrator): it would re-enable recipient reads on an administrator's decision; "revoke and
  share again" by a current owner remains the path.
- Administrators revoke by ID; there is no administrator list of all shares.
- Capture-time sharing (ADR-235) keeps default management.

## Complexity gate (AGENTS.md; plan §3.1 row 9)

1. **Frequency/harm:** team reorganisations and an owner team leaving a workload need a
   management hand-over; an administrator needs a direct stop for a mistaken share. Frequency
   unmeasured; not hypothetical (REQ-SHR-008/SC-SHR-008 scenarios).
2. **Risk accepted:** yes, by the §2.4 maintainer decision (every spec feature in the first
   release).
3. **Typical:** uncommon path (transfer, administrator stop); the default management still covers
   the common case.
4. **Precedent:** team-owned ACL hand-over and administrator revoke of shared links (e.g. GitLab
   group transfer, Google Drive owner transfer and admin link revocation); general product
   knowledge, not a verified research baseline.
5. **Privileges added:** administrator revoke for the existing fleet operators, restricting only
   and granting no read; 3 column UPDATE grants for the existing `evidence-share` duty; 0 Kubernetes,
   network, collector or worker changes; no credentials.
6. **Failure/degraded states:** 0 new phases (Active/Expired/Revoked/Suspended unchanged); one new
   refusal (`ManagementNotHeld`).
7. **Configuration for its own machinery:** no (administrators come from the existing fleet
   administration).
8. **Outside Asservat's control:** IdP stable group IDs (as ADR-232).
9. **Cost:** create: 0 extra reads. Transfer: 1 share read + 1 permission projection read + 1
   catalog read + 1 locked UPDATE. Administrator revoke: 1 share read + 1 projection read (as
   before) + 1 read of the existing protected fleet-administration reader, only when the
   caller is neither creator nor manager. No watches, no background work; rows unchanged in number.
10. **Upgrade/rollback/disable:** additive migration (two nullable columns, constraint and trigger
    replacement, audit-name functions); floor stays 81. An older binary never serves
    `transfer_share`; it reads unrevoked revision 1 and revoked revision 2 rows as before, but
    refuses a transferred row (revision above 2 or unrevoked 2) as invalid, so a rollback fails
    closed for those shares' reads until they expire (at most seven days). As for ADR-232, an
    in-place `installer-upgrade` applies no new runtime grants (ADR-227): until the grants are
    reapplied, `transfer_share` is unavailable (permission denied → `NotAvailable`), everything else
    works. Disable transfer and explicit management by withholding `evidence:share`; administrator
    revocation by leaving the fleet administration unconfigured. Rollback of the tool: remove it;
    rows unchanged.
11. **Smaller fix:** "revoke and share again" plus a Deny binding was §2.3's smaller fix; the
    maintainer decision requires the spec features. This is the smallest form: one column update,
    one tool, one existing administrator check, no new role or record.

## Qualification

Results are in
[implementation progress](../implementation-progress.md#s-06-increment-9-explicit-management-and-administrator-revocation-adr-238-2026-10-26).
