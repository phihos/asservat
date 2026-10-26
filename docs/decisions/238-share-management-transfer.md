# ADR-238 — Explicit share management, transfer, administrator delegation and revocation (S-06 increment 9)

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-SHR-008 (narrowed below), REQ-SHR-001 to REQ-SHR-003 (administrator revocation),
S-06 (TASK-07). Plan: `docs/reviews/s06-plan-2026-10-26.md`, §2.4 (maintainer decision
2026-10-26: every spec feature ships in the first release), §3 row 9 and §3.1 gate row 9.

## Problem

[ADR-232 increment 4](232-concrete-evidence-share.md#increment-4-team-management) pins the
creator's owner teams as a share's managers and offers no choice, no transfer, no recovery and no
administrator revocation; the S-06 plan §2.3 had replaced the canonical `management` selection with
that default, transfer with "revoke and share again", and the administrator API with an explicit
Deny AccessBinding. The maintainer's §2.4 decision restores these spec features for the first
release. REQ-SHR-008 asks for an optional `management: {mode: creator | teams}`; "selecting
additional existing owner teams requires scoped delegation to assign management (normally evidence
administrator); show that requirement in preview"; an audited replacement of the pinned manager
set; "loss of every manager suspends … and requires explicit authorized resume"; "authority
recovery can be performed by a scoped administrator without changing the recorded creator"; and
"currently authorized personal/team managers and authorized administrators MUST be able to revoke
immediately".

## Decision

1. **Administrator authority.** The installation administrator is an operator of the protected
   fleet administration (`fleet.Administration.Operator`: configured issuer, clients, subjects or
   groups, not suspended; the Kubernetes-protected installation projection that already authorizes
   cluster enrollment). This is the same installation-wide administrator check ADR-237 (permission
   impact preview, increment 10) uses; the method is shared verbatim. It is this installation's
   scoped delegation to assign management and its "authorized administrator" for revocation. No new
   role type, Kubernetes object or configuration is added; without a configured fleet
   administration all administrator paths are off.
2. **Explicit management at creation.** `create_share` accepts the canonical optional
   `management` (`specs/contracts/management.schema.json#/$defs/request`). `mode: teams` names one to
   eight stable group IDs of the creator's issuer; the share pins the creator's contributing
   `evidence-owner` assignments of exactly those groups (ordinary `ReadApproved` of the artifact,
   retained audience included, `evidence:share`). `mode: creator` pins only the creator's individual
   `evidence-owner` assignment. Omitted, the ADR-232 increment 4 default applies unchanged (also for
   capture-time sharing, ADR-235). The selection is part of the create request digest (a default
   request keeps the increment 1 digest).
3. **Delegated team selection.** A team the creator does not hold now is refused with
   `ManagementNotHeld` — unless the creator is also an administrator (decision 1), whose scoped
   delegation may name any owner team that currently holds an undenied `evidence-owner` assignment
   covering the target and inside the artifact's retained audience (`AdministeredShareManagement`).
   Still at most eight assignments, still covering the target, never outside the retained audience,
   so the delegation can never widen who may read the artifact. The administrator must still be
   allowed to share (ordinary rights, an own owner assignment and `evidence:share`). The console's
   Share panel and transfer form, the tool descriptions and the `ManagementNotHeld` message state
   that assigning owner teams the user does not belong to requires an installation administrator.
4. **Audited transfer and recovery.** New shared browser/MCP operation `transfer_share(share_id,
   expected_revision, idempotency_key, management)` on the normal operation-audit lane (the audit
   records the acting principal, the input and the outcome). The caller must be a current manager
   (ADR-232 `ManagedBy`) or, otherwise, an administrator — checked before the revocation/expiry
   check and before any catalog read. A manager names teams they hold now (or, as creator,
   `mode: creator`); a manager who is also an administrator, or an administrator, may name any
   current owner teams as in decision 3 (`mode: teams` only, so management never names a person).
   An administrator may also transfer a **Suspended** share: this is the explicit authorized
   resume / authority recovery. Revoked and expired shares cannot be transferred. The store requires
   every held assignment to be pinned by the locked row (skipped for an administrator, whose
   authority the service checked), replaces only `management`, records the transfer's idempotency
   key and request digest, and adds one revision. Creator, recipients, artifact, version and expiry
   never change (the trigger enforces it), so neither transfer nor recovery can extend a share or
   widen its audience; REQ-SHR-008: replacement carries original deadlines and cannot reset budgets.
5. **Revision.** Each transfer and the one revocation add one revision (migration 00091 replaces the
   increment 1 rule "1 unrevoked, 2 revoked" with `1..10^9`, revoked ≥ 2). `list_shares` returns
   `revision` for managed and administered rows; `revoke_share` and `transfer_share` compare it
   (`Conflict` when stale). The latest transfer key replays the same request; the same key for
   another request is `Conflict`.
6. **Administrator revocation.** An administrator may `revoke_share` any share. The check runs only
   after the caller is neither creator nor current manager, and an unavailable permission
   projection does not block it (revocation only restricts). It grants no read; the operation audit
   records the administrator principal.
7. **Management-only administrator listing.** `list_shares(view=administration, limit ≤ 100,
   cursor)` returns every share of the installation, newest first, keyset-paged on
   `(created_at, id)` with an opaque cursor (`next_cursor`; new index
   `evidence_share_administered`). Rows carry the opaque share, case and artifact IDs, derived phase
   (Suspended when the projection is unavailable), expiry, revision, `created_by` and `managed_by`
   — the stable IDs already shown to managers. Recipients are **not** listed: REQ-SHR-008 limits a
   management-only view to "opaque IDs, expiry and revoke/stop controls, not hidden evidence,
   unrelated recipients or other teams' membership". Administrators only (checked before the read
   and again after it); `evidence:share` is required like the owned view.
8. **Console.** The case Share panel has a collapsed "Managed by (optional)" team list with the
   administrator note; `/shares` shows "Created by" and "Managed by" per owned row, a "Transfer
   management" form on Active rows, uses the listed revision for revoke, and a collapsed "All shares
   (installation administrators)" section: load and page the administrator listing, revoke, and
   "Assign managing teams" (recovery of Suspended shares). The server decides every case.
9. **Interfaces.** `transfer_share` is added to `specs/contracts/mcp-tools.json`,
   `docs/interfaces/operations.yaml` and the browser OpenAPI; it implements the earlier design-only
   console operation `replace_share_managers`, which is removed. The canonical `list_shares` gains
   `view: administration` (no intents) and an optional row `artifact_id`; the runtime subset keeps
   the canonical `cursor` and `next_cursor`. Migration 00091 adds `transfer_share` to
   `operation_audit_lane` and `operation_audit_human_input_valid`, copying the latest definitions
   including the names of the parallel migrations 00089 (`list_capture_history`,
   `get_capture_settings`) and 00090 (`preview_access_change`) plus `explain_access`, so their merge
   order drops no name. The `evidence-share` duty gains column UPDATE on `management`,
   `transfer_key`, `transfer_digest`; the table trigger allows a revocation or a management transfer
   of a live share only.

### Spec narrowing (agent-authored, recorded in specs/authorization.md)

- The scoped delegation is installation-wide (fleet operators), not a per-namespace "assign
  management" role; the permission model has no such role, and adding one needs its own review.
- No separate "Manage existing sharing"/"Read existing evidence" preview step: a transfer or
  recovery of a concrete metadata share hands over management only and never reading; the console
  and tool text state that managing grants no read. Raw sharing (which needs independent review
  for widened transfers) does not exist yet.
- Administrators cannot pin a person (`mode: creator`) and cannot recover a revoked or expired
  share.
- The administrator listing shows no recipients (REQ-SHR-008 management-only view).
- Capture-time sharing (ADR-235) keeps default management.

## Complexity gate (AGENTS.md; plan §3.1 row 9)

1. **Frequency/harm:** team reorganisations and an owner team leaving a workload need a
   management hand-over; losing every manager strands a share as Suspended; an administrator needs
   to find and stop a mistaken share. Frequency unmeasured; not hypothetical (REQ-SHR-008/SC-SHR-008
   scenarios).
2. **Risk accepted:** yes, by the §2.4 maintainer decision (every spec feature in the first
   release).
3. **Typical:** uncommon paths (transfer, recovery, administrator stop); the default management
   still covers the common case.
4. **Precedent:** team-owned ACL hand-over, administrator ownership recovery and admin revoke of
   shared links (e.g. GitLab group/project transfer, Google Drive owner transfer and admin link
   revocation); general product knowledge, not a verified research baseline.
5. **Privileges added:** for the existing fleet operators: revoke any share, assign current owner
   teams (also on a Suspended share) and list share management metadata. Recovery re-enables
   recipient reads that were Suspended, but only through teams that already hold `evidence-owner`
   inside the artifact's original audience and only until the original expiry; it grants the
   administrator no read and no recipient change. 3 column UPDATE grants and one index for the
   existing `evidence-share` duty; 0 Kubernetes, network, collector or worker changes; no
   credentials.
6. **Failure/degraded states:** 0 new phases (Active/Expired/Revoked/Suspended unchanged); one new
   refusal (`ManagementNotHeld`); an administrator row without a current projection shows Suspended.
7. **Configuration for its own machinery:** no (administrators come from the existing fleet
   administration).
8. **Outside Asservat's control:** IdP stable group IDs (as ADR-232).
9. **Cost:** create: 0 extra reads (1 administration read only for a refused delegated selection).
   Transfer: 1 share read + 1 projection read + at most 1 administration read + 1 catalog read + 1
   locked UPDATE. Administrator revoke: as before + 1 administration read when the caller is
   neither creator nor manager. Administrator listing: 2 administration reads + 1 indexed keyset
   page (≤ 101 rows) + 1 projection read per distinct target on the page. No watches, no
   background work; rows unchanged in number.
10. **Upgrade/rollback/disable:** additive migration (two nullable columns, one index, constraint and
    trigger replacement, audit-name functions); floor stays 81. An older binary never serves
    `transfer_share` or the administration view; it reads unrevoked revision 1 and revoked revision
    2 rows as before, but refuses a transferred row (revision above 2 or unrevoked 2) as invalid, so
    a rollback fails closed for those shares' reads until they expire (at most seven days). As for
    ADR-232, an in-place `installer-upgrade` applies no new runtime grants (ADR-227): until the
    grants are reapplied, `transfer_share` is unavailable (permission denied → `NotAvailable`),
    everything else works. Disable transfer and explicit management by withholding
    `evidence:share`; all administrator paths by leaving the fleet administration unconfigured.
    Rollback of the tool/view: remove them; rows unchanged.
11. **Smaller fix:** "revoke and share again" plus a Deny binding was §2.3's smaller fix; the
    maintainer decision requires the spec features. This is the smallest form: one column update,
    one tool, one list view, one existing administrator check, no new role or record.

## Qualification

Results are in
[implementation progress](../implementation-progress.md#s-06-increment-9-explicit-management-and-administrator-revocation-adr-238-2026-10-26).
