# ADR-232 — Concrete evidence share of one stored artifact (S-06 increment 1)

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-SHR-001/002/003 (narrowed below), S-06 (TASK-07). Plan: the S-06 plan
`docs/reviews/s06-plan-2026-10-26.md` (branch `simplify/s06-plan`), increment 1 (F1 concrete share, F2 recipient-only
view, F3 revocation).

## Problem

Every read of stored evidence requires current whole-pod rights on the workload plus membership in
the artifact's retained audience. A developer of another team who should look at one incident's
pod-status snapshot can only be given an AccessBinding, which grants every current and future
artifact of the workload. The maintainer accepted sharing within the organization; nothing
implemented it.

## Prerequisites (plan section 4)

**(a) Group freshness ≤ 5 minutes: yes.** Browser sessions, MCP tokens and download tokens all
resolve through `identities.Service.ObserveCredential` → `identity.Admit`, which bounds every
identity's `ValidUntil` by `IssuedAt + GroupMaxAge`, and `identity.Policy.Validate` rejects a
`GroupMaxAge` above five minutes (Helm default `groupMaxAgeSeconds: 300`). Group claims are the
stable `asservat_groups` IDs issued with the token (`GroupsAtIssueQualified` is required). A stale
group claim cannot outlive five minutes, so this increment accepts **Group and User recipients**.

**(b) Keycloak `evidence:share` scope without a longer setup: yes.** The installed realm adds one
client scope in the existing scope loop and lists it as an optional scope of the existing MCP
client (`test/integration/installed_identity_test.go`): one more admin POST, no new client, user,
group or wait. The share focus requests it only for the owner's session; every other session's
scopes are unchanged.

## Decision

1. **One row per share** (migration 00086, table `evidence_share`, schema 86, floor stays 81:
   additive, an older binary never reads it). A row binds root, one published artifact, its case
   and exact whole-pod target (copied from the published case locator, never only from the
   caller), the verified artifact version the creator saw, the immutable creator, the pinned
   management assignments, ≤ 8 recipients and their lookup keys, the idempotency key and request
   digest, `expires_at`, and `revoked_at`/`revoke_key`/`revision` (1, or 2 once revoked). A
   trigger makes every column immutable except the one revocation. State is derived at read time:
   **Active, Expired** (`expires_at`), **Revoked** (`revoked_at`), **Suspended** (no pinned
   management assignment is current). Constants, not configuration: 7-day maximum, 24-hour
   default (service only; the MCP contract requires `expires_at`), 8 recipients, 8 pinned
   managers, 32 active shares per artifact (a per-artifact transaction advisory lock makes the
   cap exact). A share never outlives the artifact's effective access deadline at creation.
2. **Creation** (`create_share`, MCP and the browser operation route): a human caller with
   `evidence:read` and `evidence:share`; the case route locates the artifact; ordinary target
   eligibility (`ScopeEligibility`) precedes the catalog read; the creator must pass the ordinary
   retained-audience check and hold at least one contributing `evidence-owner` assignment
   (`ShareManagement`). The submitted artifact digest must equal the current verified version
   (concrete snapshot). Recipients are stable IDs of the creator's issuer (the configured
   issuer); display names and other issuers are rejected. Runs under the recovery transaction
   fence; a replayed key with the same request returns the original share, a changed request is
   Conflict, a 33rd active share is ShareLimit.
3. **Pinned management, no silent restoration (REQ-SHR-004/007).** The share stores the creator's
   contributing evidence-owner assignments, each as the complete assignment (assignment UUID,
   subject, role, basis UID and basis digest). A share is managed only while at least one pinned
   assignment is still exactly a current allow of the target's projection and no current deny
   names its subject (or the creator). `permission_assignment.id` is a fresh UUID at every
   activation and retired rows keep theirs, so removing and re-granting a binding creates a new
   assignment: the share stays Suspended and the owner must create a new share. This read-time
   check replaces the publication-time manager check that the plan dropped.
4. **Recipient branch, not a replacement.** The ordinary evaluator is unchanged
   (`Evaluate`/`ScopeEligibility` never consult shares). A separate `EvaluateShare` is consulted
   only after the ordinary facet refuses. It requires a current projection, lets every current
   matching deny win exactly as the ordinary facet does, requires `evidence:read`, the caller as
   a recipient, an Active share for the exact target and artifact, and (with the retained record)
   a current pinned manager inside the retained audience and metadata data class. It grants only
   ReadApproved; never DownloadApproved, CollectContext, inventory or raw access.
5. **No evidence lookup before eligibility.** In every changed read path the share lookup is a
   SQL read keyed by (artifact, caller's own user and group keys) **before** the catalog read, so
   a principal without an admitting share is refused before any evidence lookup. Each read
   re-reads the share before returning: a revocation or expiry between the first read and the
   reply refuses the response. A share-ledger outage admits nobody through a share and never
   makes an ordinary reader's other artifacts unavailable.
6. **Listing and revocation.** `list_shares(view=owned)` (needs `evidence:share`) lists the
   caller's own shares with their derived phase (Revoked/Expired need no projection; a target
   without a current projection shows Suspended instead of failing the list, so revocation stays
   reachable); `view=received` lists unrevoked, unexpired shares whose share-level checks
   `EvaluateShare` admits now (not denied), filtered from the first 100 candidates and then trimmed
   to the page, newest first, no cursor. Received rows are candidates: the artifact's retained
   audience, retention end and data class are checked by the read itself.
   `revoke_share(share_id, expected_revision, idempotency_key)` is creator-only in this increment;
   revocation only restricts access, so it needs no current owner assignment. The same key after
   success is a replay; another key or a stale revision is Conflict; another principal's share is
   NotAvailable without saying why.
7. **Audit.** The three operations run through the existing audited operation path on the normal
   lane (encrypted intent/outcome with the normalized input, including recipients and reason).
   The intent is acknowledged before dispatch, so a share never exists before its audited
   decision; `create_share` and `revoke_share` record an accepted effect in the outcome. Recipient reads are audited as
   ordinary `get_case` operations. No notification is sent.
8. **Privilege.** One new hub-runtime duty `evidence-share` on the existing shared hub credential:
   SELECT on `evidence_share`, `context_case_locator` and `fleet_current_trust`, INSERT on
   `evidence_share`, UPDATE only of `revoked_at`, `revoke_key`, `revision` (plus the existing
   recovery row-lock column). No Kubernetes, collector, worker, key-service or network change.

9. **Ownership.** The share service is the C-17 package `internal/application/sharing` (the
   catalog now lets C-17 use C-02 for the request-owned current identity). The recipient
   evaluator is the C-24 domain (`EvaluateShare`, `ShareManagement`), the recipient lookup port is
   C-03 (`ShareReader`), consumed by C-16 `get_case` and C-03 approved inspection.

### Read-path call sites

| Call site | Before | Now |
| --- | --- | --- |
| `application/catalog/context.go` first loop (`get_case`) | `ScopeEligibility` refused → skip, no catalog read | refused → share lookup by (artifact, caller keys); no admitting share → skip, **no catalog read**; admitted → catalog read, then `EvaluateShare` with the retained record and exact version |
| `application/catalog/context.go` retained `Evaluate` | refused → skip | refused (whole-pod rights outside the retained audience) → share lookup after the catalog read, which ordinary eligibility already allowed |
| `application/catalog/context.go` final recheck | ordinary `Evaluate` | shared artifacts re-read the share (same ID and revision) and re-run `EvaluateShare` |
| `application/authorization/projection.go` preliminary (approved inspection) | `ScopeEligibility` refused → refuse before `ContextProjectionEvidence` | refused → share lookup; no admitting share → refuse **before** the catalog read; final and end checks re-read the share; the decision digest binds the share ID and revision |
| `application/sharing/share.go` (`create_share`, new C-17 package) | — | `ScopeEligibility` before `ContextDownloadEvidence`, then `ShareManagement` |
| `application/authorization/eligibility.go:74` (`Evaluator.EligibilityCurrent`) | ordinary only | unchanged: no share branch, recipients refused |
| `application/authorization/download.go:94` (download authorizer) | ordinary only | unchanged: recipients refused (recipient native download is increment 3); installed focus verifies |
| `adapters/postgres/context_resolution.go` (`resolve_capture_request`) | requester and ordinary scope | unchanged: shares never grant capture or resolution |
| `domain/authorization/capture_progress.go`, `policy_capture.go` | ordinary / policy executor | unchanged |

## Agent-authored restrictions and spec narrowing (recorded as such)

These narrow the specification text for increment 1 and are recorded in
[authorization](../../specs/authorization.md#implementation-refinement-adr-232); none is a new
maintainer requirement:

- One artifact per share, data class `metadata`, operation `get_case` (and approved inspection of
  that artifact); 8 recipients instead of 32; no sharing intents, management selection, cursors
  or pending replies (runtime subsets of the canonical `create_share`/`list_shares`/`revoke_share`
  contracts; canonical contracts unchanged).
- No administrator sharing-policy toggle: `evidence-owner` assignments and the `evidence:share`
  client scope are already administrator-controlled. No administrator revoke API: an explicit
  Deny AccessBinding stops recipient reads now; removing `evidence-owner` suspends the shares.
- No directory check that a group ID exists (it would need directory-reader credentials that
  ADR-059 forbids by default). Use-time admission enforces organization identity eligibility at
  every request; a creation-time recipient eligibility check is not implemented.
- Creator-only revocation and management; team managers are increment 4.

## Complexity gate (AGENTS.md)

1. **Frequency/harm:** cross-team incident review is the stated use (accepted decision "sharing
   within the organization"); frequency unmeasured; not hypothetical or test-induced.
2. **Risk accepted:** yes (accepted decisions; ADR-005/024 kept sharing).
3. **Typical:** yes, every installation with more than one team.
4. **Precedent:** an ACL entry with optional expiry per object (Google Drive, Grafana, GitLab);
   general product knowledge, not a verified research baseline.
5. **Privileges:** one hub-runtime SQL duty (decision 8) and one OAuth client scope; no
   Kubernetes, credential, network or collector/worker change; recipients gain ReadApproved of
   one artifact only.
6. **Failure/degraded states:** three derived phases (Expired, Revoked, Suspended), no stored
   state machine or background job; a share-ledger outage refuses recipients only. Three states
   were scrutinized: each is an existing timestamp or the existing projection read.
7. **Configuration for its own machinery:** none (constants).
8. **Outside Asservat's control:** IdP user subjects and stable group IDs (freshness from 2a).
9. **Aggregate cost:** ordinary reads: 0 extra. A read the ordinary facet refuses: 1 indexed SQL
   lookup per refused artifact, plus 1 re-read per admitted shared artifact. Create: 1
   transaction (lock, key read, count, insert). List: ≤ 100 rows and 1 projection read per
   distinct target. 0 Kubernetes requests. Active rows ≤ artifacts × 32; revoked and expired rows
   are kept as history (cleanup with the artifact is not implemented, see below).
10. **Upgrade/rollback/disable:** additive migration, floor 81; the custody upgrade test runs
    85 → 86. Rolling back the image leaves shares inert (no older binary honors them). Disable by
    removing the `evidence:share` scope or the `evidence-owner` assignments. As for ADR-228's
    `policy-automation` duty, an in-place `installer-upgrade` applies no new runtime grants
    (ADR-227 limitation): until role re-production exists, the share operations of an upgraded
    installation are unavailable and recipients are refused; ordinary reads are unaffected
    (decision 5).
11. **Smaller fix:** an extra AccessBinding grants all current and future evidence of the
    workload, which is broader than one artifact; User-only recipients were the fallback if 2a
    failed, and it passed. This is the plan's smallest form.

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-06-increment-1-concrete-evidence-share-adr-232-2026-10-26).

## Limitations and next increments

- Recipient approved inspection (projection authority) has unit tests only; the installed focus
  covers `get_case`, `list_shares` and the download refusal.
- A share row is not removed when its artifact is deleted; rows stay bounded by the active cap per
  artifact and the audited operation rate. Cleanup belongs with retention composition.
- Increment 2 (console), 3 (recipient native download), 4 (team management) follow the plan.
