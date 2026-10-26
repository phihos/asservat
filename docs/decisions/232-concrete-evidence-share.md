# ADR-232 — Concrete evidence share of one stored artifact (S-06 increment 1)

Date: 2026-10-26. Status: accepted; implemented; qualification below. Amended the same day by
[increment 4 (team management)](#increment-4-team-management).
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
   ReadApproved; never DownloadApproved, CollectContext, inventory or raw access. (Amended by
   [ADR-233](233-recipient-native-download.md): DownloadApproved of the same artifact.)
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
   `revoke_share(share_id, expected_revision, idempotency_key)` is creator-only in this increment
   (increment 4 adds every current manager);
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
| `application/authorization/download.go:94` (download authorizer) | ordinary only | unchanged here: recipients refused; [ADR-233](233-recipient-native-download.md) adds the share branch (increment 3) |
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
- Creator-only revocation and management; team managers are increment 4 (implemented below).

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
- Increment 2 (console) is below; 3 (recipient native download), 4 (team management) follow the plan.

## Increment 2: console sharing (2026-10-26)

Plan row 2. The console uses the three share operations of this ADR through the existing
browser operation route (`/api/v1/operations/<name>`: session cookie, exact Origin, CSRF,
identical `Idempotency-Key` header for `create_share`/`revoke_share`, canonical input/output
validation, audited dispatch). No new server operation, list endpoint, SQL grant or migration:
`list_shares` already serves both views, and its rows carry what the console lists.

1. **Case page "Share this artifact"** (one per artifact, `web/src/sharing/SharePanel.tsx`):
   User/Group recipients by stable ID of the signed-in user's own issuer (≤ 8), a duration in
   whole hours (1–168, default 24, sent as `expires_at`), the contract's required reason, and
   "What recipients will see": the artifact's kind, class/completeness and handling notice as
   the recipient's `get_case` shows them, the effective end `min(expiry, artifact access)` and
   what is not included (other evidence in the case, further sharing, workload access, new
   collections); native download is included (ADR-233). The panel renders nothing until opened
   and requests nothing until Share. A lost reply keeps the pending request and locks the form,
   so a retry sends exactly what the form shows: "Retry same share request" resends the
   identical body and key; "Discard and start over" drops it (the next Share uses a new key; the
   earlier request may still have created a share, which `/shares` lists). A canonical refusal or
   success clears it.
2. **Copyable case link** inside the panel (`/cases/<id>`); opening it checks the reader's own
   rights or share. Copying grants nothing.
3. **`/shares` page** (`SharesWorkspace`): "Shared with me" (`view=received`, links to the
   case) and "Shared by me" (`view=owned`, derived phase, Revoke on Active rows with
   `expected_revision: 1`, the revision of every Active share). A refusal of one list is shown
   in that section only. The Go console allowlist and public route set add exactly `/shares`.
4. **Recipient view:** on a case read through a share (`access: shared`) the console shows
   neither Download nor the Share panel and says that a share does not include native
   download (increment 3). This is presentation only; the server refuses both regardless.
5. **Browser scope:** browser sessions carry the token scopes of the console client. The login
   request is unchanged (`openid evidence:read evidence:download evidence:capture`); an
   operator who enables console sharing adds `evidence:share` as a **default** client scope of
   the console client, as the installed fixture now does. Without it the panel shows the
   server's NotAvailable message; nothing else changes.

Agent-authored choices (not maintainer requirements): whole-hour duration input, Revoke offered
only for Active rows, recipient entry as type + ID, hiding Download/Share on shared cases.

### Complexity gate (increment 2)

1. Frequency/harm: every console user who should share or read a share needs an MCP client
   today; not hypothetical.
2. Risk accepted: yes (sharing within the organization; increment 1).
3. Typical: yes (the console is the primary human interface).
4. Precedent: share dialog with recipients, expiry and copy-link (Google Drive, Grafana);
   general product knowledge.
5. Privileges added: 0 server privileges, 0 new operations, 0 SQL grants; 1 static console
   path (`/shares`); 1 operator step (default `evidence:share` scope on the console client). No
   browser provider token.
6. Failure/degraded states: 1 (uncertain create, retried with the same key); refusals are the
   server's canonical messages.
7. Configuration for its own machinery: no.
8. Outside Asservat's control: the Keycloak console client's default scopes.
9. Cost: case page 0 extra requests; `/shares` 2 `list_shares` calls (≤ 100 rows each, 1
   projection read per distinct target); create 1 call; revoke 1 call + 2 list calls. Main
   bundle +149 KB unminified generated validators (same pattern as the policy page).
10. Upgrade/rollback/disable: web assets plus one route, no schema; rollback removes the page;
    removing the default scope disables console sharing.
11. Smaller fix: MCP-only sharing exists and leaves console users without it; no extra list
    endpoint was needed.

### Qualification (increment 2)

Results are in [implementation progress](../implementation-progress.md#s-06-increment-2-console-sharing-adr-232-2026-10-26).
The installed browser focus (`ASSERVAT_JOURNEY_FOCUS=browser`) now also creates, lists and
revokes a share from the console session (its binding adds `evidence-owner` like the share
focus); it runs in CI, not locally.

- Increments 2 (console) and 3 (recipient native download, [ADR-233](233-recipient-native-download.md))
  are implemented (increment 2 above); increment 4 is below.

## Increment 4: team management

Plan row 4 of the S-06 plan. Increment 1 already pinned the creator's contributing
`evidence-owner` assignments (complete assignment, ID and basis digest) and derived Suspended from
them, so this increment changes which assignments are pinned, who may revoke, and what the owned
list returns. No migration, SQL grant, schema version or Kubernetes change.

1. **Default management (REQ-SHR-008).** `ShareManagement` pins the creator's contributing
   `evidence-owner` **Group** assignments (the owner teams, within the artifact's retained
   audience). Only when the creator has no owner team does it pin the individual User assignment
   (creator-only management). Increment 1 pinned both kinds; a creator's personal assignment no
   longer keeps a team share Active after every team is lost. More than eight owner assignments
   are refused (`ManagementTooBroad`), never truncated; increment 1 truncated silently.
2. **Current manager.** `Share.ManagedBy` returns the pinned assignments a caller holds now: a
   human with `evidence:share`, a current target projection with a complete fresh deny snapshot,
   no current deny naming the caller, and the pinned assignment still exactly a current allow
   (`Share.managers`, which already applied the creator-deny rule). Group membership changes within
   the same assignment keep a member managing, so the creator's departure does not affect the
   share. A newly added owner binding, even for the same group, is a new assignment ID and manages
   no older share; a share without any current pinned assignment is Suspended and nobody but the
   creator can revoke it.
3. **Revocation.** `revoke_share` reads the share by ID; its creator revokes as before (no current
   assignment needed). Anyone else must be a current manager; the service passes the held
   assignment IDs and the SQL revocation, which locks the row, requires each to be pinned by the
   immutable row. Otherwise NotAvailable, without saying whether the share exists. A team member's
   revocation of an already revoked share under another key is Conflict, as for the creator.
   The actor is recorded by the existing audited operation; the row stays creator-keyed.
4. **Owned list.** `list_shares(view=owned)` returns the caller's created shares in every phase
   plus unrevoked, unexpired shares pinning one of the caller's user or group subjects (SQL
   candidates by JSON containment on `management`), kept only while `ManagedBy` holds now. Rows
   are filtered from the first 100 candidates and then trimmed to the page, newest first. Owned
   rows carry `revision` (for `revoke_share`), `created_by` (the immutable creator) and
   `managed_by` (the pinned subjects, one per group); received rows stay minimal. The canonical
   `list_shares` row gains these optional fields (`specs/contracts/mcp-tools.json`, the browser
   OpenAPI copy and the generated runtime subset).

Management grants no read of the artifact: a manager reads only through ordinary rights or a
share, exactly as before.

### Complexity gate (AGENTS.md), increment 4

1. **Frequency/harm:** the accepted case is the creator leaving or being absent while a share
   stays active; before this increment only an administrator (Deny AccessBinding or removing
   `evidence-owner`) could stop it, both broader than one share. Frequency unmeasured; not
   hypothetical or test-induced (REQ-SHR-008, SC-SHR-008).
2. **Risk accepted:** yes (accepted decision: multiple owner teams manage shares; creators stay
   immutable audit actors).
3. **Typical:** yes; owner rights are normally granted to groups.
4. **Precedent:** group-owned objects managed by any current member (GitLab group resources,
   shared drives); general product knowledge, not a verified research baseline.
5. **Privileges:** none added: no SQL grant (the duty already has SELECT/UPDATE on
   `evidence_share`), no Kubernetes, credential, network, collector or worker change. Current team
   members gain list/revoke of shares pinning their team; no evidence read.
6. **Failure/degraded states:** 0 new phases; 1 new refusal (`ManagementTooBroad`). An unavailable
   projection refuses non-creator management (fail closed); the creator's revocation is unaffected.
7. **Configuration for its own machinery:** none.
8. **Outside Asservat's control:** IdP stable group IDs and ≤5-minute group freshness (unchanged).
9. **Aggregate cost:** ordinary reads and recipient reads: 0 extra. Owned list: 1 SQL query
   (creator index or a containment filter over the root's `evidence_share` rows, ≤ 100 candidates)
   plus 1 projection read per distinct target, as before. Non-creator revoke: +1 primary-key read
   and +1 projection read; creator revoke: +1 primary-key read. The containment filter has no
   index: rows are bounded by audited share creation; add a `jsonb_path_ops` GIN index if a
   measured owned list becomes slow. 0 Kubernetes requests.
10. **Upgrade/rollback/disable:** no migration (schema 86, floor 81). An increment-1 binary reads
    the same rows identically (its creator-only revoke and list simply ignore team members).
    Disable as before (remove `evidence:share` or `evidence-owner`).
11. **Smaller fix:** documenting the limitation leaves SC-SHR-008 unmet and administrators as the
    only stop; explicit management selection and transfer (the full REQ-SHR-008 surface) stay
    unimplemented because the default covers the accepted case.

### Qualification (increment 4)

Results are in [implementation progress](../implementation-progress.md#s-06-increment-4-team-management-adr-232-2026-10-26).
