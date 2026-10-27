# ADR-252 — Start an approved capture after its preview expires

Date: 2026-10-27. Status: implemented; targeted SQL qualification passed; final candidate gates pending.
Requirements: REQ-AUT-003/004, REQ-INV-001–003; S-04 increment 12a follow-up.
Migration: 00099. Supersedes ADR-249's preview-lifetime limitation.

## Problem

ADR-249 opens a review from a preview that lives at most five minutes. The
preview store refuses expired reads and deletes expired rows. Even after an
independent reviewer approves, the original request therefore fails before it
can start. ADR-248 supplies the recorder but does not fix this approval journey.

## Decision

Keep the original immutable preview, IDs, actor/client, exact Pod pin, frozen
filters, storage selection, relative retention, audience and approved digest.
An exact matching grant retains that passive blueprint through its original
review window and, if approved, original expiry. Retained rows still count
against the existing ten-per-principal and 1000-per-installation caps. Denial,
revocation and expiry do not renew either interval. Closing a preview continues
to refuse admission. The SQL deletion trigger protects retained blueprints,
including direct cleanup calls; no blueprint is rewritten.

Approval-required recorder plans explicitly carry `timing: approvedAcceptance/v1`
and an empty absolute `deadline`; they bind finite action/session durations.
The preview's original deadline still bounds opening a **new** review. When the
same human/client submits an approved plan, the request fixes a capture deadline
at preparation: at most five minutes from that preparation and at most the
original grant expiry. Request identity and all short request/observation
intervals keep their existing deadlines. Accepted replay never recalculates the
capture deadline or opens another capture. Retention begins at preparation.

The new timing marker prevents interpreting old approved plans as renewable:
they fail exact recompilation and require a fresh preview/review. Unapproved
metadata plans and pod-status plans keep their existing absolute timing.

The SQL admission transaction checks and holds a shared lock on the exact
approved, unrevoked, unexpired grant, requester/client, preview/capture and digest.
It bounds the actual deadline again after waits. Revocation takes the grant's
exclusive row lock, so these effects have a defined order. Direct unreviewed
admission cannot start an approval-required recording. API execution reads and
prepare/start effects recheck the same current grant. A revoked grant cannot
start new work. This does not promise instantaneous interruption of an already
started recorder. Historical accepted-operation lookup remains available under
its existing current rights/recovery checks.

Two narrow SQL functions provide blueprint read retention and exact grant
locking; preview, admission and execution duties gain only the necessary
function EXECUTE privileges, with no grant-table reads/writes. Both functions
have fixed search paths and no PUBLIC execution. A dropped `RequireApproval`
flag in `RecorderContext.Clone` is corrected so execution recompilation retains
its approval requirement.

The approval view separates `preview_deadline` from `capture_deadline_rule`
and, for the marked timing contract, `capture_window_seconds` (300 maximum).
The browser explains that the execution window starts at submission under the
approval expiry; legacy views explicitly keep their preview/start cutoff.

Submission also reads the existing cached protected approval settings once.
If `requireRecordingApproval` differs from the frozen plan in either direction,
submission requires a fresh preview/review instead of silently changing scope.
This closes the reproduced administrator false→true setting bypass and preserves
review identity for true→false changes. It adds no watcher or per-step polling.

No public operation, input parameter, configuration, credential, watch, background
loop or collector permission is added. Result-access child composition and
sensitive observation spend remain outside this fix.

## Complexity gate

| Item | Answer |
|---|---|
| 1 | Reproduced product path: an approval after a five-minute preview cannot start. Harm: the administrator-required recording workflow is unusable. |
| 2 | Yes: independent review is accepted; the five-minute preview-as-execution cutoff was an agent design choice, not a maintainer demand. |
| 3 | Every deployment requiring recording approval; not only a test path. |
| 4 | Reuses this product's existing immutable grants, SQL row locks and original expiry; no new authorization model. |
| 5 | Zero roles, credentials, network endpoints or Kubernetes permissions; two effect duties gain a narrow SQL function; preview/resolution gain a read-deadline function. |
| 6 | Zero new persisted phases; existing pending, approved, refused and unavailable outcomes. |
| 7 | Zero configuration switches. |
| 8 | Existing PostgreSQL only. |
| 9 | At most 10 retained previews per principal / 1000 per root; each up to 128 KiB. One indexed grant lookup per preview read/count/cleanup candidate; one existing cached approval-settings read per submission. Approved submission/execution adds a grant row lock/check per existing effect transaction, never per packet/node. No watches or background polling. |
| 10 | Additive migration with Down restoring the original expiry trigger; no evidence or approval is deleted. Old timing plans are explicitly refused rather than silently reinterpreted. |
| 11 | An application-only expiry bypass cannot recover deleted blueprints or serialize revocation. Reusing existing preview/grant rows is smaller than another approval-plan journal or public submit operation. |

Benefit established; proceed with bounded existing state. No new failure recovery
machinery is justified.

## Verification and limits

Application tests exercise delayed approval with the original plan/IDs/target,
new bounded deadline, retention anchor, no preview renewal, denial/revocation/
expiry, missing original Pod and revoked requester. Compiler regression checks
that approval survives clone, round-trip and later deadline recompilation while
Pod replacement changes scope. Real SQL qualification covers retained previews,
cleanup, reviewed admission after actual expiry, shared-lock/revocation ordering
and historical replay. Actual commands/results belong in implementation progress;
no unrun gate is claimed passed here. Installed independent-review/browser
journeys and participant studies remain separate qualification.
