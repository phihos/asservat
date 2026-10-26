# ADR-235 — Capture-time sharing of the published result (S-06 increment 5)

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-SHR-004 (narrowed below), S-06 (TASK-07). Plan: `docs/reviews/s06-plan-2026-10-26.md`,
increment 5 (F5) and the §2.3 simplification "one instruction on the accepted capture, materialized
at publication".

## Problem

An evidence owner who requests a capture for another team today waits for publication and then
creates a share in a second step ([ADR-232](232-concrete-evidence-share.md)). The maintainer
accepted optional capture-time sharing. The canonical design (a `SharingIntent` runtime record with
eight states, registrations, child shares per output selection and publication slots) has nothing
to select for a capture that publishes exactly one pod-status artifact.

## Decision

1. **Request.** `preview_capture` accepts the canonical `sharing` object, narrowed to
   `recipients` (1–8 User/Group stable IDs of the requester's issuer, as `create_share`) and an
   optional absolute `notAfter` (future, at most seven days after the review). The instruction is
   part of the reviewed preview blueprint, outside the execution digest (ADR-029);
   `request_capture(preview_id, …)` submits it unchanged. The preview response states in
   `warnings` who will receive the result and until when. The preview refuses without the
   `evidence:share` scope or for a non-human caller (`SharingNotPermitted`).
2. **Authority at request time.** The SQL admission transaction, after its existing locks and on
   the same permission projection it already evaluates, runs `authorization.ShareManagement` (the
   `create_share` check) with the capture's future retained audience. Without evidence-owner
   authority and `evidence:share` the whole request is refused (`SharingNotPermitted`, an audited
   denial) and no capture, custody attempt or charge exists. Otherwise the admission stores one
   immutable instruction (share ID, creator, the pinned management assignments, recipients,
   `notAfter`, request digest) in the new nullable column `context_capture.share_instruction`
   (migration 00088, schema 88, floor stays 81). Replay of the same request returns the original
   capture and writes nothing.
3. **Materialization at publication.** An owner-privileged trigger on the case-locator INSERT —
   which runs exactly once per published artifact inside the catalog publication transaction —
   inserts exactly one `evidence_share` row from the instruction (`idempotency_key`
   `capture:<capture id>`, the verified artifact version, the published locator's target).
   Publishers need no new grant. Replayed publication does not insert a locator, and the share's
   primary key makes any repeat a no-op. Expiry is `min(notAfter or publication + 24 h,
   publication + 7 d, the artifact's effective access end)`.
4. **One degraded state: SharingUnavailable.** If the share cannot be materialized — the end has
   passed, no pinned management assignment is still unretired, or the instruction is malformed —
   the capture still publishes and no share exists. The trigger never blocks publication.
5. **Status.** `get_capture` reports `sharing: {state, share_id?}` separately from the capture
   phase: `Pending` while the capture can still publish, `Shared` (with the share ID) once the
   share exists, `SharingUnavailable` when it published or ended without one. The share is an
   ordinary ADR-232 share afterwards: readers evaluate it at every read (denies, recipients,
   current pinned management, expiry), and `list_shares`/`revoke_share` manage it.
6. **Console.** The capture request form has a collapsed "Share results with…" section that
   reuses the share panel's recipient editor (`RecipientsEditor`) and an optional duration in
   hours; the review shows the server's sharing statement and the progress view the sharing
   status.

### Spec narrowing (agent-authored, recorded in specs/authorization.md)

- No `SharingIntent` record, registrations, output selection, publication slots or Draining/Stop:
  one instruction per accepted capture, one materialized share (plan §2.3).
- No `reason` override (the share row has no reason column); no management selection (the
  requester's contributing evidence-owner assignments, as `create_share`; ADR-232 increment 4
  changes that selection for both paths).
- The publication-time check is reduced to "a pinned management assignment is unretired"; the full
  manager and deny checks happen at every read (plan §2.3, REQ-SHR-004 "pinned manager authority at
  publication").
- Sharing is offered on the reviewed preview path only; `request_capture` takes no separate
  `sharing` (the canonical contract already excludes it next to `preview_id`).

## Complexity gate (AGENTS.md)

1. **Frequency/harm:** every owner-requested capture meant for another team needs a second
   step today; frequency unmeasured; not hypothetical.
2. **Risk accepted:** yes ("optional capture-time sharing" is an accepted decision).
3. **Typical:** optional; helps installations with more than one team.
4. **Precedent:** "share on create" options (e.g. GitLab/Grafana sharing at creation); general
   product knowledge, not a verified research baseline.
5. **Privileges added:** 0 runtime grants; 1 owner-privileged trigger function; 0 Kubernetes,
   network, collector or worker change. Recipients gain what an ADR-232 share grants.
6. **Failure/degraded states:** 1 (SharingUnavailable); Pending is the existing pre-publication
   phase, not a new failure state.
7. **Configuration for its own machinery:** no.
8. **Outside Asservat's control:** IdP stable user/group IDs (as ADR-232).
9. **Cost:** captures without sharing: 0 extra queries. With sharing: 1 permission-projection read
   inside admission, 1 INSERT inside publication, 1 indexed primary-key read per `get_capture`.
   Rows: at most 1 share per capture.
10. **Upgrade/rollback/disable:** additive column and trigger, floor 81; an older binary ignores
    the column. Disable by withholding `evidence:share` or `evidence-owner`. As for ADR-232, an
    in-place `installer-upgrade` applies no new runtime grants (ADR-227), but this increment needs
    none: the trigger runs with owner privileges, and `get_capture`'s share read uses the existing
    `evidence-share` duty. Where that duty is missing (the ADR-232 upgrade limitation),
    `get_capture` of a capture that requested sharing is unavailable; other captures are unaffected.
11. **Smaller fix:** documenting "share after publication" leaves the accepted requirement unmet;
    this is the plan's smallest form (one column, one trigger).

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-06-increment-5-capture-time-sharing-adr-235-2026-10-26).
