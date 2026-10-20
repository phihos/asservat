# ADR-212 — Remaining interval before one-use API preparation

Date: 2026-10-20. Status: accepted; implemented; real PostgreSQL/S3 preparation-boundary checks pass.
Qualification is recorded in [implementation progress](../implementation-progress.md).
Requirements: REQ-EXE-002, REQ-DB-003–004; S-02.

Current qualification (2026-10-20): the
[real-service regression](../../test/results/resumed-c62e02ac-api-preparation-green/result.json)
passes post-lock headroom refusal, zero new effects, a later fresh first winner
and exact expired prepared-row replay into uncertainty, with synthetic current
authority. Installed start and acquisition qualification remain open.
[Resumed native47](../../test/results/resumed-c62e02ac-native47/result.json)
admitted one capture intent but created no execution row: it stopped before
preparation under the inherited deadline. That run does not demonstrate a
preparation-floor refusal.

Native45 inserted the first API execution preparation with 433.731 ms remaining
before its original deadline. The local start object reached `Ready`, but no
start or acquisition was recorded. Preparation had already spent its one-use
key opportunity. A later request cannot renew that preparation or safely repeat
its wrapping effects.

Require at least one second remaining before inserting a new API execution
preparation. Check database time after the current recovery, permission,
retention and storage checks and their blocking locks, immediately before the
insert. Use the earlier of the original checked interval and the actual caller
deadline; cancellation still refuses the operation. Insufficient time rolls
back without an execution row or permission to prepare keys. It does not undo
capture admission, refund its charges or change its registration.

This is a new conservative admission floor, not a measured execution duration
or a guarantee that preparation and acquisition will finish. It changes no
five-second authority limit and never renews a previously observed interval.
A later explicit ADR-134 continuation may become the first preparation winner
for the same accepted capture, with fresh request-owned authority and the
original capture, target, registration and write deadlines. Polling and passive
replay remain unable to acquire evidence.

An existing exact `prepared` row is a passive no-create result, including after
its immutable start interval expires. Current authority and exact process/scope
checks remain mandatory before returning it. The runner uses its existing
`PreparationUncertain` result to stop continuation. This is not proof that no
acquisition occurred, permission to refund, or a new key/start permit. The row,
its original interval and all spent effects remain unchanged.

Qualification must reproduce insufficient remaining time after a blocking lock,
show no inserted execution or key effect, and then allow one first winner on
an explicit fresh request. Expired prepared replay must return the same
no-create row and reach nonretryable uncertainty without new effects. Repository
and installed lifecycle qualification remain separate.
