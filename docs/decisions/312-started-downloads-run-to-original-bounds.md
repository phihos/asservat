# ADR-312 — Started downloads run to their original bounds

Date: 2026-11-07. Status: accepted (maintainer decision); component and real-SQL
regressions implemented; installed qualification pending.
Requirements: REQ-DLD-002/003/004, S-02. Supersedes the post-start recheck parts
of [ADR-220](220-response-owned-download-permissions.md),
[ADR-233](233-recipient-native-download.md) and
[ADR-258](258-slow-native-response-windows.md).

## Maintainer decision

Verbatim, 2026-11-07: "Please remove these rechecks after download start if that
causes too many problems." AGENTS.md already recorded (2026-10-20) that the
maintainer did not require permission changes to interrupt in-flight downloads.
The rechecks after start have caused repeated problems: ADR-258's slow response
windows, a native-response budget failure and transient worker/identity refusals.

## Decision

A content response is authorized completely when it starts. Once started it
continues that decision until one of its original bounds, Stop or a failure ends
it. Nothing re-observes identity, permission, share, raw grant validity or policy
during the response.

**At the start (unchanged).** Every content GET authenticates the caller and
checks the session belongs to that principal/client. Before
`BeginDownloadResponse`, the C-03 authorizer performs the complete check
(identity, ordinary entitlement or share, retained audience, raw result access,
retention, delivery policy, processing and recovery), and the SQL response start
runs the complete permission/processing/retention/recovery fence. A resume is a
new GET and starts a new response under a new complete check.

**After the start (new).** `DownloadAuthority.Continue` restates the start
decision as the next at-most-five-second delivery lease without any I/O. It sets
`StartedAt` to the original check time, keeps `DecisionDigest` and revisions, and
ends at the earliest of five seconds, `AccessUntil` and the response's original
end. The five-second lease is now only a liveness/heartbeat interval: it lets a
crashed owner's response row expire quickly; renewing it is a cheap SQL update.

What still ends a started response:

- the response's original end: the browser session's fixed expiry or the bearer
  token/group-freshness expiry (the GET's hard bound), the download session
  deadline and the configured maximum transfer duration;
- `AccessUntil`, fixed at the start: the retention end, narrowed to an admitting
  share's expiry or the raw grant child's end;
- the effective retention cutoffs and managed-copy deletion read from the
  published SQL row in every window/lease transaction (they only shorten);
- explicit Stop (terminal session state), session/response generation and owner
  fences;
- the recovery incarnation fence: the installation must still be the issuer
  epoch the response started under and neither suspended nor recovery-blocked;
- byte, read-work, window and audit reservations, raw grant pool reservation per
  window (ADR-279), byte integrity, durable audit, encryption and Range/If-Match;
- worker certificate, native owner and conversation bounds, and cancellation.

What no longer stops it: permission projection changes or suspension, share
revocation, identity/group changes, delivery-policy, processing-restriction or
retention-policy observation changes, permission/trust/worker-configuration
observation staleness, and the browser session needing a refresh.

## Implementation

- `artifact.DownloadAuthority` gains `StartedAt` (omitted when zero) with
  `Started` and `Continue`. `BeginResponse` refuses a continuation.
- C-14 `DownloadResponseTransfer` fixes the start authority after
  `BeginDownloadResponse` and serves every later window and lease from
  `Continue`. No identity batch is opened after the start, except to authenticate
  a raw window's grant-pool reservation.
- SQL `downloadFence` and the recovery guard have a started branch: original
  validity, the published copy and its effective cutoffs, and the recovery
  incarnation. It skips the permission stream, processing snapshot, retention
  topology/proof and worker-configuration freshness. No migration: SQL triggers
  already accept a five-second authority interval.
- The private native handoff (`newWorkerResponseObservation`) no longer re-reads
  the caller's identity; the coordinator already authenticated it.
- Deleted: C-03 `DownloadResponseAuthority`, the response-owned 30-second
  entitlement (`downloadPermissionRecheck`) and the bootstrap
  `NewResponseAuthority` factory.

## Complexity review

| Question | Answer |
| --- | --- |
| 1. Frequency and harm? | Observed repeatedly: slow windows (ADR-258), a native-response budget failure, transient refusals that stopped running transfers. |
| 2. Accepted risk? | Yes. The maintainer explicitly accepted that permission changes need not interrupt started downloads. |
| 3. Typical benefit? | Every long or slow download; no per-lease authorizer reads. |
| 4. Comparable projects? | Presigned S3/CloudFront URLs check expiry at request admission and let an admitted transfer finish (ADR-258). |
| 5. Added privileges? | None. |
| 6. Added failure states? | None; several transient refusal states are removed. |
| 7. Added tuning? | None. |
| 8. External dependencies? | Fewer: no identity/permission/policy reads during a response. |
| 9. Aggregate cost? | Per started response, identity/permission/policy reads drop from one complete check per five-second lease to zero; one SQL transaction per lease remains. |
| 10. Upgrade and rollback? | No schema change; `StartedAt` is optional JSON in window/native audit records. Older code rejects continuations, so a mixed rollout only stops in-flight responses. |
| 11. Smaller alternative? | Longer intervals keep the failure modes; removal is smaller. |

## Known limits

- Revocation, share revocation and a processing restriction take effect at the
  next response start (a resume or new download), not within the running one.
  A response is bounded by its session deadline (default 30 minutes, at most
  eight hours) and the caller's session/token expiry.
- A raw window still reserves its bytes against the grant pool, and that
  reservation authenticates the caller and requires the grant to be current.
  Revoking a raw grant therefore still stops a raw transfer at the next 64 MiB
  window. Converting it to a start-time reservation needs a grant-ledger change.
- Each new 64 MiB native window still opens a new worker conversation with its
  own worker attestation (ADR-258); this is worker transport authentication, not
  a human authority recheck.
