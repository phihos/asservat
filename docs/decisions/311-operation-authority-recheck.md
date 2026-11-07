# ADR-311: One authority check per operation with a bounded recheck interval

Status: accepted by the maintainer on 2026-11-07; implementation in progress.

## Context

Request paths re-checked authority under several independent five-second
windows (delivery policy via about four Kubernetes API reads per observation,
recovery state, identity snapshot, per-phase budgets) and combined them with
`min()`. Each check takes about 1.7 s on a real cluster, so live views,
capture starts and downloads lapsed mid-request in about 56 installed runs.
The five-second windows were agent-added (ADR-258 row 2, ADR-310); the
maintainer authorized relaxed, measured recheck intervals (AGENTS.md,
2026-10-20). Plan: docs/reviews/authority-timing-plan-2026-11-07.md.

## Decision

- `identity.AuthorityRecheckInterval` is 30 s. An operation checks identity,
  eligibility and recovery once and may use that snapshot until the earlier of
  check time + interval and every original hard end (session, grant, watch,
  lease, privacy, retention, source). Nothing extends an original deadline.
- The delivery policy keeps the accepted 60 s observation interval
  (`DownloadPolicyObservationInterval`); live reads share that observation.
- Context deadlines come once from the operation request window; inner code
  keeps I/O timeouts only.
- One classification separates transient dependency failures (retryable, no
  disclosure) from explicit denials and from ended sources.

## Consequences

Revocation stops disclosure at the next check, at most 30 s later (60 s for a
delivery-policy change), instead of five seconds. SQL effect fences (recovery
trust, audit request window, ledger compare-and-set) are unchanged. Fewer
Kubernetes API reads per request.
