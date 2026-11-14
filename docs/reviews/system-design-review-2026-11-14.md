# System design review (2026-11-14)

The maintainer asked for an audit of the specification for poor systems
design after a delegated design re-sent remote AccessBindings every 10 s.
Eight read-only reviewers covered all of `specs/` and `docs/architecture/`;
a ninth listed the polling loops in the code. Raw findings, with file and
line references, alternatives and precedents, are in
[system-design-2026-11-14/](system-design-2026-11-14/).

| Area | Findings | High |
|---|---|---|
| Federation, capacity, persistence, deployment profiles | 33 | 13 |
| Authorization, permissions, policy automation, privacy | 22 | 10 |
| Execution, actions, triggers, targets, capture | 24 | 7 |
| Evidence, downloads, recording saves, live watch, packets | 32 | 10 |
| APIs, interfaces, MCP, user experience, contracts | 24 | 7 |
| Architecture A (api … context) | 25 | 11 |
| Architecture B (custody … native) | 25 | 9 |
| Architecture C (node … workload) | 48 | 23 |
| Code polling loops | 65 loops | 19 clear replacements |

The findings overlap heavily. Nearly all follow from fourteen patterns,
resolved by [ADR-330](../decisions/330-event-driven-system-design.md):

1. Polling and expiry-driven re-reads where watches, pushes or
   `LISTEN/NOTIFY` exist (D1). Examples: 15 s trigger polling with up to
   512 GETs per cycle per cluster; per-second peer re-resolution; client
   polling of every status; 1 s config and LIST loops kept only to renew
   5 s freshness.
2. Standby socket pools, owner relay and per-process routing for the
   connector channel (D2).
3. Private PKI and enrollment layers for hub replicas, workers and
   connectors (D3).
4. One Kubernetes Job per download or query, including 4 KiB reads (D4).
5. Five-second windows and per-hop/per-chunk rechecks against ADR-311/312
   (D5).
6. Encrypted object-store audit pairs on every request (D6); measured
   1.2 MiB/s downloads.
7. Spent-on-uncertain accounting, serialised pool locks and several
   charge ledgers (D7).
8. Small metadata stored as encrypted objects or CRDs per attempt (D8).
9. Server-side preview handles with caps and recovery tools (D9).
10. Hub-signed submission envelopes and intent versions (D10).
11. Assignment-ID continuity that suspends shares after a relist (D11).
12. Retention watermarks, checkpoints and proofs (D12).
13. Installer-era guard, UID-pin and probe requirements (D13).
14. About 55 obsolete architecture documents and ~33 contracts.

One sentence in AGENTS.md ("exact child grants are created only after
verified commit") reads as an agent summary, not a maintainer decision.
The product capability (one bounded approval covers the same human's
selected result inspection and download) is kept; whether child grants are
materialised or checked against the parent at read time is an
implementation choice under D5/D8.
