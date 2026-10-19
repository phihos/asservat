# ADR-209 — Two context-start standbys per hub owner

Date: 2026-10-19. Status: implemented with a unit test; installed qualification
pending.
Requirements: REQ-EXE-002, REQ-FED-001/003, S-02; TASK-03 / TASK-11.

## Context

Preview target resolution is a query on an idle regional standby (ADR-179).
The region kept one exchange per hub owner process; a standby lives at most 30
seconds (bounded passive residency) and the next opening starts one second
after it ends, then needs one or more attempts of up to five seconds each.
Installed native 64 had three standbys over the journey window, so previews
often found none (`router`). The hub already accepts two standbys per cluster
(`Standby: 2` in the installed public profile).

## Decision

1. The regional context-start client allows at most two concurrent exchanges
   to one owner process (`mtls.ContextStartExchangesPerOwner`), keyed by
   exchange rather than owner. The client's total bound is unchanged.
2. The regional supervisor keeps two independent slots per owner, each retried
   one second after it ends, so their residency windows drift apart.
3. Every opening, its checks and original deadlines, the hub's per-cluster
   standby and connection limits, and the 30-second residency are unchanged.

## Consequences

Opening load per owner doubles while both slots are reopening; both sides use
the ADR-208 opening limiter. A third exchange to one owner is refused before
any setup or I/O.
