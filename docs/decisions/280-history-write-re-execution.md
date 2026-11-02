# ADR-280 — One re-execution of a claimed history write

Date: 2026-11-02. Status: accepted (agent decision). Refines ADR-272.
Requirements: REQ-CPR history repeat (saved settings of a capture).

## Context

ADR-272 writes a capture's encrypted history parameters once after start,
within their own budget. The write claims its SQL row (`write_claimed`)
before the regional exchange; when that exchange fails transiently (owner
relay or regional peer, observed in 3 of 5 installed approved-recording runs on
2026-11-02), nothing may claim the row again, so the capture's saved settings
stay unavailable and repeat-from-history fails although the capture succeeded.

## Decision

1. Within the same budget and claim, a failed execution (not an integrity
   failure) is re-executed once through a fresh regional session, only when
   the region's executor process epoch is unchanged (the claim binds it).
2. The same in-memory sealed bundle is written again. The history object
   writer accepts a create-only conflict only when the existing object is
   byte-identical; different bytes stay refused.

## Complexity gate

Benefit: frequent, user-visible loss of saved settings. Cost: one bounded
retry and an identical-bytes comparison; no new state, background task,
credential or configuration. No deferred or cross-process resume is added.
