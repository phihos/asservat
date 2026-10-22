# ADR-220 — Reconstruct ordinary download permissions once per response interval

Date: 2026-10-23. Status: accepted under the maintainer's implementation and
simplification instruction; component implementation qualified; SQL and installed
qualification pending.
Requirements: REQ-DLD-002/003/004, S-02.

## Problem and accepted tradeoff

ADR-214 removes repeated protected policy reads and repeated complete authority
construction within one finite worker operation. A long HTTP response still
reconstructs ordinary entitlement for every short identity batch. The authorizer
reads the complete accepted permission projection twice per construction. The
native response then constructs complete authority again despite receiving the
coordinator's exact checked value.

Those repeated calls are visible in the source; their end-to-end frequency and
cost have not been measured in a sustained installed transfer. The maintainer
explicitly accepted relaxed bounded permission-change handling. This decision
selects **30 seconds between ordinary permission reconstructions within one
response**, without changing the existing short delivery and SQL effect checks.
It does not claim a 30-second revocation latency or diagnose native55's failure,
which happened before streaming.

## Decision

1. Bootstrap gives each content response one private C-03 ordinary-entitlement
   owner through a C-14-owned factory. It binds the original response context,
   exact principal/client, complete artifact/version and target scope. It has no
   serialized form, global cache, service, watch, timer or configuration option.
   A different GET or preparation reconstructs permission independently.
2. A new observation performs the existing complete deny/allow and retained
   audience evaluation. Its reconstruction cutoff is the start recorded **before
   any identity/permission I/O plus 30 seconds**, never completion time plus 30.
   Store it only after the entire short authority construction succeeds. Copy
   retained claim, audience and contributing-assignment slices; never modify a
   source projection's `ObservedAt`, `FreshUntil` or complete-deny interval.
3. Within that interval, obtain a new current identity and current catalog,
   retention and environment facts for each short batch. Compare group/scope sets
   without order sensitivity. A changed principal/client refuses. Changed policy,
   groups or scopes require fresh target eligibility before catalog lookup.
   A changed/unmatched retained audience or artifact version refuses reuse.
   The old identity is only a claim comparison; its expired short observation is
   never reused as authentication.
4. At the exact cutoff, reconstruct permission before further output. A failed
   reconstruction or later safety read closes this response owner; no stale
   fallback or retry through the same owner is available. Close cancels and joins
   a blocked check and discards its observation. No bytes flow during renewal.
5. Every resulting `DownloadAuthority`, identity batch, `DownloadLease` and native
   conversation remains bounded by its original at-most-five-second interval and
   all caller/session/access/retention/recovery cutoffs. The new authority is also
   bounded by the retained ordinary observation's original cutoff. Response
   accounting, SQL permission revision/suspension/freshness checks, generation,
   audit and conservative spend are unchanged. Known SQL changes can deny before
   30 seconds; this is reconstruction cadence, not delayed revocation.
6. The actual `ContextNativeResponse` accepts a package-private handoff of the
   coordinator's exact already-checked short authority and current identity
   batch. It retains `CheckedAt`, `ValidUntil`, scope and decision identity,
   intersects caller/session/identity bounds, and still reads the current SQL
   attachment before and after metadata lookup. Native source, key, worker and
   SQL lease checks remain. Direct/public current-reader methods and independent
   runtime operations continue to perform their own complete authorization.

This refines ADR-113's requirement to reconstruct ordinary permission at every
five-second lease. It does not change raw/share grants, generic domain eligibility,
the short authority value, wire schemas, SQL schemas, privileges or installation
layout. The selected implementation remains the approved context facet; it does
not authorize other artifact classes by relabeling them.

## Complexity review

| Question | Answer |
| --- | --- |
| 1. Frequency and harm? | Source proves two permission reads per full construction plus a duplicate native construction. Sustained installed frequency, latency and failure rates are not measured. |
| 2. Accepted risk? | Yes. The maintainer explicitly allowed relaxed bounded download permission rechecks. Existing cheap SQL fences remain. |
| 3. Typical benefit? | Repeated short batches in one response benefit. The actual 4 KiB context path mainly benefits from removing its duplicate construction; large-file throughput is not qualified. |
| 4. Comparable projects? | No new external comparison is asserted. This uses the existing request/response ownership model. |
| 5. Added privileges or exposure? | Zero credentials, grants, endpoints or worker authority. The hub retains one copied ordinary decision per active response. |
| 6. Added failure states? | No durable state. One in-memory observation is empty, usable or closed; refresh/safety failure closes it, with no fallback path. |
| 7. Added tuning? | Zero configuration options. One fixed 30-second reconstruction interval. |
| 8. External dependencies? | None added. Existing identity, permission, catalog, retention and environment ports remain required. |
| 9. Aggregate cost? | Six full constructions at 0/5/10/15/20/25 seconds formerly read permissions 12 times; one retained interval reads them twice, excluding entry checks or changed-claim refreshes. This is call arithmetic, not measured throughput. One record holds bounded identity claims and at most 32 original audience assignments; current SQL/safety reads still run. |
| 10. Upgrade and rollback? | No migration. Closing/restarting drops observations; older code performs more checks. No retained observation is adopted across processes. |
| 11. Smaller alternative? | Raising every lease would change unrelated authority and transport bounds. Keeping the existing short leases and retaining only ordinary entitlement removes the repeated work with one response-owned record. |

## Qualification boundary

Require actual authorizer permission-call counts across more than 30 simulated
seconds, exact cutoff and pre-I/O anchoring, fresh response isolation, changed
claim/audience refusal, copied-slice ownership, cancellation/Close join, and no
fallback after refresh or post-read failure. Exercise the actual native response
handoff with current SQL attachment reads and original cutoff negatives. The
owned real SQL response fixture must still deny a known permission suspension
while the retained ordinary observation and short authority remain live.

The [component archive](../../test/results/resumed-c62e02ac-response-permission-cadence/README.md)
records genuine RED exit 1, focused GREEN exit 0, complete authorization/evidence
package race exit 0 (1.306/3.986 seconds), and integration-package compilation.
All 2,610 Go/module hashes remained unchanged during each command. The cadence
regression spans 35 simulated seconds and observes four permission reads across
two reconstructions. Independent source review found no blockers. The first
GREEN's inconsistent short-session fixture and its corrected original worker/key
setup are preserved with their actual results.

The actual SQL suspension assertion is compiled but unrun. Combined repository
specification/architecture gates remain for integration. Synthetic clock advancement
and warm native metadata are component evidence only. Installed native transfer,
sustained availability, large artifacts and the complete investigation lifecycle
require their existing qualification; this decision does not mark those outcomes
complete.
