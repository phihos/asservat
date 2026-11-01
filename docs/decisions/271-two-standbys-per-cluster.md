# ADR-271 — Two context-start standbys per cluster

Date: 2026-10-31. Status: accepted by the maintainer (reopens the withdrawn
[ADR-209](209-two-context-start-standbys-per-owner.md)); unit tests pass,
installed qualification pending.
Requirements: REQ-EXE-002, REQ-FED-001/003, S-02, S-04.

## Context

One regional standby per cluster now serves source arms/renewals and
previews as queries ([ADR-270](270-source-work-standby-query.md)), and a
Save's history write, its start and the recording collect loop as
attachments. Installed ongoing-save runs (41182348047 to 41190979663) showed
each attachment leaving the cluster without a standby while the region
reopened: the Save's start lost to its own history exchange, renewals found
no queryable standby, and the source's state lapsed.

ADR-209 was withdrawn for two implementation reasons: the hub reserved one
standby per cluster (`installer-cluster-join --standby 1`; `Standby: 2` was
the hub-wide total), and two concurrent openings to one owner refused each
other at `setup-begin`.

## Decision

1. `installer-cluster-join --standby` defaults to 2. The hub-wide total
   remains at least the sum of the clusters' reservations.
2. The regional client allows `mtls.ContextStartExchangesPerOwner` (2)
   concurrent exchanges to one owner process; a third is refused before
   setup or I/O.
3. The regional supervisor keeps two slots per owner and opens them one at a
   time: a slot opens only while no other opening to that owner is in flight.
   Any ended exchange that had opened reopens its slot at once.
4. A standby that answered its last query is retired only while its cluster
   has another live standby; a lone exhausted standby stays for an attach
   (ADR-179).
5. Every opening's checks, deadlines, the 30-second residency and the
   per-cluster capture limit are unchanged.

## Consequences

Each cluster holds up to two idle exchanges and opening load per owner
doubles at most. Existing joined clusters keep their recorded reservation
until rejoined with `--standby 2`.
