# ADR-270 — Source work is a standby query

Date: 2026-10-31. Status: accepted by the maintainer; unit and real-stream
tests pass, installed qualification pending.
Requirements: REQ-EXE-002, S-04; specs/action-lifecycle.md.

## Context

Ongoing packet sources renew their 30-second leaf on every 15-second
maintenance tick. Each arm, renewal, stop and snapshot cancellation took an
attachment (`Router.Attach`), which consumes the cluster's one regional
standby ([ADR-209](209-two-context-start-standbys-per-owner.md) withdrawal).
Installed native run 41132757629 showed the consequence: at a Save's attach
refusal the cluster had no standby, consumed by a source renewal less than two
seconds earlier, so the accepted Save ended `Failed`. Contention grows with
every additional source.

Source delivery is already a single exchange: one signed work, one
`queued`/`unavailable` reply. That is the shape of an
[ADR-179](179-outbound-only-first-installed-profile.md) pre-work query.

## Decision

1. Source arm, renewal, stop and snapshot cancellation are one `source-work`
   query on an idle standby (`Router.DeliverSource`). The standby keeps
   waiting for capture work, as after any other query.
2. The hub signs the work only after the router selects the standby and
   checks its current receiver, because the work binds that channel. A
   signing failure before send returns the stream to passive residence.
3. The region verifies the signed work against its current owner check,
   queues the effect and answers with the existing source reply. Signature,
   trust, channel and deadline checks are unchanged. This is the one query
   that verifies and queues work; ADR-179's "queries are not operations"
   otherwise stands.
4. The dedicated source-work frame (kind 40), its attachment path and its
   receipt are removed. Source work counts against the existing eight queries
   per standby.

## Consequences

Saves and other context starts no longer race source traffic for the
standby; ADR-209 is unchanged. No state, configuration, privilege or
fallback is added. Source traffic stays one round trip per source per tick
and now also retires standbys through the query budget. The region no longer
receives a receipt for its reply; it never acted on one. Hub and region must
run the same version, as for any frame change before the first release.
