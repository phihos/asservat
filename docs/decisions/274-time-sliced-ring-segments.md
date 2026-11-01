# ADR-274 — Time-sliced ring segments

Date: 2026-11-01. Status: accepted (agent decision); unit tests pass,
installed qualification pending.
Requirements: specs/action-lifecycle.md (ongoing ring history), S-04.

## Context

The source ring rotated segments only when a segment filled, and age
eviction removed a whole segment once its oldest record passed `MaxAge`. On
sparse traffic one segment spanned far longer than `MaxAge`, so an old record
evicted much newer records with it. Installed runs 41282477857 and
41282479595 lost the pre-restart markers sent six seconds before the incident
(`failed at empty: ... evicted true`); the run that passed had its markers in
a fresh segment.

## Decision

A segment also rotates when its oldest record is at least
`MaxAge / MaxSegments` older than the new record. Age eviction is unchanged
(whole segment by its oldest record), so nothing is kept or disclosed beyond
`MaxAge`; the ring now keeps at least `MaxAge` minus one slice of history
(22.5 of 30 seconds for the shipped profiles) regardless of traffic rate.
Shortened history stays reported as `HistoryEvicted`.

## Complexity gate

Observed in 2 of 3 runs; no new state, configuration or dependency; one
comparison on the write path. Smaller alternative (longer `MaxAge`) would
keep data longer without fixing sparse traffic.
