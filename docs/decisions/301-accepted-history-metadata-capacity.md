# ADR-301 — Accepted capture history uses current metadata funding

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

Date: 2026-11-04. Status: implementation in progress; installed qualification pending.
Requirements: REQ-HIS-001–004, REQ-CAP-004/005, REQ-PRV-008.

## Observed problem

Installed TRACE41901024982 captured, published and downloaded a valid trace, but
its first settings lookup returned ParametersUnavailable. The earlier history
reservation failed with SQLSTATE23514, `managed capacity admission incomplete or
expired`. The retained logs establish that guard failure, not its internal
missing/expired condition. A managed PostgreSQL regression independently reaches
the same guard after expiring only the workload binding, with the root current.
The older history fixture had no managed source and did not exercise this gate.

History stores parameters already supplied for an accepted capture. It is
separately funded metadata, not another workload acquisition. Under the maintainer’s standing proportionality guidance, this implementation
separates accepted-request metadata admission from live workload observation;
current identity, recovery, retention, root, pool/allocation and quota checks
remain. Repeating those settings still requires a fresh ordinary acquisition.

## Decision

Keep ADR-272's after-start ordering. History before the start previously consumed
the shared route and start headroom and caused AcquisitionClosed. Do not add a
capacity refresh, retry, journal, purpose flag or new preparation lifecycle.

Make only the custody attempt's existing capacity trigger a deferrable constraint,
initially immediate. History reservation defers that constraint around its
existing transaction: charge the same allocation, insert the attempt and four
copy obligations, update bounded quotas and insert the immutable history row.
Explicitly make the constraint immediate before the existing final deadline and
recovery checks. Other callers retain immediate behavior by default.

The capacity guard recognizes history only through its actual immutable row and
a strict positive check of the exact accepted single/group capture, original
scope, cluster, store, allocation, revisions and complete registration dates.
Missing or NULL fields do not establish that association. Neither a role, a
native-size value nor a caller's choice to defer a constraint establishes purpose.
Unassociated attempts retain the ordinary live-workload admission guard.

Associated history still requires a current managed root, the existing current
compiled-pool/additive-plan check and its original pool/allocation/control funding, unpaused accounts, valid original dates and the
existing separately charged custody and history ceilings. It does not consume
the workload binding's live observation. History is not prepaid: one 128 KiB
parameter ceiling reserves 1,671,168 bytes and four object slots, and insufficient
funding still leaves the accepted acquisition intact. Unknown writes remain
charged until the existing physical cleanup proof.

PostgreSQL supports initially immediate constraint triggers and explicit checking
of deferred events with SET CONSTRAINTS. This uses the existing insertion order;
it does not assume visibility between data-modifying CTE substatements. See
[CREATE TRIGGER](https://www.postgresql.org/docs/18/sql-createtrigger.html) and
[SET CONSTRAINTS](https://www.postgresql.org/docs/18/sql-set-constraints.html).

## Cost and verification boundary

Two fixed SQL commands and bounded indexed association reads in the existing
reservation transaction; zero new rows, columns, API calls, roles, credentials,
watches, background work, services, configuration or acquisition requests.
Ordinary custody admission and existing history write/read/purge lifecycles keep
their current checks and limits. Schema 136 is required; rollback restores the
previous trigger behavior without deleting history or releasing charges.

Required qualification: managed expired-binding persistence with the exact debit;
unassociated/deferred and malformed/mismatched association rollback; current root,
pool/allocation, funding and original-date refusal; empty and retained upgrade/
rollback; existing history lifecycle and a fresh installed trace continuation.
Local SQL or TLS fixtures do not establish installed success or identify the
previous native guard's unlogged internal condition.
