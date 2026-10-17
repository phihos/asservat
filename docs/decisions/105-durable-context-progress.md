# ADR-105 — Durable, authorized context capture progress

Status: implementation decision under the maintainer's continuation authorization.
Measured qualification and public enablement are recorded in
[implementation progress](../implementation-progress.md).

A developer needs to distinguish an accepted request, an outcome awaiting
verification and available evidence. Admission does not establish that a
collector started. A request deadline alone cannot establish failure or release
uncertain resource spend. Polling also needs a revision that survives process
restart and remains coherent with actual durable transitions.

Migration 00034 adds a monotonic revision to the original context admission.
Transaction-local triggers advance it when intent audit, custody state or
retention, semantic verification, verification audit or catalog publication
changes. Identical retries and reads do not advance it. The public range ends at
1,000,000,000; a saturating private sentinel makes progress unavailable beyond
that limit while permitting retention and deletion to continue.

A separate column-scoped observer records an elapsed original deadline in pages
of at most sixteen under the permission-root lock. Its once-written timestamp
advances the revision. It cannot cancel acquisition, publish evidence, release
capacity or rewrite the original deadline. GET remains read-only. An overdue
request whose observer has not yet run retains its last durable phase rather
than inventing a new revision from wall time. Deployed supervision must run this
observer; the component alone is not a scheduler.

The first bounded projection reports Pending, Finalizing, Succeeded or
Indeterminate. Succeeded requires the original audited intent, matching
independent verification, its encrypted audit acknowledgement and catalog
publication. A stored object alone is insufficient. An observed elapsed deadline
without publication is Indeterminate, not a claim of known collector failure.
This slice has no proven Running, cancel, failed-start or partial-result journal.

Read access requires current recovery and complete current target permissions,
plus either the original requester or a scoped workload maintainer. The same
human may use another client with current `evidence:read` scope. A received
artifact share and a historical assignment are insufficient. Administrator
support requires a protected current projection; there is no inferred bypass.
Case navigation has its own current authorization port and may be omitted.
Historical Succeeded never grants current evidence access.

The trigger function has fixed, fully qualified SQL, checks its exact source
relations and trigger shape, pins `search_path`, and has no public EXECUTE grant.
Runtime roles have no function modification, trigger-creation or direct revision
write authority. It executes as the protected migration owner; this is a fixed
narrow operation, not a claim that the owner's ambient privileges are narrow.
A dedicated restricted function-owner role can be provisioned by the installer
later without changing the protocol. PostgreSQL documents both the need for a
trusted [SECURITY DEFINER search path and explicit privilege revocation](https://www.postgresql.org/docs/current/sql-createfunction.html)
and the [table TRIGGER plus function EXECUTE privileges required to attach a trigger](https://www.postgresql.org/docs/current/sql-createtrigger.html).

This decision does not retire historical capture metadata, solve workload
admission fairness, implement case authorization, enable a public listener or
prove collector execution. Those remain independent requirements.
