# ADR-161 — Separate fleet freshness from restrictive authority locks

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

> Superseded in part by ADR-328 (2026-11-13): the migration's hostile-role inventory, credential-retirement wait and trigger/reference refusals, the witness check before first activation, and the native guard part of the source read no longer apply. The split between the semantic authority row and the positive observation row, its version/ABA rule and the fixed producer functions remain valid.

Status: implemented; focused component and production SQL qualification pass. Installed availability and broad regression remain pending. Requirements: REQ-FED-001 and REQ-DB-005.

## Problem

Installed owner setup retains a SHARE lock on fleet authority while independently
checking protected Kubernetes inputs. The fleet observer currently needs UPDATE
on the same row to publish an unchanged positive observation. This makes an
otherwise healthy observer wait behind the very operation that depends on its
short freshness interval. A following operation can receive an almost expired
observation. The tenth installed-owner run completed its first projection but
failed in the following native phase; that result does not establish this lock
interaction as the only availability defect.

Keep the existing five-second authority limits, current source checks, restrictive
locking, request cancellation and spent-attempt accounting. Raising request rates,
adding delays or renewing an in-flight operation's original deadline is not the
correction.

## Decision

Migration 00059 separates the positive observation from the semantic authority
row. The existing `fleet_current_trust` view retains its nine-column contract.
Consumers continue to lock the semantic root through that view. A materialized
CTE supplies the observation without making it a target of those outer row locks.
The existing database-incarnation condition remains mandatory.

The semantic root has a database-managed monotonic version. Source/issuer,
suspension, recovery and accepted-incarnation changes advance it. Every accepted
explicit failure fence also advances it, including a repeated fence while already
suspended. An A → B → A change therefore cannot revive an older observation.
The finite positive record binds its exact semantic version, source revision,
issuer and accepted database incarnation. Missing or mismatched observations
project blocked authority and equal finite expired dates, never NULL or a fallback
to legacy positive dates.

An unchanged positive renewal takes a SHARE lock on the semantic root, checks its
retained version and source, and updates only the observation row. It can coexist
with another SHARE holder. Restrictive semantic changes still take UPDATE and
remain serialized against existing effects. An effect that explicitly holds
UPDATE can still block the observer's SHARE admission; this change does not remove
all possible contention. Producers acquire fixed ROW EXCLUSIVE table locks on
the base and observation tables before row locks, matching initial activation's
table-before-row order. They never upgrade a SHARE row lock after locking an
observation. Only an exact authority-row lock timeout can return closed
disposition 3; the adapter rolls back before the original ADR-155 unchanged-row,
version, incarnation and deadline confirmation. A table or observation-row timeout,
unknown commit or other error cannot select that exception.

The observation table retains the existing thirty-second SQL ceiling used by
explicit synthetic fixtures. Production source, pre-read basis and activation
remain limited to their original at-most-five-second intervals.

Before starting the native source read, `TrustObserver` obtains a bounded SQL
basis containing the installation, current database incarnation and semantic
version. That read and the native read share the original observation budget.
Positive persistence rechecks the retained basis after every blocking lock and
retains the earliest original interval. A missing root is a distinct absent
basis; it cannot grant authority or adopt a concurrently created replacement.

Failure fencing uses the retained semantic basis and original observation-start
ordering. It may execute in its existing separate finite restrictive interval
after the positive interval has expired. It cannot fence a newer semantic root or
a newer successful observation. This avoids using application/database wall-clock
comparison alone as proof that a source read followed a semantic transition.
Existing date ordering and database-time validity checks remain required.
After a validated source read, failure ordering includes that source's original
start, so a same-version commit with a lost reply is not mistaken for an
independently newer observation merely because native reading started after
Reconcile. No new timestamp or deadline is minted. Unknown outcomes remain
unacknowledged; an old basis cannot fence a changed semantic version, including
one whose own commit reply was lost. Its finite original expiry and invalidated
scheduling notices remain binding.

Fixed narrow producer functions own observation and fence writes. Their schema
references and search path are fixed, PUBLIC execution is revoked, and runtime
roles receive only their required functions and reads. Remove prior direct
source/date-write privileges so the protocol cannot be bypassed. Runtime
observation cannot change recovery activation or issuer ownership.

The migration revokes the former direct source/date-write grants from the
Asservat runtime roles. Roles created by the installation and database
administrators are trusted (ADR-328), so the migration does not inventory role
OIDs, wait for credential retirement or reject triggers, references and default
grants left by earlier credentials.

## Initial installation and recovery

Before activation, ordinary observation can retain the blocked root and ordering
watermark but cannot insert a positive observation. The pristine inventory includes
the new table. The first activation transaction explicitly seeds its first positive
observation. Completed
activation replay remains read-only. No trigger automatically makes an existing or
restored root fresh, and no source observer supplies restart/restore authority.

An upgrade with no valid bound observation fails closed until its supported
activation/recovery path establishes that record. Do not infer a supported upgrade
or recovery procedure from the table/view migration alone.

The first activation adds only exact-column INSERT into the observation table.
Preparation and audit cannot insert it; activation cannot update existing positive
records. Runtime observers receive fixed producer functions and read/lock access.
The CTE-backed view is structurally read-only; native negative tests must retain
the actual PostgreSQL rejection rather than require a former view error code.

## Research and qualification

PostgreSQL documents that locking a view propagates to its underlying tables,
whereas an outer locking clause does not lock a referenced WITH query unless
requested inside it. Explicit materialization prevents folding that query into
the caller. Row locks also require UPDATE privilege on at least one selected
column. These are SQL mechanics, not an authorization design by themselves.
[PostgreSQL SELECT](https://www.postgresql.org/docs/18/sql-select.html),
[row-lock conflicts](https://www.postgresql.org/docs/18/explicit-locking.html).

The isolated PostgreSQL 18.6 probe records 31 passing view-lock/ACL/binding cases:
unchanged freshness renewal alongside retained SHARE locks, restrictive writer
blocking, eight existing locking/query forms, the contrasting ordinary-join
behavior, exclusive-lock contention and absent/mismatched source/incarnation
denials. Its first run's diagnostic-name parser failure remains preserved.
Probe evidence
includes the independent archive/cleanup verification. This
synthetic schema experiment does not qualify the production migration, producer
functions, first activation or installed owner startup.

PostgreSQL documents privileged function execution hazards for REFERENCES and
TRIGGER ([PostgreSQL privileges](https://www.postgresql.org/docs/18/ddl-priv.html)).
They apply to untrusted roles; installation roles are trusted under ADR-328.

The production SQL qualification
passes all 31 named cases using the actual 58→59 migration, separate scoped roles,
encrypted audit and first activation. It covers retained SHARE renewal, restrictive
locking, exact lock-site classification, basis/ABA/failure ordering, original
expiry, missing observation, activation/replay and privilege/hook refusals.
Protected Kubernetes source inputs remain explicit fixtures.

The second component gate
passes 265 top-level / 1,428 named race tests with no skips, SQL/schema and canonical
checks; compilation and full vet passed separately. The preserved first gate
failed three old reconciler fixtures missing the new original basis; the second
uses only the reviewed fixture-input correction. Frozen source/archive hashes and
owned cleanup are independently verified.

The broader initial-installation run
passes 84 of 87 named executions but fails two old bridge expectations and their
parent. After the reviewed fixture correction, the
second full run
passes all 87 named cases without skips, including positive renewal under the
actual bridge SHARE and preserved original expiry. The
full fleet run also passes
all 176 named tests with independently verified source/archive and cleanup
closure. The database recovery run
passes all three real initial/restart/restore phases with independently verified
server/database identity changes, source/archive hashes and owned cleanup. The unchanged
installed-owner run 11
also fails a final native projection check, with a same-call source limiter
refusal. These failures remain preserved; no rate or deadline was increased.
Complete the remaining custody and full-Go qualification
and finish sustained startup availability.
The SQL split is qualified for its focused boundary, not a complete startup fix
or permission to enable public/Helm runtime.

Revision (2026-10-23): the positive fleet observation row is now stored for
30 seconds after its own observation (migration 00074, see the
[ADR-200 revision](200-on-demand-capacity-refresh.md#revision-2026-10-23));
suspension, recovery blocking and the failure fence remain immediate.
