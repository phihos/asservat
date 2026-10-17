# ADR-155 — Unchanged fleet observation persistence contention

Status: implemented; component and focused native qualification pass. Requirements: REQ-FED-001 and REQ-DB-005. Broad fleet regression and the original installed owner transition remain pending.

[ADR-161](161-fleet-observation-separation.md) supersedes the single-row write and
lock-call mechanism below. It preserves this narrow unavailable classification
through the fixed producer's authority-row abort and adds a retained semantic
basis. Historical qualification here applies to the original implementation;
updated production qualification is tracked separately. Its source-ordering fix
covers a validated native read beginning after Reconcile. Unknown commits never
become acknowledged success; an old failure basis cannot fence a changed semantic
version and relies on the original finite expiry in that case.

## Problem

A protected installer operation holds the fleet recovery row FOR SHARE through bounded native work. The independent source observer's unchanged freshness UPDATE needs FOR UPDATE and can encounter the original one-second lock timeout. The generic failure path then suspends a previously current unchanged source. Actual PostgreSQL qualification reproduced that sequence and subsequent owner constructor refusal; it did not identify the original full-bootstrap refusal's exact predicate.

The shared recovery/suspension lock remains necessary. It must not become FOR KEY SHARE or disappear merely to improve availability. Source observation cannot approve recovery or alter the original authority deadline.

## Decision

Recognize only the actual SQL adapter's failed persistence of an independently read unchanged positive source. Before the lock, read the existing complete fleet row and check database time after that read. Exact installation/issuer/source UID/generation/digest, positive suspension/recovery state, original dates and the independent source's complete validity must agree. This nonlocking comparison grants no UPDATE or COMMIT authority. Preserve the original locked predicate and all normal effect checks.

Only the last callback's actual LockFleetTrust error with SQLSTATE55P03 can mark this classification. That callback immediately returns before any source UPDATE or COMMIT attempt. Reset local callback state on the existing bounded serialization/deadlock retry. Pool, connection, other-statement, cancellation and unknown COMMIT errors cannot select this outcome. The generic Ledger error mapping and rollback cleanup remain unchanged.

After rollback/release, read the complete actual row and database time again through the same pool. Require the entire public row, including original timestamps, to remain equal and positive/current. Pin actual postmaster start, database OID and primary state before transaction admission and recheck after blocking confirmation; an independently accepted replacement incarnation cannot reuse the old classification. Include all added reads in the original five-second SQL operation budget. Use the earliest original operation/caller/source/stored deadline, with no fresh timeout. This path writes nothing and returns an unavailable error, never success, a permit, accepted freshness or a scheduling hint.

TrustObserver suppresses its extra suspension only for this typed persistence failure after a positive source read. All source-read errors, changed/new/missing/suspended/recovery state, expiry, failed confirmation and unknown outcomes retain current fencing. The same error returned by a source reader is insufficient. The bootstrap wrapper still invalidates pending and active notices for every failed SQL outcome and never emits a committed notice on this path.

The previous stored observation remains usable only until its original expiry and current recovery checks. The next ordinary cadence obtains an independent source observation. It does not renew or retry the failed proof, and no selected effect changes its deadline. No migration, grant, pool, limiter, cadence, statement/lock timeout or role changes are required.

## Qualification

[Component results](../../test/results/fleet-persistence-contention-package/component-1/result.json) preserve the meaningful failure of the unchanged original application observer, then the corrected full fleet application/domain and scoped PostgreSQL/bootstrap race tests: 119 top-level and 605 named passing entries. Compilation, vet, Go architecture and specification/design gates pass; the specification gate reports 121 schemas and 10,665 assertions.

[Focused native results](../../test/results/fleet-persistence-contention-package/native-1/result.json) pass all ten required cases: eight new contention/uncertain-outcome cases and both preserved constructor prerequisites. Actual PostgreSQL bridge locks retain the unchanged row and original expiry; changed/expired inputs retain fencing. A committed UPDATE whose successful COMMIT reply is lost still fences. Source/recovery changes and original stored expiry after server lock abort reject classification, while the existing failure CAS preserves an independently newer observation. The actual SQL/provider fixture uses explicitly synthetic source/witness/role-root inputs. PostgreSQL incarnation replacement with an independently reaccepted positive row is a pure comparison negative; this fixture does not restart the database between the two observations.

The native package took 17.808 seconds; all 2,253 native source hashes and the complete source file set matched the independent frozen closure, all 4,336 dependencies stayed unchanged, and owned cleanup completed. [Integration metadata](../../test/results/fleet-persistence-contention-integration.json) records the exact source and evidence packages. The motivating historical failures remain preserved; these results do not identify the original full-bootstrap refusal's exact predicate.

Broad fleet regression, installed owner execution and the original owner phase timing budget still require native qualification. This decision does not enable public services or the v2 observation backend.
