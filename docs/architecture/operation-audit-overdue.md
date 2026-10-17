# Overdue original operation-audit cleanup

[ADR-115](../decisions/115-overdue-operation-audit-erasure.md) extends the bounded
[healthy audit lifecycle](operation-audit-lifecycle.md). This is a private C-08
component, not a new browser/MCP operation, runtime supervisor or restore service.
It addresses an outage before the first certificate claim, without extending
retention or treating a missing object as writer completion.

## Explicit new-record capability

`OperationLifecyclePolicy.OverdueTerminal` is either omitted or the closed value
`overdue-original/v1`. Omitted JSON remains unchanged. The policy and original
binding stay immutable; Begin/Finish cannot add the capability to an old reviewed
record. Newly admitted H>0 records require `operation-audit-history/v2`, a distinct
qualified layout accounting for the added fixed columns and three conservative
extra transaction transitions in its per-slot WAL reserve. The same record
reservation backs them. Qualification includes complete row/index/TOAST and
transaction footprints; these adapters do not measure or accept a real backup
profile themselves. H=0 has no backup-history qualification.

A pool cannot change the normalized profile while old obligations or protected
residual history remain. This deliberate compatibility restriction means an
installation cannot merely switch all old41/legacy40 records to the new capability.
Reviewed existing-record adoption/profile migration is a separate required task.
No credentials, new source controller or public policy toggle is introduced.

## Atomic fence and independent current proof

The three private phases are:

1. `BeginOperationPurge(..., "overdueOriginal")` requires the original acknowledged
   intent/outcome receipts and positive completions, expiry of the original write
   period, and database time at or beyond `CertificatePurgeAt - P`. It locks current
   recovery, pool, account, operation and lifecycle in that order. It requires
   `certificate_started=false` and no certificate result, then commits the first
   immutable `overdue_selected_at` with an ordinary at-most-five-second lease.
   Certificate claims and mode selection use the same lock. A winning claim keeps
   its unknown-effect charge and blocks this branch; a winning overdue mode makes
   every later certificate claim invalid. A cached result cannot reverse it.
2. The exact-prefix purger inventories current keys, versions, delete markers and
   multipart state. It removes only the two registered originals. A certificate
   under a never-claimed prefix, unexpected key or truncated inventory fails
   integrity checks. It records a separate typed `OperationOverduePurge` containing
   the original binding/receipt/writer digests, mode, original selection time and
   current lease fence. It fabricates no certificate digest and leaves any earlier
   immutable normal retirement payload intact.
3. An independently credentialed read-only verifier checks current absence and
   acknowledges that exact result before the original lease expires. The existing
   finalizer recognizes this explicit complete proof shape, retires SQL identity,
   and uses the existing H=0 release or H>0 cooling. A renewed purge lease clears old
   result/acknowledgement, never renews original dates, and consumes the existing
   finite cleanup budget.

`OperationOverdueCleanup.Advance` composes these finite operations. Its object
ports expose only purge and absence verification. `NewOperationAuditPurger` and
`NewOperationAuditAbsenceVerifier` require no signing, wrapping, unwrapping or PUT
capabilities; production backend IAM must enforce that separation too. The
ordinary certificate path is unchanged. Scheduling and protected policy loading
remain runtime composition work.

`overdue_selected_at` and a bounded <=4096-byte `overdue_purge` live on the existing
lifecycle row. No new table or object is added. The cleanup SQL role can select
mode/record purge but cannot acknowledge or release; the verifier cannot select
mode or mutate counters; finalization remains a fixed function with transaction
markers and deferred no-stranded-state checks. Source-managed triggers reject
certificate work after mode selection and preserve original incarnation/freshness.
Original deadlines are checked after blocking locks, not restarted afterward.

## Erasure before capacity release

Object purge does not wait for the independent verifier or create a late
certificate. If verification or acknowledgement is unavailable, objects may be
gone while the original charge remains. An uncertain result/commit is reconciled
from exact state and current absence, not by repeating a certificate PUT. The
result means late present-day erasure; it does not assert the missing proof window
or deadline was met.

The first committed mode selection atomically increments the root/lane's fixed
`proof_window_missed` counter, saturating at 2^60. Retries, replacement leases and
rolled-back selection cannot add duplicate counts. No runtime role has direct
counter-update privilege, and ordinary configuration revision updates preserve it.
This content-free aggregate remains after operation/account retirement; it is not
an unbounded series of identifying audit records. It is a storage fact for future
bounded operator reporting, not a claimed implemented dashboard or alert.

H>0 finalization marks the history contribution overdue even when the original
live-SQL retirement date has not yet passed: losing P is itself a recorded breach.
Safe release waits until at least actual identifying-row retirement+H and retains
all original dates. The fixed pool protects the last residual backup generation
through actual drain+H. These accounting floors do not grant longer retention or
new authority. Unknown/live records and the other lane retain their charges.

## Qualification and exclusions

Targeted tests cover immutable capability/old JSON, required new layout/backing,
strict failure ordering, overdue object confinement and forbidden unexpected
certificates. The new real SQL/S3 fixture source covers a long outage past the
original hard date, old-policy/unknown-original/claimed-certificate exclusion,
concurrent exact lease replay, actual account-row blocking past the original lease,
purge without acknowledgement, rollback after operation deletion/history transfer,
finite overdue cooling and narrow SQL privileges. The selected real SQL/S3 run
passed both existing healthy/cooling cases and both new overdue cases; the full
custody regression also passed. Both retained unchanged source hashes and clean
teardown. These tests use synthetic protected policy and backup-profile inputs;
they do not qualify an installed backup system or runtime scheduler. Exact
commands, failed migration evidence and terminal results are recorded in
[implementation progress](../implementation-progress.md).

No automatic adoption of legacy40 or old41 records is implemented. No historical
GET can produce original writer closure. Claimed-but-unknown or positively written
but unaudited certificates need a separately qualified path. Lease exhaustion and
unknown writer barriers remain required work. PostgreSQL restart/restore still
fails closed until independent reconciliation bridges original provenance to
current cleanup authority, including this no-certificate fence. That bridge is
separate from ordinary source observation and is not supplied here.

The design relies on qualified backend semantics: [S3 strong consistency](https://aws.amazon.com/s3/consistency/)
does not prove writer quiescence, and [versioned DELETE](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html)
can leave older data behind. The fixed lock order and durable mode are needed
because [PostgreSQL row locks](https://www.postgresql.org/docs/18/explicit-locking.html)
end with the transaction. Provider compatibility, backup/WAL profile measurements,
IAM and runtime supervision remain separate qualification requirements.
