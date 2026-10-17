# ADR-125: Spend a bounded allowance before operation-certificate verification

Status: Accepted design; staged component checks and actual provider qualification
are distinguished in [the architecture contract](../architecture/operation-audit-lifecycle.md).

## Context

ADR-112's positive certificate writer prevents repeated creation, but its independent
verification had no durable attempt counter. Once writer completion was stored, an
unavailable acknowledgement allowed every cleanup retry to repeat GET/decryption.
The failing regression performed eight verifier calls and eight failed acknowledgements
with zero pre-provider claims. A finite write interval alone does not provide the
explicitly reserved work allowance.

## Decision

The independent acknowledgement credential must first spend one of two immutable
certificate-verification attempts under the existing recovery, pool, principal
account, operation and lifecycle lock order. Match the exact positive completion,
retirement and receipt. Return only the earliest original caller, current recovery,
five-second observation and certificate deadline. Keep that same context through
provider verification and acknowledgement. An uncertain claim reply grants no
provider work; failed verification, lost acknowledgement and cancellation never
refund or refill the counter. No additional key service or worker scheduler is added.

Require the explicitly accepted `operation-audit-history/v3` qualification for new
healthy admission, including zero-backup-horizon profiles. Its measured row/index/TOAST
and whole-transaction WAL bounds must include the new counter. Per slot reserve two
residual generations, 21 fixed transitions and three transitions per finite purge
lease: the original sixteen, three reserved overdue transitions and two verifier
claims. The fixed certificate work allowance includes both independent GET/unwrap
attempts. Provider/IAM and backup qualification remain protected installation inputs,
not claims established by this adapter or synthetic fixture numbers.

Migration48 gives every existing lifecycle row a constant default of two spent
attempts. It does not update individual old rows, replace policies, rewrite dates,
create receipts or infer which past unacknowledged verifier calls completed. Old
bindings remain readable. An already acknowledged certificate still permits the
existing terminal-purge and SQL/history-retirement path. Old incomplete or uncertain
records receive no new verification authority and remain conservatively charged.
The normal coordinator rejects them before original purge or certificate creation;
already opted-in overdue-original reconciliation stays a separate path.

An installation can explicitly accept a covering v3 resource profile without
waiting for old uncertain rows to disappear. The current accepted admission must
cover every backed slot and every outstanding/residual profile. Keep root, lane,
installation, store, backup identity/digest, horizon, purge limit and overdue mode
unchanged; qualified row footprint, transaction WAL and copy counts can only grow.
Qualification identity/digest changes require that independent acceptance. Source
renewal fields and budgets retain their existing checks. Unknown layouts, downgrades,
smaller backing and unrelated profile changes deny. The upgrade changes the resource
coverage for new work; it never grants attempts to historical records or reanchors
an obligation. Migration and ordinary observation cannot accept this upgrade.

## Consequences

One acknowledgement failure can no longer cause unbounded certificate decryption
retries. Exhausted/unknown work remains an explicit reconciliation obligation; this
change supplies neither a restart/restore bridge nor a way to erase uncertain spend.
Historical managed backup/WAL cutoffs and independent finalization remain binding.

The real SQL fixture uses a separately owned temporary database to apply actual
migrations through47, admits synthetic old records through their active guards,
then applies48. It checks conservative backfill, old acknowledged cleanup and
explicit covering upgrades without disabling triggers or downgrading the harness
database. Separate SQL/S3 source checks concurrent claims, provider failure,
unknown-claim spend, roles and expiry after a blocking lock. Compile-only checks do
not qualify those external paths. No public runtime is enabled by this correction.
