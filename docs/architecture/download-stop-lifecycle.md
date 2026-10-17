# Prepaid Stop lifecycle

[ADR-124](../decisions/124-prepaid-stop-retirement.md) extends C-14's bounded Stop
decision and C-08/C-21 audit storage. The application still performs the SQL
restriction before audit I/O. This lifecycle neither authorizes evidence reads
nor changes the minimal public cancellation receipt.

## New admission and unchanged historical bytes

Configure the independently accepted Stop lifecycle policy before the first
download uses its backing pool. Its policy and qualification identities, store,
backup horizon, fixed proof/cleanup intervals, footprint and finite purge count
must match the existing prepaid pool. The configuration adapter supplies no
qualification itself. Pool renewal preserves the binding and all outstanding
charges. Historical unbound rows keep their original immutable v1 decision and
conservative accounting; a later read cannot upgrade them.

Migration 47 creates `download_stop_lifecycle` and `download_stop_history`. The
first is an exact child of the already charged Stop reservation. The second uses
the same charge for cooling, with allocation and original dates but no download,
actor, request key or native metadata. Neither is a new work queue or an additional
unbacked pool. Parent download allocations and their identifying records remain
subject to their own retention and are not deleted or refunded here.

`NewHealthyDownloadStopObjects` explicitly joins the existing Stop coordinator,
closed object producer and SQL completion facet. Only successful create, exact
readback/cryptographic verification and joined closure yield completion. A lost
SQL completion response can recover the exact persisted value. A lost provider
response, an existing object, or an unpersisted completion cannot. Legacy Find is
used only after a matching positive completion was independently read from SQL.

## Three original outcomes

The original purge cutoff closes further Stop decision/write/lookup admission
under the same lock used to claim a write. After closure no competing claim can
succeed, even if it was read before the fence.

| Mode | Required proof | Meaning |
| --- | --- | --- |
| `unused` | No decision or issued write exists at closure | The reservation was not used |
| `unwritten` | A decision exists, its opportunity ended and no write was issued | The restrictive action has a missed audit; retain/report that breach |
| `written` | Exact positive completion and independently acknowledged receipt | The original encrypted decision completed |

An issued write without that completion is not one of these proven modes. It
stays charged, even if inventory currently looks empty. Missing finalization
replies are retried against the original persisted result; they do not create a
new decision, writer or allowance.

## Finite object and SQL cleanup

Cleanup uses at most the configured 2–32 finite purge leases. Each lease preserves
its original maximum five-second interval through provider I/O, SQL locks and
independent acknowledgement. Reusing a live lease returns the same fence/end;
advancing one clears old terminal proofs. The store inventories complete bounded
versions, delete markers, keys and multipart uploads. An unexpected name,
truncation, unknown deletion or nonempty recheck prevents success.

Purge the original before creating one signed encrypted certificate in that same
64 KiB slot. A once-only certificate claim fixes at most thirty seconds within
the original proof window. Only its actual joined writer may supply completion.
The independent verifier has read/open and public signature keys, with no delete,
seal or signing methods. The typed certificate records the mode, immutable
binding and ciphertext/writer digests, exact purge fence and fixed dates. It
contains no actor, request key, filename or native checksum.

When the certificate cutoff arrives, purge every registered key/version and
independently acknowledge absence before atomic SQL retirement. If the proof
window was missed before any certificate attempt, first record an irreversible
no-certificate fence, then use the overdue absence path. A claimed unknown
certificate cannot use that shortcut. A late cleanup never moves promised dates.

All identifying-row deletion, charge/history transfer and private transaction
marker retirement are atomic. Rollback restores the original row and charge.
Runtime credentials cannot directly delete rows, change finalization markers or
decrement counters. Separate cleanup and acknowledgement roles prevent a deletion
worker from signing off its own terminal absence.

## Retention and backed history

Let D be the original hard Stop retention end, H the accepted residual recoverable
SQL/replica/backup/WAL horizon, B the cleanup allowance and P the proof interval:

| Frozen date | Value |
| --- | --- |
| Original purge / Stop replay cutoff | D − 2H − 3B − P |
| Certificate purge | D − 2H − 2B |
| Identifying Stop SQL retirement | D − 2H − B |
| Cooling release eligible | D − H − B |
| Cooling SQL removal | D − H |
| End of supported managed history | D |

The first cutoff must leave more than thirty seconds after the original transfer
deadline. Pools that cannot fit that arithmetic are rejected before use. At least
twelve purpose-bound key operations and one ciphertext slot per reservation cover
the original bounded attempts and certificate. Two residual SQL generations plus
the qualified transaction/WAL envelope and finite cleanup transitions are backed
at admission. These are accepted qualification bounds, not measured capacity
claims; deployment testing must include row-lock, rollback and retry traffic.

H=0 releases the Stop charge only with positive retirement. H>0 retains it in the
exact allocation/date cooling bucket. Actual late retirement adds an `actual+H`
safe-reuse floor without moving D or hiding the overdue condition. History drain
releases exactly its original count and protects the pool's last residual
generation through actual drain+H. No parent acquisition/output/worker balance is
changed. This addresses supported recoverable managed history, not forensic disk
sanitization. Qualification must include MVCC/vacuum, snapshots, replicas and all
supported base-backup/WAL recovery chains.

## Bounded recovery and current authority

Cleanup takes current recovery before pool/backing/Stop/lifecycle locks. Original
issuer epoch must still match the independently accepted current installation.
The dynamic database-incarnation fence remains mandatory; an observer cannot
approve restart or restore. Historical admission timestamps are not used as a
permanent ban after an independently qualified recovery has accepted a new
incarnation. Unknown writer reconciliation remains separate and required.

`ReconcilePending` uses one original five-second pass and at most sixteen records.
It prioritizes unstarted writes by their original end before bounded lookup
recovery. Exhausted, expired-unclaimed and lifecycle-closed obligations stay
charged but leave that active selection. A failed row does not prevent other
selected obligations from using the remaining interval; cancellation or the
original deadline still ends the pass. There is no per-row retry or fresh budget.

## Qualification boundary

Focused tests cover exact signed/encrypted framing, public-only verification,
successful/412/unknown/canceled writes, joined completion, inventory confinement,
fixed retention arithmetic and unknown-completion replay. The real SQL/S3 fixture
source uses actual clocks for H=0/H>0, distinct SQL roles, unused/unwritten/positive
and uncertain writers, rollback and conservative charge release. The
[parent-owned native run](../../test/results/stop-retirement-native-combined.log)
passes this case in 64.08 seconds. Its
[terminal report](../../test/results/stop-retirement-native-combined-check.log)
records 1,081 unchanged source hashes and complete cleanup. The accepted policy,
footprint and backup-horizon inputs remain synthetic; this is no qualification of
production backup/WAL capacity. See [implementation progress](../implementation-progress.md)
for subsequent combined source and first-installation/recovery results.

Protected policy/signer production, actual backend IAM and backup/WAL qualification,
supervision and unknown-writer recovery remain required before enablement. These
components add no public endpoint, scheduler, administrator consent or evidence
decryption during GET.

Certificate verification spends one of two fixed SQL attempts before the independent
provider read/open. A lost verification/acknowledgement reply cannot refill those
attempts. The twelve-operation key reservation includes both verifier attempts;
provider success is still not an acknowledgement.

## Cross-component lock order

New download admission already owns recovery, `permission_stream` and
`download_allocation` before inserting `artifact_download`. Its Stop trigger then
locks pool, backing and the new Stop/lifecycle. Cleanup, verification and
retirement use recovery → pool → backing → Stop → lifecycle/history; they never
lock or change the parent `download_allocation` or `artifact_download` row.
Restriction uses `artifact_download` → Stop and acquires none of the cleanup
pool/backing/lifecycle locks. Historical audit claims take recovery → Stop.

The trigger's reads of `artifact_download` use plain MVCC SELECTs, with no explicit
row lock that would reverse the restriction order. The backing UPDATE branch
used by cleanup never enters the INSERT branch's parent-allocation SHARE lookup.
Installation `BindDownloadStopBacking` holds `permission_stream` before its
pool/allocation work, serializing it with ordinary reservation. All reads may
still wait on database work and remain subject to the original transaction
context; “plain read” does not exempt them from final deadline checks.
