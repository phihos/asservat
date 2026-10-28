# ADR-213 — Storage readiness at consumption

Date: 2026-10-20. Status: implemented; component race checks pass; installed qualification pending.
Requirements: REQ-CAP-002–003, REQ-EXE-002; S-02.
Refines [ADR-200](200-on-demand-capacity-refresh.md).

## Context

[Resumed native47](../../test/results/resumed-c62e02ac-native47/result.json)
passed the installed demand-refresh check with six distinct observations and
37 usable samples over 15 seconds. Its first capture request nevertheless
failed at `request/facts/storage/margin`: the final authoritative storage
selection no longer had one second remaining. A successful early readiness
hint cannot guarantee the remaining interval after target and facts reads.
The existing wait finished before that final read and immediately refused a
thin result, even if another independent binding could become available
within every retained fact's original deadline.

## Decision

Keep one owned readiness operation per Preview, Request or CheckDiagnostic.
Its early hint may overlap the existing target and ordered facts reads.
After joining that hint, the operation retains its original upper bound and
whether its single refresh-demand attempt was spent or failed. It may then
enter a consumption phase; it does not start another hint or another
independent wait.

The authoritative storage read still requires a valid binding and the
existing one-second selection margin. A valid same-selection binding
with less than that margin, or the typed expired-only result described below,
permits consumption polling. With refresh configured,
use the call's sole demand attempt if it has not already been spent, then
read at the existing 250 ms interval. A failed demand prevents further polling.
Each candidate retains its own original observation and freshness timestamps;
a later independently observed binding must satisfy the margin in its own
right. Never extend or copy the first binding's interval.

Before and after blocking work, check cancellation and the earliest original
caller, initial identity/recovery, preview, exact target, eligibility and
verified identity, capability, retention/proof/expiry and optional reason
deadline. The first thin binding's freshness is not the consumption wait's
deadline: that binding is discarded, while every retained non-storage fact
must remain current. A malformed expired or otherwise invalid binding returned without the explicit
expired-only result still refuses the operation.

Request binds the storage selection already reviewed in the passive preview.
Preview and CheckDiagnostic bind their first valid authoritative selection.
A changed pool, policy, allocation or revision refuses the operation rather
than silently selecting replacement storage. Read errors, cancellation and
any expired retained fact also refuse. Missing refresh or an earlier failed
demand prevents polling for a thin result; a valid authoritative read with
sufficient margin can still succeed. The early hint's existing bounded
handling of a missing/stale binding is unchanged.

Resolve accepted idempotency before draft expiry or this work. Resolve the
target once and keep the initial eligibility, capability and retention reads
in their existing order, followed by the existing final eligibility recheck.
Do not refresh retained facts, reselect a Pod, retry admission
or repeat an effect. Cancel and join hint work on every early return.
No SQL schema, public response, permission, quota, demand lifetime or
five-second authority interval changes.

## Response scheduling refinement (2026-10-27)

Installed run 40581901798 exhausted the original public five seconds during
initial preview storage readiness and returned an HTTP/2 stream reset. The
optional readiness work now ends at the earlier original authority cutoff or
one second before the actual parent context deadline. This changes scheduling,
not an authority interval: a fresh authoritative read remains possible under
the original context, including short parents; thin storage after the readiness
cutoff returns the existing retryable unavailability. No hint, demand or polling
starts in the reserved tail. The already owned hint is joined and a final
independent read still supplies any usable binding. The one-demand rule,
selection pin, original observations and final checks remain.

One second is a practical candidate, informed by earlier completed native
requests with audit Finish below 100 ms and pre-service marks below 250 ms.
The failed run's immediate failure timing does not measure its Finish duration.
The reserve does not guarantee audit or response completion and is not yet
installed-qualified. See [the implementation and cost record](../implementation-progress.md#storage-readiness-response-reserve-2026-10-27).

## Qualification

The component regression must first reproduce the immediate margin refusal
after early binding A loses headroom during independent facts work. The
correction must consume independently refreshed B without changing B's
timestamps, with one exact target resolution, the unchanged ordered facts sequence,
at most one demand and one admission. Separate cases must cover every
original deadline, changed/invalid/expired bindings, failed demand, blocking
read cancellation, joined hint cleanup and the exact one-second boundary.

Component checks and installed qualification are recorded separately in
[implementation progress](../implementation-progress.md). Selecting storage
with a one-second margin does not promise that later audit, SQL locks or
execution will finish before the original deadlines. ADR-212's preparation
floor and passive uncertainty rules remain unchanged.

The [component regression](../../test/results/resumed-c62e02ac-storage-consumption/verification.json)
failed before implementation. The full capture race suite then passed
(10.066 seconds, exit 0), including original-cutoff, selection, cancellation
and one-demand cases. Independent review found no blockers. The integration
package compiled with no tests selected; no installed result is inferred
from that compile check.

[Native48](../../test/results/resumed-c62e02ac-native48/result.json) includes
this correction and reaches installed admission, acquisition and publication.
Its timing logs do not establish whether a consumption-phase poll was
required. The complete test failed in subsequent client recovery before
public retrieval/download and expiry/deletion qualification.

## Natural source expiry correction (2026-10-28)

The prior terminal-expiry rule was an engineering choice in these tests/contracts,
not a maintainer requirement. A local actual-Request regression reproduces a legal
30-second original source near expiry: the early hint succeeds, but the later
authoritative read reports its natural expiry and previously returned immediately
without using the existing refresh owner. Native 40634973872 refused source
validation before traffic; its row timestamps were not retained, so this local
defect does not establish the installed failure's exact cause.

A dedicated availability result may retain expired original Binding/Selection
metadata with a nonnil error. The consumer validates the original interval, rejects
future/malformed/mismatched metadata and compares Request's exact preview selection
before waiting. It reuses the existing sole demand, 250 ms cadence, response reserve
and original caller/non-storage bounds; an earlier failed demand prevents waiting.
Only a new successful, current, margin-sufficient same-selection read can authorize
admission. Known source/pool revisions refuse before or after waiting. No TTL,
demand lifetime, permission, audit, admission retry or authority interval is extended;
the persisted binding already lasts 30 seconds under ADR-200/migration 00072.


## SQL transaction classification correction (2026-10-28)

Native 40648568602 on af9bb589 stopped before capture at
`request/facts/storage/read/observation/source-expired`, despite the typed natural
expiry change above. Its demand worker completed refreshes in about 2.3–4 seconds;
the first 3.98-second refresh reported only 880 ms left on its original guarded
namespace/workload observation, sampled before its 70 ms reconciliation. That is
less than the existing one-second storage margin; other original source/recovery
bounds can shorten the effective binding further. This diagnostic is not a row
freshness timestamp. Later refreshes can
supply usable windows, but must be independently read inside the request's
unchanged authority/readiness cutoffs. These measurements neither justify
extending five-second source freshness nor identify every request's exact timing.

A concrete adapter defect prevented this existing readiness path: the real
Ledger.transaction error list included generic capture unavailability but omitted
its more specific ErrStorageBindingExpired child. Its callback correctly marked
source expiry, then transaction normalization erased that classification. The
reader consequently discarded expired Binding/Selection metadata, and the
consumer immediately returned generic unavailability. The earlier pure adapter
wrapper and synthetic Request-port tests bypassed that actual SQL transaction
boundary; their passing results did not prove preservation through it.

The new focused existing PG/S3 fixture calls the real SELECT-only storage reader
and real Ledger.transaction. A valid original 30-second binding is made naturally
expired by the fixture administrator; the unchanged implementation returns the
wrong generic class and zero selection (RED exit 1, child 0.57 s, Go package
1.103 s). The same case checks changed expired selection, malformed/future source,
canceled SQL read and an independent restored-original successful read, with no
capture admission. Protected source setup remains synthetic; this is SQL adapter
qualification, not a new installed run or runtime refresh authority.

The correction adds the specific expiry marker before generic unavailability in
the existing closed error list. It retains the original metadata and nonnil
availability error so only the existing sole readiness owner can demand/poll;
only a later current same-selection read can authorize admission. No query,
transaction, timer, watcher, provider call, credential, retry, schema or authority
interval is added. The worker's cumulative refresh cost is unchanged. The
installed path and combined runtime budget still need their own later result;
this fix is not a promise that every refresh fits an already-short caller.
