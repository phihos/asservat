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
namespace/workload observation, sampled before its 70 ms reconciliation. That
number is not the persisted raw binding cutoff or the consumer's final effective
cutoff, and cannot establish a one-second storage-margin refusal. Migration 00072
keeps the raw source binding's original 30-second interval separate from checked
work facts/receipts within their original five seconds. The storage reader tests
raw source expiry before its successful-result managed/control/pool/allocation
intersection. Later successful observations must still be independently read
inside the request's unchanged authority/readiness cutoffs. These measurements
neither justify extending source freshness nor identify every request's exact
timing.

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

The identical selected SQL case passed after the one-sentinel fix on 606c43e2
(command/Go exit 0, child 0.52 s, Go package 1.995 s). RED used unchanged production
on 2f95706f; GREEN's dates, selection and negative checks were unchanged. Both
owned PG/S3 runs matched all 3,343 source hashes, reported unchanged sources and
empty cleanup failures, and independently confirmed exact owned container/network
absence. The role remained SELECT-only and no capture row was created. Offline
complete PostgreSQL-adapter and capture races also exited 0 (2.577 s and 12.256 s).
The SQL proofs establish this normalization boundary, not installed capture,
regional refresh speed or end-to-end response success. No broader external suite
or hosted run was executed for this fix.


## Readiness decision diagnostics and composed boundary (2026-10-28)

Native 40744858749 on `3f434f00` again ended at
`request/facts/storage/read/observation/source-expired`, before capture (Go
599.782s, approved-recording case 132.28s). The corrected transaction marker was
present. A full source trace finds the real storage reader assigned directly to
`ContextInvestigation.Storage` and carried unchanged into `ContextSubmission`.
The old final label also described recognized typed expiry when the existing
readiness cutoff was exhausted or the single wakeup demand had failed. It did
not prove another lost-marker defect or identify the installed failure branch.

Keep the returned typed cause and all behavior unchanged. Recognized expired
metadata now distinguishes the fixed private readiness decisions
`facts/storage/expired/readiness-tail`, `demand-failed` and
`refresh-unavailable`. An unrecognized/read failure retains its old read-stage
classification. `q-pre-storage` uses the existing bounded timing recorder to
measure Request's initial identity/recovery/replay/preview/approval work before
its first storage hint. Shared timing logs sample powers of two, so a given
request's timing may still be absent; the first fixed refusal label can identify
its decision without request identifiers, dependency strings or new machinery.

A failed wakeup is not authority. A fresh, current, margin-sufficient independent
first/final read is accepted **before** the failed-demand gate. That gate stops
additional polling only. Whether allowing further bounded polling improves
availability after failed/uncertain demand is an engineering load choice; the
retained Native does not identify that branch, so no polling behavior changes.

The composed fixture exercises actual Ledger/ContextStorageReader through
Preview/Request with actual SQL previews, replay and admission. Source publication,
identity, target and processing facts remain explicit synthetic inputs; it does
not qualify the worker or protected source producer. Cases cover one demand and
fresh source, failed demand followed by an independently fresh source, failed
wakeup without a fresh source and an original short-parent readiness tail.
Accepted replay must recover the original capture without storage refresh.
External execution of this new composition remains pending.

This adds zero SQL/API/provider calls, watches, credentials, timers, retries or
authority intervals. It adds three fixed diagnostic labels and two clock reads
for one existing timing step. Request retains its original five seconds and the
one-second response reserve. With a cold source, a 2.48–3.11s successful producer
exchange leaves at most 1.52–0.89s of that four-second readiness ceiling for all
pre-hint work, polling jitter and other overhead; earlier original bounds may
shorten it further. This is source-bound arithmetic, not a measurement of the
failed request's prefix or proof of its exact cause. The deliberate two-minute
preview-expiry wait can outlast both the 60s demand and raw 30s source binding.
No earlier wakeup, extra demand, new deadline or TTL change is implemented here.

The first authorized composed PG/S3 run on `f2f7d2a` failed initial Preview in
all four cases (child 1.20s, Go 1.644s, exit 1), before the expired-row Request
checks. All 3,347 source hashes and 35,980 tracked files were unchanged; cleanup
was empty and exact owned resources were absent. Its environment SHA256 is
`a64a0b594b1b1de65396d75536d7825c13bb69cd5f89f525efc3906c3a79b333`.
This failed setup provides no composed expiry or admission qualification.

Source review found a deterministic fixture error: its synthetic processing
coverage used `now+5s` after the original identity/recovery bounds had already
begun, while the real consumer rejects a proof beyond those bounds. A pure test
reproduced this contract violation (exit 1, Go 0.014s) for both caller-first and
recovery-first cutoffs. The fixture now intersects its five-second ceiling with
the received caller deadline and original recovery freshness; the unchanged
consumer still verifies every original bound. The focused race passes (exit 0,
Go 1.060s). The fixture diagnostic callback now precedes initial Preview, so a
later setup failure retains its fixed stage. The first failed run did not retain
that stage; the deterministic defect is not presented as an observed Native
cause. Independent source preflight of identity/permission, target/pin/class,
capability, retention, preview and admission found no second concrete mismatch.
Corrected composed PostgreSQL execution remains pending separate authorization.
