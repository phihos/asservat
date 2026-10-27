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
existing one-second selection margin. Only a valid same-selection binding
with less than that margin permits consumption polling. With refresh configured,
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
must remain current. An expired or otherwise invalid binding returned by the
authoritative reader still refuses the operation.

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
