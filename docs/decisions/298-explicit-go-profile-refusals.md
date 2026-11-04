# ADR-298: explicit Go endpoint refusals

Status: implemented; local/service qualification passed, native qualification pending.

## Observed problem and decision

REQ-PRF-001/002 and SC-PRF-002 require missing/disabled endpoints to report
`ProfileUnavailable` and a conflicting application-owned session to report
`ProfilerBusy` without stopping it. The diagnostics adapter already distinguishes
these errors, but the node maps every non-busy acquisition error to generic
`CaptureFailed`; regional completion/public progress therefore loses the missing
endpoint reason. Busy propagation exists, but application-owned coexistence has
no installed qualification.

Preserve the existing typed unavailable error through node result validation,
regional terminal completion and SQL execution state into the existing bounded
public progress reason string. Document these stable codes without inventing a
new operation or narrowing the general reason-string contract. Add the terminal `profileUnavailable` phase to the current execution
state contract and map it to public `Failed` / `ProfileUnavailable`, just as
`profilerBusy` already maps to `Failed` / `ProfilerBusy`. Keep all other errors
and existing generic failure behavior unchanged. Missing means a reviewed adapter
observation, never inferred from an arbitrary failure. Existing `ProfilerBusy`
can also reflect node capacity or an original uncertain-runtime slot; public
guidance says busy or possibly still running rather than claiming an application
profiler definitely exists in every case. Make database migration135
additive and refuse downgrade while retained new-phase rows exist; retain the
current immutable execution guard and completed-state timing/custody rules.

Neither refusal creates an artifact, new grant, retry, replacement target or
refund. An uncertain HTTP start remains spent and cannot authorize a stop request.
The existing uncertain-start runtime slot remains held until the original
accepted start plus profile timeout, including after an HTTP refusal. The
installed fixture passively waits that persisted cutoff before the next capture;
it does not shorten quarantine or infer a refund. Only the application/test owner
stops its own profiler. Production acquisition
still calls only approved fixed Go endpoints and never a stop-profiler endpoint.

## Complexity and cost

1. Observed missing user-visible result: yes, reproducible node mapping loss;
   occurrence frequency unknown. Busy coexistence is required, not a new threat.
2. Accepted risk reopened: no; preserve existing conservative spend/cancellation.
3. Typical Go endpoint users benefit from actionable endpoint/busy failures.
4. Reuse existing diagnostics sentinels, collector reasons and profilerBusy flow.
5. New production privileges, credentials, API access or listeners:0.
6. New externally distinguished terminal reason:1; no new fallback/retry state.
7. New configuration:0.
8. External dependency changes:0; existing Go runtime/HTTP/PostgreSQL only.
9. Extra production API/watch/storage/key calls:0; same bounded completion row.
10. Additive migration with retained-state downgrade refusal; disabling unchanged.
11. Generic failure violates the explicit existing requirement. Preserving the
    already known error is smaller than adding probes or endpoint repair.

## Validation direction

Reproduce mapping loss with a focused failing unit test, then verify collector
result validation, regional completion and public schema/mapper parity. Test SQL
terminal transition, immutable/no-copies rules and upgrade/downgrade behavior.
Extend the existing synthetic profile workload/native fixture to demonstrate a
real application-owned CPU profiler survives Asservat busy refusal and a missing
endpoint produces no artifact/retry. Native collectors run only on a fresh
owned disposable hosted VM, never this workstation. Extend the existing manual
installed profile journey for exact public refusals and retained accounting;
reuse its authority/quota/approval pipeline and existing suites/time limits.
No local fixture is an installed qualification; record actual exits, frozen
source hashes and cleanup before claiming either workflow.

## Local qualification

The typed mapping and UI loss were reproduced with failing focused tests before
fixing them. Integrated profile races and pre-push gates passed (435 console
tests; 13,543 specification assertions), as did built-console browser checks
(33.620s, 27 journeys/26 accessibility scans plus restart/comparison drivers).
Three independent read-only cross-reviews found no blocking defects.

The focused real PostgreSQL/S3/OpenBao profile-admission outcome test passed
4.168s: terminal/replay/immutable failure, actual authorized progress, no new
cancellation work, no evidence/observation and original reservations retained.
Its missing-endpoint observation is synthetic. Schema135→134→135 and original
guard/constraint restoration passed6.049s. All4,052 source hashes match committed
blobs, sources unchanged, cleanup failures empty and scratch removed.

Fresh owned Kubernetes/PostgreSQL/S3/OpenBao empty-schema loading and original
compiled activation Pod passed147.435s. All4,106 hashes match committed blobs;
sources unchanged, cleanup failures empty and scratch removed. Original reports
are retained in `test/results/profile-refusals-services/`,
`test/results/profile-refusals-schema/` and `test/results/profile-refusals-local/`. The
first service run's read-only native proof used a JSON operator on bytea; that
failed run remains under `test/results/profile-refusals-first-service/`. Correct
UTF-8 JSON decoding fixed the proof without changing the runtime outcome.

Collector-native `collector-profile` and installed `continuation-manual-profile`
qualification remain pending, under their existing time limits. No installed
refusal/coexistence, broader profile matrix, S-05 or full-spec exit is claimed.
