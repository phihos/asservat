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
(initial33.620s; final33.162s after precise busy wording, 27 journeys/26
accessibility scans plus restart/comparison drivers).
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

Initial hosted checks: exact CI41784993617 passed at ad8b3a42. Collector41785026939
passed its native assertions but lacked image/binary/source-inventory provenance;
retain that limitation rather than inventing hashes. Report instrumentation now
captures those facts without production changes or new Kubernetes requests.
Manual41785030470 passed CPU/summary/repeat and busy preservation before the third
admission correctly exhausted its original two-attempt regional funding. Four
captures plus history require exactly141MiB/48objects and a12-record fixture
root. Production composed preflight reproduced the old shortage and verifies
6,720/10,000 system objects with unchanged ten-unit summary/per-action/runtime
limits. Corrected whole-workflow qualification remains pending.


## Instrumented native evidence and passive progress recovery

On frozen `f2f49124`, collector41789805115 passed (Go0/83.253s).
Both4,103-path source inventories independently match committed blobs. Actual
Pod images match recorded manifests, distinct from Docker config IDs. CPU/heap
originals match hashes and reopen with pprof; busy-owner preservation, missing
endpoint/no output/no retry and cleanup assertions passed. Original reports and
limits are retained in `test/results/profile-refusals-collector-41789805115/`.
This is collector evidence with synthetic admission authority.

Exact CI41789771763 passed. Installed41789808818 failed (Go1/745.941s) after
CPU/native download/summary/repeat and independently approved busy preservation
passed. A later `get_capture` received HTTP503. PostgreSQL rejected current
capacity audit profiles before journal admission or backing/counter checks; a
capacity-source acceptance failure preceded it by464ms. There is no evidence
of exhausted audit records or a five-minute root lifetime. The logs do not
identify which trust, permission, source or root predicate failed. All4,107
source hashes match the frozen commit, sources unchanged, cleanup[] and scratch
removed; originals remain in `test/results/profile-refusals-native-41789808818/`.
Missing-endpoint/Stop installed qualification remains pending.

The source observer retains its original bounded authority, then sleeps one
second between serial observations. Returning a valid observation with less
than a second left can leave a freshness gap before the next read completes;
that mechanism is possible, not a proved attribution of this particular failure.
Keep the current fail-closed behavior. A bounded passive status read can be
repeated with fresh authorization without repeating acquisition. The fixture
already allows four typed transient read failures with two-second pauses, but
its transport-error path aborts before that budget. The next qualification
candidate covers numeric HTTP503 only for passive `get_capture` within that same
budget. It retains the original refusal progress deadline and reports retries.
No mutation, preview, resolution, unknown network outcome or permission denial is
replayed. A finite test-only SQL snapshot after a failure records safe current
flags/timing and explicitly remains a later observation. This adds no production
request, credential, fallback, setting or relaxed freshness requirement and does
not establish continuous source availability.
