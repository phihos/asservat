# ADR-216 — One authority observation for a context start

Date: 2026-10-22. Status: accepted; implemented; affected race and selected real
SQL suites pass. The installed journey reaches capture, verification and
publication; native download and complete installed qualification remain pending.
Requirements: REQ-EXE-002, REQ-DB-003–004; S-02.

## Observed problem

The installed native54 journey accepted and audited its capture but created no
execution. The original start and four explicit continuations returned unavailable;
the final continuation reached ADR-212's remaining-time refusal. This does not
establish one cause for every refusal. It does establish that start availability
remains poor with the complete deployed composition.

The source performs duplicate work inside the same original five-second interval.
The hub reads identity, recovery, accepted work and protected capability before
signing. The runner then reads those inputs again and performs a complete target,
eligibility, capability, retention, recovery and process check three times: before
preparation, after wrapping and after start readiness. A successful start therefore
reads protected capability four times. SQL independently checks current permission,
retention, recovery and storage state at its effect boundaries.

The composed pre-preparation regression confirms two accepted-work reads and
48 capability HTTP requests before the first SQL preparation (36 observer and
12 probe requests). Each complete capability read uses 18 observer and six probe
requests, including the namespace reads around both source snapshots. Its regional,
SQL and identity replies are synthetic; the actual capability adapter runs over
loopback TLS at the installed client limit. This measures duplicated work, not
native latency or the cause of every native54 refusal.

Per-helper external re-observation is an agent-authored choice. The maintainer's
complexity guidance requires its cumulative cost to justify its benefit. Repeating
the complete observation within a single interval adds latency and failure points
without providing instantaneous distributed revocation.

## Decision

One request-owned context start uses one complete authority observation within its
earliest original cutoff, at most five seconds. The hub's initial accepted work,
caller, recovery and capability observations may feed the runner directly through
an in-process service call. They are not request fields or a regional authority
claim. Their exact identities and original intervals remain binding.

The runner resolves the exact target and evaluates eligibility, retention and
process once before the first preparation. Later checks after blocking operations
validate that completed observation locally, including cancellation and every
original expiry. They do not refresh its timestamps or fetch replacement facts to
rescue an expired start. Each new explicit start obtains new observations; accepted
capture and execution identities, spent effects and write deadlines remain fixed.

SQL still evaluates current accepted permission, retention, recovery and storage
state under its existing locks. A changed revision or deny cannot be ignored at
those writes. The regional journal retains current capacity/admission/CAS checks,
and acquisition still reads the exact pinned Pod and owner identities. No step may
select a replacement Pod. Actual process restart or channel loss still invalidates
the exchange. Native evidence and data keys remain regional.

An external identity or capability change not yet observed can remain unknown
within the original observation interval. This bounded freshness is deliberate;
it does not promise immediate revocation between helper calls. A known failure,
cancellation, expiry or failed current SQL effect check still stops the operation.
The next operation performs a complete observation. This refines ADR-171's hub
runner and ADR-173's unchanged-hub-check statement; it changes no wire format,
database schema, grant scope or retained execution interval.

## Complexity and verification

The observed failure affects the ordinary first pod-status workflow. Existing
ADR-173 process observations and ADR-214 download operations supply the same
request-owned pattern. Added privileges, credentials, endpoints, configuration,
background loops and durable states: **zero**. No provider or library is added.
The intended successful-start count is one complete runner check instead of three
and one protected capability read instead of four (24 capability HTTP requests
instead of 96 across the successful source path). Exact measured counts and
timings belong in the qualification record, not an assumed performance claim.

A larger timeout or additional automatic retry does not remove duplicate work.
This change keeps all original limits and the one-second first-preparation floor.
It requires no persisted-state migration; an older binary retains its stricter,
more expensive observation behavior against the same records.

Qualification must show a failing composed call-budget regression on the original
source, original-bound expiry/cancellation after blocking work, fresh observations
for a new operation, current SQL refusals, exact-target acquisition and unchanged
uncertain-effect behavior. Component evidence does not establish installed
availability. Record actual results and remaining gaps in
[implementation progress](../implementation-progress.md).

The [component archive](../../test/results/resumed-c62e02ac-capture-start-observation/README.md)
records genuine failing baseline regressions and passing execution, bootstrap,
context-start and mTLS race suites. Before first preparation, the composed path
now makes one accepted-work read and 24 capability HTTP requests. The successful
runner makes one target/eligibility/capability/retention observation and retains
its separate completion process check. These results do not qualify installed
latency or a complete native capture/download.

The [selected real PostgreSQL/S3 gates](../../test/results/resumed-c62e02ac-capture-start-gates/README.md)
pass on frozen `9543cff7`, including permission revocation committed while the
retained observation waits on the permission lock. The effect refuses while the
original observation and caller remain live, and preserves the immutable
preparation. Both compiled verifier/publisher lifecycle cases also pass.

The installed native55 run on that same commit reaches a regional capture,
verification and catalog publication after two earlier unknown start outcomes.
It then fails native-download preparation with an acknowledged unavailable reply.
That result demonstrates a successful installed capture path, not sustained
availability or a complete investigation. See the current
[qualification record](../implementation-progress.md).

## Admission metadata and the start phase

`Accepted.MetadataValidUntil` is a response observation, not an execution permit.
The submission coordinator previously copied it into the context deadline for
intent acknowledgement and the independently authorized start. A deterministic
composition reproduces the resulting failure: a still-current 100 ms metadata
observation limits a five-second caller even though the start obtains its own
current authority. Work consuming 200 ms then fails before start or after its
effect. Native57's short accepted interval motivated this check; its archived
minimum does not identify which individual source supplied the winning cutoff.

Consume the exact accepted identity while its metadata is current, without
turning that response-only cutoff into a deadline for later phases. The original
caller, identity, capture and write deadlines remain binding. The audit publisher
keeps its persisted first-write `RequestUntil`; the start keeps its own original
permission, recovery, capability, work and prepared-execution bounds. This is a
refinement of the existing phase separation, not a larger request interval.

If the original metadata is still current after a successful start, return it
without extending it. If it expired, make one existing read-only exact-key lookup
under current identity and recovery, requiring the identical capture, scope,
pin, expectation, creation time and deadline. Only that observation can supply
new response metadata. Failure preserves the known admission with an error;
there is no admission, audit or start retry. Ordinary accepted replay remains
passive and does not acquire this extra lookup merely to extend its response.

This affects the ordinary first capture and explicit continuation. It adds zero
privileges, credentials, endpoints, configuration, durable states or background
work. A successful start whose metadata expired adds one recovery observation
and one existing SQL replay transaction, followed by the existing current-identity
check; all other paths retain their read count.
There is no measured installed latency claim or comparable-project assumption.
No migration is needed; older code retains its more restrictive phase coupling.
Simply increasing a timeout would preserve that coupling. Focused regressions
exercise the real investigation, request-owned identity, submission and audit
publisher with synthetic SQL/start ports, including unchanged first-write expiry.
Installed qualification of this refinement remains pending.
