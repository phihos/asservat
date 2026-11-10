# Live node runtime counters

GitHub native run: 42766629788, attempt 2
Commit: `30bf195073ab75481079f0ffbc7b6d6a68a751a1`
Suite: `continuation-ongoing-live`

Result: pass. `TestInitialBootstrapChainWithRealServices` completed in 439.47
seconds (package 439.506 seconds); the installed live focus took 161.96 seconds.
The environment records the complete selected test path, unchanged sources,
removed build scratch and no cleanup failures.

All three policy projections completed with their original sources. The run
retained bounded sustained reads, the shared multi-principal ceiling and owner
failover. The HTTP native Save contained 3,147 bytes with SHA-256
`eff551f4c17e7702706b545f3a47b1390ee206dfe5554d6eb97715a34f53e935`.
There were 33 bounded live MCP operations and no viewer acquisition.

This is installed evidence that the existing live workflow passes with the new
status field. Counter semantics, content minimization, manual/policy delivery
accounting and concurrent report ordering are covered by the affected Go tests;
this run is not an operator-metrics UI or long-duration load qualification.

Earlier attempts are not passes. Run 42761290164 failed once on a retryable
principal-ceiling open and once on a browser `SourceUnavailable`; its remaining
stale attempt was cancelled after correction. Run 42764408892 showed that the
fixture's slow warming poll missed the original five-second start window and
then correctly refused a replacement HTTP source. Run 42766629788 attempt 1
timed out downloading Ubuntu's tshark packages before any product test started.

Evidence files include the Go log, harness environment, timing/service logs and
captured Pod diagnostics.
