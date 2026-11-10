# Live loss/drop metrics: policy native workflow

GitHub native run: 42803550038, attempt 1
Commit: `d65ccbd021235785089c4de25fc7a367aa542075`
Suite: `continuation-ongoing-live`

Result: pass. `TestInitialBootstrapChainWithRealServices` completed in 426.22
seconds (package 426.241 seconds); the installed live focus took 152.71 seconds.
The environment records the exact selected tests, unchanged sources, removed
build scratch and no cleanup failures.

All three policy projections completed against their original sources, with
bounded sustained reads, the shared multi-principal ceiling and exact owner
failover. The HTTP native Save contained 3,145 bytes with SHA-256
`ec396763e22da1d39d68d2df632f802d3e4dda320bcdd2dca0aecdc03855ca3e`.
There were 32 bounded live MCP operations and no viewer acquisition.

This is installed evidence that the existing policy live workflow passes with
cumulative loss/drop and pending-row status accounting. It is not a
fleet-administrator capacity-operation or long-duration load measurement.

Earlier attempts are not passes. Run 42800184032 attempt 1 failed the
second-principal handle check after sustained reads; attempt 2 ended earlier on
a transient `LiveUnavailable`. Their evidence is retained separately. The
same-suite `main` control 42803544505 passed after a retryable `LiveUnavailable`,
confirming that transient behavior exists independently of this increment.
