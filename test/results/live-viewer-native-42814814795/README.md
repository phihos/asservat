# Active-viewer native qualification on final head

GitHub native run: 42814814795, attempt 1
Commit: `4a699d9a06218b1778e2ecabc1d8985f31e2aeb0`
Suite: `continuation-ongoing-live`

Result: pass. `TestInitialBootstrapChainWithRealServices` completed in 449.60
seconds (package 449.626 seconds); the installed live focus took 174.90 seconds.
The environment records the exact selected tests, unchanged sources, removed
build scratch and no cleanup failures.

All three policy projections completed against their original sources, with
bounded sustained reads, the shared multi-principal ceiling and exact owner
failover. The HTTP native Save contained 3,148 bytes with SHA-256
`13ebe84a112f59dd873c6af247b77d622bdd5067e0c5597e71ec802c6755a548`.
There were 31 bounded live MCP operations and no viewer acquisition.

This is installed evidence that the existing policy live workflow passes after
the exact-viewer SQL and composition changes. It is not a fleet-administrator
capacity-operation or long-duration load measurement.

Earlier attempts 42810631259 and 42813341849 failed transient browser-source and
principal-ceiling-open episodes and are not passes. Their evidence is retained
separately. Final-head CI run 42814070024 passed every job except `test (1/14)`,
which failed the same fixed-date accepted-policy fixtures that expired on
`main`; that unrelated baseline failure is not hidden by this native pass.
