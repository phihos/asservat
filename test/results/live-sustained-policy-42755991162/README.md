# Sustained installed live reads: policy sources

GitHub native run: 42755991162
Commit: `f36aed40b5c0ed2ac04be244b9e3f03dd1e51b77`
Suite: `continuation-ongoing-live`

Result: pass. `TestInitialBootstrapChainWithRealServices` completed in 437.40
seconds (package 437.430 seconds); the installed live focus took 163.58 seconds.
The environment records the complete selected test path, unchanged sources,
removed build scratch and no cleanup failures.

The first policy episode followed continuation through five bounded one-second
live batches. Every batch retained the original watch revision, source,
projection and row expiry, with no synthetic canary in approved content. Spend
increased cumulatively and matched the minimized SQL ledger. All three policy
source projections then completed their ordinary episodes, including the 2,944
byte HTTP native Save with SHA-256
`54838de17a0d6c229971639f5ae553ad899e7a3d425cc37145bcc2ba08981271`.
The run used 31 bounded live MCP operations and no viewer acquisition.

This is a short installed sustained-read proof, not a long-duration load or
operator-metrics measurement.

Evidence files include the Go log, harness environment, timing/service logs and
captured Pod diagnostics.
