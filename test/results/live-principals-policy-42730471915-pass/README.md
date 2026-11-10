# Installed multi-principal live ceiling: policy sources

GitHub native run: 42730471915, attempt 2
Commit: `55cd5861fa00af5f7c78b1a3e82bc92c8f3ede4e`
Suite: `continuation-ongoing-live`

Result: pass. `TestInitialBootstrapChainWithRealServices` completed in 419.34
seconds (package 419.365 seconds); the installed live focus took 145.46 seconds.
The environment records the complete selected test path, unchanged sources,
removed build scratch and no cleanup failures.

The installed fixture used React plus the developer's MCP session for the first
principal and the existing reviewer's separately authenticated MCP session for
the second. Two installation/workload watches per principal were not permitted:
three total installation/workload slots and two principal slots made the limits
unambiguous. The two principals held three active controls; the reviewer's next
open was refused below its principal ceiling, and closing its original control
released the third slot without changing its deadline. SQL independently found
three active controls across two distinct principal keys before closure and two
across one afterwards.

This native scenario qualifies multi-principal behavior but does not distinguish
the equal installation and workload limits. PR #205's real-PostgreSQL fixture
separately isolates installation-only accounting.

All three policy projections completed their original-source episodes, with 26
bounded live MCP operations and no viewer acquisition. The packet episode also
retained its terminal owner-failover proof. The HTTP Save downloaded 2,810 native
bytes with SHA-256
`5cea9c77bc58ad358f48757282698971bb87e38e3a47c81ac3ca093d4067b308`.

Attempt 1 passed the new multi-principal assertions but later failed at the
existing HTTP Save preview with `NotAvailable`; attempt 2 passed unchanged and
is the complete qualification. Earlier run 42728495709 failed before opening a
watch because workload slots exceeded installation slots. Neither failed run is
reported as a pass.

Evidence files include the Go log, harness environment, timing and service logs,
and captured Pod diagnostics.
