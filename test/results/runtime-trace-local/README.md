Local runtime trace preparation evidence
========================================

This archive covers the test-only namespace runtimeTrace workflow: one approved 5-second interval, 10-second action timeout and 32MiB output limit, native `.trace` download, finite local `go tool trace -pprof=sched` opening, and planned read-only SQL checks that pprof summary creates no query. Funding and production behavior are unchanged.

`manifest.json` pins commands, observed exits, source mapping and hashes. The selector RED uses a temporarily restored old fixture grammar; it is not a product failure. The first final preflight failed because ignored node dependencies were absent. The same clean code passed after linking existing dependencies, with no lockfile/source change.

The positive tool-opening unit uses synthetic locally generated `runtime/trace` bytes. No installed trace capture/download, external SQL fixture, VM, browser trace or maximum-resource qualification ran here. Older evidence retains its original source attribution; file equality does not turn it into a run at the final commit.
