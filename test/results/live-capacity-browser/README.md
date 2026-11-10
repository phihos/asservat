# Live runtime capacity browser evidence

`make console-browser-check` passed with 29 journeys and 28 accessibility
scans. The capacity journey used the actual built React page and Go HTTPS
operation: entering one cluster, reading its counters, gauges and rates, and
rendering exact active viewers, cumulative source-loss events, transport-dropped
rows and buffered pending-row occupancy without content labels.
[Screenshot](../console-browser/live-capacity.png).

Pending rows are shared-buffer occupancy, not exact per-viewer lag. Active
viewers is the exact count of distinct unexpired Active, Paused and
Disconnected watch control records with current trust, an active owner
enrollment and an activated unexpired certificate; it is distinct from
node-reported cohorts. Source-loss and reply-drop rates use report-to-report counter deltas
and are withheld when any current live-enabled node lacks a valid predecessor.

Historical real PostgreSQL evidence (recorded in [PR #215](https://github.com/phihos/asservat/pull/215)) covers
active/closed counts, retired-owner exclusion, cluster isolation and migration
rollback under the compiled hub role, with unchanged sources and no cleanup
failures.

The operation has application and presentation tests for current fleet
operator/administration/recovery checks, unknown clusters, incomplete rates,
error freshness and recursive content-label rejection. All 613 console tests,
full `make pre-push`, and focused race tests for bootstrap, delivery, live
buffers and node transport passed.

This is built-browser/TLS/component evidence with synthetic authority and runtime
facts. Later [installed run 42887449162](https://github.com/phihos/asservat/actions/runs/42887449162)
qualified protected fleet capacity reads with two active viewers alongside the
real policy live workflow. It does not establish multi-node sustained load or
render the capacity page with installed runtime facts. The current candidate's
complete checks and scope are recorded in
[implementation progress](../../../docs/implementation-progress.md).
