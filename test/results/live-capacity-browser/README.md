# Live runtime capacity browser evidence

`make console-browser-check` passed with 29 journeys and 28 accessibility
scans. The capacity journey used the actual built React page and Go HTTPS
operation: entering one cluster, reading its counters, gauges and rates, and
rendering cumulative source-loss events, transport-dropped rows and buffered
pending-row occupancy without content labels.
[Screenshot](../console-browser/live-capacity.png).

Pending rows are shared-buffer occupancy, not exact per-viewer lag. Active
cohorts are not an exact viewer count. Source-loss and reply-drop rates use
report-to-report counter deltas and are withheld when any current live-enabled
node lacks a valid predecessor.

The operation has application and presentation tests for current fleet
operator/administration/recovery checks, unknown clusters, incomplete rates,
error freshness and recursive content-label rejection. All 613 console tests,
full `make pre-push`, and focused race tests for bootstrap, delivery, live
buffers and node transport passed.

This is real browser/TLS/component evidence with synthetic authority and runtime
facts, not an installed multi-node or fleet-administrator measurement. The
installed live fixture does not enable fleet administration, so it cannot
qualify this operation. Guarded native suites exercise the existing policy and
manual live workflows; they do not establish that missing installed measurement.
