# Live runtime capacity browser evidence

Commit: `f86f4eed2ce99108a514b9f67022c40aed7238b7`

`make console-browser-check` passed with 29 journeys and 28 accessibility
scans. The capacity journey used the actual built React page and Go HTTPS
operation: entering one cluster, reading its cumulative counters and rates, and
rendering them without content labels. [Screenshot](../console-browser/live-capacity.png).

The operation itself has application and presentation tests for current fleet
operator/administration/recovery checks, unknown clusters, incomplete rates,
error freshness and recursive content-label rejection. The shared operation
router, audit normalization, static route and packaged browser path are also
covered. All 613 console tests and full `make pre-push` passed. PR CI run
42792664049 and Gitar review passed.

This is real browser/TLS/component evidence with synthetic authority and runtime
facts, not an installed multi-node measurement. The installed live fixture does
not enable fleet administration, so it cannot qualify this operation. Earlier
attempts are not passes: browser-only MCP calls were correctly refused, and they
also exposed missing audit input preservation, operation-router and static-route
branches that are now covered. Richer lag/drop aggregation and a fleet-enabled
installed run remain open.
