# ADR138 staged public endpoint composition

Scope: C-20 bootstrap composition of the existing browser sessions, healthy
operation audit, shared browser/MCP investigation service, console and ADR136's
authenticated native-content handler. No live product Go source is changed.

Stage: `/home/phil/.cache/asservat-build/planning/public-context-runtime-20261012`.
`public-context138-manifest.json` records base/payload SHA256 for the five staged
paths. All are new paths; later integration must check both absent originals
and the current ADR136 constructor/constant signatures. Archived Go evidence
ends in `.go.txt` so that normal Go tooling does not compile it as a package.

The router preserves the original request/response writer, routes each protocol
to its existing owner, rejects encoded/absolute/incorrect-host targets and does
not clean paths, redirect methods, buffer native bodies or use HTML as an API
fallback. Authentication callback queries remain unchanged. The complete
factory constructs one `NewHealthyAuditedOperations` instance and passes it to
all three audited transports. The factory compiles against ADR136's frozen
22-file `dependency-http-v1` snapshot, whose manifest SHA256 is
`e79ddbe309cf870b08fbec0b864d86de40451a6cd02726a00897aab86ff20da1`.
All original/payload hashes matched before the combined 25-file overlay check.
It is not an installed service or a new authority source.

Verification: both isolated route overlays returned exit 0 using
`GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp go test -race
-count=1 -overlay=<stage>/routes-overlay.json ./internal/bootstrap -run
'^TestPublicContextRoutes'`. The final run contains five top-level tests and
returns `ok .../internal/bootstrap 1.061s`. It includes an actual loopback TLS
request through the router preserving native bytes, attachment header, response
deadlines and flush. Protocol handlers in these routing tests are explicitly
synthetic; no identity, collection, audit, SQL or installed-native qualification
is claimed. Logs are `public-context138-routes-first.log` and
`public-context138-routes-final.log`.

The subsequent full factory compile plus the same five routing races also
returned exit 0, using `<stage>/full-overlay.json`; its log is
`public-context138-factory-compile-routes.log` and Go reports 1.061s. No live Go
source was changed, and no unfinished SQL53/PostgreSQL/bootstrap adapter is
included in the dependency snapshot. This proves matching concrete constructor
signatures and routing behavior, not successful installed-provider construction.

Remaining: test the full constructor against integrated ADR136 and its actual
configured providers;
check complete shared-audit/refresh-owner composition; integrate its architecture
record/catalog and run repository gates. Protected provider/source provisioning,
supervision, bounded public listener and installed console/MCP/native-download
journey remain required before enabling the chart runtime.
