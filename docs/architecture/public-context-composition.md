# Public context endpoint composition

C-20 bootstrap joins the existing browser session service, built console,
audited investigation operations, MCP and authenticated native content under
one installed HTTPS origin. `NewPublicContextHandler` constructs the actual
handlers rather than taking arbitrary HTTP callbacks in public configuration.
It opens no listener and does not enable collection in Helm.

One concrete healthy operation-audit owner wraps the shared investigation
service. Browser mutations, MCP calls and native HTTP preflight use that same
owner, preserving its independent normal/resolution/Stop limits and protected
MAC. The browser operation handler requires its existing POST-admitted refresh
owner. Downloads receive the same browser session service and the separately
accepted refresh-pause reader. MCP and native content receive separately pinned
bearer resource resolvers; the router never guesses token audiences or treats a
browser cookie as MCP authorization.

The installed origin and issuer are shared across all constructor inputs.
Console assets use the existing bounded trusted-package reader. The operation
set must contain context preview/progress/recovery, case metadata and download
preparation/status/cancellation. Disabling new collection preserves retained
evidence access; it cannot qualify the complete first capture journey.

The private router uses the original literal request path. It has no automatic
path cleaning, slash redirect, generic app-shell fallback, body buffering,
compression, provider request, shared ingress semaphore or credential logging.
It passes the original request and response writer to the correct owner, so
native Range/conditional inputs, response-controller deadlines, flushing and
stream cancellation remain available. API and private-path errors cannot turn
into successful HTML responses. Authentication callbacks keep their original
query parameters and their existing protocol checks. Only actual request TLS
and the exact installed host satisfy the routing boundary; forwarded headers
grant no transport authority.

Existing routes are composed without additions:

| Route | Owning handler |
| --- | --- |
| Explicit `/auth/*` routes and `/api/v1/session` | Browser session handler |
| `/api/v1/operations/{operation}` | Audited browser operations |
| `/mcp` and its protected-resource metadata | Audited MCP handler |
| `/api/v1/downloads/{id}/content` and downloads resource metadata | Authenticated native-content handler |
| Existing console paths and packaged assets | Console handler |

Construction does not qualify the service inputs. Protected provider, client,
permission, retention, storage, capability and audit provisioning; source and
cleanup supervision; regional acquisition/publication; the native runtime; and
bounded public listener/ingress configuration remain deployment prerequisites.
The installed browser/MCP/native-byte journey must pass before chart runtime
enablement. A routing fixture with synthetic services supplies no evidence or
collection authority.

Current checkpoint: staged source. The routing regression checks include actual
loopback TLS response-controller use, distinct protocol ownership, original
callback/range fields, rejected encoded/absolute/cross-host paths and absence of
redirects/API fallback. The complete constructor also compiles against ADR136's
frozen 22-file HTTP dependency snapshot after exact payload/base checks. The five
routing races pass in that combined overlay. This is not a positive configured-
provider or installed-service test. Actual exits are retained in the staged
handoff; this document makes no native-service qualification claim.

## Shared application assembly

[ADR-160](../decisions/160-public-context-service-assembly.md) adds
`NewPublicContextOperations` below this existing HTTP boundary. Accepted
installation inputs supply the scoped application adapters; the constructor
validates a single root and installation, then binds the fixed use cases:

| Public operation | Concrete composition |
| --- | --- |
| Diagnostic discovery, review, submission and resolution | `ContextSubmission` with `ContextInvestigation`, acknowledged capture-intent publication and `RegionalAPIContextStart` |
| Capture progress | `ContextProgressService` and `ContextCaseNavigator` using the same verified case service |
| Case detail | `ContextCaseService` |
| Native download preparation/status | `ContextDownloadCoordinator` with the original `ContextNativeRuntime` |
| Stop download | `ContextDownloadStopCoordinator` with that same runtime as active-transfer owner |

The constructor fixes one recovery reader across these use cases and the same
qualified capability reader for review and regional start. It creates neither
freshness observations nor replacement request contexts. Continued acquisition
uses the concrete submission's existing accepted-only path. Caller-supplied
regional capability/recovery, progress navigation or download runtime overrides
are rejected; installation must use the explicit shared binding. The returned
operations go directly into `NewPublicContextHandler`; there is no parallel
browser/MCP route or fallback dispatcher.

`capture-preview` (46) constructs `ContextPreviews`; `capture-resolution` (47)
constructs `ContextRequestResolutions` with the same root's recovery guard.
They do not reuse capture-admission credentials. The first may insert passive
blueprints and delete expired previews/fences; the second may close an existing
preview or install its bounded missing-preview fence. Both require the original
permission-root lock. Resolution additionally checks current recovery and SQL
permission/accepted-capture state before disposition. SQL33/36 keep original
blueprints immutable, closure one-way, fences finite and live deletion denied.
No grant permits new capture, custody or audit effects.

Under [ADR-215](../decisions/215-hub-metadata-reader-role.md), the permission,
retention, storage, capture-progress, case, processing and catalog readers share
one `hub-metadata-read` credential and pool. Their typed methods and transaction
checks remain separate. Its seven-connection maximum preserves their former
aggregate concurrency; it remains cold under the unchanged 32-connection hub
governor. It has the exact union of the former metadata grants, including their
existing lock columns, without evidence-key, acquisition, publication, audit-write
or deletion privileges. Those duties retain their credentials.

The fixed inventory contains 81 public-runtime credentials, including 46 hub
entries. These are credential counts, not simultaneously open connections.
Exact-count and layout-digest validation reject unsupported development
states/manifests before effects; startup cannot adopt or migrate retained state.
The qualification below records the earlier assembly. Current results are in
[implementation progress](../implementation-progress.md).

The [component gate](../../test/results/public-context-assembly-component-1/result.json)
passes focused assembly, original-layout rejection, grant-plan and surrounding
use-case regressions. Actual generated SQL-role effects also pass the
[independently verified first-installation fixture](../../test/results/public-context-assembly-native-verification/result.json).
The positive combined capture-to-download journey remains pending. The constructor requires
already accepted dependencies; it does not complete their installed loaders,
regional producer/control graph, downstream native credentials or supervision.
Public serving and Helm runtime remain disabled pending the complete installed
capture, publication, case and native-download journey.
