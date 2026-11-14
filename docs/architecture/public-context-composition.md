# Public context endpoint composition

C-20 bootstrap joins the browser session service, the built console, the
investigation operations, MCP and authenticated native content under one
installed HTTPS origin. `NewPublicContextHandler` constructs the actual
handlers rather than taking arbitrary HTTP callbacks. It opens no listener.

## Routing

| Route | Owning handler |
| --- | --- |
| Explicit `/auth/*` routes and `/api/v1/session` | Browser session handler |
| `/api/v1/operations/{operation}` | Browser operations |
| `/mcp` and its protected-resource metadata | MCP handler |
| `/api/v1/downloads/{id}/content` and downloads resource metadata | Native-content handler |
| Console paths and packaged assets | Console handler |

- The router uses the literal request path: no path cleaning, slash redirect,
  generic app-shell fallback, body buffering or compression. API errors never
  become HTML responses.
- It passes the original request and response writer to the owning handler,
  so Range/conditional inputs, response deadlines, flushing and stream
  cancellation remain available.
- Browser operations use the browser session; MCP and native content use
  their bearer resource resolvers. The router never guesses token audiences
  or treats a browser cookie as MCP authorization.
- Only request TLS and the installed host satisfy the routing boundary;
  forwarded headers grant nothing. Authentication callbacks keep their query
  parameters and protocol checks.

## Operations

`NewPublicContextOperations` binds the fixed use cases for one installation:

| Public operation | Composition |
| --- | --- |
| Diagnostic discovery, review, submission and resolution | `ContextSubmission` with `ContextInvestigation` and `RegionalAPIContextStart` |
| Capture progress | `ContextProgressService` and `ContextCaseNavigator` |
| Case detail | `ContextCaseService` |
| Native download preparation/status | `ContextDownloadCoordinator` with the regional reader |
| Stop download | `ContextDownloadStopCoordinator` |

Every operation:

- authorizes once against the caller's current identity and permissions and
  reuses that decision for at most `identity.AuthorityRecheckInterval` (30 s;
  60 s for the shared policy observation), never past the original deadline
  ([ADR-311](../decisions/311-operation-authority-recheck.md));
- carries an idempotency key; a retry with the same key returns the stored
  outcome;
- writes one append-only audit row in the same transaction as its effect and
  fails if the row cannot be written ([operation audit](operation-audit.md)).

Previews are stateless dry runs that return the resolved plan and its digest;
submission with the digest accepts that plan or reports what changed
([ADR-330](../decisions/330-event-driven-system-design.md) D9).

Progress and status changes are published with PostgreSQL `LISTEN/NOTIFY` in
the writing transaction. The console receives them over one Server-Sent
Events stream per page, served by the browser operations handler. MCP status
tools wait server-side for at most 30 s and return on the first change.

## SQL

Each Deployment has one non-administrator SQL login and one pool: hub-api,
hub-worker and key-service. A separate migration owner is used only by the
Helm hook Jobs. Use cases keep their typed ports and SQL effect checks; they
do not get per-purpose roles, pools or layout digests.

Disabling new collection preserves access to retained evidence.
