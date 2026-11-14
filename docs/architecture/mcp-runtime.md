# MCP runtime boundary

C-20 provides the authenticated MCP HTTP boundary in `internal/transport/mcp`,
using the official Go SDK (pinned in `go.mod`). It serves REQ-MCP-001 and
REQ-MCP-004 under TASK-07.

`NewHandler` advertises no tools. `NewContextHandler` adds the implemented
[pod-status operations](context-operations.md) with strict schemas over the
same application services as the console; capture mutation is registered only
when the deployment enables it. The
[canonical catalogue](../../specs/contracts/mcp-tools.json) is the planned
interface; no tool is presented as working before its service exists. Tools are
registered individually, never through a generic dispatcher. Supported protocol
revisions are `2026-07-28` and `2025-11-25`.

## Authentication

The deployment configures the public HTTPS origin, issuer, product version,
concurrency limits and the C-02 identity resolver, whose verifier is pinned to
the MCP resource URL as audience.

- Every POST to `/mcp` carries one bearer header. Cookies, session IDs, query
  credentials, replay event IDs and forwarded-header assertions do not
  authenticate.
- The request must arrive over TLS. Host must equal the configured origin; a
  supplied Origin must match. Clients without Origin still need a bearer token.
- `identity.NewBearerRequest` authenticates once and returns the request's
  `CurrentIdentity` ([current request identity](current-request-identity.md)).
  Tool adapters pass that handle to the shared application services, which
  authorize the workload or artifact once before lookup. The handler does not
  re-read identity before writing the response.
- An operation whose deadline passes before the response is written returns a
  generic 503 without metadata or an authentication challenge.

GET `/.well-known/oauth-protected-resource/mcp` publishes the resource, issuer,
`evidence:read` scope (plus `evidence:capture` when capture is enabled) and the
header bearer method. 401 challenges name that URL; a missing scope yields a 403
`insufficient_scope` challenge. Provider failures yield a generic 503 without
diagnostics, tokens or evidence. There is no dynamic client registration,
directory lookup, session replay or anonymous tool access.

## Transport behavior

The SDK runs stateless Streamable HTTP with JSON responses: no sticky session,
event store, subscription, server-to-client callback or replay. Accepted
methods are `initialize`, `notifications/initialized`, `server/discover`,
`ping`, `tools/list` and `tools/call`. Unknown tools are protocol errors.

Status tools that report progress (capture, preparation, live state) wait
server-side for the next change, at most 30 s and never past the identity
handle, then return; clients do not poll them in a loop (ADR-330 D1). Waiting
is woken by the same change events that drive the console stream.

Bounds:

- A request lives at most until its identity handle ends (≤30 s) and its
  operation deadline; socket read/write timeouts follow that deadline.
- Input: at most 32 KiB, one JSON object, depth 32. Duplicate members, aliased
  envelope or routing members, batches, encoded bodies and conflicting routing
  headers are rejected, including contradictory method/name hints from older
  clients.
- Concurrency: 1–64 requests per process and 1–4 per principal/client (the
  latter ≤ the former). Capacity stays charged until the handler returns.
  These are local transport limits, not collection or disclosure budgets.
- Output: buffered to a hard 64 KiB. `preview_recording_save` uses a 256 KiB
  frame for its 128 KiB metadata result. Evidence tools enforce their 24 KiB
  default/32 KiB hard structured envelope before this ceiling. Responses are
  `no-store, private`. Native evidence is never returned inline.

## Dependencies

The SDK adds `google/jsonschema-go`, `segmentio/encoding`, `segmentio/asm` and
`yosida95/uritemplate/v3`, all under permissive licences (Apache-2.0/MIT, MIT,
BSD-style). Sources: the
[SDK protocol documentation](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/docs/protocol.md)
and the
[MCP authorization requirements](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
