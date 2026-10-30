# MCP runtime boundary

C-20 now has an authenticated HTTP boundary in
`internal/transport/mcp`, using the pinned official Go SDK v1.8.0. This advances
REQ-MCP-001 and REQ-MCP-004 under TASK-07; it does not complete either requirement
or S-02. It is not wired into a public listener or enabled by Helm.

`NewHandler` advertises no tool capability and returns an empty tool list.
`NewContextHandler` additionally composes the implemented
[pod-status operations](context-operations.md) with explicit qualified-subset
schemas and shared application services; capture mutation remains disabled unless
protected composition enables it. The
[canonical catalogue](../../specs/contracts/mcp-tools.json) remains the complete
planned product interface. No placeholder query or download tool is presented
as working. Protocol initialization/discovery is actual SDK behavior, not a mock
JSON-RPC implementation. Supported revisions are explicitly restricted to
`2026-07-28` and `2025-11-25`.

## Authentication and ownership

Protected bootstrap supplies the exact public HTTPS origin, issuer, product
version, concurrency limits and existing C-02 identity resolver. That resolver
must use an access-token verifier pinned to the MCP resource URL as audience,
plus current organization/client policy. Transport construction cannot establish
that a supplied resolver qualifies its provider, token audience or group claims.
Production composition and real provider qualification remain mandatory.

Every POST to `/mcp` requires one bearer header. Browser cookies, session IDs,
query credentials, replay event IDs and forwarded-header transport assertions do
not authenticate it. This component currently requires actual request TLS; a
future operator-gateway adapter requires separate qualification. Host matches the
configured origin exactly. A supplied Origin must match; cross-site fetches and
ambiguous Origin headers are rejected. Clients without an Origin still require
bearer authentication.

`identity.NewBearerRequest` supplies a request-owned `CurrentIdentity`. The first
snapshot is used only for principal capacity and its original deadline. Before
releasing the SDK response, the handler rechecks current identity through that
handle. Changed principal, policy, scope or group membership, expiry and original
request cancellation stop delivery. Fresh observations never extend the initial
five-second request limit. Tool adapters must use the same handle in shared
application services, perform workload/artifact authorization before lookup and
retain their independent quota, audit, retention and recovery effect checks.

Composed operations also return a private metadata-delivery deadline. The handler
retains the earliest original value in request-owned state through SDK encoding,
the final identity lookup and the actual socket write deadline. A short workload
permission or recovery lease cannot be extended by another successful identity
check. Expired operation authority returns a generic 503 without metadata or an
authentication challenge; a valid identity is not logged out for that condition.
The deadline is neither a wire field nor reusable authority. Targeted regression
tests reproduce expiry during final identity lookup for both protocol revisions
and check the final deadline on the real TLS response writer.

GET `/.well-known/oauth-protected-resource/mcp` publishes only the exact resource,
configured issuer, `evidence:read` scope and header bearer method. A composed,
enabled capture mutation also advertises `evidence:capture`. This public
metadata contains no evidence and does not contact an arbitrary issuer. OAuth
401 challenges identify that metadata URL; a missing read scope yields a precise
403 insufficient-scope challenge. Provider failures yield a generic 503 without
provider diagnostics, tokens or evidence. No DCR, directory lookup, browser
session replay or anonymous tool access is added.

## Finite transport behavior

The SDK uses stateless Streamable HTTP with JSON responses. There is no sticky
session, event store, long-lived subscription, server-to-client callback or
transport replay. The only accepted protocol methods are initialize,
notifications/initialized, server/discover, ping, tools/list and tools/call.
Unknown tool calls remain protocol errors. Logging, roots, prompts, resources and
subscriptions are unavailable.

The whole request is bounded to five seconds and the original identity deadline,
with corresponding socket read/write deadlines. Input is at most 32 KiB, one
JSON object and depth 32. Duplicate object members, aliased envelope/routing
members, JSON batches, encoded request bodies and conflicting routing headers
are rejected. SDK v1.8.0 validates routing headers only for the newer protocol;
Asservat also rejects a supplied contradictory method/name hint from older
clients without imposing newer mandatory headers on them.

Configured per-process capacity is 1–64 concurrent requests and 1–4 per exact
principal/client, with the latter no larger than the former. The global limit
covers authentication work; per-principal state is bounded by admitted requests.
Capacity stays charged through cancellation until actual handler completion.
These are local transport limits, not distributed collection or disclosure
budgets. Listener connection/header limits and fleet-wide abuse controls remain
separate composition work.

Responses are buffered to a hard 64 KiB before the final identity check. Only the
composed `preview_recording_save` tool uses a fixed 256 KiB SDK frame for its
128 KiB canonical metadata result, preserving both text and structured forms.
The named producer marks that private delivery budget; every other tool,
discovery response and owned evidence reply retains its original ceiling. Flushing
cannot disclose buffered bytes early. The SDK cannot relax HTTP `no-store,
private` or publish session identifiers; its cacheable protocol results receive
zero lifetime and private scope. Once evidence tools exist, their stricter
24 KiB default/32 KiB hard structured envelope and combined representation bounds
must be enforced before this final transport ceiling; the named recording-save
preview uses its dedicated bound. No native evidence is
returned inline through an invented download tool.

## Qualification and dependency review

On 2026-10-11, targeted `go test -race ./internal/transport/mcp` passed, including
actual official clients negotiating both revisions, independent TLS server
instances, current ingress/delivery authentication, empty discovery, metadata and
OAuth challenges, routing ambiguity, request/output bounds, revocation, capacity
and cancellation. `test/results/mcp-boundary-final.log` records that component
run. Targeted `go vet` also passed. This is synthetic loopback TLS qualification,
not real Keycloak OAuth, multi-replica deployment or a user investigation.

Two regressions were reproduced before correction:
`test/results/mcp-boundary-before.log` records contradictory legacy routing hints
being accepted, and `test/results/mcp-alias-before.log` records differently cased
method fields being accepted. Their rejection is covered by the final suite.
The former initial run also contained a test-fixture error: new-protocol metadata
must use SDK namespaced constants, not guessed field names; actual SDK clients
now independently exercise negotiation.

The module change adds the official SDK and four pinned upstream dependencies:
`google/jsonschema-go v0.4.3`, `segmentio/encoding v0.5.4`,
`segmentio/asm v1.1.3` and `yosida95/uritemplate/v3 v3.0.2`. Existing direct and
indirect versions are unchanged. The actual tagged LICENSE files were inspected:
SDK contributions are in the documented Apache-2.0/MIT transition, JSON Schema
and Segment libraries are MIT, and URI Template is BSD-style. `go mod verify`
passed. The targeted pinned `govulncheck v1.8.0` call graph reported no known
vulnerabilities; see `test/results/mcp-boundary-vulnerability.log`. This does not
complete release-wide maintenance, notices, image or security qualification.
The ancillary URI-template/assembly libraries have a smaller release surface;
no claim of active maintenance for every transitive follows from adopting the
maintained official SDK.

Primary upstream sources reviewed on 2026-10-11:

- [Official SDK release and resource-hardening notes](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.8.0).
- [Tagged SDK protocol documentation](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/docs/protocol.md).
- [MCP authorization requirements](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
- [Tagged SDK licence](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/LICENSE).
- [JSON Schema releases](https://github.com/google/jsonschema-go/releases), [encoding releases](https://github.com/segmentio/encoding/releases), [assembly repository](https://github.com/segmentio/asm) and [URI-template repository](https://github.com/yosida95/uritemplate).

## Next composition

Continue composing the registered context subset with protected runtime service
producers, actual acquisition/publication and native download. Register subsequent
implemented operations explicitly against canonical strict schemas and the same
application service used by the console. Do not
expose the entire design catalogue through a generic dispatcher, accept a caller
actor, let annotations authorize effects or substitute fixed fixture data. Current
identity is necessary but is not workload/evidence authority. Tool schemas,
structured/text envelopes, cursor authorization, mutation idempotency, raw grants,
authenticated native-download navigation and real provider/resource mapping need
their own qualification before declaring an investigation flow available.

## Grouped recording Save request window

[ADR-268](../decisions/268-grouped-save-dispatch-window.md) gives `request_capture`
a prospective fifteen-second transport/audit envelope, selected while routing
the original owned bearer request. Other ordinary operations keep five seconds;
evidence-read windows keep twenty. All earlier caller/credential/session ends
remain binding. Group admission keeps its original five-second facts phase and
new manual groups select a fixed StartBy within original ingress end and SQL t0+15s, with all source/processing limits (ADR-269). Old accepted dates and ordinary/singleton five-second builders remain unchanged. Optional encrypted history
follows mandatory start attempts. Continue uses the same operation window and
never changes accepted dates; passive replay does not dispatch.
