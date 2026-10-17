# Browser and MCP context operations

C-20 now maps the same C-09 [context investigation](context-investigation.md)
and progress services into browser and MCP operations. This implements transport
composition for REQ-GDE-001, REQ-MCP-001/004 and the S-02 diagnostic. It does not
enable a public listener, supply production service dependencies or qualify the
complete execution/publication/download workflow.

The implemented subset is deliberately explicit: `list_diagnostics` accepts an
ordinary named workload reference; `preview_capture` accepts that reference,
`pod-status/v1` and an optional positive requested retention in seconds;
`request_capture` accepts the original preview ID and idempotency key;
`resolve_capture_request` accepts that same pair to resolve or close an uncertain
request; and `get_capture` accepts the capture ID. The canonical broader product contracts
remain required future work. Unsupported reason text, sharing, history, profile
composition, diagnostic handles and expanded submissions are rejected, never
silently discarded or mapped to this narrower diagnostic.

`scripts/investigation-schemas.py` derives this subset from the canonical
contracts. Each tool has local schema references and closed input/output
validation; no runtime schema fetch or dynamic tool registration occurs.
`make investigation-schema-check`, included in `go-check`, rejects drift.
The shared wire validator rejects duplicate/case-aliased keys, excessive nesting,
trailing documents and invalid numeric/null values before a service call. The
same approved JSON result is returned through either transport. Metadata is
bounded to 24 KiB so MCP can include both structured and compatibility-text
copies within its existing 64 KiB response ceiling.

## Review and acceptance

Diagnostic listing performs current passive checks without creating preview
rows, generating capture IDs or reserving work. Preview names the selected Pod
and its actual owner, distinguishing explicit Pod selection from lexical choice
among eligible replicas. It includes lifecycle, impact/data-handling assessment,
relative retention and the server-owned preview expiry. Neither a diagnostic
listing nor successful planning makes collection available.

Protected runtime composition supplies an explicit collection-enable switch,
independent of current caller rights. Missing complete execution/publication
composition must leave it disabled. In that state, the browser receives a
specific blocker, previews report `capture_enabled: false`, and MCP omits the
collection mutation from discovery. Resolution remains available with
`evidence:read`, current identity/recovery and exact original actor/client.
Closing an own unaccepted preview returns no target metadata and needs no target
entitlement; returning an accepted receipt still requires current original-target
read rights. An unreadable accepted capture stays unresolved, never falsely closed.
Enabled collection requests still require `evidence:capture` and
all ordinary admission checks. An annotation or client field cannot enable it.

`request_capture` reports `phase: Accepted` as a transaction receipt. This does
not guess that an old retried request is still Pending or that evidence exists.
The caller follows `get_capture` for actual authorized progress. No operation
automatically creates a replacement preview or key after a lost reply. Errors
preserve uncertainty and current rights; raw provider/SQL/Kubernetes errors and
pre-eligibility target-existence distinctions never reach the client.

The browser request and resolution require an `Idempotency-Key` header equal to
the original body key. Resolution acknowledges exactly an accepted receipt or
durable closure; closure cannot cancel accepted work. Its successful envelope
contains no warnings, provenance, pagination or other extra disclosure. The UI
requires acknowledged closure before editing a replacement request and never
automatically submits one. A lost resolution reply preserves the original pair.
The MCP preview navigation link opens a fresh browser review at `/captures/new`;
it does not transfer a client-bound MCP preview into browser submission authority.
Capture navigation uses the same-installation `/captures/<UUID>` route with no
credential or preauthorized evidence access in the URL. Independently authorized
case links may be omitted without hiding otherwise authorized capture progress.

## Transport boundaries

Browser operations use exact-origin TLS, the existing private session cookie and
session-bound CSRF on every POST, including metadata operations. MCP uses its
independently pinned bearer resource. Both create request-owned current identity,
retain the original at-most-five-second request deadline and recheck identity
after service work and output validation. Neither transport reads SQL or decides
workload/evidence permissions. The browser bounds global requests and concurrent
requests per current principal; it never extends socket lifetime past its original
request or session observation. Each successful service result also carries its
earliest original permission/recovery/read deadline privately. The shared
presentation layer and both transports preserve it through final identity
checks, encoding and socket writes. A still-valid identity cannot extend an
expired permission observation; no metadata is delivered after that bound.
If the final identity check returns a still-shorter deadline, that deadline also
restricts the actual socket write in both transports; successful revalidation
does not restore an earlier, longer interval.
The deadline is never serialized into a credential or persisted for reuse.

`NewContextHandler` registers only these implemented tools with the official MCP
SDK. `NewHandler` remains a valid empty boundary. The low-level SDK registration
uses the shared validator rather than generated permissive Go struct decoding.
Tool annotations do not authorize mutations. No subscriptions, client callbacks,
input-required state, evidence resources, server prompts or arbitrary proxying
are introduced.

## Verification scope

Focused race tests in `context-operations-shared-unit.log` cover canonical wire
mapping, disabled mutation, scope checks, bounded local schemas, unsupported
feature rejection, API execution-class review and retention mapping. Actual
loopback TLS browser/MCP tests cover CSRF, conflicting/duplicate idempotency
headers, current identity loss after acceptance, disabled discovery, both SDK
protocol revisions and structured results. Their service data is explicitly
synthetic test input, not production authorization or real capture qualification.
Repository/native and console results are recorded in
[implementation progress](../implementation-progress.md) after coordinated
source freezes.

Protected capability/storage producers, authorized friendly target discovery,
encrypted reason creation, execution/result provenance, publication, native
download and installation composition remain required. These registered service
adapters do not establish those missing authorities or complete S-02.
