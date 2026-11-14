# Browser and MCP context operations

C-20 maps the C-09 [context investigation](context-investigation.md) and
progress services into browser and MCP operations for REQ-GDE-001,
REQ-MCP-001/004 and the S-02 diagnostic.

The subset: `list_diagnostics` takes a named workload reference;
`preview_capture` takes that reference, `pod-status/v1` and an optional
requested retention in seconds and returns the resolved plan and its digest;
`request_capture` takes the plan digest and an idempotency key; `get_capture`
takes the capture ID. Unsupported reason text, sharing, history, profile
composition and expanded submissions are rejected, never silently dropped.

`scripts/investigation-schemas.py` derives this subset from the canonical
contracts; `make investigation-schema-check` rejects drift. The shared wire
validator rejects duplicate or case-aliased keys, excessive nesting, trailing
documents and invalid values before a service call. The same JSON result goes
to both transports. Metadata is bounded to 24 KiB so MCP can carry structured
and text copies within 64 KiB.

## Review and acceptance

Listing and previewing are dry runs (ADR-330 D9): they create no rows, IDs or
reservations. A preview names the selected Pod and its owner, distinguishing
explicit Pod selection from lexical choice among eligible replicas, and
includes lifecycle, the impact/data-handling assessment and relative retention.

A Helm value enables collection. While disabled, the browser shows the
blocker, previews report `capture_enabled: false` and MCP omits the
collection mutation from discovery. Enabled requests require `evidence:capture`
and all admission checks.

`request_capture` either accepts the plan whose digest it carries or reports
what changed. It returns `phase: Accepted` as a receipt; the caller follows
`get_capture` for progress. After a lost reply the client retries with the
same key and receives the stored outcome (D7); the server never creates a
replacement key. Errors expose no raw provider, SQL or Kubernetes text and no
target existence before eligibility.

The browser request requires an `Idempotency-Key` header equal to the body
key. The MCP preview link opens a fresh browser review at `/captures/new`; it
transfers no MCP authority. Capture navigation uses `/captures/<UUID>` with no
credential in the URL.

## Transport boundaries

Browser operations use exact-origin TLS, the session cookie and session-bound
CSRF on every POST. MCP uses its bearer resource. Each request authorizes once
([ADR-311](../decisions/311-operation-authority-recheck.md)); ordinary HTTP
timeouts bound I/O, and no validity deadline is carried into encoders or
socket writes. Neither transport reads SQL or decides permissions. The
browser bounds global and per-principal concurrent requests.

`NewContextHandler` registers only these tools with the official MCP SDK,
validated by the shared validator. Tool annotations do not authorize
mutations. No client callbacks, input-required state, evidence resources,
server prompts or arbitrary proxying exist. Progress is delivered over SSE in
the browser and by a bounded server-side wait in MCP `get_capture`.
