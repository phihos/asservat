# ADR-282 — HTTP header projection (S-04 increment 13, slice 1)

Date: 2026-11-02. Status: accepted (agent decision); implementation in slices.
Requirements: REQ-NET-004 (`httpHeaders`, `http-response-headers/v1`,
SC-NET-004), REQ-AUT-006, ADR-248 (header-only packets), ADR-249
(individual approval), ADR-261 (metered observation), ADR-279 (manual finite
raw packets).

## Context

`httpHeaders` is a specified first-release profile: plain HTTP/1 method,
status, Content-Type and Content-Length, never URLs, Host, bodies or
credential headers. Acquisition reads payload bytes, so it is SensitiveRead
even though the output is an extract. The node's tcpdump gadget already
delivers frames with their original wire length for the other packet
profiles; what was missing is a bounded user-space step that reassembles TCP
and frames HTTP/1 without retaining anything outside the projection.

## Decision

1. Manual first, like ADR-279: one finite `httpHeaders` packet action per
   manual capture (`onTrigger`, `before: 0s`, `after` at most 15 s) with a
   required packet filter, individual approval (SensitiveRead acquisition)
   and observation metered from the approved ad hoc grant pool before any
   parsing. The artifact is the existing `httpHeaders` native type
   (`http-response-headers/v1`, JSON) with data class `extract`; the native
   type's verifiable class list is aligned when planning is wired (slice 2).
2. Reassembly and framing use maintained libraries only: gopacket layers and
   `gopacket/reassembly` for TCP, `net/http` (`ReadRequest`, `ReadResponse`),
   `httputil.NewChunkedReader` and `net/textproto` for HTTP/1. No hand-written
   packet or HTTP parser, no Lua, no custom eBPF. Package:
   `internal/adapters/httpheaders` (C-23).
3. Each direction is parsed in a coroutine (`iter.Pull`) fed synchronously
   from the assembler, so reassembled bytes live only in gopacket's bounded
   out-of-order pages and one 4 KiB bufio buffer per direction. Bodies and
   trailers are read through and discarded; the net/http body reader is not
   used because its trailer parsing is unbounded.
4. Bounds are the profile values, validated against the spec maxima (1,024
   flows, 32 KiB header block, 256 KiB per flow, 16 MiB total, 30 s idle):
   the stream factory admits a flow only from a client SYN and below the flow
   cap and keeps no state otherwise; per-flow and total out-of-order pages are
   derived from the byte bounds; reader state (buffers and in-flight header
   blocks) is charged to a shared counter holding the other half of the total;
   idle flows close through `FlushCloseOlderThan`; at most 32 pipelined
   requests wait per flow; records are capped so the document fits the
   16 MiB native limit.
5. The engine snaplen stays 1500. A frame whose captured TCP payload is
   shorter than its IP length is a gap: that direction stops and the gap is
   counted, no bytes are guessed. Whether 1500 loses material coverage (for
   example to GRO-sized frames on veth) is measured natively before any
   change.
6. Unsupported traffic is visible, never parsed as something else: midstream
   flows, TLS (first byte 0x16), HTTP/2 prior knowledge and h2c, Upgrade and
   CONNECT tunnels, malformed framing, header/budget/pipeline bounds and
   unpaired responses each have a counter. Approved values pass fixed checks
   (status 100-599, a single digits-only Content-Length, a single parseable
   Content-Type reduced to its media type and a registered charset); any
   other value is dropped and counted.
7. Deferred: the ongoing ring, Saves, live watch and enabling the builtin
   `http-headers/v1` capture profile.

## Complexity gate

1. Benefit: a specified first-release capability; no workaround exists
   without raw payload approval. 2. Not a reopened risk. 3. Typical plain
   HTTP/1 service-to-service traffic. 4. Precedent: gopacket's reassembly
   examples and tcpflow-style sniffers. 5. No new privilege, credential or
   network access; the existing gadget and grant are reused. 6. No fallback
   state: unsupported input only stops a direction. 7. No configuration
   beyond the schema's profile fields. 8. Depends on gopacket v1.7.4 (already
   a dependency) and the standard library. 9. Memory bounded by 16 MiB of
   reassembly plus the output limit per capture; CPU bounded by the node
   profile. 10. Disabling: the profile is unavailable unless a manual capture
   requests it. 11. Documenting the limitation instead would leave a
   specified profile unimplemented.

## Implementation (slice 1)

`httpheaders.NewProjector(limits, started)`, `Add(frame, wire, at)` and
`Close(ended, lost)` return the projection and counters; `Projection.Encode`
is the canonical JSON. Records have the `get_http_headers` record shape
(timestamp, method, status, headers, partial); requests without a final
response become partial records. Unit tests cover the EXP-03 synthetic
corpus and every bound; `FuzzProjector` checks bounds, state release and that
a secret marker in credentials and bodies never appears in the output.
Planning, node and download wiring follow in later slices.

## Implementation (slice 3: node execution and publisher recheck)

The node runs an `httpHeaders` work item only as a metered finite
observation with `Raw.Snaplen` 1500: each frame is charged to the
observation meter, the hub-compiled program (proven by
`packets.CheckPrefixProgram`) selects frames exactly as for header and raw
recordings, and matching frames feed the projector. The native output is the
projection, at most the recording's output cap: `Projection.EncodeWithin`
drops the latest records and counts them as `records_dropped`. Limits below
the parser's floors are refused (`WorkUnknown`) before budget, observation or
engine use. Frame counters keep their PCAPNG meaning: `Seen` is every
delivered frame, `Filtered` the frames the program refused, `Retained` the
frames handed to the projector and `WireBytes` their original lengths; the
projector's own accounting stays in the document's counters.

The publisher rechecks the stored document in the verification read
(`httpheaders.NewProjectionCheck`): strict decode without unknown fields,
byte-identical canonical re-encoding (no duplicate keys, whitespace or
escapes), format/protocol, the accepted limits, the recording's output cap,
record times inside the document's window in order, projected methods,
statuses and only `content-type` then `content-length` whose values the
projector's own checks leave unchanged, and matching record counters. Record
times are node clock values and are not compared with the connector's
manifest window. The hub collect loop lists `httpHeaders` executions.

## Implementation (slice 4: get_http_headers boundary)

`get_http_headers(case_id, artifact_id, cursor?, limit?)` is a shared
browser/MCP read in the normal audited lane (`context-input/v1`, five-second
request window, migration 00120). The runtime contract is the canonical one
without the `pending` branch: one synchronous page of at most `limit`
(default and maximum 100) records, `data_class: extract`, one provenance
entry (artifact ID and verified ciphertext-copy version), the fixed
SensitiveDataHandling notice, `truncated: false` and `next_cursor` either
null or `<next record index>:<first 16 bytes of the projection SHA-256, hex>`.
The cursor is an unkeyed index into an immutable, already authorized
document: each call reauthorizes, a forged index reaches nothing paging
would not, and a cursor of another document, beyond its end or malformed is
`InvalidCursor`, judged only after current read rights.

C-18 `HTTPHeaderReads` resolves the identity (`evidence:read`), takes the C-03
`HTTPHeaderReadAuthority` (ReadApproved, original audience, retained policy,
effective access date; only a published `httpHeaders` extract of exactly
`http-response-headers/v1` is valid), reads one page through the C-14
`HTTPHeaderPageReader` under the earliest identity/authority/access bound,
then reauthorizes and rechecks the identity before returning. The reader's
contract is `httpheaders.ReadPage`: the full publisher recheck of the stored
document, its SHA-256 as projection digest, the exact requested slice and
the gap report. Stop counters count flow directions, so `dropped_flows`
(no SYN seen, TLS, HTTP/2) and `incomplete_flows` (stopped after parsing
began) are upper bounds on flows; frame losses, output drops and dropped
values appear only as fixed `coverage_gaps` text. The presentation serializes
the longest prefix that fits the 24 KiB response and continues the cursor
after the last delivered record; nothing is skipped. Every refusal other than
a cursor is the same nondisclosing `NotAvailable`.

The operation is advertised only when an installation composes the service
(`NewInvestigationHTTPHeaderOperations`). No production C-03 authorizer or
C-14 regional page reader exists yet: the existing approved-read path
(ADR-206 query ledger, projection worker, native wire DTO, key slots and the
4 MiB read-work profile) is pinned to the 4096-byte pod-status metadata and
must be generalized to a 16 MiB recording extract, with measured cost, before
the tool can be enabled. Raw packets never reach this path.

Complexity gate: 1. A specified first-release read; without it an approved
extract is reachable only by download. 2. No reopened risk. 3. Typical
HTTP/1 investigations. 4. Mirrors get_file_excerpt/get_case. 5. No new
privilege; reads stay behind current ordinary rights. 6. One refusal state
plus InvalidCursor. 7. No configuration. 8. None outside Asservat. 9. One
bounded page per call; the regional read cost is part of the pending
composition. 10. Unadvertised unless composed. 11. Download alone would not
meet REQ-MCP-005's bounded agent read.

## Implementation (slice 5, part 1: read authority and worker page)

The approved-read path now has a closed second source. `analysis.ProjectionSource`
admits exactly the pod-status metadata context or an `httpHeaders` extract
(`http-response-headers/v1`, evidence type `packetCapture`, the one-frame
`RecordingNativeLimit`, no manifest projection digest). `ContextProjectionScope`
and its candidate carry `NativeType` and an `HTTPHeaderWindow` (start, limit,
cursor binding) as a selection union with the line selection; both fields are
omitted when zero, so stored pod-status queries and decision digests keep their
bytes. The catalog evidence read, processing facet, query fence and
C-03/C-14 source checks use this source instead of the pod-status pins, so a
pod-status scope never accepts an extract and the reverse.

C-03 `HTTPHeaderReadAuthority` implements `CurrentHTTPHeaderRead`: identity
with `evidence:read`, current recovery, the private case route
(`ResolveProjectionRoute`), then the unchanged `ContextProjectionAuthority`
facets (ReadApproved permissions, shares, recorded reviews, audience,
retained policy origins, environment, all repeated after blocking reads) for
the extract source. The decision covers the document; its bound window is the
first page.

The acquisition worker's branch is `evidence.ReadHTTPHeaderPage`: an artifact
opened with the batch's key authority is read whole as its single frame,
rechecked and paged by `httpheaders.RecordingPage` (the publisher's
`RecordingLimits`, moved into the adapter), the plaintext is cleared and only
the page leaves; its projection digest must equal the manifest-authenticated
native SHA-256. An invalid cursor stays distinct from other refusals.

Remaining before the tool is advertised: the query ledger migration
(`get_http_headers` in the query tables and intent checks, the extract scope
keys, `context-query-input/v1` audit input instead of the slice 4 lane, and a
per-page read cost of one frame — `NativeWindowReadWork(httpHeaders)` — rather
than the 4 MiB pod-status profile, so one page costs one worker Job), the
result union through the regional read, native wire (a page payload bounded
below the 64 KiB control frame; records beyond the 24 KiB response are never
delivered, so the worker sends the longest fitting prefix) and hub decode,
`HTTPHeaderReads` as Begin (`pending` + query id) plus a `get_query_result`
branch, the restored canonical `pending` branch in the generated schema with
browser OpenAPI parity, and composition in `newPublicProjection`.
