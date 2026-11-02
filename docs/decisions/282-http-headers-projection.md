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
