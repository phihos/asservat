# Bounded approved context projection

[ADR-206](../decisions/206-bounded-context-projection.md) lets a user inspect saved, approved pod status through the canonical browser/MCP `get_extract(view=fileExcerpt)` and `get_query_result` contracts without downloading it. Queries run on the regional reader (A-READ) and reach the hub over the connector connection ([ADR-330](../decisions/330-event-driven-system-design.md) D2/D4). Limits are in [query capacity](context-query-capacity.md).

## Exact result

The source is the published artifact for `asservat-pod-status/v1`, with the immutable `artifact.ContextProjectionDefinition` digest and no separate native byte ceiling: its closed schema bounds the document to at most 3,437 bytes of JSON (every string at its schema maximum with each code point escaped, the longest RFC 3339 timestamp), which the recipe's 4096-byte reservation covers. Case, capture, target, attempt, store and ciphertext version come from the artifact row, not from the caller. The reader checks the envelope, manifest, native schema and expected format before projecting fields; another format or additional properties fail closed.

Display version `approved-pod-status-display/v1` returns `pod-status.txt` with one line per field in this order:

1. `format`
2. `namespaceUID`
3. `podUID`
4. `resourceVersion`
5. `observedAt`
6. `phase`
7. `ready`
8. `initialized`
9. `scheduled`
10. `runtimeInstances`
11. `running`
12. `waiting`
13. `terminated`
14. `restarts`

Each line is the field name, `: ` and its JSON scalar. Strings use JSON quoting and escaping; integers use decimal notation without exponent. The timestamp is UTC RFC 3339 with necessary fractional precision and no trailing zeros. `True`, `False` and `Unknown` stay strings. The field list follows the collector `statusProjection` and `specs/contracts/pod-status.schema.json`; changing it requires a new display version.

Absent `line_start` is 1 and absent `max_lines` returns all remaining lines; the fourteen-line result is the only line bound. The result is the requested contiguous intersection with the fourteen lines; a start after the last line returns an empty list. There is no pagination cursor. The complete envelope, including the nested `get_query_result` wrapper, fits well within the 24 KiB default MCP result target ([MCP runtime](mcp-runtime.md): one 96 KiB result bound from the common MCP client tool-output limit). `data_class` is `metadata`; it does not claim the identifiers are anonymous.

## Ownership

C-24 owns the query, selection and result values (`internal/domain/analysis`); C-18 owns the coordinator (`internal/application/analysis`); C-03 read authorization; C-14 the reader; C-07 limits; C-08 audit rows; C-20 the browser/MCP mapping; C-21 the SQL, object-store and connector adapters.

| Owner | Port | Contract |
| --- | --- | --- |
| C-24 | `ContextExcerptSelection` | Case/artifact IDs and normalized line range; no source, worker, deadline, key or path. |
| C-24 | `ContextProjectionScope` | Case/capture/artifact IDs, whole-pod target, committed ciphertext version, projection digest, display version, selection and principal/client. |
| C-03 | `ContextProjectionAuthority.ResolveProjectionCurrent(ctx, identity, candidate)` | Checks ordinary target rights before reading the artifact row, then builds the version-bound scope and returns the operation's authorization. |
| C-18 | `ContextProjectionService.BeginExcerpt(ctx, identity, invocation, selection)` | Admits one query and returns the result or a pending handle. |
| C-18 | `ContextProjectionResults.GetQueryResult(ctx, identity, invocation, handle)` | Returns the stored result, or waits server-side (at most 30 s, the ADR-330 D1 MCP wait) for the first change. Never starts another read. |
| C-14 | `ContextProjectionReader.ReadProjection(ctx, scope)` | Runs on the reader: opens the three keysets, decrypts and verifies the source, returns the typed status DTO. |

C-03 builds the scope from the route candidate and, only after ordinary target rights pass, the artifact row, so a caller without rights cannot probe catalog data. It uses `ReadApproved` / `evidence:read` and never requires or grants `evidence:download`. There is no conversion between download authority and query authority.

## Execution

1. `BeginExcerpt` authorizes once (ADR-311), checks the stored retention deadline and processing/locality policy, takes the principal and workload concurrency slots and inserts the query row with its execution deadline and audit row in one transaction (D6). The execution deadline is the scan cap divided by the reader's measured throughput, a minutes-scale value (default 10 minutes, ADR-335 D9), shortened by the artifact's access deadline; the scan cap, not the deadline, bounds the reader's work.
2. The hub sends the read to the region's reader over the connector connection. The reader returns the DTO; the hub stores the formatted result in the query row, releases the slots and `NOTIFY`s.
3. If the result is ready within the request, it is returned directly. Otherwise the response is a pending handle. `get_query_result` waits server-side for the notification; the browser receives it over its Server-Sent Events stream. Neither polls on a timer, and waiting is never charged.
4. The stored result stays available as long as the evidence (ADR-335 D9): until the artifact's retention deadline. Revocation, Stop or a retention cut-off cancels a running query and removes the stored result (D1).

A handle is bound to its principal and client; another actor or client cannot read it. A lost reply is recovered with `get_query_result` on the same handle, which returns the stored result without reading again. A query whose reader outcome is unknown is retried by the hub with backoff under the same query ID (the read is idempotent) until the execution deadline, which then ends it and releases the slots.

Each invocation (initial and `get_query_result`) writes one audit row with tool, case/artifact or query reference, display version and selection — never output lines. A `get_query_result` result is nested under `tool_name=`get_extract(view=fileExcerpt)` and validated against that tool's output schema. Successful and pending data carry `query_observed_at` and `query_expires_at`; both wrappers share timing and request IDs.

The reader holds only the source and projection needed for the response; the hub receives only the approved DTO and has no unwrap capability. There is no disk, PVC or persisted browser result cache.

## Browser

The case evidence screen mounts one view per unexpired pod-status artifact. Mounting performs no query. **Inspect saved status** starts the fourteen-line request; a pending view updates from the page's event stream. The view clears its result on session loss, artifact removal or closure. Native download stays a separate action; an unavailable query never falls back to a download.

## Further projections on the same coordinator

Each reuses the reader, query row, limits and audit rows above and adds no Job, volume or service.

- **Saved syscall views** ([ADR-294](../decisions/294-saved-syscall-projections.md)): fixed summary and event views of saved metadata or argument sources; source/view/filter identity is separate from raw disclosure authority.
- **Raw syscall queries** ([ADR-306](../decisions/306-bounded-saved-syscall-queries.md)): `approved-syscall-query/v1` over saved argument originals. C-03 requires current ordinary/retained rights and an exact `query_artifact(operation=syscalls)` human/client grant; metadata views, download grants and raw shares cannot supply it. Pages of whole events sized to the 24 KiB default MCP result target, continued with a cursor. SQL and audit carry selectors, never argument values.
- **Raw packet summary** ([ADR-304](../decisions/304-transient-raw-packet-summary.md)): one aggregate `approved-raw-pcap-summary/v1` over a raw PCAPNG, authorized by ordinary target/retained rights; `unclassified_packets` counts prefixes without usable headers. No derivative is stored.
- **Saved-packet queries** ([ADR-305](../decisions/305-bounded-saved-packet-queries.md)): `query_artifact(operation=packets)` with tcpdump/libpcap filter syntax compiled by the pinned hub compiler (the compiled program is at most 4096 classic-BPF instructions, `BPF_MAXINSNS`, which satisfies the maintainer's "bounded pcap filters"; the text has no separate cap) and evaluated by the `packets.Filter` VM; typed time and flag selectors; a closed field catalog and a bounded captured-frame prefix. Metadata fields from metadata sources need ordinary rights; any raw original needs an exact `query_artifact(operation=packets)` grant whose use is charged against the parent disclosure pool. The scan visits records in order up to the scan cap, which bounds reader CPU per query; a page is sized to the 24 KiB default MCP result target and continued with a cursor, and its fields come from the closed field catalog. The initial request carries an idempotency key bound to caller, client and normalized input; a replay returns the original query, a changed selection conflicts.
- **Profile summary** ([ADR-291](../decisions/291-bounded-profile-summary.md)): closed `get_extract(view=profileSummary)` over one raw pprof source; a bounded extract with no raw share fallback or download authority.
- **Profile comparison** ([ADR-295](../decisions/295-two-source-profile-comparison.md)): `compare_profiles` over exactly two independently authorized pprof sources (baseline and incident) on the same reader; both native hashes are verified and full aggregation precedes top-N selection. Results use the same `get_query_result`.

## Acceptance

1. Browser and MCP with ordinary evidence-read rights return exactly the fourteen fields and matching line selections from the committed artifact, with no download scope, collector call or live Pod read.
2. Wrong case/artifact/version/native or display projection, extra native fields, malformed values, unpublished/raw/unsupported sources and query/download cross-purpose use are rejected. A reader without target rights cannot probe catalog data.
3. Deny, audience change, retention shortening and processing restriction before admission refuse the query; the same changes while it runs cancel it and remove the stored result.
4. A lost reply is recovered from the stored result without a second read; another actor or client cannot use the handle.
5. Pending results arrive over SSE and the MCP bounded wait without timer polling; concurrent waiters receive the same result.
6. Envelope schema, the MCP result bound, text escaping and browser clearing are validated for both transports.
