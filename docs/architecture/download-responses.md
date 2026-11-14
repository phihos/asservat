# Native download responses

C-14/C-20 contract for one native HTTP content response under
[ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md) and
[ADR-330](../decisions/330-event-driven-system-design.md). Session, quota,
audit and Stop rules are in [download sessions](download-sessions.md).

## Start

A content GET is served by the hub replica that receives it:

1. Authenticate the caller once ([native reader identity](native-reader-identity.md))
   and authorize the exact session, artifact and version once.
2. Parse the single range with RFC 9110 `Range`, `If-Range` and `If-Match`.
   A stale `If-Range` yields a full 200 response; a failed `If-Match` yields 412.
3. In one SQL transaction: check session state, stored deletion deadline and
   database incarnation, reserve the selected range on the workload allocation,
   move the session to Streaming and write the response-start audit row.
4. Send headers: `Content-Length`, strong `ETag`, optional `Content-Range`,
   attachment disposition, `Cache-Control: no-store`, `nosniff`.

Any failure before step 3 commits has no effect and emits nothing.

## Bytes

The hub opens one stream to a regional reader over the connector's connection
to the hub ([ADR-330](../decisions/330-event-driven-system-design.md) D2, D4).
The reader is a long-running Deployment; it opens the artifact's keys once per
response, reads frames sequentially, authenticates each frame before passing its
bytes, and streams the selected range back. The hub copies the stream to the
HTTP response. For a whole-file response the reader verifies the whole-file
SHA-256 and withholds the last chunk on mismatch. The hub holds no unwrap keys
and buffers at most one bounded chunk.

## Bounds

The started response reads no further identity, permission, share or policy
state. It ends at the first of:

- completion of the selected range;
- client disconnect or write timeout;
- Stop (delivered by `NOTIFY`, see download sessions);
- the caller's session or token expiry, the session deadline, the artifact's
  access end or stored deletion deadline;
- a database-incarnation change (restore).

Revocation and retention changes reach the stream as events, not by
re-checking per chunk.

## End

One SQL transaction records the emitted bytes, releases the unused reservation,
sets the session to Completed (whole file, exact length, checksum verified) or
Interrupted, and writes the response-end audit row. Interrupted sessions resume
with a new GET and `Range` within their original deadlines. A partial range
never reaches Completed.
