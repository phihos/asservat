# Native content delivery

C-14 owns the download session and native stream, C-03 evidence authority, C-02 request identity, C-20 HTTP transport and C-21 the SQL, object-store and connector adapters. Implements REQ-DLD-001/003 for every evidence kind (PCAPNG, cores and companions, JSON projections) under [ADR-330](../decisions/330-event-driven-system-design.md) D2/D4/D5 and [ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md). Session state is described in [download sessions](download-sessions.md).

## Preparation

`prepare_artifact_download` (browser or MCP) carries an idempotency key. In one SQL transaction it authorizes the caller once (ADR-311), checks the artifact's stored retention deadline, charges the workload's transfer budget, inserts the session row with its original bounds (session deadline, `AccessUntil`, byte reservation) and writes the audit row. A retry with the same key returns the same session. It returns the content URL immediately; no Job, worker enrollment or key slot is created.

## Serving bytes

`NewDownloadContentHandler` serves `/api/v1/downloads/{id}/content` and the `/.well-known/oauth-protected-resource/downloads` metadata path, over TLS on the configured host, without forwarded trust, query/body credentials, redirects or CORS. Browser requests use the session cookie with same-origin Fetch Metadata; bearer requests use the pinned resource/issuer resolver. Both require `evidence:read` and `evidence:download` plus current rights to the artifact.

For each GET:

1. Authenticate the principal and client and authorize the session's artifact once, before the response starts.
2. Evaluate `If-Match`/`If-Range`/`Range`. A 304, 412 or 416 transfers nothing and consumes no budget.
3. The hub sends the read request to the region's reader (A-READ, `asservat download-worker`) as a stream on the connector connection ([connector identity](connector-credentials.md)). The reader holds the region's unwrap credential, opens the three keysets, reads the range with the framed cursor ([artifact format](artifact-format.md)) and streams the bytes back on the same connection.
4. The response continues under `DownloadAuthority.Continue`: a local comparison with the original bounds — caller session or token expiry, session deadline, `AccessUntil`, stored retention deadline, Stop and the byte reservation. There are no identity, permission, share or policy reads after the response starts, and no per-chunk, per-frame or per-window checks.
5. Delivered bytes are recorded against the reservation when the response ends; the unused remainder is released.

Range requests resume interrupted transfers; each GET is its own operation. The reader is long-running and scaled by replicas; reads do not depend on live source-workload capacity. Failures after headers abort the stream.

## Stop and revocation

Stop, revocation and retention cut-offs are SQL updates that `NOTIFY` the hub replica serving the response and the reader; both cancel matching streams. A Stop is complete when its SQL row commits; delivery of the cancellation is best effort within seconds.

## Metadata reads

Status reads (`get_download`) are plain SQL reads under the operation's authorization; browsers receive changes over Server-Sent Events, MCP clients through a bounded server-side wait (at most 30 s) that returns on the first change. Status reads are never charged.
