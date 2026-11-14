# Ordinary context download operations

`ContextDownloadOperations` projects the C-14 download coordinator's views
into the shared canonical browser/MCP envelope. It exposes prepare, get and
Stop.

## Prepare and status

- Prepare authorizes once ([download authority](download-authority.md)),
  creates the download session row with the caller's idempotency key and
  dispatches the work to a [regional reader](worker-startup.md). A repeated
  prepare with the same key returns the existing session. Browser and MCP
  preparation are the same call.
- Native filename, length, SHA-256, ETag and coverage form one verified
  group. Catalog metadata and custody candidates do not supply it. Ready,
  Streaming and Interrupted require it; Completed may keep only terminal
  status after the transfer ends.
- Session state changes are published with `LISTEN/NOTIFY` in the writing
  transaction. The console follows them on its page's Server-Sent Events
  stream instead of repeating prepare; MCP `get` waits server-side for at
  most 30 s and returns on the first change.
- The content route is `/api/v1/downloads/{download_id}/content`. Returning
  that path is not a byte permit: each content GET authenticates the session's
  principal and client and completes authorization before the response
  starts. The started response runs to its original bounds
  ([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md)).

## Stop

`ContextDownloadStopCoordinator` resolves the current actor and client, then
in one SQL transaction:

1. locks the caller's own session row (it cannot stop another principal's or
   client's download),
2. sets the session terminal,
3. inserts the audit row ([operation audit](operation-audit.md)),
4. issues `NOTIFY` on the session channel.

Stop needs no evidence scope, catalog read, retention check or current Pod.
Active byte streams end when the notification reaches the hub and the reader.
Source artifacts are untouched. Byte and transfer charges are released when
the terminal state is committed.

The first Stop for a session stores its idempotency key, request digest,
actor and database timestamp. A retry with the same key returns that outcome;
another key on a terminal session returns AlreadyTerminal with the stored
outcome. The public receipt contains no artifact ID, native metadata or
retention dates. The console clears native state and shows the receipt for
the rest of the page session.

Stop is not delayed by audit export or any object-store operation.

## Admission

Normal and Stop requests have separate process-local concurrency slots and
per-principal limits in both transports, so a saturated normal lane cannot
block Stop. Only schema-valid cancellation enters the Stop lane.
