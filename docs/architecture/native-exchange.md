# Native evidence exchange

C-14 moves native evidence bytes between the regional
[download reader](download-worker-dispatch.md) and the hub replica serving the
caller's request (I-13), following
[ADR-330](../decisions/330-event-driven-system-design.md) D2/D5 and
[ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md). The
public response contract is in [download responses](download-responses.md).
Supersedes the owner rendezvous, owner relay and native owner listener of
ADR-074–088, 116, 122 and 288.

## Connections and routing

- Each connector holds one outbound, multiplexed HTTP/2 connection with mutual
  TLS to the hub. Download commands and bytes are streams on it, alongside the
  connector's other streams.
- Reader replicas hold one long-lived HTTP/2 connection to the connector of
  their cluster (combined mode: an in-process call). The connector forwards
  each download stream to a reader with free capacity.
- The hub replica holding a connector's connection records it in a SQL row
  (`connector_connection`: cluster, replica address, connection ID). A replica
  that serves a request for that cluster but does not hold the connection
  forwards the stream to the named replica over hub mTLS. A changed row is
  announced with `LISTEN/NOTIFY`; on reconnect the connector replaces the row.
- All hub, connector and reader certificates come from the installation CA and
  name ordinary Service DNS names. No per-Pod or per-process identity, owner
  registry, EndpointSlice discovery or route proof exists.

## Authority

The hub authorizes the public request once (ADR-311) and, for content,
creates the download operation row in the same transaction as its start audit
row and byte reservation. The operation ID is the idempotency key for the
stream. The command sent to the reader names only the operation ID, artifact
version and byte range.

After the response starts, nothing is rechecked per frame, chunk or hop. The
stream ends at its original bounds (ADR-312): caller session/token expiry,
session deadline, `AccessUntil`, effective retention cut-off, Stop, recovery
incarnation change or exhausted reservation. Stop and retention changes are SQL
transitions announced with `LISTEN/NOTIFY`; the hub replica serving the stream
cancels it, which resets the stream to the reader.

## Preparation and content

The reader is the only participant that unwraps keys; the hub and connector
forward the decrypted native bytes but never hold keys, and collectors stay
wrap-only. For one operation the reader obtains the artifact's data, index and
manifest keys from the key service (see
[local key service](local-key-service.md)), keeps them in memory for
the stream's lifetime and clears them when it ends.

- Preparation reads the artifact, verifies it, computes its native facts
  (length, SHA-256, filename) and returns them to the hub, which stores them
  with the download. Later metadata reads use the stored facts and never
  decrypt again.
- Content decrypts and sends exactly the requested range. Each frame's AEAD
  tag authenticates it; a failing tag ends the stream with an error.

## Frames and flow control

- Command and control frames are at most 64 KiB; data frames at most 1 MiB.
- HTTP/2 flow control provides backpressure end to end. Each hop holds at most
  one pending data frame; a slow client slows the reader, not memory.
- The reader ends a successful stream with `Done` carrying the byte count.
  Clients use no retry-enabling headers and follow no redirects; a failed
  stream is never replayed automatically.

## Outcome

The hub is the final writer to the caller and therefore knows the bytes it
handed to the transport. When the response ends it writes one outcome audit
row and settles the reservation to the bytes delivered, in one transaction:

- Completed: `Done` received and the full range written and flushed.
- Interrupted: stream reset, reader loss, caller disconnect or a bound ended
  it; actual bytes are charged and the rest released.

A retry after an unknown outcome looks up the operation ID. No charge stays
spent because an outcome was uncertain. An HTTP flush does not prove that the
client saved the file; clients verify the SHA-256.
