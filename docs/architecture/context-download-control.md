# Context download control

C-14 `ContextDownloadCoordinator` prepares and reports native downloads of
approved pod-status evidence (REQ-DLD-002–004, S-02). Every evidence kind uses
the same path; the mechanism supplies its native format.

## Prepare

`prepare_artifact_download` carries an idempotency key bound to the exact
artifact. One authorization per operation ([ADR-311](../decisions/311-operation-authority-recheck.md))
covers identity, whole-pod download rights, retained audience, stored
retention deadlines and environment restrictions. The artifact locator gives
routing only and discloses no native metadata.

One SQL transaction then reserves the transfer budget on the workload's
counter, creates the session row with the key and writes the audit row (D6).
A retry with the same key returns the existing session; the same key with a
different artifact conflicts. A failed reservation releases nothing because
nothing was charged. A missing regional reader denies before any reservation.

The hub forwards the prepared session to the regional reader (A-READ) over
the cluster's connector connection ([ADR-330](../decisions/330-event-driven-system-design.md) D2/D4).
The reader reads the committed manifest, unwraps with its own credential and
returns the native metadata: format, length, full SHA-256, coverage and
filename. No Job, certificate or key slot is created per download.

## Status

Session state changes (Preparing, Ready, Streaming, Interrupted, Completed,
Cancelled, Failed, Denied, Expired) are written to SQL and signalled with
`NOTIFY`. The console receives them over its SSE stream; MCP
`get_artifact_download` waits server-side up to 30 s and returns on the first
change. Clients do not repeat prepare requests to make progress.

Status reads are MVCC selects under the operation's authorization. The reader
keeps the session's native metadata for the session lifetime; status never
re-decrypts evidence. If the reader lost it, status reports unavailable, never
a placeholder hash. SQL stores no native filename or checksum.

Terminal sessions stay terminal. An elapsed nonterminal session reports
Expired. Status returns the stored `AccessUntil` and deletion deadline; it does
not extend any session, retention or authority bound.

## Bytes

The content GET authenticates the session's principal and client and
authorizes once before the response starts. The reader streams the native
bytes over the connector connection; the started response then continues to
its original bounds (session deadline, `AccessUntil`, retention cutoff, Stop,
byte reservation) without further identity or permission reads
([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md)).
Stop and retention cut-offs reach the stream as events.

## Storage

Sessions are rows in the existing SQL download facet of the hub's single SQL
login. Released or unused transfer budget returns to the workload counter
when the session ends.
