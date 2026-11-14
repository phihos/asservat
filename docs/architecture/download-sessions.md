# Native download sessions and accounting

C-14/C-07/C-08/C-21 contract for REQ-DLD-002–004 under
[ADR-054](../decisions/054-native-download-protocol.md) and
[ADR-330](../decisions/330-event-driven-system-design.md). Byte delivery is in
[native responses](download-responses.md); caller identity in
[native reader identity](native-reader-identity.md).

## Session

`prepare_artifact_download` creates one SQL `ArtifactDownload` row for an exact
immutable artifact/version, actor/client and absolute deadline. The request
carries an idempotency key: a retry with the same key and request returns the
existing session; a different request under the same key conflicts. States:
Preparing, Ready, Streaming, Completed, Interrupted, Cancelled, Expired, Denied,
Failed. Terminal states never restart.

Preparation authorizes once ([ADR-311](../decisions/311-operation-authority-recheck.md)),
then a regional reader verifies the artifact's encrypted manifest and returns its
native metadata (filename, format, size, SHA-256, ETag, coverage). Before that
metadata exists the session exposes none of it; Ready, Streaming and Interrupted
expose the complete group. Evidence bytes, unwrap keys and tokens never enter SQL.

## Quotas

Downloads draw on a per-workload transfer allocation configured by the
administrator. Admission is one conditional update on the affected workload
allocation row (`used + n <= limit`); no installation-wide lock or row is
taken. Concurrency limits per principal and per workload are administrator
settings, not fixed constants, and incident uploads have priority over
downloads in reader scheduling.

A response reserves its selected range at start and records the actual emitted
bytes when it ends; the unused remainder is released then. If the end is not
known (process crash), the reservation is released when the response's hard
deadline has passed, because no writer can emit after it. Bytes already emitted
stay counted. Emitted-byte counters are server facts, not proof that a client
stored the bytes.

## Audit

Every prepare, response start, response end and Stop writes one append-only
audit row in the same SQL transaction as its state change; the operation fails
if the row cannot be written. Rows record actor/client, artifact/version, range
and emitted bytes; they contain no native filename, checksum or evidence bytes.
Rows are exported in batches and retained under the common audit retention.

## Stop

`cancel_artifact_download` requires the original actor/client to authenticate
and remains available after the caller loses download scopes. It is one SQL
transition to Cancelled with its audit row, keyed by the request's idempotency
key; a replay returns the first receipt. The receipt is `Cancelled` or
`AlreadyTerminal` and reveals no other metadata. The transaction issues
`NOTIFY`; the hub replica serving an active response for that session receives
it and closes the stream. Bytes already in transport buffers cannot be recalled.
Stop does not delete the artifact.

## Credentials

Each hub process uses its one SQL login (ADR-222). Table grants and triggers
reject terminal revival, decreasing counters and rewritten scope; no process
has database-owner or schema-creation rights.

## Retention and recovery

Catalog lookup and response start use the artifact's stored effective deletion
deadline; a started response is cut off at that deadline
([retention lifecycle](retention-lifecycle.md)). Effects compare the current
database incarnation in their transaction ([download recovery](download-recovery.md)).
