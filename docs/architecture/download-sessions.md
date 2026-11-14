# Native download sessions and accounting

C-14/C-07/C-08/C-21 contract for REQ-DLD-002–004 under
[ADR-054](../decisions/054-native-download-protocol.md) and
[ADR-330](../decisions/330-event-driven-system-design.md). Byte delivery is in
[native responses](download-responses.md); caller identity in
[native reader identity](native-reader-identity.md).

## Session

`download_artifact(action=prepare)` creates one SQL `ArtifactDownload` row for an exact
immutable artifact/version, actor/client and absolute deadline. The request
carries an idempotency key: a retry with the same key and request returns the
existing session; a different request under the same key conflicts. States:
Ready, Completed, Failed and Cancelled ([REQ-DLD-003](../../specs/artifact-downloads.md));
terminal states never restart.

Preparation authorizes once ([ADR-311](../decisions/311-operation-authority-recheck.md))
and returns Ready with the native metadata (filename, format, size, SHA-256, ETag,
coverage) from the verified catalog row. Evidence bytes, unwrap keys and tokens
never enter SQL.

## Quotas

Ordinary downloads read existing evidence, use no storage and have no transfer
byte budget or request-count cap ([ADR-335](../decisions/335-usable-by-default.md) D9).
A raw evidence download charges its raw grant's finite parent disclosure pool
(maintainer decision) with one conditional update on that pool row; no
installation-wide lock or row is taken.

Reader capacity is the real cost. Download concurrency defaults to reader
replicas × streams per replica ([download reader deployment](download-worker-dispatch.md)),
and one workload may use at most half of it (fair share on the shared reader);
both are administrator-configurable with these derived defaults. Incident
uploads have priority over downloads in reader scheduling.

A raw download reserves its selected range on the pool at start and records the
actual emitted bytes when it ends; the unused remainder is released then. If
the end is not known (process crash), the reservation is released when the
response's hard deadline has passed, because no writer can emit after it
(ADR-312 original bound). Bytes already emitted
stay counted. Emitted-byte counters are server facts, not proof that a client
stored the bytes.

## Audit

Every prepare, response start, response end and Stop writes one append-only
audit row in the same SQL transaction as its state change; the operation fails
if the row cannot be written. Rows record actor/client, artifact/version, range
and emitted bytes; they contain no native filename, checksum or evidence bytes.
Rows are exported in batches and retained under the common audit retention.

## Stop

`download_artifact(action=cancel)` requires the original actor/client to authenticate
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

## Retention

Catalog lookup and response start use the artifact's stored effective deletion
deadline; a started response is cut off at that deadline
([retention lifecycle](retention-lifecycle.md)). Restore runs with all
workloads stopped ([persistence](../../specs/persistence.md)).
