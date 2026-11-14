# Operation audit

C-08 owns audit persistence; C-20 produces the canonical operation projection
and invokes C-09/C-16 services. Implements REQ-AUT-005 and the audit parts of
REQ-DB-004 under ADR-330 D6. Supersedes the encrypted intent/outcome object
pairs, finite audit accounts and deletion certificates of ADR-110/111/112/115.

## Audit table

Audit records are rows in one append-only, time-partitioned PostgreSQL table,
`audit_event`. Each row holds: time, server-generated request ID, principal
(issuer and subject) and registered client, normalized operation name, keyed
argument digest, case/artifact/share/grant/session IDs, decision and closed
reason, operation ID (idempotency key), output size and digest, and trace ID.
Raw arguments, tokens, free-text reasons, log contents, memory or packet
fields never enter a row. Arguments whose values could be guessed are covered
by an HMAC with a dedicated, rotatable audit key; the HMAC key is not a
wrapping root.

The hub process's SQL login may INSERT and SELECT but not UPDATE or DELETE
rows. Partition maintenance runs under the migration owner. Creators recorded
in a row are immutable audit actors; no controller, group or later editor
replaces them.

## What is written

A security-relevant operation writes its row in the same transaction as its
effect. If the row cannot be written, the transaction fails and no effect,
disclosure or start happens. No separate acknowledgement step exists.

- **Mutations** (grant/share/policy changes, capture requests, Stop,
  retention and processing decisions): one row in the mutating transaction.
- **Intrusive starts:** one row in the admission transaction that commits the
  start; the terminal outcome is a row in the transaction that records the
  outcome. An unknown outcome is resolved by looking up the operation ID
  (ADR-330 D7).
- **Evidence disclosure** (metadata reads, query results, downloads): one row
  with the result digest, committed before the first result byte is sent. A
  client disconnect afterwards leaves delivery unknown; the row never claims
  receipt.
- **Authorization denials, invalid input and unknown tools after
  authenticated admission:** one row. The requested tool name and input are
  covered only by the keyed digest.
- **Unauthenticated, CSRF or pre-admission overload failures:** no
  individual row; fixed saturating counters and rate-limited logs record them,
  so log volume does not grow with attack traffic.
- **Fail-closed revocations and denials** take effect even if the audit
  insert fails; the hub retries that row from the revocation's own committed
  state and never undoes the denial.

Ordinary unauthenticated protocol traffic (handshake, discovery, list, ping)
is not an application operation. MCP status tools that wait server-side are
audited once per call, not per wake-up.

## Ingress handling

`presentation.AuditedOperations` assigns one server request ID per public
invocation; callers cannot supply it. Retries of a mutation reuse the
original business operation ID, so they return the existing outcome and add
no second effect. Error responses never echo submitted IDs and never forward
SDK error text. A private typed classification (denied, unsupported, invalid,
provider failure) is recorded in the row; it is not a wire field.

## Export and retention

An exporter reads committed rows in order and writes batches to an object
store bucket with Object Lock, or to a SIEM. Export is asynchronous and never
blocks an operation; its cursor is a committed row position.

Audit retention follows the administrator's audit-metadata maximum
(administrator-enforced retention, a maintainer decision; specs/privacy.md). Retention drops whole partitions whose newest row is past
the maximum. The pgBackRest `repo-retention-full` setting and WAL archive
retention MUST NOT keep backups longer than the audit retention window;
backups are the only other copy, and expiring them is how audit rows leave
managed storage. Exported copies are outside Asservat's deletion and follow
the receiving system's retention.

## Capacity

Audit uses the hub process's ordinary connection pool. There is no audit
semaphore, prepaid account or reserved audit capacity. Audit volume is bounded
by authenticated admission and per-principal rate limits at ingress (storm
protection, ADR-335 D8; defaults derive from cluster size).
