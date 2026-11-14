# Storage custody transactions

Scope: C-07 capacity, C-14 evidence, C-15 privacy and C-21 adapters under I-05/I-09; part of REQ-DB-002–004, REQ-CAP-004/005, REQ-EVD-001–003 and REQ-PRV-004. Design follows [ADR-330](../decisions/330-event-driven-system-design.md). The [verification record](../research/custody-foundation.md) and [implementation progress](../implementation-progress.md) hold test results.

## Records

[Migration 00001](../../migrations/00001_custody.sql) defines the storage facet:

- `custody_pool`: accepted backing.
- `custody_allocation`: one workload or service allocation with its byte/object limit and `used` counter.
- `custody_attempt`: immutable attempt identity, operation ID and deadlines.
- `custody_copy`: one row per object (envelope, manifest, index, data), created before any write.
- `custody_event`: transactional outbox rows. Hub processes signal outbox inserts with `LISTEN/NOTIFY` in the writing transaction.

These rows track storage progress. They are not a published artifact or an authorized capture.

`Register` is idempotent by attempt ID (the operation's idempotency key) and a digest of the normalized registration. The same ID with different bounds, deadlines, store, allocation or identities conflicts. A repeated call returns the existing state; a replay after deletion never authorizes another acquisition or key reuse. One artifact identity belongs to one attempt.

Registration charges the allocation with one conditional update and locks no pool row:

```sql
UPDATE custody_allocation SET used = used + $n
 WHERE id = $allocation AND used + $n <= limit RETURNING used;
```

No row returned means `CapacityUnavailable`. The charge covers ADR-048's worst-case data/index ceilings, the 1088 KiB manifest, the 32 KiB envelope and four object slots. Allocations do not borrow each other's space. Allocation limits come from the Helm-rendered configuration; capture clients never choose the allocation ID.

## Integrity and visibility

The writer computes each object's SHA-256 while streaming and sends it as the S3 `x-amz-checksum-sha256` checksum, so the store rejects a corrupted upload. `StoreCopies` records each object's identity, version, length and checksum in one transaction with its outbox event. A stored copy is not a catalog entry, a grant or permission to unwrap or download.

The configured store UUID must match the registration. Absence or a copy on another bucket never releases or publishes this store's charge.

The regional reader checks the envelope, manifest and index before publication ([manifest verification](manifest-verification.md)); data frames are authenticated by their AEAD tag when read. Publication ([context publication](context-publication.md)) requires that verification, the stored deadlines and its `audit_event` row in the publishing transaction; a custody status alone never confers visibility.

SQL holds opaque identities and ciphertext checksums, never evidence bytes, native hashes, plaintext keysets or full manifests.

## Transactions

Queries use pgx v5 with checked-in sqlc bindings and goose migrations. Each hub process uses one SQL login (ADR-222); the database role's grants, not runtime self-checks, limit what it can do. The pool rejects plaintext TLS and more than 32 connections and checks the migration version.

Lock order within a registration is allocation, then attempt. Use `clock_timestamp()` after blocking locks. Statement and lock timeouts are I/O bounds (five-second statements, one-second lock waits); the operation's original deadline is the authority bound. No storage, identity or Kubernetes call runs while a transaction holds a lock.

Serialization and deadlock aborts are retried up to three times. An unknown COMMIT outcome is resolved by looking up the attempt ID; the charge stays until the lookup shows the outcome, then follows it.

## Deletion

Each attempt stores its effective deletion deadline (`delete_due_at`, see [retention lifecycle](retention-lifecycle.md)); a retention change shortens it with one SQL update. A partial index on `delete_due_at` orders deletion work. The deletion worker sleeps until the earliest due row and wakes early on a `NOTIFY` from any update that moves a deadline earlier.

Writers are fenced by their deadline: an upload credential and the attempt's write deadline end before `delete_due_at`, `StoreCopies` refuses after the write deadline, and the bucket's `AbortIncompleteMultipartUpload` lifecycle rule removes abandoned multipart uploads. A claimed deletion row carries a fence number; only the current fence may complete it.

The S3 cleanup adapter lists versions, delete markers, multipart uploads and current objects under the attempt's UUID-derived prefix, aborts uploads, deletes explicit versions (including null versions) and lists again. Each LIST response must carry an explicit `IsTruncated`; a missing value is incomplete, never empty. Missing permissions, malformed responses or remaining entries leave the charge in place and the row due. One pass handles at most 128 entries per inventory API.

Completion releases the charge once (`used = used - $n`), clears receipts and keeps the minimized deleted record for restore suppression. Duplicate completion of the same fence is idempotent; an old fence cannot release. Failures stay due and are retried at the next wake.

AWS documents that [multipart abort may need repeating while parts are in flight](https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html), that [lifecycle rules abort incomplete multipart uploads](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpu-abort-incomplete-mpu-lifecycle-config.html) and that [versioned DELETE creates a delete marker](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html).

## Recovery fence

Effects compare the database incarnation from [ADR-096](../decisions/096-database-incarnation-fence.md) in their WHERE clause, reading it without a lock. A restore changes the incarnation, so later effects fail their check. `setup` seeds the first incarnation.
