# Context evidence deletion

Part of REQ-EVD-006 and REQ-PRV-004 for the four-object regional API context
artifact. Retention deletion is a maintainer requirement; this is its
mechanism.

## Producer completion

`evidence.StoredContextCloser.CompleteStored` succeeds only after all four
`PutSmall` responses, exact copy receipts and closure within the write
interval. Closing disables further writes. Repeated completion returns the
original stored and closed times; a partial or failed handle cannot complete.
The runner records the stored outcome and closed writer in one transaction
keyed by the capture's operation ID, so a retry returns the same record.

## Deletion

Each artifact row stores its effective deletion deadline (ADR-330 D12). The
hub worker keeps one timer to the earliest due deadline from an index;
retention shortening updates the deadlines in one statement and wakes it with
`NOTIFY`. For each due artifact the worker:

1. Claims it with `FOR UPDATE SKIP LOCKED`, so replicas never work on the same
   artifact.
2. Deletes every object version, delete marker and incomplete multipart upload
   under the artifact's prefix.
3. Verifies absence with one LIST of the prefix.
4. In one transaction marks the artifact deleted, removes its case locator,
   releases its storage charge and writes the audit row (D6).

A failed or uncertain step leaves the artifact due and charged; the next
wake-up retries it. Deletion does not depend on the departed requester's
rights. Bucket lifecycle rules (`NoncurrentVersionExpiration`,
`AbortIncompleteMultipartUpload`) are the backstop for objects a crash leaves
behind.

The worker uses the hub worker's single SQL login and the region's
evidence-delete credential. No lease, second inventory, signed deletion
record or separate finalizer credential is used.

Other capture mechanisms, local copies, PVCs and backup horizons follow the
same deadline-driven pattern through C-15.
