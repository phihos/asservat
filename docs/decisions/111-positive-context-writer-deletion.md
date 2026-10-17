# ADR-111: Positive context writer completion and audited deletion

- Status: accepted for implementation; external qualification pending
- Date: 2026-10-11
- Requirements: REQ-EVD-001, REQ-EVD-006, REQ-PRV-004, REQ-CAP-004, REQ-DB-005; S-02
- Owners: C-11 execution, C-14 evidence, C-15 privacy

## Decision

Introduce a positive completion protocol for the bounded regional API context
producer and an independently audited deletion checkpoint. Migration 00039 pins
new API executions to `closed-small-context/v1`. Historical executions retain
NULL and cannot be upgraded merely because their stored phase appears complete.

The concrete one-use producer issues a completion only after all four exact
conditional object writes returned success and its handle has joined and closed.
The API executor records that completion atomically with its immutable stored
outcome. SQL keeps the registration, expectation, ciphertext-copy and execution
digests, original completion times and current accepted database incarnation.
The receipt is not a generic caller declaration that a remote writer stopped.

A separately credentialed privacy worker can claim due deletion only for this
persisted positive completion. It inventories and removes all current objects,
versions, delete markers and multipart uploads under the exact attempt prefix,
then inventories again. A successful purge becomes one immutable checkpoint
before the original deletion lease expires. The original successful result can
be replayed after a lost response without extending that lease or repeating an
already recorded purge.

A separate audit role verifies the exact encrypted, signed checkpoint object and
acknowledges its immutable ciphertext receipt. Only then can a distinct finalizer
release the original evidence storage reservation once. SQL guards every new
protocol attempt's transition to `deleted`, including the older generic custody
facet. A private same-transaction finalization marker prevents legacy/direct
roles from using the new checkpoint; a deferred constraint prevents committing
a stranded marker. The supported path always locks recovery before storage.
Recovery, issuer epoch and the accepted PostgreSQL process/database
incarnation remain mandatory at each durable transition.

## Reasons and limits

Cancellation, timeout, a failed PUT, an empty inventory or a historical stored
label cannot prove that a late writer has stopped. Positive acknowledgements
from all four bounded writes and joined local closure establish a narrower,
implementable case. Unknown or failed writers remain charged and need a separate
remote drain/reconciliation protocol. This change does not infer completion for
those attempts, multipart acquisition, node collectors or restored state.

Evidence-byte accounting and control metadata retirement have different proof
requirements. Deletion releases only the original evidence bytes and four copy
slots. Accepted-request, replay, execution, case, download, retention and audit
records remain intact; full/replay control charges remain spent. Finite metadata
and audit cleanup, independent backup checkpoints and restore reconciliation are
still required. No cascade deletion, capacity refund for uncertain work, runtime
activation or new public endpoint is introduced.

See [the implementation contract](../architecture/context-deletion.md) for the
exact ports, trust boundaries, tests and remaining runtime composition.
