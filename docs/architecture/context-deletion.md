# Positive context completion and audited cleanup

[ADR-111](../decisions/111-positive-context-writer-deletion.md) adds a narrow
cleanup path for the four-object, at-most-4096-byte regional API context artifact.
It implements part of REQ-EVD-006 and REQ-PRV-004. It does not complete general
writer fencing, managed-copy deletion, finite metadata retention or S-02.

## Producer-owned evidence

`evidence.StoredContextCloser` extends the existing prepared producer with
`CompleteStored`. `ContextProducer` serializes acquisition writes and closure
with the same mutex. A successful completion requires all four `PutSmall`
responses, exact bounded copy receipts, an unexpired write interval and joined
closure. Closing disables future writes and drops the producer's encoder/key
references; it does not promise Go heap erasure. Repeated completion returns
identical original stored/closed times. An unused, partial, failed or uncertain
handle cannot yield positive completion. No retry performs another PUT.

The regional API runner requires this capability before starting. It pins the
writer protocol when preparing its one immutable execution. Historical protocol
absence fails closed; it cannot authorize another capture. The successful path
closes the actual producer before calling `RecordAPIStoredCompletion`. Its
purpose-specific SQL facet records the immutable stored result and writer
checkpoint in one transaction, with exact accepted registration/expectation,
process/start, copies and current recovery. Generic `RecordAPIOutcome` cannot
record a new-protocol successful store without that checkpoint.

Migration 00039 requires the protocol for new execution inserts and forbids any
protocol rewrite. Historical NULL rows remain historical. A deferred constraint
checks that each new-protocol stored transition has its matching checkpoint.
Writer completion is INSERT-only, and requires the exact persisted execution,
registered write interval, accepted issuer and current database incarnation.
Runtime roles cannot rewrite or delete it. This trusts the dedicated producer
and execution role, not a public wire DTO or an arbitrary boolean proof.

## Bounded deletion and independent acknowledgement

`privacy.ContextCleaner` uses separate cleanup, audit and finalization ports.
`postgres.ContextDeletions` is constructed independently for each narrow SQL
credential. Cleanup does not depend on a departed human retaining evidence
rights; current installation recovery and exact accepted attempt scope remain
required. It is not a public evidence lookup interface.

The cleanup facet locks recovery, permission root, storage pool, workload
allocation and attempt in the established order. It requires the persisted
positive writer checkpoint, effective access cutoff and no live deletion lease.
It then grants one thirty-second lease with a new fence. The concrete
`CustodyStore` checks the configured backend identity and bounded complete
version, delete-marker, multipart and current-object inventories. A second full
inventory must show absence. Truncation, unavailable permissions, malformed
responses and unknown deletion results retain the obligation.

A positive purge is recorded only before that exact original lease expires.
The adapter rechecks it after all blocking locks and after the final recovery
read. The immutable checkpoint binds root, capture, attempt, store, registration
and writer digests, original fence/purge time, issuer epoch and PostgreSQL
process/database identity. It contains no native content, native checksum,
credentials, user reason or group claims. Unknown SQL COMMIT results permit
exact lookup of that checkpoint, never a made-up success or storage refund.

`ContextDeletionObjects` writes a purpose-separated signed/encrypted record at
`context-deletion/v1/<root>/<attempt>/record`. Conditional creation and exact GET
allow the independent verifier to reuse an already committed object. The
ciphertext receipt is at most 128 KiB and is immutable after acknowledgement.
The signature purpose is `asservat-context-deletion+jws`; verification checks
both its exact typed record and authenticated encrypted contents. It cannot
reuse a lifecycle signature or move a record across attempts/incarnations.

Only the separate audit credential can acknowledge the exact verified object.
Only the finalizer can then atomically release the original evidence reservation,
clear copy receipts and mark custody deleted. Concurrent finalization replays
release once. A new-protocol attempt cannot bypass this requirement by invoking
the generic custody finalizer or directly updating `custody_attempt.state` with
another runtime credential. Fixed-source SECURITY DEFINER trigger functions use
an explicit `pg_catalog,pg_temp` search path, qualified application relations and
no public EXECUTE grant. The generic facet refuses protocol-pinned attempts before storage locks. Only
the dedicated finalizer can set a transaction-bound `finalization_xid` marker,
which the common deleted-transition guard requires. A deferred constraint
rejects a marker committed without the corresponding deletion; rollback cannot
strand a claim. The marker is outside the immutable audit payload. Recovery is
locked before storage on the supported path, and the trigger rechecks that same
row. A legacy/direct caller cannot create the marker or substitute a historical
transaction ID; the exact current incarnation remains mandatory.

The audit can complete after the purge lease ended because it acknowledges an
already persisted successful result; it cannot perform a fresh purge or alter
its fence/time. An exact current recovery observation is still required. An
issuer change, recovery block, suspension or PostgreSQL restart invalidates this
active-incarnation path. Independent restore reconciliation remains required;
the persisted checkpoint must never clear migration 00031's recovery fence.

## Capacity and remaining work

The two fixed rows are bounded by the already accepted capture's full control
slot. They do not allocate a variable-length history. The existing immutable
execution, publication/case, download and retention dependencies stay present.
No deletion or refund of full/replay control slots occurs. The encrypted deletion
audit remains subject to the pending explicit control-object capacity/retention
composition; its bounded size is not an installation-wide quota guarantee.

Production scheduling, protected credentials/key sources, automatic deadline
polling, unknown remote-write drain, other capture mechanisms, extra replicas,
backup/WAL obligations and finite audit/tombstone retirement are not supplied by
this component. The older generic `WriterBarrier` remains necessary for writers
outside the positively completed API protocol. This change cannot authorize
Helm runtime enablement or claim complete managed-copy erasure.

## Verification boundary

Focused tests exercise actual Tink production and local TLS S3 responses: every
failed write position, a lost final PUT response, joined in-flight closure,
immutable completion replay, unused handles and no repeated writes. API runner
tests cover protocol absence and retained failure spend. Signature/framing tests
cover purpose, record/incarnation binding, tampering and historical public keys.
Cleanup unit tests retain positive purge results across audit failure and reject
uncertain purge results.

The added real-service fixture extends the existing API execution/publication
case. It uses the actual producer, scoped SQL roles and S3 inventory/deletion,
with synthetic process/bootstrap/retention inputs. It checks role denials by SQL
state, generic-finalizer refusal, original lease expiry behind a blocking lock,
independent encrypted audit, recovery rejection, immutable receipts and concurrent
single release while full/replay metadata charges remain spent. Presence of this
fixture is not a passing native result. External qualification is performed by
the parent under a source freeze and recorded with terminal cleanup/source hashes
in implementation progress. No complete-runtime or restore claim follows from a
focused component test.
