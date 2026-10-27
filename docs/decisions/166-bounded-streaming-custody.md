# ADR-166 — Bounded streaming custody for larger native outputs

Date: 2026-10-14. Status: accepted scope (agreed during the runtime-profile
assessment); storage components implemented and real-service qualified. Requirements: REQ-EVD and REQ-DLD
storage/download requirements, REQ-CAP fair storage; TASK-05 / TASK-07 / TASK-11.

Amended by [ADR-244](244-native-artifact-types.md) (2026-10-27): the qualification bound is
256 MiB with at most 33 parts (migration 00095), a framed encoder now feeds this writer together
with small index/manifest/commit objects, and verification and native download of the stored
artifact exist at component level. The 128 MiB/17-part figures below are historical.

## Problem

ADR-048's framed v1 format represents up to 1 TiB, but the only implemented
write path stores four small objects. `Registration.Validate` limits native
output to one 8 MiB frame, and `Store.PutSmall`/`Verify` reject objects above
16 MiB. Runtime profiles (64 MiB) and traces (128 MiB), bounded command and file
outputs, and finite packet saves cannot be stored. Raising a constant would skip
the temporary multipart obligations, uncertain-reply handling and cleanup proof
that larger writes need.

## Decision

Add one shared streaming path for declared native limits above 8 MiB, initially
qualified up to **128 MiB**. This initial bound does not narrow the product's
1 TiB/large-core requirement; larger bounds need their own part-size and
resource qualification. The small-object path and the 4,096-byte context
authority are unchanged.

- **Plan.** An immutable `StreamingPlan` extends the original storage obligation.
  `Registration.Validate` accepts native limits up to 128 MiB, so the existing
  copy, verification and deletion facets apply unchanged. Only the streaming
  registration may create such an attempt. The small `Register` path rejects
  anything above one frame, and a deferred SQL constraint rejects any attempt
  above one frame that lacks its streaming journal row. No caller can bypass
  temporary accounting.
- **Accounting.** One atomic SQL reservation charges the existing four final-copy
  ceilings **and** the temporary multipart obligation against the same protected
  workload allocation: one complete data ceiling for unfinished or uncertain
  parts, plus one upload slot and at most 17 part slots. The temporary charge is
  released only after a verified final object and an inventory showing no open
  upload or parts, or after a verified abort and absence. Uncertain outcomes keep
  every charge.
- **Journal.** One SQL child row per attempt (`custody_stream`, migration
  **00061**) records the plan digest and a bounded state: create spent,
  acknowledged upload ID, at most 17 exact part receipts (number, bytes,
  ciphertext SHA-256, ETag), complete spent with the expected full ciphertext
  length/hash, and the final receipt. Each transition is a revision
  compare-and-swap. Create and complete are one-use claims written **before** the
  request. No credentials, keysets, native hashes or evidence bytes are stored.
- **Writer.** Sequential 8 MiB ciphertext parts with concurrency one and a single
  SDK attempt per request. No hidden upload manager, retry or speculative
  parallelism. Completion uses `If-None-Match: *` with the exact retained part
  list, and the result (ETag, non-null version) is validated. An uncertain
  completion is never repeated. Read-only reconciliation may then adopt only an
  exact unique object whose complete ciphertext length and hash match the
  journal.
- **Verification.** The complete ciphertext is reread in bounded ranges and
  hashed before `StoreCopies`; HEAD/ETag is never sufficient. Index, manifest and
  commit stay small objects. The result is still only `stored_unpublished`.
- **Cleanup.** Abort plus a `ListParts`/`ListMultipartUploads` inventory must
  positively show absence; a canceled local writer is not remote quiescence.
- **Deadlines.** Storage backpressure consumes the original acquisition and
  `WriteUntil` time. No five-second authority observation, context lifetime or
  verification bound is extended.

## Consequences

Storage needs `ListMultipartUploads`/`ListParts` permission on the evidence
bucket prefix. AWS documents the multipart semantics used here
([CreateMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html),
[CompleteMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html),
[AbortMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html)).
SeaweedFS and other backends must be qualified against them, including
conditional completion; documentation alone does not qualify a backend.

## Implementation status

Implemented:

- `artifact.StreamingPlan`/`StreamingState`: the bounded journal with one-use
  claims, exact replay identity and a release that requires either a receipt or
  proven abort.
- Migration 00061: `custody_stream`, a deferred constraint requiring the journal
  for attempts above one frame, and append-only guard triggers.
- `Ledger.RegisterStreaming`/`AdvanceStreaming`/`ReadStreaming`, with atomic
  final plus temporary charges. Fresh claims recheck custody after all locks.
- Object-store multipart create/part/complete (`If-None-Match: *`),
  abort/inventory, and ranged full-ciphertext verification.
- `privacy.StreamingWriter` and `ReleaseStreaming`.
- Attempt deletion now also releases an unreleased temporary charge, because the
  attempt purge proved the prefix and its uploads absent.

The plain `Register` path refuses attempts above one frame.

Verification:
[adr166-streaming-custody-6](../../test/results/adr166-streaming-custody-6/result.json)
passes the whole `TestCustodyWithRealServices` on real PostgreSQL and SeaweedFS,
including the streaming subtest. It covers 20 MiB in three parts, refusal of
spent creates, the SQL constraint for journal-less large attempts, and create-only
completion (SeaweedFS answers 412). It also covers complete verification, exact
release, abort release, and an uncertain completion that stays charged until
attempt deletion releases it once. Earlier runs 1–5 are retained failures: an SDK
error-typing assumption (SeaweedFS reports `NoSuchUpload` by code, which the SDK
does not type for `ListParts`), a test-only diagnostic run, and an undersized
fixture allocation.

Remaining: connecting a real encoder sink (runtime profiles) and the index,
manifest and commit objects into one `StoreCopies`; reconciliation that adopts
an exact unique object after an uncertain completion; qualification at the full
128 MiB bound and of throughput; and profile admission, publication and download.
