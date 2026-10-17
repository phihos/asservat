# Large native download: source gap map and proposed next package

Source-only review, 2026-10-12. No implementation, new authority, build, native result or performance claim. Existing ADR048/113/136 decisions remain binding. The qualified context path stays at 4096 bytes.

## Reusable product components

| Component | Actual source and reusable behavior |
| --- | --- |
| Persistent bytes | `internal/domain/artifact/storage.go:8`: existing `asservat-framed/v1`, 8 MiB native frames, 1 TiB maximum, 256 entries/page, 512 pages. No storage-format change needed. |
| Generic codec | `internal/adapters/objectstore/framed/decode.go:26,111`: two key opens plus separately opened manifest, exact paged seeks, bounded full frame authentication/decompression before output, at-most-1 MiB delivery, full native/data/index hashes before final batch. Encoder is streaming too. |
| Pinned S3 reads | `internal/adapters/objectstore/s3.go:128,135`: exact object identity, version/ETag, Content-Range and length; at most an encrypted frame per request. Can read ranges of a large existing object. |
| Whole response | `internal/application/evidence/download_response_transfer.go:271,315`: current identity/SQL leases, 64 MiB prepaid windows, sequential <=1 MiB chunks, acknowledged intent/outcome, contiguous cursor, incremental native hash and withheld last chunk. |
| HTTP | `internal/transport/browser/download_range.go:26` and `download_response.go:31,67`: full/range conditionals, one Content-Length, per-write lease/cancellation and joined deadline restoration. No Blob needed. |
| Identity and policy | Original reader batches, SQL50 route/processing proof, recovery/retention, session/actor/client, Stop and separate server refresh owner remain reusable. A larger transport must consume them, not recreate or serialize them. |

Existing `TestPagedRangeBeyondTwoGiB` (`framed/framed_test.go:309`) encodes a highly compressible generated 2 GiB+73-byte logical file and reads only its last 20 bytes from in-memory ciphertext. This is useful pagination/seek evidence. It is neither an incompressible multi-GiB transfer nor SQL/S3/I-13/RSS qualification. The earlier mechanism spikes are separate evidence again.

## Concrete blockers

1. **Current authority and catalog deliberately describe context metadata.** `application/authorization/download.go:44,86` checks evidence type context, potentialPersonalData and approved metadata; `postgres/download.go:155,178` rereads `ReadPublishedContext`/`ContextExpectation`. `NativeContextSource.Valid` (`evidence/native_context.go:22`) repeats that exact binding. There is no implemented generic published-artifact/raw-grant/share download facet. A generic file type must enter through verified publication and current covering rights before existence-sensitive facts are disclosed. Merely increasing a size limit or relabeling a core as context would bypass the intended boundary.

2. **Metadata and read adapters materialize the whole context.** `objectstore/context_verify.go:117` collects the native file in `contextBuffer`; `RegionalContextResult.Prepare/Read` (`evidence/native_context.go:128,198`) requires <=4096 and rereads the whole native file for each content selection. `manifest/context.go:154,216` parses the supported context manifest and validates pod JSON. Generic metadata must come from the authenticated committed native manifest plus independent published expectation, not a multi-GiB preparatory buffer or a kind whitelist.

3. **The source port is pull-based, but the codec is push-based.** `framed.Reader.Read` correctly owns sequential hash/page/frame state. `NativeResponseSource.ReadChunk` must return one exact chunk under the present short call. Naively calling `Read` separately for each 1 MiB delivery rereads/decrypts up to 8 MiB per chunk and loses whole-object verification continuity. The current remote adapters also require chunk offset/length to equal the entire delivery lease/window (`native_response_source.go:94`, `context_native_response.go:109`), not just fall within it.

4. **Three prepaid unwraps belong to a window, while the current conversation belongs to one tiny chunk.** `NativeKeys.BindNativeDownloadKeys` (`postgres/native_keys.go:85`) binds the window to an exact operation/fence, peer/proof and original short deadline. Reusing that row for a different operation is denied; spent key roles never refill. `RemoteContextSource.AcknowledgeNativeChunk` closes the exchange after the one chunk. Opening another exchange per delivery chunk either fails this binding or would require a prohibited key/spend reset. This cannot be fixed by adding a loop around current context reads.

5. **I-13 v1 is explicitly small and short.** `contracts/native_exchange.go:12,27` names context/v1 and caps each direction at 32 frames. `transport/native/worker.go:75,232` permits only <=4096 and one data frame. `NativeAttachment.open:105` caps operation end to the current observation; `NativeOperation.CurrentValid` (`domain/authorization/native_exchange.go:125`) caps it to the original processing proof. The server's original socket residency is also finite. Do not extend these observations or rearm a failed stream. A 64 MiB window already needs more data/ack frames than this first protocol allows; one conversation per MiB also runs into the 32768 conversation budget long before the 1 TiB format bound.

6. **Control/audit finite retirement is still missing.** SQL42 explicitly rejects deletion of control/response/window rows (`migrations/00042_download_responses.sql:54,67,90`). The object adapter writes paired window audits but has no complete separately acknowledged retirement path. SQL45 native owner/key cleanup and SQL47 Stop cleanup do not dispose of these parents. Large transfer admission needs measured backing for rows, transitions/WAL, encrypted audit objects, supported backup horizons and independent retirement. A 1 TiB response has 16384 windows and 32768 audit objects; the configured maximum 128 KiB/object reserves 4 GiB of audit capacity. This arithmetic is not a throughput or cost measurement.

7. **Large publication is also unfinished.** Generic framed encoding exists, but the concrete context producer buffers data/index, and `Store.PutSmall`/`Verify` cap objects at 16 MiB (`objectstore/s3.go:28,102,163`). Multipart cleanup is not a generic streaming uploader or verifier. Actual large cores/PCAPs cannot be product-published through the context producer. A synthetic large source can qualify transfer mechanisms only, never grant production artifact authority.

## Proposed contracts before runtime changes

### Byte format and incremental reader

Keep `asservat-framed/v1`, all hashes/AAD/limits and ordinary readable native output unchanged. Add a bounded sequential pull cursor in the existing framed adapter. Proposed shape (not a public wire/API):

- exact immutable layout, selected offset/length, original owning context;
- `Next(currentContext)` returns one <=1 MiB owned buffer, actual read/decode work and final-integrity disposition; the current context can only shorten the owner context;
- one operation at a time; Close cancels and joins it; retained handles fail after Close;
- one authenticated page and one decoded frame plus bounded cipher/decompressor workspace; no whole-file/64 MiB buffer and no plaintext scratch;
- no background reads or prefetch while the caller obtains current authority;
- full reads keep native/data/index hash continuity and withhold the final chunk; ranges verify intersecting frames and exact range length, without claiming full-file verification;
- existing `Reader.Read` delegates to the same internal decode/cursor path to avoid a second integrity implementation. No new key calls from Next or per delivery chunk.

The codec remains nonauthorizing. A missing current permit at the application boundary cannot be satisfied by a cursor, layout, hash or certificate.

### Window key ownership versus short conversations

The later regional composition needs a distinct **live window reader**: exact response/window/worker process/version/range, one original three-role key spend and finite owning lifetime. It may retain the successful local key primitives/frame cursor across several positively joined short conversations for that same window. Such retention is bounded memory, not cached permission. Every object read, local decrypt and output still requires the fresh exact lease; idle retention emits/reads nothing. A new accounting window acquires its own original three-slot key set. Provider errors/unknown opens cannot be retried under the old set. Unknown/unjoined conversation or process loss closes the reader and retains spend; a new response/session uses fresh admitted budget.

This requires an explicit SQL/key contract change: a versioned original reader/window binding separate from the changing short operation/fence. Do not extend `download_native_key.valid_until`, reset `used_roles`, or silently accept a new operation on a v1 binding. The expiry remains the deadline for the original unwrap attempts; subsequent local use requires the same surviving process reader plus a newly admitted current conversation. No recreated reader after loss. Extra state/counters and cleanup must be prepaid and qualified, including final-marker uncertainty.

Whole-response verification state contains only bounded in-process cursor/hash facts and exact immutable source binding. It spans acknowledged windows without preserving old authority or serializing resumable hash state into SQL. Full-file windows are frame-aligned; index pages reauthenticated under later window keys are hashed once in original order. Partial window boundary rereads are explicitly charged. No lookup/old receipt certifies remote Joined.

### Versioned private conversation

Use a separate closed large-native capability/version; keep context/v1 bytes, paths and behavior unchanged. Each actual conversation keeps its original <=5s authority and finite frame/byte count, carries exact window/cursor/lease sequence and waits for the final sink acknowledgement before progressing. Its frames remain <=1 MiB. Multiple chunks may fit one current conversation; the next starts only after positive joined closure and fresh identity/SQL/native peer/Pod checks. No data while reauthorizing. Missing final marker retains uncertainty and cannot create a reusable reader.

Exact v2 frame/conversation ceilings must be derived from the originally admitted window/transition budgets. Increasing the v1 32-frame or process conversation cap without that calculation is not the change. The schema42 window is accounting only, never a 64 MiB permission token or a promise all of it fits in five seconds. Actual slow storage, slow client and key-service latency need qualification; the protocol cannot lengthen a stale observation to improve availability.

## Smallest aligned next implementation package

First implement the generic framed pull cursor and conservative per-range work accounting, before touching I-13 or SQL. This removes the concrete byte-reader mismatch while preserving the already implemented format and integrity rules. Proposed ownership:

- new `internal/adapters/objectstore/framed/cursor.go` and focused tests;
- narrow refactor of `framed/decode.go` to share authenticated page/frame logic and retain legacy `Read` behavior;
- new bounded work arithmetic/tests under `internal/domain/artifact` if kept independent of transport types;
- update `docs/architecture/artifact-format.md` only for the precise implemented cursor/ownership behavior and truthful test scope.

Tests should cover cross-frame/page ranges; alternating short call contexts over a longer original owner without extending a call; cancellation/Close joining a blocked object read; no output or provider calls while idle; constant key calls as delivery chunks increase; exact work counters and limits; duplicate/reordered/overflow input; and corrupt native/data/index final hashes withholding the last chunk. Use existing deterministic sources and codec tests, not new libraries or a full in-memory multi-GiB fixture. Failure-before tests target the missing pull/lease composition and repeated-work issue; existing corruption fixtures remain unchanged.

This first package does not enable a generic public source. Following it, the window-reader/key contract, closed private protocol, generic publication/authority and finite window retirement need separate reviewable implementation boundaries. Large synthetic native SQL/S3/I-13/HTTPS tests can then measure >1 GiB exact bytes, partial transfer plus Range/If-Match reconstruction, loss/slow readers, short-lease changes and actual memory/provider/control counts. Actual PCAP/core/companions and installed browser/MCP/local-tool acceptance remain final workflow checks, not properties inferred from codec arithmetic.

No source edits beyond this planning file, no builds and no native labs were performed for this review.
