# Framed pull cursor — frozen isolated package

Seven payload paths, two existing bases, 356 unchanged package-closure dependencies. No live source edits or external/native fixture. Persistent `asservat-framed/v1`, provider/key counts, SQL, protocol and application authority are unchanged. Parent owns integration and full repository gates.

## Behavior and boundary

`Reader.Cursor(owner, offset, length)` selects one exact range without object I/O. `Cursor.Next(currentCall)` returns <=1 MiB caller-owned bytes, attempted work and selection/full-file integrity dispositions. It retains one authenticated index page and one decoded frame, never prefetches or performs idle I/O, and uses Reader's already opened local keys. The caller clears returned buffers and supplies current application authority independently.

Current-call cancellation/deadlines can only shorten the original owner's interval. Successful calls detach and join their cancellation callback before a later call may enter. Concurrent reads are rejected without work; an already canceled call rejected before admission performs no work. Any admitted error/cancellation ends that cursor. `Close` cancels and joins the actual synchronous source read before clearing retained buffers. A source still unwinding after cancellation remains joined work; no timeout is substituted for completion. Close cannot erase caller-owned output or Reader-owned key primitives.

A full native read verifies native/data/index SHA-256 before returning the final chunk. A partial selection verifies its complete intersecting pages/frames and exact selected length but never claims whole-file integrity. Empty files still yield one authenticated empty final buffer and cross the existing push delivery boundary once. Legacy `Reader.Read` uses the same cursor rather than a second decoder.

`Layout.RangeReadWork` validates the complete directory and 1 TiB limit before arithmetic. It charges full selected native frames (including boundary bytes outside the range), exact selected index ciphertext and intersecting page/frame counts. The pre-index data bound is the smaller of each selected page's total data and selected full native sizes plus format overhead. This conservatively includes compressed or short final frames. Independent overlapping cursors/windows owe the overlap again.

Per-pull work counts requested data/index bytes before I/O and full native decode allowance before decode, retaining failed/unknown attempts. It is not a refundable receipt. Pages separately bound index JSON work. Manifest/key opening, output, audit, transport and independent retries remain separate. No SQL/accounting consumer is wired here.

## Payload

- `internal/adapters/objectstore/framed/cursor.go`
- `internal/adapters/objectstore/framed/cursor_test.go`
- `internal/adapters/objectstore/framed/decode.go`
- `internal/adapters/objectstore/framed/reader_boundary_test.go`
- `internal/domain/artifact/framed_read_work.go`
- `internal/domain/artifact/framed_read_work_test.go`
- `docs/architecture/artifact-format.md`

The decode diff removes the duplicated push loop, adds a post-index-read context check before local decryption, and clears the strict JSON syntax workspace. There are no storage byte/AAD/schema changes.

## Actual evidence

1. **Before, handle 33082, exit 1 as intended.** `TestReaderDenialAtFrameBoundaryDoesNotReadNextFrame` builds against the original push decoder and a test-only overlay. It observed two data reads before the application's eighth-chunk denial, with 7,340,032 bytes delivered. This demonstrates unnecessary next-frame work before a current application delivery refusal. `evidence/boundary-before.log`.
2. **First corrected diagnostic, handle 49582, exit 1 retained.** Selected framed cursor/boundary races passed, but artifact tests did not compile because typed int MaxFrames/MaxPages constants were assigned to int64 fixture fields. Explicit casts corrected only that fixture. `evidence/cursor-after.log`.
3. **Final sequential job, handle 68992, terminal exit 0.** Corrected targeted races: exit 0, 2.575s wall. Complete existing framed/artifact race suite: exit 0, 8.276s wall (51 top-level PASS entries; package times 7.822s/3.714s). Affected vet: exit 0, 1.703s. Exact commands/exits in `evidence/final-checks.json`.
4. The full suite includes `TestPagedRangeBeyondTwoGiB`, PASS in 3.95s: synthetic 2,147,483,721-byte logical input; ciphertext data 244,550 bytes/index 71,288 bytes; selected tail reads 70/381 bytes. This is highly compressible codec pagination/tail-read evidence, not full multi-GiB network throughput or backend/RSS qualification. New sparse page-boundary tests back only their two selected frames with real ciphertext; unselected placeholders are explicitly not full-file evidence.
5. All final payloads, both bases and all 356 pinned dependency files matched after checks. That dependency closure also matches the original stage snapshot. The broader initial all-Go snapshot saw a separate parent integration-fixture edit; it was outside the tested dependency closure and is recorded in `evidence/before.json` rather than claimed unchanged globally.

`evidence/verification.json` records actual scope and hashes checked. No native lab ran. Full repository Go/architecture/spec gates are parent integration work; no staged documentation gate is claimed here.

## Reproduction

Run from `/home/phil/Projekte/asservat`, keeping the stage and original bases available:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/planning/large-native-reader-20261012/tmp go test -count=1 -overlay=/home/phil/.cache/asservat-build/planning/large-native-reader-20261012/before-overlay.json ./internal/adapters/objectstore/framed -run '^TestReaderDenialAtFrameBoundaryDoesNotReadNextFrame$'
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/planning/large-native-reader-20261012/tmp go test -race -count=1 -overlay=/home/phil/.cache/asservat-build/planning/large-native-reader-20261012/overlay.json ./internal/adapters/objectstore/framed ./internal/domain/artifact -run '^(TestCursor|TestFramedRangeWork|TestReaderDenialAtFrameBoundaryDoesNotReadNextFrame)'
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/planning/large-native-reader-20261012/tmp go test -race -count=1 -v -overlay=/home/phil/.cache/asservat-build/planning/large-native-reader-20261012/overlay.json ./internal/adapters/objectstore/framed ./internal/domain/artifact
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/planning/large-native-reader-20261012/tmp go vet -overlay=/home/phil/.cache/asservat-build/planning/large-native-reader-20261012/overlay.json ./internal/adapters/objectstore/framed ./internal/domain/artifact
```

The before command requires the original decoder. Its failure is expected and must not be erased. New API tests necessarily require the new API; they are not described as buildable-before tests.

## Guarded integration and next work

Check `manifest.json` base hashes/new-path absence, payload hashes, and `dependencies.json` before copying. The package contains no generated bindings or shared SQL changes. Archive copied Go evidence as `.go.txt` outside product paths; `.go` evidence under `test/results` becomes an unintended package. `package-hashes.json` pins the whole frozen handoff, including the failed logs.

The 4096-byte context service remains unchanged. Generic published-artifact authority, a live regional window reader with prepaid key ownership across independent short conversations, finite window/control audit retirement, large-object publication and installed PCAP/core/local-tool acceptance remain unimplemented prerequisites in `PROPOSAL.md`. The cursor/hash is not cached authority or a persisted resumable state. This package does not authorize increasing context limits or key budgets.
