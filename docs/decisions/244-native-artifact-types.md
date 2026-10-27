# ADR-244 — Native artifact types and larger saves (S-04 increment 2)

Date: 2026-10-27. Status: accepted; implemented at component level; qualification below.
Requirements: REQ-DLD-001/003 (SC-DLD-001/003), REQ-LIF-005/006, REQ-EVD-001–003, REQ-NET-001,
REQ-SYS-001; TASK-05/07/11. Plan: [S-04 plan](../reviews/s04-plan-2026-10-27.md) §4 row 2, gate
row P19 and open item 12. Amends [ADR-166](166-bounded-streaming-custody.md) (qualification bound
128 MiB → 256 MiB) and refines [ADR-113](113-large-native-response-accounting.md) for local
multi-frame sources. Migration **00095**.

## Problem

Every S-04 recording save (PCAPNG, syscall records, the HTTP header projection) must be stored,
verified and downloaded in its native representation. The code could do this only for one
artifact: pod status, 4,096 bytes, `application/json`, `artifact-<id>.json`. The verifier,
manifest, producer and download source each refused anything else; ADR-166 streaming custody
stored up to 128 MiB of ciphertext but nothing published or downloaded it; the largest S-04
frozen ceiling is 256 MiB. The first real 200 MiB download in this increment's qualification also
showed that the ADR-113 transfer could not finish a large file: a frame load or a 1 MiB socket
write that started close to the end of its five-second delivery lease failed the whole response
(`stage read: context deadline exceeded` at about 168 MiB, `stage write: download authority or
session expired` at about 179 MiB).

## Decision

1. **Artifact-type registry** (`internal/domain/artifact/native_types.go`). A type fixes the
   manifest kind and evidence type, the native media type and format, the server-generated filename
   extension, the fixed coverage sentence, its native size bound and the data classes this
   increment can verify:

   | Type | Kind | Media type | Format | File | Max | Classes |
   | --- | --- | --- | --- | --- | --- | --- |
   | pod status (empty name, historical) | `kubernetesSnapshot` | `application/json` | `asservat-pod-status/v1` | `.json` | 4 KiB | metadata, raw |
   | `pcapng` | `packetCapture` | `application/x-pcapng` | `pcapng` | `.pcapng` | 256 MiB | metadata (networkHeaders) |
   | `syscallRecords` | `syscallTrace` | `application/x-ndjson` (JSON Lines) | `asservat-syscall-events/v1` | `.jsonl` | 256 MiB | metadata |
   | `httpHeaders` | `packetCapture` | `application/json` | `http-response-headers/v1` | `.json` | 16 MiB | metadata |

   The HTTP projection is structured JSON with its own format and extension, never labelled as a
   packet capture. Raw packets and syscall arguments add their classes in their own increments
   (14, 15). The HTTP response itself stays `application/octet-stream` (REQ-DLD-003); the native
   media type is in the encrypted manifest, the AAD binding and the registry
   (`NativeTypeForFormat`).
2. **Typed expectations.** `ContextExpectation` gains `NativeType` and `Lifecycle`, both omitted
   when empty, so every existing pod-status expectation, its JSON and its digest are unchanged.
   `Validate` applies the type's size bound and classes; the Kubernetes API class stays pod status
   only; a pod-status expectation cannot carry ongoing provenance. Pod-status-only consumers (the
   context producer, native context source, context reader and projection) refuse other types.
3. **`actionLifecycle` provenance for ongoing saves.** `OngoingLifecycle` holds the accepted
   source facts: trigger kind (`policy`, `manual`, `recordingSave`), source session (one source
   epoch: a restarted source is a new session), source start, snapshot ID, requested before/after,
   history coverage, gap reasons, `sourceStoppedAt` and `windowCoverage`, plus the
   `recordingSaveOrigin` of a save. The expectation's `TriggeredAt` is t0. Validation enforces
   action-lifecycle.md: full history needs a source armed by t0−before; incomplete history names a
   reason; full window coverage needs full history, no gap and no known stop before t0+after; a
   save has `after: 0s` and an origin. The manifest writes the schema's ongoing fields
   (`gapReasons` present even when empty), `completeness.source` follows the window coverage and
   `completeness.gaps` the gap reasons; a save's acquisition may start before t0 (its prehistory)
   but never before the source started. Parsing still compares the whole manifest with the
   independent expectation, so a changed snapshot, session, coverage, stop, trigger or type is an
   integrity failure.
4. **Streaming native checks.** Each type has a validator that sees the native stream while it is
   encoded and again on every verification, retaining at most one record: pod status (unchanged
   schema check), PCAPNG block structure (section header and byte-order magic, bounded aligned
   lengths with matching trailers, packets only on described interfaces within their snapshot
   length, and only section header, interface description, enhanced packet and interface
   statistics blocks), JSON Lines events against `syscall-results.schema.json#/$defs/event` for
   the expected pod within the acquisition interval (the schema is now the ninth resource of the
   embedded manifest bundle), and one strict JSON object for the HTTP projection. The PCAPNG check
   is structural: payload truncation is enforced by the node sanitizer (increment 4).
5. **Producer and verification.** `objectstore.ArtifactProducer` wraps the three keys before the
   source is read, encodes framed v1, sends the data object through the ADR-166 journaled
   multipart writer above one frame (`PutSmall` below), and writes small index, manifest and
   commit objects; the copies go to `StoreCopies` (`stored_unpublished`). `VerifyContext` for a
   recorder type rereads the whole artifact through the framed reader and the type check, with
   the original write cutoff and a bound of 30 s plus 1 s per 8 MiB frame (62 s at 256 MiB).
6. **256 MiB streaming custody.** `StreamingNativeLimit` is 256 MiB and `StreamingMaxParts` 33
   (256 MiB plus 32 frames of 64 KiB overhead in 8 MiB parts). Migration 00095 only widens the
   attempt, temporary-byte and temporary-object checks; journal, claims, the deferred journal
   requirement and release rules are unchanged; the ADR-227 floor stays 81.
7. **Native download of multi-frame artifacts.** `ContextVerifier.OpenNative` authenticates the
   commit and manifest against the expectation and opens the data/index keys once;
   `FramedNativeSource` implements the ADR-113 `NativeResponseSource` over the framed cursor:
   filename `artifact-<id><ext>`, format, strong ETag `"v1-<copies digest>"`, coverage (type text
   plus recorded history and window coverage), size and native SHA-256 from the authenticated
   manifest; exact sequential chunks; per-window read work bounded by nine frames and two index
   pages; every frame authenticated before its bytes; a whole-file response ends with the verified
   whole-file hashes. If-Match, If-Range, single ranges and 412/416 stay with the existing HTTP
   resolver and sink.
8. **Delivery lease margin for local sources (refines ADR-113).** Reading and authenticating the
   next frame discloses nothing, so a local source loads it under the response, not the lease
   deadline (cancellation still stops it). Before writing a chunk, the transfer renews the lease,
   with a fresh current-authority observation, whenever less than two seconds remain; a chunk is
   written only under such a lease or cleared. Remote sources are unchanged because their chunk
   acknowledgement is bound to the original lease. The five-second lease, one-MiB chunks and
   64 MiB windows are unchanged.

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | Every recording save of increments 4, 10 and 13 needs it; without it none can be verified or downloaded (REQ-DLD-001). No production producer exists yet. The lease defect is observed, not hypothetical: four of the first five 200 MiB qualification runs failed on it. |
| 2 | Risk accepted | Yes: native download of all evidence incl. PCAPNG is a maintainer requirement; plan §2 P19 and increment 2; ADR-166's raised bound is plan open item 12. The lease margin uses the maintainer's 2026-10-20 authorization of relaxed, measured recheck intervals. |
| 3 | Typical deployments | Yes: every packet and syscall investigation ends in such a save. |
| 4 | Precedent | tcpdump/Wireshark write PCAPNG (draft-ietf-opsawg-pcapng); JSON Lines is the usual event export (Falco, Tetragon); S3 multipart for large objects; RFC 9110 ranges/If-Match/If-Range. |
| 5 | Privileges added | None: no credential, SQL grant, Kubernetes permission, network path or key call; still three key wraps per attempt and three unwraps per reader, independent of size. |
| 6 | Failure/degraded states | 0 new states; refusals reuse existing errors. |
| 7 | Self-configuration | No: registry, bounds and the two-second margin are constants. |
| 8 | External dependencies | S3 multipart, conditional completion and ranged reads (ADR-166), qualified on SeaweedFS at 33 parts; the PCAPNG block format. |
| 9 | Cost at scale | Per 256 MiB save: 1 create + ≤33 parts + 1 complete, one full ciphertext reread at completion, one full verification read, a temporary charge ≤258 MiB until release, ≤8 MiB part buffer + one 8 MiB frame + zstd workspace. Per download: ≤73 MiB ciphertext read per 64 MiB window; one lease renewal and authority observation about every 3 s per active large response (≤16 installation streams). Measured on the race-instrumented test binary with local SeaweedFS: 200 MiB stored in 22 s, verified in 5 s, downloaded in 5.5 s. |
| 10 | Upgrade/rollback | The migration only widens checks (floor 81); new expectation fields are omitted when empty, so stored rows and digests are unchanged; no recorder rows exist for an older binary to meet. |
| 11 | Smaller fix | Raising constants alone leaves the 4 KiB verifier buffer and the one-chunk-per-window source. Per-recorder storage/download paths would duplicate custody, verification and transfer. Deferring to increment 4 would first exercise 200 MiB storage and download together with the first privileged collector. |

Benefit established, cost small: proceed.

## Remaining limits

- **Not yet composed into the installed path.** The regional worker exchange
  (`transport/native` operations, `RegionalContextResult`) and the first-context SQL response facet
  remain pod-status-only (4 KiB, one window); catalog publication (migration 00050's processing
  trigger) still admits only pod status, and no admission creates a recorder capture. Increment 4
  composes admission, publication and the regional source for its first PCAPNG save.
- **Synthetic qualification inputs.** Keys, identity, download authority and the download
  session/window ledger of the 200 MiB test are synthetic (in-memory domain transitions; the SQL
  window ledger keeps its own real-service test); storage, journal, charges, multipart, encrypted
  window audit, verification and HTTP are real.
- **Slow clients.** A chunk write gets at least two and at most five seconds, so a client below
  about 0.2–0.5 MiB/s per 1 MiB chunk is interrupted and must resume. Longer delivery leases for
  writes would need the measured interval the maintainer's clarification asks for.
- **`tshark -r`** runs in the test only where Wireshark's CLI is installed; neither the workstation
  nor the CI image has it, so the downloaded file was checked byte-for-byte (SHA-256) and by the
  structural PCAPNG check.
- **HTTP projection and syscall records** have no producer yet; their checks are the schema and
  strict-JSON checks above.

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-04-increment-2-native-artifact-types-and-larger-saves-adr-244-2026-10-27).
