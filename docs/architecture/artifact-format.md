# Persistent artifact format and commit boundary

Decision: ADR-048; mechanisms follow [ADR-330](../decisions/330-event-driven-system-design.md). Implements the storage detail behind REQ-EVD-001–003 and REQ-DLD-001/003. The product codec is `asservat-framed/v1`. Capability negotiation names the supported format explicitly.

[ADR-064](../decisions/064-local-key-material.md) adds a versioned local wrapping backend behind the same key ports ([local keys](local-keys.md), [key service](local-key-service.md)). It replaces only the key wrapper; native files and the framed data/index/manifest layout are unchanged.

## Native files and physical objects

The native file is unchanged: PCAPNG stays PCAPNG, a core stays its native dump format, a context projection is ordinary JSON. Storage compression removes only Asservat's wrapper; intrinsic compression in the native format is preserved.

Each attempt uses four immutable keys:

```text
v1/{clusterUUID}/{artifactUUID}/{attemptUUID}/data
v1/{clusterUUID}/{artifactUUID}/{attemptUUID}/index
v1/{clusterUUID}/{artifactUUID}/{attemptUUID}/manifest
v1/{clusterUUID}/{artifactUUID}/{attemptUUID}/commit
```

UUIDs are canonical lowercase, nonzero identities; names, target paths, label values and user reasons never enter object keys. Keys are never reused. A retry that acquires new bytes receives a new attempt and fresh keys; reconciling the same attempt never reacquires bytes.

| Object | Representation and bound |
| --- | --- |
| data | Concatenated complete Tink streams, one per native frame. Frames are 8 MiB except the last (memory per in-flight frame in encoder and reader); an empty file has one authenticated empty frame. The data object is at most 5 TiB, the [S3 maximum object size](https://docs.aws.amazon.com/AmazonS3/latest/userguide/upload-objects.html); with 64 KiB authentication overhead per 8 MiB frame that allows about 4.96 TiB of native bytes (650,279 full frames plus a final partial frame). The index supplies exact offsets. |
| index | Concatenated Tink streams of JSON pages: at most 256 frame entries and 256 KiB decoded JSON per page, the memory a reader retains for one page. The page count follows from the native size (at most 2,541 pages at the S3 object maximum). No compression. The manifest contains the page directory. |
| manifest | One Tink stream with the detailed `artifact/v1` manifest, including the layout and exact data/index object identities. Its size is derived: fixed fields plus one directory entry per index page. Evidence metadata, native hashes and wrapped data/index keys stay encrypted. |
| commit | Plaintext JSON matching `artifact-commit/v1`: opaque IDs, format, the manifest's ciphertext digest/size, object identity and wrapped manifest key; its size follows from the schema's field maxima (about 4 KiB). A storage receipt, not a bearer capability. |

Schemas: [layout, index and commit](../../specs/contracts/framed-storage.schema.json), [detailed manifest](../../specs/contracts/manifest.schema.json). `storageObjects` pins data/index ETags and, when supported, version IDs; the commit pins the manifest identity; the artifact row pins the commit. Unversioned backends use `versionID: null`, conditional creation, immutable keys and exact ETag comparison.

Every data frame uses identity encoding or one independent zstd frame, whichever is smaller. Decoder window and output are limited to the 8 MiB frame size; no dictionaries, cross-frame compression or guessed codec. An encrypted data frame is at most native bytes plus 64 KiB: the Tink stream header and a 16-byte tag per 1 MiB segment take far less, and the identity/zstd choice never expands a frame.

Index entries contain sequence, native offset/length, ciphertext offset/length, codec and both SHA-256 hashes. The page directory adds contiguous data/index spans and each encrypted page's hash. Root totals must equal the manifest's size and hash fields. `sizes.ciphertextBytes` and `hashes.ciphertextSHA256` describe the data object only. ETags are identities, not integrity hashes.

[ADR-244](../decisions/244-native-artifact-types.md) connects the encoder to the [ADR-166](../decisions/166-bounded-streaming-custody.md) multipart data writer and the artifact-type registry whose media type enters the AAD: `application/x-pcapng`, `application/x-ndjson` (syscall JSON Lines) and `application/json` (pod status, HTTP header projection). Multipart parts are independent of frame boundaries; the part size is at least native size ÷ 10,000 so the upload stays within S3's 10,000-part limit (parts ≤ 5 GiB; 5 TiB needs parts of at least 525 MiB).

## Cryptography and key scope

Use Tink `AES256_GCM_HKDF_1MB` with a fresh keyset for each of data, index and manifest. Readers accept exactly one enabled RAW primary key: AES-GCM-HKDF version 0, 32-byte key material, 32-byte derived key, SHA-256, 1 MiB ciphertext segments. Streams within one object share that object's keyset; Tink generates per-stream salt and nonces ([Tink streaming AEAD](https://developers.google.com/tink/streaming-aead)).

All three keysets are prepared and wrapped before the source is opened. The collector has only wrap permission; the regional reader (A-READ) holds the region's unwrap permission; hub roles have neither. Because Tink's encrypted-keyset writer performs a decrypt self-check, the adapter serializes the keyset (at most 4 KiB; one RAW AES-GCM-HKDF key serializes to a few hundred bytes) into process memory, wraps it and clears the buffer. No clear keyset file is written.

The OpenBao adapter uses a configured Transit mount/key and encrypts a JSON payload with `format: asservat-keyset/v1`, `bindingSHA256` and the base64 keyset; unwrap checks the binding before parsing. The KMS sees only small keys, never payloads ([envelope encryption](https://developer.hashicorp.com/vault/docs/secrets/transit/envelope-encryption), [OpenBao Transit](https://openbao.org/docs/secrets/transit/)). A write needs three wraps and a reader three unwraps per artifact, independent of size, frame or part count; range reads add no key calls. The crash path uses prewrapped attempts and never makes a network call from the host helper.

Every Tink stream and wrapped-key payload uses canonical RFC 8785 associated data with all of these fields:

```json
{"format":"asservat-framed/v1","schema":"artifact/v1","clusterID":"UUID","artifactID":"UUID","attemptID":"UUID","mediaType":"native type","role":"data","sequence":0,"nativeOffset":0,"nativeBytes":8388608,"codec":"identity"}
```

Integers are nonnegative and below 2^53 (the RFC 8785 / JavaScript safe-integer range). Data roles bind frame sequence/offset/length and `identity` or `zstd`; index roles bind page number/native span and `json`. Key roles are `data-key`, `index-key`, `manifest-key` with zero numeric fields and codec `none`. The manifest role has zero numeric fields and codec `json`. Manifest and manifest-key AAD use `application/vnd.asservat.manifest+json`; the native type is verified inside the manifest and data/index bindings.

## Writes, reads and corruption

For native limit L, the writer charges N = max(1, ceil(L / 8 MiB)) frames and P = ceil(N / 256) pages: data L + N × 64 KiB, index P × 320 KiB, the manifest and commit at their derived sizes, four object slots. These are internal estimates derived from the layout (ADR-335 D2). At 5 TiB the index charge is 800 MiB. The encoder holds one frame and one index page; it never retains a full artifact. A source I/O error fails the attempt; truncated evidence needs an explicit acquisition completeness result.

A range read loads only overlapping index pages and data frames. Each page is authenticated and checked for strict JSON and contiguous ranges; each selected frame is authenticated, decompressed and hash-checked before any of it is delivered. A range decodes at most its length plus two boundary frames (frames are the decode unit). Unknown formats, malformed directories, gaps, overlaps, changed versions, wrong AAD, overflow and truncated ciphertext fail closed. Full-file reads also verify whole data/index/native hashes and length and hold the last delivery batch until they pass, so a client never receives a complete Content-Length after an integrity failure. Clients verify the file hash when assembling resumed ranges.

The framed adapter exposes a sequential pull cursor over one range. Each pull returns an owned buffer of at most 1 MiB, one Tink segment, which bounds cursor memory per stream. The cursor does no prefetching and opens no additional keys; it retains at most one index page and one decoded frame, and clears them on completion, error or close. A failed or canceled read makes the cursor terminal. `Close` cancels and joins the pending object read. `Layout.RangeReadWork` gives the frame, page and ciphertext bound of a range before the index is opened.

The codec carries no authorization. A started download continues under `DownloadAuthority.Continue`: a local comparison against the original bounds (session or token expiry, `AccessUntil`, stored retention deadline, Stop), with no per-chunk or per-window recheck ([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md), [download sessions](download-sessions.md)).

## Commit and deletion

Remote I/O never runs while SQL row locks are held.

1. Admission (one SQL transaction): authorize the operation once, charge the workload's byte/object quota, register the pending copies and the attempt with its idempotency key, and write the audit row.
2. Prepare wrapped keys, then start the source. Write data and index with conditional creation ([S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)) and record upload IDs.
3. The producer validates the native format before encryption, writes the manifest, then the commit object. The connector reports the commit over its hub connection; while disconnected it keeps the commit reference locally.
4. Verification: the regional reader checks the commit envelope against the stored registration and decrypts and checks the manifest and index against the stored expectation ([manifest verification](manifest-verification.md)). Data frames are not reread; every later read authenticates each frame by AEAD.
5. Publication (one SQL transaction): record the artifact, lineage, stored retention deadline and catalog association; settle the charge to actual size; write the `audit_event` row; NOTIFY listeners. A duplicate receipt resolves the same artifact; conflicting content is an error.
6. An unknown upload or commit outcome is resolved by looking up the attempt's idempotency key; the charge is released once the outcome is known.
7. At the stored deadline new and resumed access is refused. Deletion removes data, index, manifest, commit, noncurrent versions and incomplete multipart uploads, checks absence with one listing, then marks the artifact deleted, releases its charge and writes the audit row in one transaction. Bucket lifecycle rules (`NoncurrentVersionExpiration`, `AbortIncompleteMultipartUpload`) are the backstop. KMS key rotation is not selective erasure.

[Custody transactions](custody-transactions.md) implement the copy registration and charge facets; [pod-status verification](manifest-verification.md) implements the native schema check for the context profile.
