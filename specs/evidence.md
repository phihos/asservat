# Evidence storage, cases and analysis

## REQ-EVD-001 — Encryption and integrity

Every artifact MUST be encrypted at its collection node before transmission outside that node. Use a reviewed streaming-AEAD library, proposed Tink Go AES-GCM-HKDF streaming, with a fresh keyset per object. Compress before encrypting where useful. Bind cluster UUID, artifact ID, schema version and media type as canonical associated data. Never implement an ad hoc nonce/chunk protocol.

Wrap the keyset using the selected KMS adapter; the collector role may wrap/encrypt, not unwrap/decrypt old evidence. Keys are generated from the OS CSPRNG and wrapped before collection starts. A backend data-key API MAY be used only if it produces the exact required key representation. Zero/best-effort clear short-lived key buffers; do not claim Go garbage collection guarantees physical zeroization.

The selected key provider may be external or the planned local static-key service under [REQ-DEP-003](deployment-profiles.md#req-dep-003--local-key-services-with-unchanged-evidence-isolation). That alternative preserves artifact bindings, purpose separation and wrap-only collection. It is not permission to distribute a shared evidence-decryption key to hub/collector pods or store plaintext managed evidence.

ADR-048 fixes the first product storage layout as [`asservat-framed/v1`](../docs/architecture/artifact-format.md): independently authenticated 8 MiB native frames, bounded encrypted index pages and a separately keyed manifest. These are complete library-managed Tink streams, not custom AEAD chunks. Encrypted detailed manifests bind their layout totals/native hashes to the outer artifact fields and exact immutable object identities. Wrap all physical-object keysets before acquisition; key wrapping must not require a collector decrypt self-check. The earlier single-stream format name is not an alias and is unsupported by the new reader.

This is envelope encryption: the key provider processes bounded keysets, never the core, PCAP, profile or other evidence payload. For this format, preparing an artifact attempt wraps exactly three fresh keysets (data, index, manifest), each at most 4096 bytes, independently of native size or frame count. Compression, payload encryption and upload run locally; ciphertext goes directly to the configured object store. Opening all three objects unwraps their keys once for that reader; subsequent frame/range reads on the reader perform no key-service calls. A new reader/attempt, derivative, audit object or authentication operation may require additional calls. These are not installation-wide call-count or throughput guarantees. Keep key material within its authorized process lifetime; do not introduce cross-operation plaintext key caching to reduce service load.

Compute plaintext SHA-256 over the collected uncompressed bytes and ciphertext SHA-256 over the stored object. Hashes, full metadata and wrapped-key details belong in an encrypted detailed manifest; a minimal commit envelope exposes only opaque IDs, ciphertext digest/size, encryption format and necessary wrapped metadata-key reference. Never infer integrity from an S3 multipart ETag. [Tink primitive](https://developers.google.com/tink/streaming-aead), [Tink Go API](https://pkg.go.dev/github.com/tink-crypto/tink-go/v2/streamingaead).

### SC-EVD-001

Given a multi-part encrypted artifact, when any byte, associated-data field, segment order or final segment is altered, then decryption fails without releasing an unauthenticated result. Reusing a request ID does not reuse encryption material for a new object.

## REQ-EVD-002 — Commit protocol and partial artifacts

An upload MUST use a unique artifact/attempt ID and limited prefix credentials. Reserve worst-case bytes/object slots through the [capacity ledger](capacity.md) before acquisition; active attempts, versions and deletion-pending copies remain charged. A manifest expiry alone does not free quota. The collector may initiate/upload/complete/abort that artifact but may not read unrelated evidence or overwrite committed objects. Configure conditional creation and bucket policy where supported; verify the selected S3 backend's exact semantics.

Managed audit storage MUST use versioning with immutable, nonempty, non-`null` version identities. Successful audit receipts bind the exact committed version; current reads and verification MUST request that version rather than the mutable latest-key pointer. Runtime writers MUST be denied object/version deletion and versioning changes. Conditional creation remains required for bounded legitimate retries, but application behavior alone is not proof of backend permission enforcement. This is the accepted installation requirement; no extra audit gateway service is required.

A current provider-credential observation used by an audit operation MUST retain its original deadline through signed requests, response-body closure and verification. Credential expiration checked only before request signing is insufficient. Reusing that exact observation within one finite operation MUST NOT renew its interval or bypass independent current application/recovery checks. Private per-operation transports MUST remain within the accepted aggregate concurrency bound; expiration alone does not prove blocked I/O or verification has joined.

Reserve and account for all physical audit copies, including failed or unacknowledged writes, noncurrent/null versions, delete markers and unfinished multipart uploads. Independent retirement MUST enumerate every version and pending upload, delete or abort them under the original retention deadline, and verify complete absence after positive writer quiescence before releasing charges. A latest-key deletion or empty current-object listing is insufficient. Uncertain inventory/deletion remains charged and visible as unresolved cleanup. Versioning does not establish storage quota, and Object Lock MUST NOT prevent required early erasure or maximum retention. The [backend qualification record](../docs/research/audit-storage-qualification.md) distinguishes the accepted design from remaining installation, accounting and recovery tests.

Order: reserve ID → create durable intent → stream bounded bytes → finalize encryption/upload → commit encrypted manifest and envelope → commit a verified SQL artifact/catalog row and occurrence association → publish durable work → project controller status. Local outage collection keeps bounded durable completion references for later SQL synchronization; object commit alone does not make evidence discoverable at the hub. Each transition is idempotent. Immutable object keys are never reused. If completion acknowledgement is lost, reconciliation checks object identity/digest through a separate verifier role; the writer does not gain read access.

A source truncated intentionally at a limit can form a valid encrypted object while containing an incomplete diagnostic file. Record these two completeness dimensions separately. Interrupted ciphertext that lacks a valid final segment MUST NOT be presented as a valid partial artifact; abort it or salvage only independently authenticated segments under a new explicit artifact format. Never silently concatenate attempts.

### SC-EVD-002

Given a successful S3 completion followed by a lost controller response, when reconciliation runs, then one artifact becomes visible. An unfinished multipart upload is eventually aborted and never appears as `Complete`.

## REQ-EVD-003 — Manifest and provenance

Manifests MUST include immutable IDs and schema version, target identity, desired/observed image identity and certainty, trigger/plan digests, timings, collection method/tool digests, byte/packet counts, truncation/gaps, checksums, encryption references, sensitivity, privacy class/purpose, retention policy provenance and deadlines, transformations and parent artifact digests. `collectionProvenance` binds acquisition capture UID, action ID and immutable resolved plan digest. It is required for acquired artifacts; derived outputs carry it only when all parents have that same origin. Mixed-origin derivatives instead retain the complete parent graph and cannot enter automatic result sharing. A versioned approved extract also records provenance.projectionDigest covering its exact projection/configuration. collector.policyDigest is present only when a policy applies; manual captures do not invent one. Record unknown build IDs/source revision explicitly, not as guessed values. Encrypted manifests also record immutable permission audience/source provenance under [permission management](permissions.md), so changing namespace ownership does not silently expose old evidence.

Manifest target.scope distinguishes pod, runtimeSource and process provenance. Pod-network/aggregate context has no invented container/PID/image; per-source artifacts identify their runtime instance, and process artifacts additionally require host PID/start time. Emit separate bounded source artifacts or an encrypted bounded member record for pod aggregates; all members remain under the same pod/action budget and retained audience.

The first implemented native context projection is [`asservat-pod-status/v1`](contracts/pod-status.schema.json): at most 4096 bytes of fixed identity/status/count fields, without labels, workload configuration, free-text messages or container names. Its complete manifest is checked against independently resolved target, audience, capture, projection, privacy and retention facts, and its native identity/timing/counts are validated after authenticated decryption. The [initial verification contract](../docs/architecture/manifest-verification.md) restricts this implementation to manual `onTrigger` context. It does not narrow the product's other specified artifact types. The [context publication facet](../docs/architecture/context-publication.md) adds separate semantic verification, encrypted audit and catalog records; production current-result/privacy authority and public collection/disclosure wiring remain required.

`containerStatuses.imageID` is runtime-reported identity; it is not always a registry manifest digest suitable for pulling. Resolve the image via an authenticated registry/runtime adapter and record whether exact content was established. Image revision labels are supply-chain hints, not proof of source correspondence. Offline symbols are keyed by build ID/runtime identity and verified independently.

Signed manifest support MUST use offline-verifiable in-toto/DSSE statements and operator-held signing keys, with no mandatory public transparency-log traffic. Signing proves the stated collector identity and record integrity, not that a compromised host told the truth. [in-toto statements](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), [OCI image metadata](https://github.com/opencontainers/image-spec/blob/main/annotations.md).

### SC-EVD-003

Given a runtime imageID that cannot be mapped to a pullable digest, when analysis stages binaries, then it reports `ExactImageUnavailable` rather than substituting the latest tag. A signed record retains the original uncertainty.

## REQ-EVD-004 — Cases and recurrence

The first bounded implementation is [ordinary pod-status case navigation](../docs/architecture/context-cases.md), with a shared [browser/MCP projection](../docs/architecture/context-case-transport.md). It derives routing from verified publication and checks current ordinary rights, original audience and effective retention before returning metadata. Its immutable artifact version is distinct from the native file checksum. This subset does not implement recurrence, case editing, search, sharing or the public operation audit prerequisite described below and in REQ-AUT-005.

A case groups occurrences by cluster UUID, workload UID and a versioned signature/correlation policy. Store immutable occurrence payloads in encrypted object storage and content-minimized associations, aliases and catalog indexes in SQL. Case identity remains deterministic; transactional uniqueness replaces a mutable S3 case-head as hub authority. Start with a provisional signature; refine with normalized stack frames/build IDs or trigger features after analysis. Preserve aliases and original keys. Image upgrades SHOULD split crash signatures when build IDs differ; explicit case links may connect them.

SQL serves structured catalog filters and joins. Exact similarity and bounded full-text search over permitted extracts use separately protected regional rebuildable indexes; no extracted text/full manifests go into ordinary SQL backups. Indexes expire with their parent evidence. All counts, facets and results pass current authorization before delivery. No embeddings or model calls. Timeline entries preserve observed/source time and uncertainty; multi-node ordering is not assumed exact.

### SC-EVD-004

Given two crashes with the same workload/name but different binary builds, when analysis completes, then the system preserves both identities and uses versioned signatures. A search index rebuild reproduces all committed occurrence references without affecting grants.

## REQ-EVD-005 — Analysis isolation and output classes

The exact [ADR-206 pod-status projection](../docs/decisions/206-bounded-context-projection.md)
reads already committed, independently verified `asservat-pod-status/v1` metadata
through a fixed bounded formatter. It runs no general analyzer, creates no stored
derivative and uses no cross-Job scratch handoff. A purpose-scoped acquisition
worker performs verification/decryption; the hub receives only the approved DTO
and never an unwrap key. Query-specific current authority, finite charged read
batches, original deadlines, copy ownership and pre-disclosure audit are mandatory.
The exact query batch consumes its own data/index/manifest key roles under current
worker and live-request proof. Download grants and serialized worker proofs cannot
supply that authority. Local verification/buffer closure is distinct from positive
remote operation completion; uncertainty retains charges and blocks worker reuse.
After a fully written and flushed owned query response, HTTP completion without
additional application payload may use only the earlier of its original cleanup
and original request cutoffs. This does not extend payload disclosure: partial,
failed, unaudited and unowned responses retain their original write fences, and
cleanup remains synchronous with all slots held until joined. No fresh grace
interval or client-receipt claim is created by HTTP completion.
This narrow profile does not relax the following isolation and encrypted-scratch
requirements for offline analysis or other evidence formats. Its implementation
and native qualification remain pending.

Use separate acquisition, analysis and publication Jobs because network policy applies at pod scope. The acquisition Job receives one short-lived artifact-scoped decryption authorization, downloads the exact ciphertext and approved symbols/rootfs, verifies digests and writes bounded scratch. The analyzer has no credentials/token/network, runs non-root with read-only root filesystem, dropped capabilities, seccomp and resource/time/PID limits. Its input mount is read-only; output is separate and bounded.

Separate Jobs cannot share emptyDir, including memory-backed emptyDir: it belongs to one Pod. For the separate-Job design, the currently specified feasible handoff is per-analysis qualified encrypted input/output PVCs; ordinary plaintext PVCs are disallowed. Job-private bounded tmpfs is permitted only within one phase, with pages charged separately from tool working memory. ADR-036 is accepted: a qualified encrypted scratch StorageClass is a required deployment prerequisite for first-release offline analysis. Installation can provide collection while that capability is unavailable; it must report the missing prerequisite explicitly. No storage-free cross-Job handoff is supported. [Kubernetes emptyDir](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir).

The encrypted-volume path requires fenced nonoverlapping phases: acquisition ends and releases writes before analyzer input mounts read-only; analyzer ends and releases writes before publication reads output. A qualified CSI ReadWriteOncePod mode may enforce exclusive mounting; ReadWriteOnce only constrains nodes and does not prevent concurrent Pods. Neither mode replaces readOnly mounts or controller fencing. Require verified old-writer termination/unmount before handoff; node-partition uncertainty blocks the next phase. Keep separate input/output volumes and do not give the analyzer service-account, KMS, object-store or network credentials. [Kubernetes access modes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes).

Register scratch copies and their earliest parent deadlines before writing plaintext. Provision only from an operator-qualified encrypted StorageClass with bounded capacity, understood key lifecycle/reclaim behavior and automatic snapshots/backups disabled unless separately admitted into the copy ledger. An independent reconciler handles failure, cancellation, node loss and expiry; Job TTL deletion or issuing PVC delete is not verified storage deletion. Unknown/retained backend copies remain charged and overdue. A missing/unqualified scratch path makes affected offline analysis unavailable with a visible reason, without discarding safely collected encrypted evidence. Do not collapse credentials and untrusted analysis into one Pod or rely on a NetworkPolicy change between phases to avoid this prerequisite.

Run tools from trusted digest-pinned analyzer images. Treat rootfs, binaries, debugger scripts, symbols and packet dissectors as untrusted input. Disable GDB init/auto-load and unapproved plugins; restrict tshark/Zeek scripts and external resolution. Built-in projections omit locals, raw memory, environment values and packet payload unless a matching raw query is authorized. A deterministic redaction pass follows projection; uncertain fields remain raw.

Offline analysis SHOULD use a qualified gVisor/Kata RuntimeClass where available; Restricted pods alone are not a complete parser exploit boundary. A default ordinary-container mode must document this residual risk and use dedicated analysis nodes for production-sensitive evidence. Analyzer jobs do not execute the target application's entrypoint. [GDB auto-loading](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading.html), [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

### SC-EVD-005

Given an ELF file with auto-load scripts or a malformed capture, when analysis runs, then no network, host filesystem or KMS credential is available, scripts do not auto-run, and resource exhaustion ends that job without making its output an approved extract.

## REQ-EVD-006 — Retention, holds and deletion

The [privacy specification](privacy.md) defines administrator maxima, conservative classification, age from first acquisition, parent deadlines and legal-exception policy. Proposed baseline maxima are 72 hours for evidence, 7 days for content-minimized case metadata and 90 days for audit; operators may set shorter defaults/limits by privacy class, type and workload. These are product defaults, not legal recommendations. `expiresAt` denies reads and starts cleanup; `deleteBy` is the storage deadline, with the deletion budget reserved inside the maximum. Holds require a separate authorized decision and cannot bypass the applicable cap or confer readership.

The retention reconciler MUST delete current/noncurrent object versions, index/cache copies, derived artifacts and stale multipart uploads, track failures and emit a tombstone. Release the associated storage charge only after verified copy/version deletion; preserve charges across retention-policy changes, workload deletion and holds. Bucket lifecycle is a backstop, not the sole exact deadline mechanism. A legal-hold feature is only advertised as storage-enforced when the backend supports and passes Object Lock tests. Otherwise label an application hold and its limitations. Held artifacts need lifecycle rules that cannot delete them prematurely.

The first [bounded context deletion implementation](../docs/architecture/context-deletion.md) additionally requires immutable positive writer completion, a purge result persisted before its original lease expires, and independent encrypted audit before releasing evidence storage. Metadata capacity remains charged; historical stored status or an empty backend inventory cannot substitute for the writer proof. This component does not complete general managed-copy deletion or restore reconciliation.

Shared Transit key rotation/deletion MUST NOT be advertised as per-case crypto-erasure. Strong selective erasure requires separately scoped KMS keys plus demonstrated destruction of backups/copies; this is optional future capability. Restoring backups MUST follow REQ-DB-005, replay tombstones, expiries and revoked grants and fence old execution authority before serving traffic. [S3 lifecycle](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html), [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html), [Transit](https://openbao.org/docs/secrets/transit/).

### SC-EVD-006

Given an expired artifact whose bucket deletion is delayed, when an owner or share recipient requests it, then access is denied. Restoring an older catalog backup cannot resurrect that access. A valid held artifact remains stored only within its permitted deadline, without granting access to the hold creator. An overdue/unreachable copy prevents a verified-deletion claim.

## Bucket layout

Opaque UUIDs avoid leaking namespace or service names in object keys. Each cluster can have a separate bucket and KMS policy; scoped prefixes and credentials are the minimum supported alternative. Hub audit and index objects use separate service permissions. Separate installations use distinct buckets or configured root prefixes and credentials; the layout below is relative to that configured root. There is no tenant directory hierarchy.

```text
v1/clusters/<cluster-uuid>/
  artifacts/<artifact-uuid>/<attempt-uuid>/data.enc
  artifacts/<artifact-uuid>/<attempt-uuid>/manifest.enc
  artifacts/<artifact-uuid>/<attempt-uuid>/commit.json
  occurrences/<occurrence-uuid>.enc
  cases/<case-uuid>/revisions/<revision-uuid>.enc
  tombstones/<artifact-uuid>.json
v1/audit/<writer-uuid>/<record-uuid>.enc
v1/indexes/<generation-uuid>/...
```

Plaintext commit envelopes/tombstones contain only opaque references and integrity/status fields. Case revision objects are immutable recovery/history records; SQL case associations are authoritative, with no mutable S3 case head. Case details and search terms are encrypted at rest. A region assignment must be in the registered storage profile, not chosen by an untrusted capture request.

## REQ-EVD-007 — Executable fidelity before the target disappears

Exact OCI images do not prove the bytes of a running executable: writable layers, mounted libraries, deleted executables and JIT code can differ. During collection record bounded executable/mapping build IDs and identity before process loss. A qualified runtime pack may reserve a bounded companion executable/symbol bundle from the approved pod scope when image content is insufficient; this is sensitive file evidence under the same acquisition grant, quota and earliest retention deadline, never an implicit whole-rootfs copy. Index bundles by verified content/build identity. Private image/symbol sources must retain exact objects for the evidence's useful lifetime, or pre-stage them within the approved cache budget. No public fallback or latest-tag substitution.

Analysis verifies each mapped executable/library; missing/mismatched files produce partial frames with SymbolUnavailable/BinaryMismatch. Image-backed files and observed live bytes have distinct certainty. Once the target is gone, the UI suggests supplying approved exact symbols or analysis-only retry, never recollection of a replacement pod. A profile comparison checks build/sample semantics and both deadlines; pinning a baseline in the UI is a reference, not a retention extension.

### SC-EVD-007

Given a process runs a mounted binary differing from its image and the pod is then deleted, when analysis uses the image alone, then it reports mismatch rather than symbolizing with the wrong file. A previously approved captured companion bundle may complete analysis within its inherited deadline; expiry cannot be bypassed by calling it a symbol cache.

New artifacts record actionLifecycle provenance under the [lifecycle contract](contracts/action-lifecycle.schema.json): actual execution mode, trigger origin/time and, for ongoing saves, source session/start, snapshot identity and requested/achieved history. Acquisition startedAt/completedAt remain actual timestamps and privacy deadlines begin at first observation. An artifact committed after a trigger may contain older authorized ring records; neither saving nor copying resets their retention. Source readiness is not evidence of lossless capture.

## REQ-EVD-008 — Close secondary plaintext and publication paths

Child-tool stdout/stderr, debugger errors and parser diagnostics may themselves contain evidence. Launch acquisition/analyzer tools with explicitly redirected, bounded pipes or qualified scratch files. Never inherit a service's container log descriptors, enable evidence-bearing command tracing, or copy arbitrary output into Kubernetes Events, termination messages, panic reports or ordinary audit/SQL metadata. Supervisors emit allowlisted reason codes and bounded numeric counters. Needed tool diagnostics are raw evidence with the same or earlier parent deadlines, encryption and authorization; buffer pressure truncates with a gap or stops the tool, never falls back to unprotected logs. Apply the same rule to discovery helpers and user commands.

Qualify evidence/key-handling processes against secondary core dumps and swap leakage. Disable process dumping under the actual host core-handler configuration and either prohibit swapping their plaintext pages or qualify encrypted swap with the same copy/expiry obligations. RLIMIT_CORE alone is insufficient with a piped core handler. Asservat process crashes must not recursively enter workload capture or an external host crash service. No blanket host change is authorized by this specification; enrollment records the required platform profile and blocks the affected capability if unmet. Privileged host administrators remain a trust boundary; do not claim protection from a compromised kernel. [Linux core handling](https://man7.org/linux/man-pages/man5/core.5.html).

A publication Job treats the analyzer output tree as hostile. After fenced writer termination, open only expected bounded regular files beneath the pinned output root, without following links or accepting hard-linked files, devices, sockets, FIFOs, traversal or substituted mount points. Enforce file count, size, decoding/time and aggregate quotas. The trusted publisher derives target, parent lineage, class, projection version and deadlines from its accepted plan and validated projection rules, not analyzer-provided filenames/metadata. Invalid or uncertain output remains raw/quarantined under original deadlines; it cannot promote itself to shareable extract. Encrypted managed diagnostic copies participate in the same copy ledger and cleanup.

### SC-EVD-008

Given a malformed core that makes a debugger print user bytes and an analyzer that writes a symlink named as an approved report, when the run fails/publishes, then normal pod logs and termination messages contain only safe reason codes, the link is rejected, and no extract is published. A worker crash creates no uncontrolled second core; swap/diagnostic/scratch copies are included in the qualified expiry and failure tests.

Every committed gathered artifact and saved derivative supports [native download](artifact-downloads.md), with exact bytes after removing the managed storage wrapper, full-file checksum, coverage and current authorization. Download uses bounded streaming unwrap in a separate regional acquisition Job mode, never granting keys to the hub or requiring an offline-analysis PVC. Native core companions remain individually authorized existing artifacts.
