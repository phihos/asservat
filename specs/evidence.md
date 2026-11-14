# Evidence storage, cases and analysis

## REQ-EVD-001 — Encryption and integrity

Every artifact MUST be encrypted at its collection node before transmission outside that node. Use a reviewed streaming-AEAD library, proposed Tink Go AES-GCM-HKDF streaming, with a fresh keyset per object. Compress before encrypting where useful. Bind cluster UUID, artifact ID, schema version and media type as canonical associated data. Never implement an ad hoc nonce/chunk protocol.

Wrap the keyset using the selected KMS adapter; the collector role may wrap/encrypt, not unwrap/decrypt old evidence. Keys are generated from the OS CSPRNG and wrapped before collection starts. A backend data-key API MAY be used only if it produces the exact required key representation. Zero/best-effort clear short-lived key buffers; do not claim Go garbage collection guarantees physical zeroization.

The selected key provider may be external or the local static-key service under [REQ-DEP-003](deployment-profiles.md#req-dep-003--local-key-services-with-unchanged-evidence-isolation). That alternative preserves artifact bindings, purpose separation and wrap-only collection. It is not permission to distribute a shared evidence-decryption key to hub/collector pods or store plaintext managed evidence.

ADR-048 fixes the storage layout as [`asservat-framed/v1`](../docs/architecture/artifact-format.md): independently authenticated 8 MiB native frames, bounded encrypted index pages and a separately keyed manifest. These are complete library-managed Tink streams, not custom AEAD chunks. Encrypted detailed manifests bind their layout totals/native hashes to the outer artifact fields and exact immutable object identities. Wrap all physical-object keysets before acquisition; key wrapping must not require a collector decrypt self-check.

This is envelope encryption: the key provider processes bounded keysets, never the core, PCAP, profile or other evidence payload. Preparing an artifact attempt wraps exactly three fresh keysets (data, index, manifest), each at most 4096 bytes, independently of native size or frame count. Compression, payload encryption and upload run locally; ciphertext goes directly to the configured object store. The [regional reader](#req-evd-005--analysis-isolation-and-output-classes) unwraps an artifact's three keysets once and MAY keep the unwrapped keys in process memory for that artifact until the earliest `AccessUntil` of the operations using it or a short idle timeout; frame and range reads under a cached key perform no key-service calls. Unwrapped keys never leave the reader process and are never written to disk, SQL or logs.

Compute plaintext SHA-256 over the collected uncompressed bytes and ciphertext SHA-256 over the stored object. Hashes, full metadata and wrapped-key details belong in an encrypted detailed manifest; a minimal commit envelope exposes only opaque IDs, ciphertext digest/size, encryption format and necessary wrapped metadata-key reference. Never infer integrity from an S3 multipart ETag. [Tink primitive](https://developers.google.com/tink/streaming-aead), [Tink Go API](https://pkg.go.dev/github.com/tink-crypto/tink-go/v2/streamingaead).

### SC-EVD-001

Given a multi-part encrypted artifact, when any byte, associated-data field, segment order or final segment is altered, then decryption fails without releasing an unauthenticated result. Reusing a request ID does not reuse encryption material for a new object.

## REQ-EVD-002 — Commit protocol and partial artifacts

An upload MUST use a unique artifact/attempt ID, an operation ID ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D7) and limited prefix credentials. Admission charges the worst-case bytes/object count to the workload's counters in the [capacity specification](capacity.md); the charge is adjusted to the committed size on commit and released on abort or when the operation reaches a terminal outcome without a committed object. The collector may initiate/upload/complete/abort that artifact but may not read unrelated evidence or overwrite committed objects. Configure conditional creation and bucket policy where supported. Buckets carry an `AbortIncompleteMultipartUpload` lifecycle rule so abandoned parts disappear without an application inventory.

Order: reserve ID → stream bounded bytes → finalize encryption/upload → commit encrypted manifest and envelope → the regional reader verifies the envelope and decrypts and checks the manifest and index against the stored expectation (data frames are not reread; each frame is authenticated by AEAD on every read) → in one SQL transaction insert the artifact/catalog row with its stored deadlines, settle the charge to the committed size, add its occurrence association and its `audit_event` row, then `NOTIFY` interested hub processes. Local outage collection keeps bounded durable completion references for later SQL synchronization; object commit alone does not make evidence discoverable at the hub. Each transition is idempotent under the operation ID. Immutable object keys are never reused. If the completion acknowledgement is lost, the retry looks up the operation ID and checks object identity/digest; the writer does not gain read access.

A source truncated intentionally at a limit can form a valid encrypted object while containing an incomplete diagnostic file. Record these two completeness dimensions separately. Interrupted ciphertext that lacks a valid final segment MUST NOT be presented as a valid partial artifact; abort it or salvage only independently authenticated segments under a new explicit artifact format. Never silently concatenate attempts.

Security-relevant evidence operations write one append-only `audit_event` row in the effect's transaction (ADR-330 D6); the operation fails if the row cannot be written. Rows are exported in batches to the object store or a SIEM; the optional export bucket may use Object Lock within the audit maximum. Audit retention drops whole time partitions.

### SC-EVD-002

Given a successful S3 completion followed by a lost controller response, when the operation is retried with the same operation ID, then one artifact becomes visible and the charge matches its committed size. An unfinished multipart upload is removed by the bucket lifecycle rule and never appears as `Complete`.

## REQ-EVD-003 — Manifest and provenance

Manifests MUST include immutable IDs and schema version, target identity, desired/observed image identity and certainty, trigger/plan digests, timings, collection method/tool digests, byte/packet counts, truncation/gaps, checksums, encryption references, sensitivity, privacy class/purpose, retention policy provenance and deadlines, transformations and parent artifact digests. `collectionProvenance` binds acquisition capture UID, action ID and immutable resolved plan digest. It is required for acquired artifacts; derived outputs carry it only when all parents have that same origin. Mixed-origin derivatives instead retain the complete parent graph and cannot enter automatic result sharing. A versioned approved extract also records provenance.projectionDigest covering its exact projection/configuration. collector.policyDigest is present only when a policy applies; manual captures do not invent one. Record unknown build IDs/source revision explicitly, not as guessed values. Manifests also record the permission audience as stable identity-provider group IDs and subjects under [permission management](permissions.md), so changing namespace ownership does not silently expose old evidence.

Manifest target.scope distinguishes pod, runtimeSource and process provenance. Pod-network/aggregate context has no invented container/PID/image; per-source artifacts identify their runtime instance, and process artifacts additionally require host PID/start time. Emit separate bounded source artifacts or an encrypted bounded member record for pod aggregates; all members remain under the same pod/action budget and retained audience.

The native context projection [`asservat-pod-status/v1`](contracts/pod-status.schema.json) holds at most 4096 bytes of fixed identity/status/count fields, without labels, workload configuration, free-text messages or container names. Its manifest is checked against the resolved target, audience, capture, projection, privacy and retention facts, and its native identity/timing/counts are validated after authenticated decryption, before publication.

`containerStatuses.imageID` is runtime-reported identity; it is not always a registry manifest digest suitable for pulling. Resolve the image via an authenticated registry/runtime adapter and record whether exact content was established. Image revision labels are supply-chain hints, not proof of source correspondence. Offline symbols are keyed by build ID/runtime identity and verified independently.

Signed manifest support MUST use offline-verifiable in-toto/DSSE statements and operator-held signing keys, with no mandatory public transparency-log traffic. Signing proves the stated collector identity and record integrity, not that a compromised host told the truth. [in-toto statements](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), [OCI image metadata](https://github.com/opencontainers/image-spec/blob/main/annotations.md).

### SC-EVD-003

Given a runtime imageID that cannot be mapped to a pullable digest, when analysis stages binaries, then it reports `ExactImageUnavailable` rather than substituting the latest tag. A signed record retains the original uncertainty.

## REQ-EVD-004 — Cases and recurrence

A case groups occurrences by cluster UUID, workload UID and a versioned signature/correlation policy. Cases, occurrences, associations, aliases, case details and catalog indexes are SQL rows (ADR-330 D8); SQL is authoritative and backed up with pgBackRest. Evidence bytes stay in encrypted object storage. Case identity is deterministic with transactional uniqueness. Start with a provisional signature; refine with normalized stack frames/build IDs or trigger features after analysis. Preserve aliases and original keys. Image upgrades SHOULD split crash signatures when build IDs differ; explicit case links may connect them. Case navigation is shared by browser and MCP and returns metadata only after current ordinary rights, the original audience and effective retention permit it.

SQL serves structured catalog filters and joins. Exact similarity and bounded full-text search over permitted extracts use separately protected regional rebuildable indexes; no extracted text/full manifests go into ordinary SQL backups. Indexes expire with their parent evidence. All counts, facets and results pass current authorization before delivery. No embeddings or model calls. Timeline entries preserve observed/source time and uncertainty; multi-node ordering is not assumed exact.

### SC-EVD-004

Given two crashes with the same workload/name but different binary builds, when analysis completes, then the system preserves both identities and uses versioned signatures. A search index rebuild reproduces all committed occurrence references without affecting grants.

## REQ-EVD-005 — Analysis isolation and output classes

Downloads and stored-evidence queries are served by the **regional reader** (A-READ): a long-running Deployment per evidence region (part of the hub Deployment in combined mode), scaled by replicas ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D4). It has its own ServiceAccount, authenticates to the hub with an audience-bound projected ServiceAccount token checked once per connection by TokenReview, then uses mTLS on that connection. It receives work (download streams, query pages) over that connection together with the hub's authorization decision for the operation, reads exact objects and unwraps their keysets through the key service, which authorizes the reader's mTLS identity and the keyset's AEAD binding (no per-operation ticket), and serves many operations concurrently. No Kubernetes Job, certificate or key slot is created per download or query. The hub never receives an unwrap key or raw parser input; it receives native bytes for an authorized download or the approved query projection.

The fixed [pod-status projection](../docs/decisions/206-bounded-context-projection.md) reads committed, verified `asservat-pod-status/v1` metadata through a fixed bounded formatter in the reader. It runs no general analyzer and creates no stored derivative.

[ADR-286](../docs/decisions/286-bounded-go-analyzer-isolation.md) lets the reader run explicitly qualified, maintained Go analyzers that only interpret data and produce a closed bounded projection. The analyzer shares the reader's process and credentials; there is no intra-process security boundary. Each admitted query MUST have finite compressed/native input, decompressed input, parser work/structure, output and elapsed-time limits, within the reader container's memory and CPU limits. Enforce byte limits before growing buffers and bound parser structures where the library permits. Where a maintained parser allocates before validating object counts, input bounds and the container memory limit are the containment boundary. Qualification MUST measure peak process memory under adversarial maximum inputs, including decompression and reply buffers. `GOMEMLIMIT` is a soft GC target, not a per-query limit.

These analyzers MUST NOT invoke a shell, spawn tools, load plugins, execute scripts or evidence-supplied code, open evidence-selected host paths, fetch URLs, or perform symbol lookup over the network. Their parser API receives only bounded data and approved query parameters, with no network or credential callbacks. Evidence cannot choose destinations. Local symbols, when supported, must be independently authorized, digest-bound inputs. The operation's single authorization ([ADR-311](../docs/decisions/311-operation-authority-recheck.md), ADR-330 D5) covers its artifact versions, quota and raw-query grant; a library return never establishes authority or extract classification. Output is checked against the operation's closed projection and byte/field limits before disclosure.

Cancellation closes delivery immediately and cancels the parser's context. A parser that does not return keeps its concurrency slot until it returns; a reader whose slots stay held past the operation deadline is restarted by its liveness probe. OOM, panic and deadline produce no approved result. Plaintext remains bounded transient memory, with the core/swap protections of REQ-EVD-008; the reader creates no scratch file, stored derivative or plaintext cache other than the in-memory data keys of REQ-EVD-001.

Use separate acquisition, analysis and publication Jobs for native-code analyzers, external tools, or any execution of evidence-supplied content. Network policy applies at pod scope. The acquisition Job unwraps only the exact artifact's keysets, downloads the exact ciphertext and approved symbols/rootfs, verifies digests and writes bounded scratch. The analyzer has no credentials/token/network, runs non-root with read-only root filesystem, dropped capabilities, seccomp and resource/time/PID limits. Its input mount is read-only; output is separate and bounded.

Separate Jobs cannot share emptyDir: it belongs to one Pod. ADR-036 is accepted: the handoff uses per-analysis encrypted input/output PVCs from an operator-qualified encrypted scratch StorageClass, a deployment prerequisite for this analysis class including native debugger tools. Ordinary plaintext PVCs are disallowed. Job-private bounded tmpfs is permitted only within one phase. Bounded Go reader projections do not need scratch PVCs. Installation can provide collection while the prerequisite is missing; affected offline analysis is reported unavailable with a visible reason, without discarding collected encrypted evidence. [Kubernetes emptyDir](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir).

Phases do not overlap: the next phase starts after the previous Job has completed, and scratch volumes use `ReadWriteOncePod` where the CSI driver supports it, with readOnly mounts for consumers. Keep separate input/output volumes and do not give the analyzer service-account, KMS, object-store or network credentials. [Kubernetes access modes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes).

Scratch PVCs are owned by the analysis operation and deleted when it ends, at the latest at the earliest parent retention deadline. The StorageClass uses `reclaimPolicy: Delete`, bounded capacity and no automatic snapshots/backups. For the separate-Job class, do not collapse credentials and untrusted analysis into one Pod. The bounded Go reader exception above does not authorize such tools.

Run tools from trusted digest-pinned analyzer images. Treat rootfs, binaries, debugger scripts, symbols and packet dissectors as untrusted input. Disable GDB init/auto-load and unapproved plugins; restrict tshark/Zeek scripts and external resolution. Built-in projections omit locals, raw memory, environment values and packet payload unless a matching raw query is authorized. A deterministic redaction pass follows projection; uncertain fields remain raw.

Offline analysis SHOULD use a qualified gVisor/Kata RuntimeClass where available; Restricted pods alone are not a complete parser exploit boundary. A default ordinary-container mode must document this residual risk and use dedicated analysis nodes for production-sensitive evidence. Analyzer jobs do not execute the target application's entrypoint. [GDB auto-loading](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading.html), [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

### SC-EVD-005

Given an ELF file with auto-load scripts or a capture passed to a native tool,
when analysis runs, then the separate analyzer has no network, host filesystem or
KMS credential, scripts do not auto-run, and resource exhaustion ends that job
without making its output an approved extract.

Given a qualified Go analyzer in the regional reader with a hostile
compressed profile or packet file, when its input, parser-work, output or time
bound is exceeded, then no partial or late output becomes an approved result.
Test maximum-shape inputs, OOM and cancellation during parsing; verify the
process's actual resource use, absence of symbol/URL requests, child processes and
evidence-bearing logs. An expired, revoked or mismatched artifact cannot be read
through a parser retry. An unqualified analyzer stays unavailable; successful
small fixtures do not establish the configured maximum.

## REQ-EVD-006 — Retention, holds and deletion

The [privacy specification](privacy.md) defines administrator maxima, conservative classification, age from first acquisition, parent deadlines and legal-exception policy. Proposed baseline maxima are 72 hours for evidence, 7 days for content-minimized case metadata and 90 days for audit; operators may set shorter defaults/limits by privacy class, type and workload. These are product defaults, not legal recommendations. `expiresAt` denies reads and starts cleanup; `deleteBy` is the storage deadline. Holds require a separate authorized decision and cannot bypass the applicable cap or confer readership.

Each artifact row stores its effective `expiresAt`/`deleteBy` (ADR-330 D12). A retention policy change arrives as an event and applies any shorter deadline with one SQL update per affected set; deadlines never move later than the stored value. Reads, downloads and deletion use the stored deadlines; a started download stops at its `AccessUntil` (ADR-312).

The retention reconciler is driven by the stored deadlines. It deletes every object and version under the artifact's prefix, index/cache copies and derived artifacts, records failures for retry and writes a SQL tombstone and audit row. Release the storage charge when the object deletes succeed; preserve charges across retention-policy changes, workload deletion and holds. Bucket lifecycle is a backstop, not the sole deadline mechanism. A legal hold is advertised as storage-enforced only when the backend supports and passes Object Lock tests; otherwise it is an application hold with stated limitations. Held artifacts need lifecycle rules that cannot delete them prematurely.

Shared Transit key rotation/deletion MUST NOT be advertised as per-case crypto-erasure. Strong selective erasure requires separately scoped KMS keys plus demonstrated destruction of backups/copies; this is optional future capability. Restoring a backup MUST follow REQ-DB-005 and replay SQL tombstones, expiries and revoked grants before serving traffic. [S3 lifecycle](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html), [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html), [Transit](https://openbao.org/docs/secrets/transit/).

### SC-EVD-006

Given an expired artifact whose bucket deletion is delayed, when an owner or share recipient requests it, then access is denied. Restoring an older catalog backup cannot resurrect that access. A valid held artifact remains stored only within its permitted deadline, without granting access to the hold creator. A failed object deletion stays visible as overdue and is retried.

## Bucket layout

Opaque UUIDs avoid leaking namespace or service names in object keys. Each cluster can have a separate bucket and KMS policy; scoped prefixes and credentials are the minimum supported alternative. Index objects and audit exports use separate service permissions. Separate installations use distinct buckets or configured root prefixes and credentials; the layout below is relative to that configured root. There is no tenant directory hierarchy.

```text
v1/clusters/<cluster-uuid>/
  artifacts/<artifact-uuid>/<attempt-uuid>/data.enc
  artifacts/<artifact-uuid>/<attempt-uuid>/manifest.enc
  artifacts/<artifact-uuid>/<attempt-uuid>/commit.json
v1/audit-export/<partition>/<batch-uuid>.jsonl.zst
v1/indexes/<generation-uuid>/...
```

Plaintext commit envelopes contain only opaque references and integrity/status fields. Cases, occurrences and tombstones live in SQL. Extracted search text in indexes is encrypted at rest. A region assignment must be in the registered storage profile, not chosen by an untrusted capture request.

## REQ-EVD-007 — Executable fidelity before the target disappears

Exact OCI images do not prove the bytes of a running executable: writable layers, mounted libraries, deleted executables and JIT code can differ. During collection record bounded executable/mapping build IDs and identity before process loss. A qualified runtime pack may reserve a bounded companion executable/symbol bundle from the approved pod scope when image content is insufficient; this is sensitive file evidence under the same acquisition grant, quota and earliest retention deadline, never an implicit whole-rootfs copy. Index bundles by verified content/build identity. Private image/symbol sources must retain exact objects for the evidence's useful lifetime, or pre-stage them within the approved cache budget. No public fallback or latest-tag substitution.

Analysis verifies each mapped executable/library; missing/mismatched files produce partial frames with SymbolUnavailable/BinaryMismatch. Image-backed files and observed live bytes have distinct certainty. Once the target is gone, the UI suggests supplying approved exact symbols or analysis-only retry, never recollection of a replacement pod. A profile comparison checks build/sample semantics and both deadlines; pinning a baseline in the UI is a reference, not a retention extension.

### SC-EVD-007

Given a process runs a mounted binary differing from its image and the pod is then deleted, when analysis uses the image alone, then it reports mismatch rather than symbolizing with the wrong file. A previously approved captured companion bundle may complete analysis within its inherited deadline; expiry cannot be bypassed by calling it a symbol cache.

New artifacts record actionLifecycle provenance under the [lifecycle contract](contracts/action-lifecycle.schema.json): actual execution mode, trigger origin/time and, for ongoing saves, source session/start, snapshot identity and requested/achieved history. Acquisition startedAt/completedAt remain actual timestamps and privacy deadlines begin at first observation. An artifact committed after a trigger may contain older authorized ring records; neither saving nor copying resets their retention. Source readiness is not evidence of lossless capture.

## REQ-EVD-008 — Close secondary plaintext and publication paths

Child-tool stdout/stderr, debugger errors and parser diagnostics may themselves contain evidence. Launch acquisition/analyzer tools with explicitly redirected, bounded pipes or qualified scratch files. Never inherit a service's container log descriptors, enable evidence-bearing command tracing, or copy arbitrary output into Kubernetes Events, termination messages, panic reports or ordinary audit/SQL metadata. Supervisors emit allowlisted reason codes and bounded numeric counters. Needed tool diagnostics are raw evidence with the same or earlier parent deadlines, encryption and authorization; buffer pressure truncates with a gap or stops the tool, never falls back to unprotected logs. Apply the same rule to discovery helpers and user commands.

Qualify evidence/key-handling processes (collector, regional reader, analysis Jobs) against secondary core dumps and swap leakage. Disable process dumping under the actual host core-handler configuration and either prohibit swapping their plaintext pages or qualify encrypted swap. RLIMIT_CORE alone is insufficient with a piped core handler. Asservat process crashes must not recursively enter workload capture or an external host crash service. No blanket host change is authorized by this specification; the Helm values declare the required platform profile and the affected capability stays unavailable when it is unmet. Privileged host administrators remain a trust boundary; do not claim protection from a compromised kernel. [Linux core handling](https://man7.org/linux/man-pages/man5/core.5.html).

A publication Job treats the analyzer output tree as hostile. After the analyzer Job has completed, open only expected bounded regular files beneath the pinned output root, without following links or accepting hard-linked files, devices, sockets, FIFOs, traversal or substituted mount points. Enforce file count, size, decoding/time and aggregate quotas. The trusted publisher derives target, parent lineage, class, projection version and deadlines from its accepted plan and validated projection rules, not analyzer-provided filenames/metadata. Invalid or uncertain output remains raw/quarantined under original deadlines; it cannot promote itself to shareable extract. Encrypted managed diagnostic copies follow the same retention deadlines and deletion.

### SC-EVD-008

Given a malformed core that makes a debugger print user bytes and an analyzer that writes a symlink named as an approved report, when the run fails/publishes, then normal pod logs and termination messages contain only safe reason codes, the link is rejected, and no extract is published. A reader or Job crash creates no uncontrolled second core; swap/diagnostic/scratch copies are included in the expiry and failure tests.

Every committed gathered artifact and saved derivative supports [native download](artifact-downloads.md), with exact bytes after removing the managed storage wrapper, full-file checksum, coverage and current authorization. Download streams through the regional reader, never granting keys to the hub or requiring an offline-analysis PVC. Native core companions remain individually authorized existing artifacts.
