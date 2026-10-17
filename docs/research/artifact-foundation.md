# Artifact foundation implementation record

Date: 2026-10-09. Scope: first product Go packages under the reviewed component layout. This is **not** a completed S-01 or S-02 investigation, a release or a deployed collector. The maintainer's continuation authorized starting the recommended artifact contract and context foundation.

Subsequent work is recorded in the [custody continuation](custody-foundation.md): initial product PostgreSQL backing/reservations, unpublished copy receipts and verified S3 cleanup now exist. The original results below remain historical evidence for their recorded source. Complete execution authority, audit and authorized publication remain pending.

The later [manifest continuation](manifest-foundation.md) adds complete authenticated pod-status manifest/native validation and a combined Kubernetes/OpenBao/S3/PostgreSQL test. This supersedes the descriptor-only limitation for that new profile; the original component test below retains its narrower purpose. Complete product authority/audit/publication remains pending.

The [persistent format](../architecture/artifact-format.md) and ADR-048 fix `asservat-framed/v1` for implementation. The codec uses independent 8 MiB native frames, paged encrypted indexes, fresh per-object Tink keysets, bounded native range delivery and final-batch withholding. The Go module uses the local unpublished name `asservat.local/asservat`; no public repository/domain or licence ownership is invented.

## Implemented components

| Boundary | Code and scope |
| --- | --- |
| C-24 domain | [Artifact values](../../internal/domain/artifact/storage.go): binding, structural limits, layout validation and worst-case data/index capacity. No protocol clients, clocks or persistence. |
| C-14 ports | [Evidence storage ports](../../internal/application/evidence/storage.go): distinct wrap-only/open-only capabilities, pinned ciphertext reads, bounded delivery and encoder contract. They do not implement authorization or durable commits. |
| C-21 format adapter | [Framed codec](../../internal/adapters/objectstore/framed/encode.go): streaming data/index encoding, strict bounded layout/index decoding, native full/range reads and separately keyed manifest wrapping. The caller must still validate the full detailed manifest and custody record. |
| C-21 KMS | [OpenBao adapter](../../internal/adapters/kms/transit.go): explicit HTTPS/configured key, maintained API client, bounded response, sanitized errors, binding checks and disjoint credential roles. No ambient token/namespace/proxy or plaintext fallback. |
| C-21 S3 | [Object adapter](../../internal/adapters/objectstore/s3.go): conditional small-object creation, exact version/ETag range reads and independent full ciphertext verification. Maximum write size 16 MiB; no production multipart uploader/deletion implementation yet. |
| C-21 Kubernetes | [Context projection](../../internal/adapters/kubernetes/context.go): read-only API snapshot of an exact pod/namespace/controller identity, finite enum/numeric aggregate status, no labels/spec/free-text messages/environment/logs. This is one approved projection candidate, not the whole `basic-context` recipe or node `/proc` collection. |

The only storage fakes and ephemeral local wrapping keys are in tests. There is no runnable hub/node role, permissive development server, command accepting arbitrary target paths or user-facing unauthenticated capture endpoint.

## Verification record

Initial codec execution passed empty/small/multiframe exact roundtrips, range reads, tampering, moved key bindings, single-use failure, overflow, delivery revocation and strict layout checks. A synthetic **2,147,483,721-byte** zero stream crossed the first 256-frame index page: its tail read fetched one encrypted page (381 bytes) and one encrypted frame (70 bytes). Those small byte counts result from synthetic compressible input and do not estimate real dump compression or production overhead.

Final real-service test **passed under `-race` on Go 1.27.2** in two fresh Kubernetes 1.37 fixture clusters. Each read-only ServiceAccount retrieved its exact synthetic pod projection; namespace denial and changed pod UID were rejected. The 352- and 353-byte native JSON artifacts were encrypted, conditionally created in real SeaweedFS S3, independently reread/hash-verified, and recovered through newly instantiated OpenBao readers with exact full/range byte equality. Real OpenBao policy denied writer decrypt and reader encrypt; a wrong binding failed and revoked writer credentials prevented new key preparation. The encrypted metadata in this component test is the storage descriptor, **not** a complete schema-validated `artifact/v1` record or a hub commit.

The [test log](../../test/results/context-storage.log) and [environment/source report](../../test/results/context-storage-environment.json) record exact images, actual exit 0, unchanged source during execution and successful cleanup. No owned cluster, S3/OpenBao container, anonymous service volume, token file or temporary kubeconfig remains. TLS bridges protect the adapter-facing connections; private fixture backend hops remain HTTP. OpenBao dev mode is in-memory and SeaweedFS is a test backend. This does not qualify persistent KMS recovery, Ceph, production storage IAM or TLS topology.

`make go-check go-architecture-check go-vuln-check` passed: vet, race tests including a 2 GiB page-boundary seek, real import mapping and no reachable known Go vulnerabilities. Unit tests also exercise TLS protocol bounds, hidden Kubernetes fields/free text, KMS ambient-credential isolation/redirect refusal, conditional/versioned S3 reads, absent/null fields and corrupt AEAD bytes even after all non-secret checksums are repaired. The reader rejects keysets outside the format’s exact AES256-GCM-HKDF/1 MiB suite before object reads. The external integration test is explicitly skipped in ordinary Go runs and was executed separately as above. Two 15-second bounded layout fuzz runs passed: 371130 executions on the earlier Go 1.27.1 toolchain and [395345 executions on Go 1.27.2](../../test/results/framed-fuzz-patched.log). These are bounded parser tests, not exhaustive cryptographic or distributed-system qualification.

The first vulnerability scan found five reachable x/net HTTP/2 advisories. The product minimum is now Go 1.27.2 and x/net v0.60.0; [the primary advisory](https://pkg.go.dev/vuln/GO-2026-6610) gives the patch floors. Final [verbose scanner output](../../test/results/govulncheck-verbose.log) reports zero affected code/imported packages, with one module-only advisory for the unmaintained `x/crypto/openpgp` package. Asservat does not import that package, no fixed version exists, and the Go architecture gate now explicitly forbids it in the transitive import graph. Maintained x/crypto primitives used by Tink and clients remain selected. This is a bounded known-vulnerability scan, not a security certification.

All seven existing design/contract gates passed after the schema changes: 42 schemas, 48 MCP tools, 154 examples, 171 requirements/scenarios, 11 tasks and 329 rejected invalid examples. There are no GUI changes or new browser-test claims. [Gate log](../../test/results/design-checks.log).

Earlier fixture failures remain recorded: wrong OpenBao executable path; Docker required setting memory and memory-swap together; the Kind image did not expose the expected pause-image repoDigest; and OpenBao key creation returned HTTP 200 rather than the fixture's expected 204. The first failure also exposed cleanup tracking after failed `docker run`; the harness now records created containers before starting them. The leftover failed-start container was identified by its exact test label and removed. These attempts were not reported as passing integration tests.


## Remaining before an end-user context capture

S-01/S-02 still require actual role composition; identity/current entitlement and independently scoped storage IAM; Kubernetes configuration/local control and signed peer work; durable audit/intents/copy ledger/capacity; production SQL migrations/commit/recovery; expiry and verified version/multipart cleanup; central two-connector behavior; authenticated bounded relay/HTTP download sessions; React and MCP wiring. Native byte decoding alone is not an authorized download endpoint. The tests must not present a local mock as an alternate authority backend.

The larger packet/syscall/core capabilities retain their separate qualification gates. This pass changes no GUI mockups and enables no intrusive mechanism. A new format does not waive parser isolation, plaintext-process/swap qualification, backend outage/recovery or production key lifecycle tests.
