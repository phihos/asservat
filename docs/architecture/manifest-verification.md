# Initial complete-manifest verification

Scope: C-14 evidence, C-15 privacy and C-21 adapters under I-05/I-09; incremental implementation of REQ-EVD-001–003, REQ-EVD-008, REQ-PRV-004 and S-01/S-02. This completes validation of one bounded evidence format, not authorized publication or the entire slice. See the [measured results](../research/manifest-foundation.md).

## Supported context profile

The initial profile is a manual `onTrigger` pod-status snapshot, `asservat-pod-status/v1`, at most 4096 native bytes. Its [native schema](../../specs/contracts/pod-status.schema.json) permits only pinned namespace/pod identity, resource version, observation time, finite phase/condition values and aggregate runtime/restart counts. It excludes labels, annotations, workload configuration, environment, logs, addresses, container names and free-text messages/reasons. Public scope remains the whole pod.

The full encrypted `artifact/v1` manifest includes exact case/occurrence and acquisition identities, the execution-class-specific target identity, namespace/workload/pod UIDs, collector/recipe/plan digests, immutable audience assignments, conservative privacy classification, purpose, retention inputs/deadlines and their policy provenance. The fixed projection definition is hashed and shared with the Kubernetes adapter. The native document must identify the expected namespace/pod, fall within the manifest's acquisition interval and have possible aggregate state counts.

Historical node-class manifests retain their required node UID/boot and byte representation. The explicit [Kubernetes API class](api-context-execution.md) carries `target.executionClass: kubernetesAPI`, forbids node UID/boot and is restricted to the fixed `pod-status` action and metadata projection. Removing its class never turns it into a valid node manifest.

The historical node profile accepts `raw` or `metadata` only when independently expected. Structural validity never promotes evidence to an approved extract. The initial classification is `potentialPersonalData` with a default classification source. Derived artifacts, policy-triggered or ongoing saves, partial files, cores, packets and runtime profiles still need their own semantic verification. The overall manifest schema retains these designed capabilities; this implementation rejects unsupported optional fields instead of silently ignoring them. It does not sign manifests or attest that a compromised source reported truthful status.

## Expected facts and responsibility

`artifact.ContextExpectation` holds independently resolved facts; it is not an authorization token. The accepted-execution/configuration owner must construct it using current actor/client/workload rights, accepted execution identity, immutable capture scope, retained audience and effective privacy policy. It must never copy those facts from the uploaded manifest or a public caller. In tests the fixture supplies synthetic control facts and reads exact target identity from its owned cluster.

The expectation binds to the existing storage registration. The subsequent [context admission](context-admission.md) now independently constructs and persists it with the frozen context scope, current complete audience and custody reservations. No full dispatch-to-verifier resolver or verifier-role bootstrap exists yet. These boundaries prevent claiming that equality with fixture inputs proves actual authorization, current group membership or collector image attestation.

## Verification order and limits

`evidence.ContextCustodian` checks the exact registration and current SQL deadline/configuration fence. It invokes `objectstore.ContextVerifier` outside transaction locks, bounded to 30 seconds or the earlier write deadline. The verifier uses its own key-opening capability; collectors still cannot decrypt old evidence.

1. Read the exact envelope object/version and check its recorded checksum/length. Validate `artifact-commit/v1`, then bind its IDs and manifest identity/checksum to the registered receipt.
2. Read and authenticate the exact encrypted manifest with the fixed manifest AAD. Validate the complete canonical schema before decoding explicit profile DTOs.
3. Match all supported control metadata to the independent expectation. Check exact retention arithmetic, source times, collection/projection provenance and data/index identities, hashes and sizes. Reject unsupported fields, substituted targets/audiences, later expiry and false completeness.
4. Open the exact encrypted index and data objects through the existing framed reader. Verify all streams, framing, native and ciphertext hashes; retain the small native document only in bounded verifier memory.
5. Validate the native schema and cross-check its identity, observation time and counts. Return success without exposing native bytes, keys or a disclosure capability.
6. Recheck SQL time/fences when storing the immutable four-copy receipts. Verification or SQL failure leaves the existing reservation charged and does not publish evidence.

The envelope is at most 32 KiB, decoded manifest at most 1 MiB, manifest ciphertext at most 1088 KiB, and native document at most 4096 bytes. Strict JSON parsing rejects duplicate keys, invalid Unicode, trailing documents, depth over 32, more than 32768 tokens and unsupported numbers before schema arithmetic. This integer-only profile accepts decimal signed-64-bit JSON numbers subject to tighter field constraints; future noninteger formats require an explicit profile change. It is not a general-purpose public JSON validation endpoint. Error messages contain allowlisted error codes, not validation excerpts or native content.

Nine canonical local schema resources (ADR-244 added `syscall-results.schema.json` for syscall JSON Lines events) are embedded with remote loading denied and format assertions enabled. `make manifest-schema-check`, also required by `make go-check`, checks byte-for-byte equality with the source schemas. After an intentional schema change, run `python3 scripts/manifest-schemas.py --write`, review the generated bundle, and rerun affected tests. No runtime schema network request is allowed.

## Unpublished remains unpublished

The result is still `stored_unpublished`. Both the older ciphertext-only custodian and this stronger context path can produce that state. There is no persisted semantic-verification verdict that a future publisher may blindly trust. Publication must independently obtain trusted accepted scope and establish the required full verification, current authority and durable audit outcome; a custody status or caller-supplied flag is insufficient.

No SQL migration, public interface, grant, UI/MCP tool or native-download session is added by this step. Existing conservative charges, expiration and writer-barrier requirements remain. Next implement accepted execution/current authorization and durable audit, then the authorized catalog commit and qualified writer fencing/deletion. Wire the developer's context inspection/download workflow only after those prerequisites pass.

The [context publication continuation](context-publication.md) now persists a separate semantic-verification fact, immutable encrypted verification-audit receipt and catalog association. Its coordinator always verifies the full chain rather than promoting generic custody. A production current-result/privacy gate and public delivery composition remain required. Earlier absence statements describe the original verification-only boundary.

[ADR-244](../decisions/244-native-artifact-types.md) makes the expectation, manifest and verifier type-aware through the artifact-type registry: PCAPNG, syscall JSON Lines and the HTTP header projection carry their own kind, evidence type, media type and format, recorder types omit the pod-status projection digest, and ongoing saves carry the complete `actionLifecycle` provenance (source session, snapshot, t0, requested window, history and window coverage, gap reasons, `sourceStoppedAt`, recording-save origin), all compared exactly with the independent expectation. A recorder artifact is verified by rereading every frame through its streaming native check (PCAPNG block structure, syscall events against `syscall-results.schema.json#/$defs/event` for the expected pod and interval, one strict JSON object for HTTP), bounded by 30 s plus 1 s per frame. Catalog publication of these types still waits for their admission (increment 4).
