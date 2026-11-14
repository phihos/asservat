# Manifest verification

Scope: C-14 evidence, C-15 privacy and C-21 adapters under I-05/I-09; part of REQ-EVD-001–003, REQ-EVD-008 and REQ-PRV-004. See the [foundation research](../research/manifest-foundation.md) and [ADR-330](../decisions/330-event-driven-system-design.md).

## Responsibilities

Integrity is checked where it is cheapest:

1. **Producer, before encryption.** The producer runs the structural check of its native type: pod-status schema, PCAPNG block structure, syscall events against `syscall-results.schema.json#/$defs/event` for the expected Pod and interval, one strict JSON object for the HTTP header projection. Output that fails is not uploaded.
2. **Writer, during upload.** Each object's SHA-256 is computed while streaming and sent as `x-amz-checksum-sha256`; the store rejects a mismatch ([custody](custody-transactions.md)).
3. **Regional reader, before publication.** `ContextVerifier` runs in A-READ, which holds the `download-reader` unwrap role, and reads and checks only the small objects: envelope, manifest and index.
4. **Reader.** Each data frame is authenticated by its AEAD tag when read. A failed tag ends the read with an error.

Publication never rereads or redecrypts data frames.

## Expected facts

`artifact.ContextExpectation` holds facts resolved independently of the upload: target namespace/workload/Pod UIDs, case/occurrence and acquisition identities, collector/recipe/plan digests, retained audience (stable group IDs), privacy classification, purpose, retention deadlines and their policy provenance, artifact type, and for ongoing saves the complete `actionLifecycle` provenance (source session, snapshot, t0, requested window, history and window coverage, gap reasons, `sourceStoppedAt`, recording-save origin). [Context admission](context-admission.md) stores it with the reservation. It is never copied from the uploaded manifest or a caller, and it is not an authorization token.

## Reader checks

The hub assigns verification of a stored outcome to the regional reader over its connection. `evidence.ContextCustodian` checks the registration and write deadline; the reader runs `ContextVerifier` outside transaction locks with a 30-second I/O bound:

1. Read the envelope object/version, compare its recorded checksum and length, validate `artifact-commit/v1` and bind its IDs and manifest checksum to the registration.
2. Decrypt the manifest with the fixed manifest AAD and validate it against the canonical schema.
3. Compare every control field with the expectation: target, audience, origin, classification, retention arithmetic, source times, projection provenance, type, and data/index identities, sizes and checksums. Reject unsupported fields, substituted targets or audiences, later expiry and false completeness.
4. Decrypt the index and check that its frame count, sizes and data checksum agree with the manifest.
5. For the 4096-byte pod-status profile only, the whole data object is one frame: decrypt it and check identity, observation time and counts against the expectation.

A failure publishes nothing; the stored objects stay charged until deletion removes them.

Limits: envelope ≤ 32 KiB, decoded manifest ≤ 1 MiB, manifest ciphertext ≤ 1088 KiB, pod-status document ≤ 4096 bytes. Strict JSON parsing rejects duplicate keys, invalid Unicode, trailing documents, depth over 32, more than 32768 tokens and non-integer numbers. Errors carry allowlisted codes, never content.

## Profiles

- **Pod status** (`asservat-pod-status/v1`, manual `onTrigger`, ≤ 4096 bytes). The [schema](../../specs/contracts/pod-status.schema.json) allows only namespace/Pod identity, resource version, observation time, finite phase/condition values and aggregate counts; no labels, annotations, environment, logs, addresses, container names or free text. The [Kubernetes API class](api-context-execution.md) sets `target.executionClass: kubernetesAPI` and has no node UID/boot.
- **Recorder types** (PCAPNG, syscall JSON Lines, HTTP header projection, [ADR-244](../decisions/244-native-artifact-types.md)) carry their own kind, evidence type, media type and format through the artifact-type registry and omit the pod-status projection digest.

Unsupported optional manifest fields are rejected, not ignored. Classification defaults to `potentialPersonalData`. Verification does not attest that a compromised source reported the truth.

## Schemas

Nine canonical schemas are embedded with remote loading denied and format assertions on. `make manifest-schema-check` (part of `make go-check`) checks them byte for byte against the sources. After a schema change, run `python3 scripts/manifest-schemas.py --write`, review the bundle and rerun affected tests.

## Result

The reader returns pass or an allowlisted failure code. [Context publication](context-publication.md) records the catalog association, the settled charge and the `audit_event` row in one transaction.
