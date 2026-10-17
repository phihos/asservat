# Local key foundation

Implements part of REQ-DEP-003 and the provider boundary of REQ-EVD-001 under [ADR-064](../decisions/064-local-key-material.md). C-21 owns these adapters; C-14's key ports remain unchanged, and C-02 still owns browser session behavior. This is a cryptographic backend implementation, **not an enabled local key service or a completed small deployment**.

## Implemented contracts

`kms.NewLocalKeyBackend` accepts an independently configured `LocalKeyScope` and an `io.Reader` containing the [private Secret payload](../../specs/contracts/local-key-secret.schema.json). It reads at most 16 KiB plus one overflow byte. It does not open arbitrary paths, fetch Kubernetes Secrets, generate replacement keys or discover ambient configuration. Missing/invalid material fails construction with a sanitized error. Parsing rejects duplicate/unknown/case-alias members, trailing values, unrecognized format, scope mismatch, invalid or duplicate versions, repeated or non-32-byte material, zero material and an absent primary. All temporary owned secret buffers are best-effort cleared; Go/library allocations do not promise physical zeroization.

The first three purposes (`artifact`, `audit`, `browser-credentials`) use Tink's existing XChaCha20-Poly1305 AEAD. Each keyset is 1–4096 bytes; the supplied canonical binding is 1–2048 bytes. The reference is exactly:

```text
asservat-local-keyset/v1/{installationUUID}/{purpose}/{keyID}/{decimalVersion}
```

The ciphertext field is canonical padded base64 of the library-produced nonce/ciphertext/tag. Canonical JSON associated data contains `format: asservat-local-keyset/v1`, the full `reference`, and `bindingSHA256`. That digest covers the exact caller binding bytes; the provider never normalizes a caller's artifact/session binding. Readers accept only a reference present in their immutable configured snapshot. No URL resolution or fallback key search. A changed installation, purpose, key ID, version, binding or ciphertext cannot disclose a keyset. Operations check context cancellation before and after cryptography.

`kms.NewLocalSigningKey` accepts only the `policy-submission` purpose, an explicitly selected active version and a pinned Ed25519 public key. Its seed must derive that exact public key. `ForContext` provides the standard `crypto.Signer` consumed by JWS, with a copied public key, 1–16384-byte input, pure Ed25519 only and cancellation. Private seeds never leave the backend. Both local and OpenBao signers reject a typed-nil `*ed25519.Options` without panicking; the regression was reproduced against the previous OpenBao implementation.

`BrowserCipher` now accepts application-owned `KeySealer` and `KeyOpener` ports. It retains `asservat-browser-credentials/v1`, its fresh Tink AEAD keyset and existing installation/issuer/client/row/version binding. External OpenBao callers retain the same constructors and behavior. The local backend's `policy-submission` seed cannot be loaded as an encryption key.

Missing, typed-nil and uninitialized local/OpenBao provider instances fail without panicking. The interface conversion exposed the old OpenBao nil-receiver assumption; a failing browser-envelope regression precedes its fix. This is configuration-error handling, not permission to run without a key provider.

## Role boundary and lifecycle still required

The backends hold root/private material. They are eligible only for the isolated key-service process. Tests directly join ports in one process to exercise ciphertext behavior; those fixtures are not production role composition. A struct exposing only `Seal` while retaining a root key in a collector would violate REQ-DEP-003.

[I-14](local-key-service.md) now adds authenticated remote wrap/unwrap/sign facets, bounded handler and current-authority coordination ports with real TLS/crypto tests. [ADR-066](download-key-authority.md) now supplies a current SQL resolver for audited context downloads. [ADR-067](local-key-lifecycle.md) now adds protected Secret loading, accepted revision/recovery fencing and per-installation distinct purpose/version fingerprints. Before runtime use, implement remaining current purpose/key/artifact authority resolvers, protected source enrollment/retirement, scoped PKI and local enrollment-secret delivery. Provider downtime, key retirement, rotation acknowledgement, backup/restore and lost-Secret recovery need real lifecycle tests. Avoid retaining a stale backend indefinitely after a revoked configuration. Root key removal is not per-artifact erasure.

Reconfiguration constructs a new immutable backend and does not mutate maps used by concurrent calls. Only the active version creates new wrappers/signatures; configured historical wrapping versions may decrypt retained material. Lowering/removing versions or activating an older snapshot is not authorized by this constructor: protected current configuration, durable acceptance and old-process fencing must enforce that lifecycle. No Helm value is accepted or silently ignored on the basis of these adapters.

## Verification scope

Unit/race tests cover malformed Secret input, scope/version/binding substitution, ciphertext tampering, cancellation, concurrent wrapping, random wrapper variation, reloading the serialized key snapshot, rotation preserving old reads and removed-key rejection. Composition tests use the real framed codec for empty, short and multi-frame native files, including a range spanning an 8 MiB boundary, and exercise browser credential envelopes through the provider ports. These tests use synthetic data and real cryptographic implementations, with in-process storage/authority fixtures. They do not establish Kubernetes Secret persistence, process fencing, TLS authorization, production backup recovery or a working login/download UI.

The owned S3 integration additionally stores encrypted data/index/manifest objects, reconstructs a local backend from serialized material, reads the stored manifest and recovers the exact 8,389,341-byte native file/hash and a cross-frame range. S3 is real and reached through the fixture TLS bridge; local root-key operations remain inside the test process. The existing Keycloak/PostgreSQL/OpenBao suite verifies external credential and submission-signing behavior after the provider-port changes. Both runs completed with unchanged source hashes and full fixture cleanup. Neither run is a small-profile deployment test.

Actual gate and external-provider regression outcomes are maintained in [implementation progress](../implementation-progress.md). No passing static/schema/codec check completes REQ-DEP-003 or S-01/S-02.
