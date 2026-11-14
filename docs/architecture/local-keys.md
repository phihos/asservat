# Local key material

Implements the local provider of REQ-DEP-003 and REQ-EVD-001 under [ADR-064](../decisions/064-local-key-material.md). C-21 owns these adapters; only the [local key service](local-key-service.md) loads them.

## Source and reload

The Helm `secrets` Job creates the key Secret once if it is missing. The Secret contains only `keys.json`, closed by the [private Secret schema](../../specs/contracts/local-key-secret.schema.json), at most 16 KiB. The key service mounts it read-only; no other workload mounts it. The service rejects a key file readable by group or world ([security evidence review](../reviews/security-evidence-2026-11-13.md), item 9f).

The service watches the mounted file (kubelet replaces it with an atomic symlink swap) and builds a new immutable backend on change. A reload is accepted only if every version loaded before is still present with identical bytes and the active version did not decrease. A rejected reload is logged and the current backend stays in use. Concurrent calls keep the backend they started with. Nothing in SQL or Kubernetes acts as a second ledger for key versions (ADR-330 D1).

## Format

`kms.NewLocalKeyBackend` takes the configured `LocalKeyScope` and an `io.Reader` with the payload, reading at most 16 KiB plus one overflow byte. Parsing rejects duplicate, unknown or case-alias members, trailing values, unknown format, scope mismatch, invalid or duplicate versions, repeated, zero or non-32-byte material, keys reused across purposes and a missing active version. Invalid material fails construction with a sanitized error. Owned secret buffers are cleared as best effort; Go and library allocations are not guaranteed to be zeroed.

Purposes are `artifact` and `browser-credentials`. Both use Tink XChaCha20-Poly1305 AEAD. Each keyset is 1–4096 bytes; the caller binding is 1–2048 bytes. The reference is:

```text
asservat-local-keyset/v1/{installationUUID}/{purpose}/{keyID}/{decimalVersion}
```

The ciphertext is canonical padded base64 of the library's nonce, ciphertext and tag. The associated data is canonical JSON with `format: asservat-local-keyset/v1`, the full `reference` and `bindingSHA256` of the exact caller binding. Readers accept only references present in the loaded backend; there is no fallback key search. A changed installation, purpose, key ID, version, binding or ciphertext cannot disclose a keyset. Operations check cancellation before and after cryptography.

`BrowserCipher` uses the `KeySealer`/`KeyOpener` ports with format `asservat-browser-credentials/v1` and its installation/issuer/client/row/version binding. External OpenBao callers use the same ports. Missing or typed-nil providers fail without panicking.

## Rotation

Rotation is additive: the administrator adds a version to the Secret and raises the active version. New wraps use the active version; older versions keep decrypting retained ciphertext. Removing a version is refused while retained artifacts or browser credentials may still reference it; retirement is an explicit administrator procedure. Root key removal is not per-artifact erasure. At most sixteen versions per purpose.
