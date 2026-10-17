# Protected local key lifecycle

[ADR-067](../decisions/067-protected-local-key-lifecycle.md) refines REQ-DEP-003. This is a private source/consumer contract, not another permission API. C-03 owns `KeyMaterialReader`, `KeyConfigurationLedger` and `KeyConfigurationGuard`; C-21 supplies Kubernetes, SQL and root-holding crypto adapters. The public I-14 request and artifact format remain unchanged.

## Protected source

A pinned control namespace and ConfigMap contain only `keys.json`, matching [local-key-configuration/v1](../../specs/contracts/local-key-configuration.schema.json), at most 4096 bytes. The payload contains the installation/purpose/key ID, current recovery epoch, positive revision, suspended flag and an immutable Secret reference. Policy signing also supplies an independently protected Ed25519 public key. ConfigMap UID and namespace UID come from protected installation wiring. Arbitrary names/UIDs from callers cannot select a source.

The referenced Opaque Secret is immutable, contains only `keys.json`, and has the exact UID and SHA-256. Its private payload follows [ADR-064](local-keys.md), at most 16 KiB. A read rejects deletion, replacement, changed content, missing/extra data, untrusted scope, unsupported signing public key or stale observation. The reader checks namespace identity around the ConfigMap GET and checks the configuration again after reading the Secret. API metadata is not an administrator-protection attestation. Root bytes stay in the isolated service; SQL receives fingerprints only. Temporary buffers are cleared as best effort without claiming Go memory zeroization.

## Loading and use

`LoadProtectedLocalOperations` independently parses the actual Secret, verifies signing public material and derives ordered version fingerprints before `ObserveLocalKeys`. The lifecycle facet pins scope, source cluster, namespace and ConfigMap UID, checks the current fleet recovery epoch/availability and accepts the snapshot transactionally. A suspended snapshot can be recorded to prevent rollback but cannot create a working backend. The loaded crypto maps remain immutable.

The service requires the same backend to implement the current-configuration guard. After the exact operation permit is resolved, it rechecks configuration/recovery, bounds execution by both original deadlines, performs crypto, rechecks configuration/authority and only then releases output. A failed final check clears returned key bytes. Configuration state does not grant a key operation; the artifact/session/signature authorizer remains independently mandatory.

The backend reuses only public source observations for their original five-second lifetime. It coalesces refreshes per loaded scope and still consults SQL for every guard call. Cache hits never extend time; expiry, source outage or cancellation fails without an old-snapshot fallback. Acceptance of a newer revision by any service instance stops an old instance even while its Kubernetes observation is otherwise fresh. Deletion/suspension not yet observed has at most the original five-second exposure window. This is bounded freshness, not an instantaneous distributed revocation claim. Post-crypto refreshes cannot extend an operation.

## SQL and rotation

Migration 23 owns `local_key_configuration` and `local_key_version`. Snapshots contain only public identity, revision, digest, version fingerprints and observation timestamps. Stored timestamps are history, never a renewable authority lease. No root keys or wrapped artifact keys go into these tables. Transactions lock current fleet recovery before the key scope; freshness is checked again after blocking locks and before commit. Per-installation unique fingerprints reject key reuse across purposes/IDs. Version rows cannot be changed or deleted by the runtime SQL role.

Additive rotation uses a new immutable Secret, an incremented configuration revision and a nondecreasing active version. Existing version bytes must remain identical. A newly loaded backend writes with the new active key and can read retained old ciphertext; already loaded instances deny because their accepted snapshot differs. Same-name Secret recreation does not match the old UID. A lower accepted revision, same-revision edit, changed key material, removed historical version or reactivated older key fails. Administrative recovery does not happen through these ordinary operations.

Current limits: sixteen versions per payload, no automatic pruning. Safe retirement needs a separate obligation-aware administrative transaction covering retained artifacts, audit, browser credentials, signatures and recoverable backups. This path deliberately refuses removal until that exists. It does not promise unlimited unattended rotations or completed key recovery.

## Qualification boundary

Unit tests cover closed/pinned sources, source changes during reading, expiry, configuration checks around crypto, original deadline preservation and coalesced refreshes without lease renewal. The real lifecycle test uses owned Kubernetes, named read-only RBAC, immutable Secrets, PostgreSQL and actual mTLS/crypto; its operation approval mapping is explicitly synthetic. SQL download authority is independently tested under [ADR-066](download-key-authority.md); composing that authority with this lifecycle and protected peer issuance in a runnable installation remains required.

Actual command exits and immutable test reports belong in [implementation progress](../implementation-progress.md). Production source enrollment/admission, peer PKI, encrypted administrative audit, automatic process replacement, restart/backup/restore/lost-key recovery, retirement, aggregate load and Helm installation are unfinished. Neither static validation nor this lifecycle fixture enables collection.
