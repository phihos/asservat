# Policy submission provenance

C-09 implements this part of REQ-PER-007 and REQ-EXE-001 under [ADR-062](../decisions/062-policy-submission-signatures.md). These are private component ports, not a new public token or permission-management API.

## Inputs and authority

`PolicySubmissionIntent` binds an authenticated human actor, exact persisted policy revision, cluster/namespace/name, independently compiled execution digest, original nonce/lifetime and optional previous acceptance. It also pins the permission root, installation and recovery issuer epoch. The versioned `asservat-policy-submission/v1` envelope uses the private Go intent representation in canonical JSON; these fields are not a caller-authored transport DTO. The envelope contains no bearer token, copied group memberships or diagnostic parameters. The complete authored spec remains bound by its source digest.

`PolicySubmissionSigner` signs that intent using JWX's standard JWS implementation. `PolicySubmissionVerifier` compares the exact canonical payload with independent expected facts; decoding a signed actor or scope never supplies those facts. Accept exactly Ed25519, the purpose-specific protected type and key ID. Alternate key locations, extra headers, encoding ambiguity, changed payloads and unknown keys fail closed. Hash canonical payload bytes for immutable submission identity; signatures and key rotation do not reset a consumed nonce.

`SubmissionTrustReader` reads a pinned administrator ConfigMap containing `submission.json`, validated against [submission-trust/v1](../../specs/contracts/submission-trust.schema.json). It pins root/installation/epoch and ConfigMap UID, accepts at most 32 unique key IDs with finite validity intervals, and preserves the original five-second observation deadline. Same-name replacement and read failure cannot reuse old trust. This reader does not establish bootstrap protection by itself.

The KMS adapter supplies a per-request `crypto.Signer` backed by a dedicated nonexportable OpenBao Transit Ed25519 key. It pins key version and public key, preserves cancellation, bounds request/response sizes and verifies the provider's output locally. A sign-only credential has no key export, rotation, management, evidence decryption or identity-directory capability. Provider rotation leaves the pinned version unchanged until explicitly reconfigured; retirement rejects its further use.

## Acceptance and retries

`SignedPolicyAcceptor` requires independent authenticated/compiler inputs, verifies the envelope and carries a `SubmissionCheck` into the existing `PolicyAcceptor`. This proof expires at the earliest of original public-trust freshness, envelope expiry and key expiry. SQL checks the exact proof/input match again after blocking locks and before commit, alongside current source, human rights, delegation and recovery. There is no schema migration: the proof is transient, while the existing immutable acceptance and encrypted audit retain minimized provenance.

The acceptance request digest excludes refreshable verification timestamps. A retry with the same canonical intent therefore identifies the original receipt. The private SQL historical lookup can return that receipt without extending or reactivating it. The signed application entry point requires current verification even for retry, and a future public status lookup must independently enforce current caller access. Expired envelopes do not justify silently issuing a new nonce. Handling public lost-response lookup is still required.

Later team execution authenticates the durable accepted record and rechecks current delegation, source, review, budgets and short execution permit. The human submission's sixty-second lifetime is an admission bound, not the lifetime of a recurring policy. Public sign-in does not refresh or revoke team execution by itself.

## Qualification and remaining composition

Unit tests cover actor/source/scope/epoch tampering, purpose and header confusion, stale or replaced trust, cancellation and time spent signing. Real-provider fixtures exercise current browser identity and nonexportable signing with separate OpenBao credentials; real Kubernetes fixtures exercise named read-only ConfigMap access and key/source replacement; real SQL fixtures exercise signed acceptance, replay and verification expiry during a lock wait. Actual run results are recorded in [implementation progress](../implementation-progress.md), separately from these intended checks.

Complete policy compilation, protected key/bootstrap/restore lifecycle, discovery/watch supervision, Kubernetes admission-origin mapping, GitOps service submissions and public browser/MCP operation state remain unfinished. The profile currently accepts humans only. Synthetic source/compiler/bootstrap facts in tests never enable collection or substitute for those missing producers. Direct Kubernetes admission occurs before storage; its origin attestation remains separate from the final persisted-UID signature.
