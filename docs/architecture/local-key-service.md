# Private local key service

[ADR-065](../decisions/065-local-key-service-boundary.md) defines I-14 and the planned A-KEY runtime for REQ-DEP-003. Crypto, current-authority coordination ports, private HTTP handler, mTLS verification and remote facets are implemented components. [ADR-066](download-key-authority.md) now adds a concrete SQL resolver for the initial audited context-download batch. [ADR-067](local-key-lifecycle.md) adds protected source reads, durable additive rotation and mandatory configuration checks. Other-purpose resolvers, protected peer/source enrollment/retirement, runnable service bootstrap and chart deployment remain pending. Fixtures do not authorize public collection or disclosure.

## Ownership and process boundary

A-KEY is an optional unprivileged Deployment in each configured key-service region. It holds only its protected purpose/key snapshots and credentials needed to resolve current authority. It does not read artifact payloads, collect workloads or serve public users. Existing external OpenBao deployments keep their provider path. The local service substitutes for those key operations, not for PostgreSQL, storage or the public authorization model.

| Component | Responsibility |
| --- | --- |
| C-03, `application/authorization.KeyService` | Resolve exact current operation authority, enforce request/peer/deadline bindings and call the crypto port. |
| C-20, `transport/keyservice` and `contracts` | Private HTTP framing, closed operation-specific DTOs, bounded concurrency and response delivery. |
| C-21, `adapters/kms` | Local root-holding backend and separate `RemoteSealer`, `RemoteOpener`, `RemoteSigner` clients. |
| C-21, `adapters/mtls` | Validate pinned real TLS peer chain and the key-client identity profile on every request. |
| C-24, `domain/authorization` | Key scope, request identity, peer and finite permit values. |

Root/private key bytes remain inside `LocalOperations`, constructed from the [private key payload](local-keys.md). Remote facets retain client TLS credentials and an opaque authority reference, never wrapping roots. Even a process implementing only `Seal` must not mount the root key. Up to 32 explicitly configured scopes from one installation may share a handler. Every scope requires its own backend and authorizer; there is no default allow route.

## I-14 wire contract

`POST /internal/key-service/v1` on a fixed private HTTPS endpoint with `Content-Type: application/json`, no query, cookies, authorization header, compression or redirect. The [schema](../../specs/contracts/local-key-service.schema.json) defines format `asservat-local-key-rpc/v1`. This is not a browser/MCP or permission-management API.

All requests contain `format`, `scope` (installation/purpose/key ID), `authorityID` and `operation`. The UUID identifies independently stored authority, not a bearer grant. Operations have exactly these additional fields:

| Operation | Request fields | Successful result |
| --- | --- | --- |
| `wrap` | `binding` (1–2048 bytes), `input` keyset (1–4096 bytes) | `sealed` reference/ciphertext |
| `unwrap` | `binding`, `sealed` from the same configured installation/purpose/key scope | `output` keyset (1–4096 bytes) |
| `sign` | Explicit positive version and `input` (1–16384 bytes), only for policy submission | `output`, a 64-byte Ed25519 signature |

Binary JSON members use canonical padded base64; null, aliases, duplicate/unknown members, irrelevant operation fields and trailing values are rejected. HTTP bodies are at most 32768 bytes. Sealed references are at most 256 bytes; encoded ciphertext is at most 8192 bytes. The local backend further validates the exact reference/version and authenticated binding. The parser compares a canonical re-encoding with the input, while accepting irrelevant JSON whitespace/member order.

Responses also bind `format`, `operation`, `requestSHA256` and canonical UTC `validUntil`. The client rejects mismatches, unknown fields, expired responses, leases over five seconds, malformed output and redirects. A remote signer verifies every result against its independently pinned public key. Non-200 bodies are not treated as cryptographic results. Failure responses carry only status, without key material or provider diagnostics: malformed request 400, denied authority 403, immediate saturation 429 and unavailable operation 503. TLS failures can occur before HTTP.

## Identity and authorization

Both sides use TLS 1.3. The private server must require and verify client certificates against pinned roots. No proxy header supplies identity. The verifier repeats chain/time checks on each request, including reused TLS connections. The leaf has no subject names, DNS/IP/email SANs or unknown extended usages; exactly one URI is allowed:

```text
spiffe://asservat.{installationUUID}/key-client/{role}/{peerUUID}
```

The leaf is a non-CA client-auth certificate, digital-signature usage only, with at most one hour lifetime and a chain of at most four supplied certificates. The peer binds the exact certificate SHA-256 and installation; the permit cannot outlive the effective verified chain expiry. This profile uses standard X.509 and a SPIFFE-shaped URI; it does not introduce a SPIRE dependency or claim automatic workload attestation. Issuance and current process/registration binding remain bootstrap work.

| Peer role | Allowed candidate operations |
| --- | --- |
| `collector`, `publisher` | Artifact wrapping only |
| `acquisition` | Artifact unwrapping only |
| `audit-writer` / `audit-reader` | Audit wrapping / unwrapping respectively |
| `hub-session` | Browser-credential wrapping/unwrapping |
| `policy-submitter` | Policy-submission signing only |

These are negative guards, never grants. `KeyOperationAuthorizer.Resolve` must consult current accepted authority and verify the exact peer, purpose/key/version, artifact attempt or credential/signing operation, canonical binding, original deadline, recovery/issuer state and applicable budgets. Binding a signature requires verifying the expected signing-input hash. A collector or publisher never obtains historical unwrap through another purpose. Restored/retired configuration cannot revive a grant.

The resolver receives binding bytes and payload hashes, not a plaintext keyset or signing input. It returns an authority/recovery UUID, positive revision, exact peer-certificate and request digests, observation time and deadline, valid for at most five seconds. The coordinator rechecks after resolution and after cryptography. The same backend must implement `KeyConfigurationGuard` under [ADR-067](local-key-lifecycle.md); raw crypto backends alone cannot construct a service handler. Original operation and configuration deadlines are intersected and never renewed. Backend execution and response delivery use the intersection of caller deadline and permit expiry, without extending the accepted operation. Current production resolvers must obtain those bounds from protected state; the generic port's shape does not prove this behavior.

## Request identity

`DescribeKeyRequest` hashes RFC 8785 canonical JSON with all of these exact member names (including capitalization): `Format`, `Installation`, `Purpose`, `KeyID`, `Authority`, `Operation`, `Reference`, `Version`, `Binding`, `Input`, `Ciphertext`. `Format` is `asservat-key-request-digest/v1`; the string and version members come from the validated request, with empty reference/version zero when absent. `Binding` and `Input` are SHA-256 of decoded bytes; `Ciphertext` is SHA-256 of the exact encoded ciphertext string's UTF-8 bytes, including the empty string when absent. These three digests are JSON arrays of 32 integers in 0–255. The final digest is SHA-256 of that canonical JSON and appears as lowercase hex in the response. This separate digest representation is versioned; it is not the wire request reserialized, an authorization credential or a secret-bearing log record.

## Resource and delivery bounds

The handler admits only its configured 1–64 concurrent operations; excess requests receive 429 without queueing or invoking authority. Each admitted operation has at most five seconds, including body read, authority I/O, crypto and response. The handler requires HTTP read/write deadline support and flushes key output before removing the original deadline. Failed decoding closes the connection. Bootstrap must also set finite read-header, idle, connection/header and private-network bounds; the handler alone does not limit idle TLS handshakes.

Clients use verified TLS, no ambient proxy/cookie jar, 4096-byte response headers, 32768-byte response bodies and at most eight connections per client transport. Application retries and body replay are disabled. Reuse bounded process-owned facets/credentials; repeatedly constructing clients must not multiply global budgets. A transport connection cap can queue callers, so its five-second timeout and higher-level aggregate admission remain required. No root keys, plaintext keysets, inputs or complete request/response bodies go into logs.

Envelope encryption sends only small keysets to this service. [Artifact framing](artifact-format.md) uses three wraps per prepared attempt, regardless of native bytes; local payload encryption and object uploads dominate dump-byte work. Aggregate key-call scheduling, caller replicas, audit/identity operations and failure bursts still require REQ-CAP-003 qualification. A handler semaphore is only a local bound.

## Measured coverage and remaining work

Application tests cover request/certificate substitution, absent authority, future/expired/overlong permits, expiry after blocking resolution or crypto, cancellation, malformed output clearing and resolver mutation isolation. Real TLS fixture tests compose local crypto, handler and remote facets; they cover role/purpose separation, signing, malformed wire/results, untrusted identity, revocation and certificate expiry on reused connections, and immediate rejection while both configured slots are occupied. Authority is a test-only exact mapping, not production SQL/Kubernetes resolution.

An explicit irrelevant `sealed` object reproduced acceptance on a wrap request and malformed response; both sides now reject it. The [progress record](../implementation-progress.md) records real command exits separately from these coverage claims. Provider/service failure and lifecycle qualification still need protected source enrollment/administration/retirement, certificate issuer and rotation, the remaining operation resolvers, restart/restore/lost-key tests, chart bootstrap and shared-load qualification. [The context-download resolver](download-key-authority.md) has separate SQL/TLS/S3 qualification; public collection remains disabled until the enclosing slice passes.

[Audited worker enrollment](worker-enrollment.md) now implements the initial acquisition credential path with scoped real Kubernetes/OpenBao/TLS and SQL/S3 qualification. Other-purpose enrollment, protected issuer installation/rotation, the local CA and actual worker/control transport remain separate required work.
