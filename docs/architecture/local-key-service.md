# Local key service

[ADR-065](../decisions/065-local-key-service-boundary.md) defines I-14 and the A-KEY runtime for REQ-DEP-003. A-KEY is the only process that holds the [local root keys](local-keys.md). Installations that use external OpenBao keep that provider path; A-KEY replaces only its key operations.

## Process boundary

A-KEY is an unprivileged Deployment in the hub namespace. It mounts the key Secret and nothing else that grants evidence access. It opens no PostgreSQL connection, reads no artifact payloads, collects nothing and serves no public users.

| Component | Responsibility |
| --- | --- |
| C-03, `application/authorization.KeyService` | Map the verified peer role and scope to an allowed operation and call the crypto port. |
| C-20, `transport/keyservice`, `contracts` | Private HTTP framing, closed DTOs, bounded concurrency. |
| C-21, `adapters/kms` | Root-holding backend and the `RemoteSealer`/`RemoteOpener` clients. |
| C-21, `adapters/mtls` | TLS peer chain and key-client identity profile. |
| C-24, `domain/authorization` | Key scope and request identity values. |

Remote clients hold only their TLS credentials. A process that only wraps never mounts a root key.

## Wire contract

`POST /internal/key-service/v1` over HTTPS, `Content-Type: application/json`, with no query, cookies, authorization header, compression or redirect. The [schema](../../specs/contracts/local-key-service.schema.json) defines format `asservat-local-key-rpc/v1`.

Every request contains `format`, `scope` (installation/purpose/key ID), `authorityID` and `operation`. `authorityID` is the caller's operation ID: it appears in logs and makes retries recognizable. It grants nothing.

| Operation | Request fields | Result |
| --- | --- | --- |
| `wrap` | `binding` (1–2048 bytes), `input` keyset (1–4096 bytes) | `sealed` reference and ciphertext |
| `unwrap` | `binding`, `sealed` from the same scope | `output` keyset (1–4096 bytes) |

Binary members use canonical padded base64. Null, aliases, duplicate or unknown members, fields irrelevant to the operation and trailing values are rejected. Bodies are at most 32768 bytes (base64 of the 4096-byte keyset, 2048-byte binding and 8192-byte ciphertext plus JSON; internal fixed-shape RPC, so per-request memory stays bounded), sealed references at most 256 bytes and encoded ciphertext at most 8192 bytes. Responses carry `format`, `operation` and `requestSHA256`; the client rejects mismatches, unknown fields, malformed output and redirects. Failures carry only a status: 400 malformed, 403 denied, 429 saturated, 503 unavailable.

`requestSHA256` is SHA-256 of RFC 8785 canonical JSON with members `Format` (`asservat-key-request-digest/v1`), `Installation`, `Purpose`, `KeyID`, `Authority`, `Operation`, `Reference`, `Version`, `Binding`, `Input` and `Ciphertext`. `Binding` and `Input` are SHA-256 of the decoded bytes; `Ciphertext` is SHA-256 of the encoded ciphertext string (empty when absent). These three digests are arrays of 32 integers 0–255. The digest is not a credential and is safe to log.

## Identity and authorization

Both sides use TLS 1.3 with certificates from the installation CA ([ADR-330](../decisions/330-event-driven-system-design.md) D3). The server requires a client certificate; no proxy header supplies identity. The client leaf carries exactly one URI SAN:

```text
spiffe://asservat.{installationUUID}/key-client/{role}/{instance}
```

The role decides the allowed operations:

| Peer role | Allowed operations |
| --- | --- |
| `connector`, `publisher` | `artifact` wrap |
| `download-reader` | `artifact` unwrap |
| `hub` | `browser-credentials` wrap and unwrap |

The hub process never unwraps artifact keys; collectors and connectors never unwrap. The caller authorizes the user operation before it calls A-KEY: the hub authorizes the download ([download authorization](download-authority.md)) and assigns it to a download reader over the reader's connection. The `binding` is the authenticated associated data of the wrapped keyset, so an unwrap returns only the keyset of the artifact attempt it was wrapped for ([artifact format](artifact-format.md)). A-KEY performs no per-call SQL lookup, permit or slot accounting. Wrap and unwrap are idempotent: a retry after a lost reply repeats the same operation.

A download reader unwraps the data, index and manifest keysets once per response and holds them in memory for that response only. Payload bytes never pass through A-KEY; artifact framing needs three wraps per prepared attempt regardless of payload size.

Each operation is logged with role, instance, scope, `authorityID` and `requestSHA256`. The security audit row belongs to the user operation in the hub (ADR-330 D6).

## Resource bounds

The handler admits a configured number of concurrent operations (Helm value; default: CPU cores × 4, since wrap/unwrap is CPU-bound, no fixed maximum) and answers 429 beyond that without queueing. Five seconds is the I/O timeout for one request, including body read, crypto and response (ADR-330 D5). The server sets finite read-header, idle and connection limits. Clients use verified TLS, no ambient proxy or cookie jar, 4096-byte response headers (a fixed internal response, well under common 8–16 KiB HTTP header limits), 32768-byte bodies and HTTP/2 multiplexing over one connection per transport, and reuse one client per process. No root keys, plaintext keysets or request bodies are logged.
