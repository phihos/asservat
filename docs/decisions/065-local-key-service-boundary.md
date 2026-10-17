# ADR-065 — Private local key operations

Status: engineering refinement under the accepted small-deployment implementation. Date: 2026-10-10. Implements part of REQ-DEP-003 and preserves REQ-EVD-001; does not enable a runnable installation.

## Decision

Keep static wrapping roots and signing seeds inside the optional A-KEY process. Use private TLS 1.3 with independently pinned trust and short-lived, purpose-limited client certificates. I-14 carries closed, bounded wrap/unwrap/sign requests; clients receive only the operation-specific provider facet. No public endpoint, forwarded identity, bearer root key or new administration API.

Certificate identity and role constrain possible requests but cannot grant them. C-03 requires an injected current operation authorizer to resolve the exact accepted authority, artifact/session/signature binding, recovery generation, original deadline and relevant spend. Its permit binds the full request digest and peer certificate for at most five seconds. Missing authority denies the operation. Expiry/cancellation are checked after blocking resolution and after cryptography, and response delivery retains the original deadline.

C-20 owns the bounded handler and wire contracts; C-21 supplies strict local crypto, real mTLS verification and remote provider adapters. Existing artifact/browser formats and application key ports are unchanged. No new library dependency is added. One process may host multiple explicitly configured purpose/key scopes without distributing roots to callers. PKI issuance remains a separate purpose; this RPC does not mint peer certificates.

## Consequences and qualification

The [contract](../architecture/local-key-service.md) fixes the peer profile, digest and limits. Actual TLS tests exercise the handler/client/crypto boundary with a synthetic authority resolver. They do not qualify a production current-authority adapter, Secret lifecycle, certificate issuer, recovery fencing or Helm bootstrap. Those remain mandatory before enabling A-KEY. A per-process concurrency bound is not a shared-provider capacity guarantee.

The alternative of mounting roots in collector/hub pods would defeat wrap-only authority and is rejected by REQ-DEP-003. Matching a Kubernetes service account or a static certificate ACL alone would likewise fail exact operation authorization. Public permission management remains Kubernetes configuration; this is a private implementation protocol.
