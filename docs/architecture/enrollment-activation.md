# Optional connector certificates

C-04 with the C-21 PKI adapter under TASK-03, S-01 and REQ-FED-001
([ADR-334](../decisions/334-connector-workload-identity.md) item 6). The
connector's credential is its projected ServiceAccount token
([connector identity](connector-credentials.md)). Where the hub is exposed by
TLS passthrough, a cluster's values may additionally enable a client
certificate. Nothing is copied from the hub: the certificate request is
authenticated by the same token, following kubelet TLS bootstrapping. Behind a
TLS-terminating Ingress or Gateway this path is unavailable and not needed.

## Certificate request

The connector generates its private key in process memory at start and POSTs
a DER PKCS#10 CSR on its hub connection, authenticated by its ServiceAccount
token. The token's verified cluster attribution fixes the identity; the request
cannot choose installation or cluster.

- The CSR body is at most 8192 bytes: the largest accepted key, RSA-4096,
  without subject, SANs or extensions yields a CSR under 2 KiB.
- Standard-library X.509 verifies proof of possession. Accepted keys: Ed25519,
  ECDSA P-256/P-384/P-521, RSA 2048–4096 with exponent 65537 and SHA-2/PSS
  signatures (NIST SP 800-57 minimum and the Go standard-library verifier).
- Requested subjects, SANs, extensions and attributes are rejected; the
  signed attribute set is checked explicitly because the parsed `Attributes`
  field drops some shapes.
- The installation CA signs outside any SQL transaction. A retry with the same
  key returns the stored certificate or signs again; there is no attempt
  count, since each request is authenticated by a current token.

SQL stores the public certificate and its digest on the cluster row; it never
holds a private key. A process restart generates a new key and requests a new
certificate.

## Profile

The URI SAN is `spiffe://asservat.<installation-uuid>/cluster/<cluster-uuid>/connector`,
with exact canonical spelling and no query, fragment, port or additional
identity. The certificate uses digital-signature usage, the client-auth EKU,
non-CA basic constraints and no common name, DNS, IP or email identity. TLS 1.3
is required (RFC 8446). There is no forwarded-certificate or proxy-header
fallback.

Validity ends with the issuing installation CA's validity: RFC 5280 path
validation rejects a certificate beyond its issuer anyway, and a shorter
lifetime would add renewals without a benefit, because revocation does not
depend on expiry. The connector requests a new certificate when the CA is
rotated (a changed `hub.caBundle` or CA Secret) and at each process start.

## Verification and revocation

`mtls.PeerVerifier` verifies the chain against the installation roots during
the handshake. The hub checks the cluster row (registered, not revoked,
certificate digest current) at handshake. Removing the cluster from the
values or setting `revoked: true` closes its open connection when the change
event arrives (ADR-330 D1) and rejects later handshakes; there is no
per-request registry lookup on a reused connection.
