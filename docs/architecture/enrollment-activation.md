# Connector enrollment

C-04 with C-21 SQL/PKI adapters under TASK-03, S-01 and REQ-FED-001/002. A
connector obtains its cluster identity from a one-use bootstrap token and a
certificate signing request, following kubelet TLS bootstrapping and Open
Cluster Management registration (ADR-330 D3). Bootstrap issuance
creates the token; connector PKI signs; [peer identity](peer-identity.md)
checks the certificate on every connection.

## Bootstrap token

- A random 256-bit secret in canonical unpadded base64url, generated with a
  CSPRNG. SQL `fleet_bootstrap` stores only a purpose-, installation- and
  bootstrap-bound SHA-256 digest, the preassigned peer, cluster and issuer
  epoch, and the token's expiry.
- The operator supplies the token to the connector through its Helm values or
  Secret. It travels in the request body or header, never in a URL, log, CRD
  status or error.
- Possessing the token never lets the caller choose installation, cluster, peer
  or epoch; the bootstrap row fixes them.

## Enrollment request

The connector generates its private key, keeps it in its own Secret and POSTs
the token with a DER PKCS#10 CSR (at most 8192 bytes).

- Standard-library X.509 verifies proof of possession. Accepted keys: Ed25519,
  ECDSA P-256/P-384/P-521, RSA 2048–4096 with exponent 65537 and SHA-2/PSS
  signatures.
- Requested subjects, SANs, extensions and all attributes are rejected; the
  identity comes from the bootstrap row. The signed attribute set is checked
  explicitly because the parsed `Attributes` field drops some shapes.
- The canonical public-key digest is the idempotency key. The first valid
  request binds that key to the bootstrap row; a retry with the same key (and a
  fresh CSR signature) returns the same enrollment and certificate. A different
  key cannot claim a bound token.

Signing goes through the installation CA (OpenBao PKI or the Helm-generated CA)
outside any SQL transaction. The connector may retry the same request any
number of times until the token expires; an unknown outcome is resolved by the
retry, which looks the enrollment up by key digest and, if no certificate was
stored, signs again. The certificate profile (one URI SAN, client-auth EKU, at
most one hour validity) is in [peer identity](peer-identity.md).

One transaction stores the public certificate and chain (at most 48 KiB), its
digest and validity, enables the peer, marks the token consumed and writes one
append-only audit row. If the audit row cannot be written, nothing is
committed. A trigger keeps the binding, certificate and audit rows immutable.
SQL never holds a private key.

Expired or revoked tokens and suspended or recovering installations are
rejected. A revoked peer is never re-enabled by a replay.

## Rotation and revocation

The connector requests its next certificate with a new CSR over its existing
mTLS connection before the current one expires. The request is idempotent by
public-key digest; two certificate slots allow overlap, and retiring a slot
blocks its certificate even while the CA signature is valid. Revoking the peer
closes its connection and rejects later handshakes.

## Persistence

`fleet_bootstrap`, `fleet_peer`, `fleet_certificate_issue` and the audit table
are written by the hub process's single SQL role (ADR-222); immutability is
enforced by triggers, not by per-column role splits. The ceilings in
[fleet administration](fleet-administration.md) bound active tokens, retained
bootstrap records and registered clusters. `ClaimConnector` has no public
endpoint that accepts caller-created domain values.
