# ADR-084 — Process-owned hub credentials and renewal

Date: 2026-10-10. Status: selected for implementation under the maintainer's continuing authorization. Requirements: REQ-FED-001, REQ-DEP-003, REQ-DLD-003; part of TASK-02 and S-01/S-02.

## Problem

Audited enrollment and current peer authentication do not own a running hub's private keys. Passing a fixture-generated key to TLS leaves process shutdown, concurrent enrollment, renewal and retained signer lifetimes unspecified. A restarted process must not inherit the old process's identity or live requests.

## Decision

Add a C-21 credential owner for each independent server/client purpose. It generates a P-256 private key and identity-free CSR using Go's standard library. Keys remain in that owner; no key import, serialization, Secret file or generic signing service is exposed. Protected runtime supplies a fresh process epoch, independent issuer roots, the C-04 audited enrollment port and independently pinned active registry. The existing coordinator implements the enrollment port; this adds no second enrollment HTTP protocol.

Retain the CSR for retry and renewal. Permit one in-flight enrollment and at most one attempted enrollment per second, with an original thirty-second operation bound. Before installation, independently verify actual DER/key/binding/purpose, bounded lifetime and fixed UTC period, pinned roots, exact active registration and currently accepted roots. Failed renewal retains only the original valid leaf. Credentials do not supply request authorization.

Expose TLS callbacks backed by a restricted signer, with copied public certificate/key state. Snapshots keep their original expiry across renewal. Closing the owner cancels enrollment and disables all retained signers. No physical heap zeroization or automatic closure of another component's socket is claimed. Use the established [TLS callbacks](https://pkg.go.dev/crypto/tls#Config) and [crypto.Signer](https://pkg.go.dev/crypto#Signer) interfaces; no dependency is added.

C-04 supervises the pair. Initial enrollment is bounded to ninety seconds. Renew one minute before the earlier original expiry; retry at most eight times within that deadline, with exponential delay capped at thirty seconds and jitter no greater than 500 ms. A partial success cannot extend the pair's deadline. Cancellation, failed renewal or expiry closes both credential owners. Identity notifications are nonblocking and never confer runtime readiness or evidence access.

## Qualification and remaining work

Unit tests isolate custody, exact certificate/registry checks, actual mutual TLS, retained-snapshot mutation/expiry, concurrent enrollment/cancellation and accelerated renewal. The native integration uses the existing Kubernetes proof, scoped OpenBao issuer/audit, SQL enrollment/registry and S3 audit with process-owned TLS callbacks. Initial recovery and installer pins remain fixture inputs; the test process owns keys/listeners outside the pause Pod. Actual outcomes belong in [implementation progress](../implementation-progress.md).

No SQL migration, public API, permission mechanism or user approval is added. Protected runtime bootstrap, private forwarding, listener/connection lifetime, local CA, native transfer and public UI/MCP/download workflows remain required. Live-provider renewal endurance and fleet-wide burst qualification remain separate from accelerated unit checks.
