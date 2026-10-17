# ADR-086 — Outbound owner enrollment transfer

Follow-up: [ADR-087](087-live-owner-delivery.md) supersedes the finite-only transport limitation with a versioned live response, retaining this decision's authentication and no-replay constraints.

Date: 2026-10-10. Status: selected for implementation under the maintainer's continuing authorization. Requirements: REQ-FED-001, REQ-DEP-003, REQ-DLD-003, REQ-CAP-003; part of TASK-02 and S-01/S-02.

## Problem

The private receiver does not safely route an incoming worker request to its current hub owner. An ordinary HTTP client would send its Authorization header after checking only CA/name validity; it would not establish the exact active process registration, protected Ready route or current request fence first. A cached address, redirect or retry of an uncertain POST could disclose a Pod token or repeat work at the wrong process.

A completed HTTP response also cannot manufacture the remote request's live cancellation context. Returning it as `WorkerEnrollmentDelivery` would falsely promise continued remote ownership through a later downstream write.

## Decision

Add a finite C-21 sender using the existing owner-relay/v1 wire. It takes independently accepted hub-pool, worker-profile and separate owner/worker roots, process-owned client credentials and purpose-scoped current readers. Add the narrow C-14 `WorkerOwnerLookup` port, embedded by the existing store; the sender cannot claim, release, renew or take over a locator. Add C-04 `OwnerClientIdentity` with the same active registry/protection/Ready checks as local serving, while preserving distinct client/server purposes and actual remote TLS authentication.

Resolve one current locator and admitted worker, then the exact protected route. Dial only its bounded canonical Pod IPs and configured port. Allow at most two TCP-address attempts within the original setup observations, before any HTTP bytes; never retry a handshake or POST after that stage. Establish a fresh TLS 1.3 connection with the exact deterministic server name, explicit roots and process-owned client key. Before forwarding token/CSR, repeat current local and remote identity checks, verify route/configuration agreement and re-read the same locator. Intersect original freshness and operation deadlines.

Use a fresh one-use [Go HTTP transport](https://pkg.go.dev/net/http#Transport) over that already authenticated connection. The non-replayable POST has no proxy, cookies, redirect handling, alternate dial or connection cache. TLS handshake uses [HandshakeContext](https://pkg.go.dev/crypto/tls#Conn.HandshakeContext); caller/root cancellation independently closes the owned socket. Bound headers, body, active calls and total time.

Verify the reply's correlation, bounded DER, worker issuer/role/Pod, CSR key and original certificate periods using the same validator as the worker. Recheck actual server identity/current roots, local client identity, the unchanged locator and current exact worker before returning public certificate bytes. An uncertain failure never triggers another POST or resets signing spend.

This sender returns a public `WorkerCertificate`, not a live remote owner or an authorization capability. It deliberately does not implement `WorkerEnrollmentExchange`/`WorkerEnrollmentDelivery`. The receiver preserves its owner through its network flush; the sender preserves its own caller/root/deadline through receiving and revalidation. Final worker-ingress composition must still preserve live original control ownership through downstream delivery. No permission, key-service check, disclosure rule or cancellation requirement is weakened by equating the returned certificate with authority.

## Consequences and qualification

No SQL migration, public endpoint, wire change, dependency or user decision is added. A local concurrency bound does not establish aggregate scheduling fairness or provider/API burst capacity. Constructor inputs remain protected bootstrap obligations. Production constructors expose no address override or injected dial callback.

Tests compose the sender with the actual receiver and cryptographic implementations, using explicit synthetic registry/route/worker/operation ports. Test-only address remapping reaches an owned loopback listener; it does not qualify native Pod routing. Native integration separately qualifies the new local client identity checks with real Kubernetes, OpenBao, SQL and S3. Actual outcomes belong in [implementation progress](../implementation-progress.md).

Protected in-Pod startup, complete native routing, live downstream ownership/cancellation, connector proof mediation and native evidence transfer remain required before the public investigation workflow can use this path.
