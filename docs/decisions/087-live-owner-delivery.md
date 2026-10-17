# ADR-087 — Live owner cancellation through worker delivery

Date: 2026-10-10. Status: selected for implementation under the maintainer's continuing authorization. Requirements: REQ-FED-001, REQ-DEP-003, REQ-DLD-003, REQ-CAP-003; part of TASK-02 and S-01/S-02. Supersedes ADR-085's finite private response and ADR-086's finite-only sender limitation. Current identity, locator, certificate, admission and no-replay requirements remain unchanged.

## Problem

The owner receiver closes its live operation after flushing a finite HTTP response. The forwarding hub still has to deliver that certificate to the worker. Treating the completed reply as a live `WorkerEnrollmentDelivery` would lose original human-request cancellation during the last write. A locator, certificate or renewed polling lease cannot replace that ownership.

## Decision

Version the private protocol to owner-relay/v2 and `/internal/hub-owner/v2/enroll-worker`. The request retains the same bounded closed JSON and dedicated Pod bearer token. The response uses HTTP/1.1 chunked framing with content type `application/vnd.asservat.owner-enrollment-stream`. One four-byte big-endian length prefix precedes at most 49664 bytes of closed JSON: format, the original effective output deadline, and the existing worker-enrollment/v1 response. The public worker protocol does not change. Reject fixed-length replies and v1; there are no deployed clients or data requiring a compatibility fallback.

After flushing the one frame, the owner keeps its exact operation and concurrency slot until cancellation, disconnect or the original deadline. It sends no heartbeat, second frame, renewed deadline or authority token. The forwarding hub keeps that socket and one bounded body reader alive through downstream response delivery. EOF, any further payload byte, any read error or local cancellation cancels the returned delivery. `Close` cancels the call, closes the socket, joins the monitor, and releases the sender's slot exactly once. It is mandatory on every downstream path. The existing worker handler already retains that delivery through its final write and flush.

Intersect the received deadline with all independently established local call, locator, worker, client-certificate, current peer and returned worker-certificate limits. Final fresh peer checks provide at most five seconds, without extending the original thirty-second exchange. Keep current worker freshness through delivery. No successful read, keepalive, repeated request or reconnect renews the lifetime. The existing finite utility may return public certificate bytes only by explicitly closing its live delivery; it does not supply a live handle to callers.

No network protocol provides instantaneous cancellation across a partition or retracts bytes already delivered. A healthy connection propagates owner cancellation; a lost connection fails closed when observed, and a silent partition is bounded by the independently enforced original output deadline, at most five seconds after the final local identity check. Certificate possession remains separate from current activation, developer and evidence permissions. This is not a promise of revoking a certificate already received by the worker.

The stream carries certificate metadata only, over the existing direct protected Pod route with no reverse proxy, cache or connection reuse. Retain absolute connection lifetime, TLS identities, pre-transmission checks, scoped token handling, strict framing and no uncertain POST retry. No SQL row, durable lease, dependency, user setting or approval is added.

## Validation and remaining work

Exercise actual sender/receiver TLS, retained remote ownership and slots after certificate receipt, remote/caller/root cancellation, explicit close, network loss, deadline expiry and malformed/terminated streams. Compose the real worker handler with a deterministically blocked TLS response to prove that remote cancellation reaches the final write. Keep strict parser and existing current-identity rejection cases.

These component tests use explicit synthetic authority and remapped owned test addresses. Native identity integration must remain separately recorded; neither suite establishes protected in-Pod startup, native cross-replica routing, connector-local proof mediation, actual evidence transfer or the public investigation workflow. Measured results and source/cleanup evidence belong in the implementation progress record.
