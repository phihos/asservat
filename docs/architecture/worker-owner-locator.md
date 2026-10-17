# Shared worker request locator

[ADR-075](../decisions/075-worker-owner-locator.md) extends [local request routing](worker-request-routing.md) under REQ-FED-001, REQ-DLD-003, REQ-DEP-003 and REQ-CAP-003. C-14 owns local registration and the exact-owner receiver; C-15 owns the minimized transactional locator. C-21's PostgreSQL adapter implements `WorkerOwnerStore`. This is an internal part of I-13, not a public permission or routing API.

## Publish a current local request

`WorkerRequestOwners.Register` first obtains ADR-074 local ownership. It repeats current human authority and admitted-worker observation before asking the store to claim a locator. The request UUID comes from trusted control; hub Pod UID and process epoch come from process bootstrap, never a worker parameter. The locator deadline is the original local operation deadline, rounded down to PostgreSQL microsecond precision. It is never extended to cover registration, retries or forwarding.

`WorkerOwners.ClaimWorkerOwner` locks recovery, permission root and download session through the existing current download facet, followed by the exact worker and its locator row. The worker must remain bound, audited, unterminated, unretired and in the configured profile. Current rights, configuration, recovery, parent state and time are rechecked after blocking operations. The locator expires no later than the original request, session, worker and access windows, with a thirty-second ceiling. It is routing metadata; the authority decision used to admit it does not stay valid for thirty seconds.

The same request can reconcile an uncertain successful claim only with its original owner/timing and unchanged current fence. Another request is rejected while that fence is active. Explicit release or expiry permits a fresh request with the next fence. Fences never decrease, an old request cannot change its own timestamps, and a closed row cannot be revived. Database constraints/trigger enforce those transitions alongside application checks. A process epoch prevents a restarted process from inheriting the old owner's identity; authenticated transport must independently prove that epoch later.

## Locate and receive

The separate lookup role can select the locator and parent metadata but cannot claim, change or release ownership. Lookup requires exact installation, root, session and worker; it rejects expired/released owners and terminal or stopped parents. It returns only opaque IDs, fence and original times. It does not authorize enrollment, attest the named process, supply an endpoint or cache human rights. Permission changes can make an otherwise unexpired locator unusable; the actual owner must repeat current authorization.

`WorkerOwnerRegistration.BeginWorkerEnrollment` is the private exact-owner receiver facet. It accepts an expected locator already resolved by trusted transport, verifies the current shared record, then atomically selects the exact local handle rather than merely its session/worker key. Closing/replacing a local route during lookup cannot redirect the request to a new operation. Enrollment retains the existing independently checked Pod/CSR, current human scope, audit, signing budget and activation. Before returning a delivery, repeat the locator check. Original owner/locator cancellation and deadlines still bound delivery through write/flush.

The public worker wire remains unchanged. Future private forwarding must authenticate the precise hub Pod/process and caller role, resolve endpoints only from protected discovery, reject stale fences and retain connector-origin proof. A caller-supplied locator is not a capability. This implementation has no hub-held workload kubeconfig and cannot replace regional TokenReview with a locator.

## Failure, cleanup and resource bounds

Failed registration closes the local route. If SQL committed but its reply was lost, leave that unknown fence alone until reconciliation or its original expiry; no fabricated fence, takeover or renewal. Explicit `Close` cancels local work immediately, then releases only the exact request, process, fence and original times. Cleanup has a separate maximum five-second context so disconnection does not prevent metadata cleanup. A failed cleanup remains bounded by original expiry; it starts no background retry goroutine. Duplicate/late release is a no-op against a replacement.

Local in-flight work remains charged under ADR-074 until it actually returns, even if the SQL locator was released. Locator release/expiry is not worker termination, signing-budget recovery, download-byte refund or verified evidence deletion. There is one locator row per admitted worker and one current owner per row; the worker's existing admission limits bound simultaneous eligible workers. Global endpoint/SQL/provider request-rate fairness remains separately required. Closed rows retain only the latest minimized lifecycle metadata and follow parent worker/session cleanup; this is not an append-only history of requests or a personal-token store.

## Verification boundary

The owned SQL fixture uses two independent runtime pools and local owner registries plus a separate lookup role. It exercises current owner discovery, exact enrollment/same-certificate replay across replacement, eight competing claims, original-deadline replay, stale release, foreign actor/session, immutable SQL transitions, role separation, actual row-lock expiry, unattended expiry, cancellation and cleanup after authority ends. Pod/process identities and Pod/CA proof remain explicit synthetic inputs. Unit/race checks cover cancelled, unknown and mismatched claim results and local-route release. [Implementation progress](../implementation-progress.md) records actual commands, source reports and cleanup.

Still required: protected hub process identity/discovery, private mTLS forwarding, connector-local proof/reference exchange, public browser/MCP ownership registration, operational failover testing and native evidence transfer. This SQL locator is necessary shared state, not a claim that those network paths are implemented.
