# Current hub peer authentication

[ADR-083](../decisions/083-current-owner-authentication.md) joins the [enrollment lifecycle](owner-registration.md), [native proof](owner-enrollment-proof.md), [owner routes](hub-owner-discovery.md) and [workload protection](owner-workload-protection.md). C-04 owns `OwnerPeerConnection`, `OwnerProtectionReader` and the authenticator; C-21 owns TLS/native adapters; C-24 owns `OwnerProtection` and `AuthenticatedOwner`. SQL remains migration 30. Existing public UI/MCP and private wire schemas are unchanged.

## Current identity check

`OwnerAuthenticator.AuthenticateOwner` runs for an actual peer on each protected use, including an existing connection. It captures one original start and five-second context:

1. Obtain the actual connection's independently verified current certificate. Reject missing/expired TLS identity before registry or routing work.
2. Read the exact active SQL registration and copy its current accepted configuration. Require certificate equality and the existing enrollment/audit/recovery checks.
3. Revalidate the actual connection against that current configuration's roots as well as independently pinned trust.
4. Read native workload protection bound to the exact accepted pool.
5. Resolve the current Ready route. Require the same configuration content, exact process binding/pool, Pod name and ReplicaSet UID as the enrollment. Endpoint presence or labels alone are insufficient.
6. Re-read workload protection and registration. Require unchanged protection digest, enrollment identity and configuration content; revoked/unavailable state denies use.
7. Revalidate current TLS again, then check every earlier observation and context at the final time. Return only through the earliest original registry, route, protection, certificate or five-second deadline.

`AuthenticatedOwner` contains the exact certificate and enrollment ID, accepted pool, Pod/ReplicaSet identity, configuration revision, workload-protection digest and verification/deadline. It contains no token, private key, personal credential or evidence. It is neither serialized bearer authority nor permission to take over a request. The eventual forwarding operation must additionally bind the exact shared locator/local handle and current developer/evidence authority, retain parent cancellation/deadlines through writing, and separately bound request concurrency and bytes. This change does not enable that network forwarding.

## Actual TLS snapshot

`mtls.NewOwnerServerConnection` requires the configured owner verifier, actual completed TLS state and exact expected server binding. `NewOwnerClientConnection` extracts a verified client-only identity from actual TLS state. Both retain an owned snapshot of only the handshake facts used for validation, copy all public DER and reparse it. Caller-owned parsed fields or byte slices cannot mutate subsequent checks. No private key is retained by this adapter.

A peer chain has at most four certificates and 32 KiB combined DER. At most eight verified paths are retained; each has at most five certificates and 48 KiB, allowing the separately trusted root beyond the four peer-supplied certificates. Every certificate remains individually capped at 16 KiB. These are bounded adapter inputs, not support for arbitrary chains or system-root fallback.

`OwnerCertificate` revalidates the strict original TLS/purpose/identity profile against pinned roots and current time. `VerifyCurrentOwner` also requires a fresh nonsuspended accepted configuration matching installation/cluster/issuer and repeats actual X.509 validation under its roots. Require the identical certificate value under both trust sets. A previously completed handshake does not freeze root acceptance or certificate expiry. A snapshot does not own/keep alive the underlying socket; transports remain responsible for real connection/request lifetime and closing their sockets.

`OwnerWorkloadProtection.ReadOwnerProtection` rejects foreign cluster, namespace name/UID or Deployment name/UID before API I/O. It calls the existing current native admission/dry-run proof and clips the result to the original wrapper and underlying proof deadlines. This proof concerns the private hub workload, not observed application permissions, historical integrity or evidence authority.

## Native composition test

The owned Kubernetes fixture creates a real controller-owned Pod with an unsatisfied readiness gate. It uses actual online Pod TokenReview/CSR proof under administrator-protected workload/configuration and accepted SQL configuration. Separate runtime SQL facets, scoped OpenBao issuer credentials and wrap-only/unwrap-only Transit credentials produce independently verified encrypted S3 enrollment/certificate audit and activation while the Pod is still unready.

The source administrator suspends the actual ConfigMap after client signing/audit but before activation. The coordinator must retain the signed public result, deny activation, and reuse the exact leaf after an explicitly observed resume. Actual loopback mTLS uses those leaves. The peer authenticator rejects use before Pod readiness; normal kubelet/controller status must later make the same Pod routable. The test reuses the same verified TLS snapshots when replacing the actual accepted root, retiring one purpose and deleting the Pod. A separate injected protection outage tests the composite service; native guard removal is already exercised independently by the outer workload-protection fixture.

The initial fleet recovery/issuer bootstrap and recovery-observation refresh are fixture inputs. The administrator requests the short Pod-bound token; CSR/private keys and TLS listener are owned by the test process, outside the pause Pod. This does not prove protected runtime startup, a deployed owner process, private enrollment transport, process-key custody inside that Pod or real forwarded download bytes. Unit fixtures isolate orchestration with synthetic ports; actual-TLS tests additionally check snapshot ownership, SNI/binding mismatch, incomplete/unverified handshakes, current-root/suspension/freshness rejection and expiry on reuse. See [implementation progress](../implementation-progress.md) for actual exits and source/cleanup reports.

## Rendered federation account read

The installed delegated path runs this same authenticator through
`federationOwnerReads`, including `OwnerEndpoints`' live owner ServiceAccount
UID check. `BuildFederationWorkload` accepts that account's independently pinned
name from `InitialRuntimeResourceInventory.OwnerAccount`, separately from the
Deployment name, and renders only an exact-name `get` rule for it. The original
namespace, account UID, Pod/ReplicaSet/Deployment, route, workload guard and SQL
checks remain mandatory. This adds no account listing, token creation or writes.
The focused [RBAC investigation](../research/federation-owner-read-rbac.md)
separates the source defect and native component qualification from the installed
journey's still-unresolved first refusal.
