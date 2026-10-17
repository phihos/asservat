# Hub owner enrollment proof

[ADR-081](../decisions/081-hub-owner-enrollment-proof.md) joins [accepted owner configuration](owner-configuration.md), [private workload protection](owner-workload-protection.md) and the existing [CSR verifier](owner-issuance.md). C-24 owns `OwnerEnrollmentRequest`/`OwnerEnrollmentProof`, C-04 owns `OwnerPodToken`/`OwnerEnrollmentProofReader`, and C-21 owns the Kubernetes attester and shared bounded TokenReview decoder. Public wire contracts, SQL migration 29, evidence authority and the Ready route reader are unchanged.

## Input and authority boundary

The private request contains the exact installation/hub-cluster/issuer/Pod/process binding, one leaf purpose (`server` or `client`) and a DER CSR between 32 and 8192 bytes. Standard X.509 parsing verifies the identity-free CSR and signature before any Kubernetes I/O; existing supported-key and attribute restrictions apply. The request cannot name an account, Pod name, namespace, endpoint, provider credential or issuer roots.

The constructor requires an independently configured Kubernetes client, the accepted owner configuration reader, its concrete qualified workload guard, and a request-specific token source. The guard's observer must be that same client. Production composition must use the audited SQL configuration projection; implementing the reader interface alone does not establish acceptance. The configured namespace and independently pinned Deployment name/UID must equal the current pool. Validate path names before API use. Configuration suspension, scope disagreement or unavailable protection prevents token use.

`OwnerPodToken` returns an owned byte buffer for this request, at most 16 KiB with no leading/trailing whitespace. The adapter clears it on success and every failure, including a token source returning both bytes and an error. Go does not guarantee complete secret zeroization. There is no token cache, file persistence, provider-error passthrough or ordinary log entry containing credentials. Ingress must supply separate token readers for concurrent requests and independently bound request rate/concurrency; this in-process adapter is not a public listener or an installation-wide admission limiter.

## Observation sequence

The dedicated audience is `https://asservat.<installationUUID>/hub-owner-enrollment`. It is distinct from Kubernetes API and acquisition-worker audiences. Online TokenReview must authenticate the exact service-account username and UID, return exactly the requested audience, and identify exactly one Pod name/UID matching the request's Pod UID. Validate the returned Pod name as a Kubernetes DNS subdomain before using it in a path. Reject unbound, foreign, opaque, expired or longer-than-one-hour tokens. Read only standard `iat`/`exp` after Kubernetes has verified the token; do not duplicate Kubernetes private-claim verification or treat its unverified node extras as node attestation.

Within one original five-second context:

1. Read and copy the current accepted configuration; check scope and suspension.
2. Prove current private namespace protection through the existing exact admission/dry-run guard.
3. Read the owned token buffer, verify it online and retain its original expiry.
4. GET the exact namespace, account, Deployment, Pod and controlling ReplicaSet. Require matching UIDs, no deletion, nonzero Deployment/ReplicaSet desired replicas, matching nonempty selectors and the expected account in both templates and the Pod. Require exactly one controlling ReplicaSet and its exact controlling Deployment.
5. Accept only scheduled Pending/Running Pods without host network/PID/IPC or ephemeral process injection. Readiness, Pod IPs, Service endpoints and certificate availability are not enrollment prerequisites.
6. Repeat TokenReview and those live reads. Compare a bounded canonical digest of the pool, Pod/ReplicaSet identities, full Pod/ReplicaSet/Deployment specs, Pod labels and controller references. Allow status/resourceVersion-only startup changes; reject security-relevant mutation.
7. Re-prove protection and re-read accepted configuration. Require the same protection digest and exact configuration content. Preserve the earliest of the original observation, both configuration observations, both guard deadlines and the token expiry. Do not restart a five-second lease after blocking I/O.

The digest uses the `asservat-owner-enrollment-workload/v1` purpose prefix and canonical RFC 8785 JSON, capped at 128 KiB. Full specs remain temporary adapter input; only the digest leaves this layer. Existing bounded API bodies/page checks still apply. Errors are sanitized and no partial proof is returned after failure.

The result contains the request binding/purpose, copied public configuration observation, Pod/ReplicaSet names and UID, CSR public-key/token/workload/protection digests and original times. A structurally valid result is not a cryptographic capability: only trusted composition may consume it. The Pod token cannot distinguish processes in the same Pod; durable enrollment must establish one permitted key/process registration and bound renewals/signing before issuance. Proof expiry must be rechecked after subsequent SQL locks or other blocking work.

## Bootstrap and qualification limits

ADR-080's clean-installation and historical-integrity prerequisites remain. An administrator-controlled namespace may contain multiple legitimate revisions during a rolling update; membership is not equality with only the newest Deployment template. Both observations must agree on the exact live specs. No matching owner-reference chain is trusted without current namespace protection and the separate trusted installation boundary.

Unit fixtures cover pre-Ready startup, status-only change, original cached-configuration/token cutoffs, CSR/purpose rejection before I/O, scope/configuration/protection changes, token audience/account/Pod binding, deletion/phase/host/injection/selector failures, workload mutation, expiry and credential-buffer/error handling. Existing acquisition-worker token tests also exercise the shared decoder. Unit configuration and Kubernetes responses are synthetic and establish no production authority.

The native fixture composes administrator-protected ConfigMap observation, audited SQL/S3 acceptance, real workload admission and real Kubernetes token review. It creates a new Deployment revision with an unsatisfied readiness gate, requests a short Pod-bound token, and expects proof while ordinary routing remains unavailable. Once the gate is satisfied, the same Pod must become routable. Wrong audience, unbound/foreign/deleted Pod and malformed CSR inputs must fail. Initial recovery/issuer roots and process requests remain fixture inputs; no peer signing or activation is performed. Actual exits, immutable-source reports and cleanup are recorded in [implementation progress](../implementation-progress.md).

[ADR-082](owner-registration.md) now adds durable owner enrollment, independent encrypted enrollment audit, nonrefundable pre-I/O signing attempts, exact returned-certificate audit/activation and bounded renewal/retirement. [ADR-083](owner-authentication.md) adds the native composition fixture and current peer authentication. Protected installation and credential transport remain separate prerequisites. A passed proof fixture does not qualify the installer, public runtime, native transfer or full S-01/S-02 workflow.
