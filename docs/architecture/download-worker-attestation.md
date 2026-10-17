# Download worker identity and key access

[ADR-068](../decisions/068-download-worker-attestation.md) refines REQ-DLD-003 and REQ-DEP-003. The existing [download key binding](download-key-authority.md) still owns the audited batch, exact artifact, three unwrap slots and finite authority. This component proves which current Kubernetes worker is presenting that request; it does not grant evidence access or issue a certificate.

## Ownership and inputs

C-14 owns `AttestedDownloadKeyGrants` and its `DownloadPeerProofReader`, `DownloadPeerToken` and `DownloadKeyBindingLedger` ports. C-21 implements Kubernetes observation and SQL consumption; C-24 owns the shared `KeyWorkerBinding` and `KeyWorkerProof` values. `LocalKeyContextReader` keeps its existing `DownloadKeyGrants` port; the SQL facet can no longer directly satisfy it without the proof coordinator.

Protected dispatch supplies an independently trusted binding with installation/download/worker-cluster UUIDs, namespace/account/Job/Pod names and UIDs, and the complete API-defaulted Job/Pod spec digests. `WorkerSpecDigest` uses RFC 8785 canonical JSON with a versioned kind-specific prefix and SHA-256. It limits each spec to 128 KiB. Pinning an arbitrary current spec is not approval: the dispatcher must first validate the intended restricted, download-only template and deployment admission. A mutation requires fresh reviewed dispatch; it cannot silently update an existing binding.

The TLS peer must be an acquisition peer in the same installation, with peer ID equal to the pinned Pod UID. The exact certificate digest is part of the proof. The worker cluster is intentionally distinct from the artifact's originating cluster. No container-level public permission, selector or configuration is introduced.

## Current Kubernetes proof

The adapter uses a separately credentialed `PermissionClient` for the pinned worker cluster and namespace. It receives the worker token through an authenticated internal channel via `DownloadPeerToken`, whose returned byte slice is owned and cleared by the adapter. A public request must never supply trusted token/dispatch fields. The dedicated audience is `https://asservat.{installationUUID}/key-worker-enrollment`.

Within one original five-second interval, the adapter performs TokenReview, current object reads, a second TokenReview and a second set of object reads. It requires the exact audience, account username/UID and returned bound Pod name/UID. Standard `iat`/`exp` claims are read only after server verification to reject unbounded/expired tokens and cap the proof at the original expiry. Supported tokens have at most a one-hour lifetime. The adapter does not inspect Kubernetes-private JWT claim layouts or treat node claims as current node identity.

Current exact reads reject namespace/account/Job/Pod replacement or deletion. The Job must use the expected account, match the full spec digest and be neither suspended nor terminating/completed/failed. The Pod must match its full spec digest, use the expected account, have exactly the intended controlling Job and be Pending or Running without host network/PID/IPC. The initial phase allowance permits enrollment during startup; actual runnable-worker/readiness acceptance remains dispatch's responsibility. The proof deadline is the earliest of original observation + five seconds, token expiry and certificate expiry. API failure, cancellation, malformed responses and expired observations deny access.

The reviewer needs only TokenReview creation and exact named reads of the pinned objects. It receives no token issuance, Secret read, workload mutation or broad list authority. The worker receives no TokenReview authority. Runtime bootstrap must qualify this separation, projected-token delivery, protected dispatch and the cluster's audit configuration: neither TokenReview request/response bodies nor bearer credentials may enter ordinary logs. Per-observation API work is bounded; aggregate review rate and controller replicas still require REQ-CAP-003 capacity qualification.

These source semantics follow [Kubernetes' documented bound-token review behavior](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/). Double reads are bounded observations, not atomic multi-object transactions or proof that nothing changed between reads. Previously issued proofs expire within their original five seconds; deletion cannot instantly retract bytes already authorized or delivered. Protected workload mutation boundaries remain necessary.

## SQL consumption and expiry

`AttestedDownloadKeyGrants` obtains the current proof, matches its session/certificate and caps the ledger call by the proof's original deadline. Migration `00024_download_worker_proof.sql` adds bounded private proof JSON to `download_key_binding`. It contains identities, hashes and original times, never the token or full Job/Pod specs. The row inherits the download history's finite cleanup and backup obligations.

The SQL binder validates the proof under the existing recovery → permission → session locks. It intersects proof expiry with the original parent authority, active batch and certificate lifetimes. The consumer repeats those checks with the key-child lock and database time after blocking work, including a final check after tentative slot spending. Expiry rolls back the uncommitted spend; committed unknown/failed crypto outcomes remain spent under ADR-066.

An idempotent binding retry must retain the original proof and deadline byte-for-byte. It cannot revive an expired child with a new observation. Binding and key-service database roles cannot update the proof. Legacy NULL proof rows deny both replay and unwrap; no upgrade backfill manufactures a worker identity. The original independent download/retention/recovery/audit fences and three irreversible key slots still apply.

## Qualification and remaining composition

Unit tests exercise bounded TokenReview/object responses, identity/spec substitution, deletion, cancellation, expiry, original coordinator deadlines and sanitized errors. The owned Kubernetes/TLS integration checks actual Pod-bound tokens, dedicated audiences, limited reviewer RBAC, same-account worker substitution, spec mutation and termination. Its dispatch pins and certificate issuer are explicit fixture inputs. SQL/TLS/S3 tests consume explicit synthetic worker proofs to isolate persistence, replay, legacy rows, held-lock expiry and native-download behavior. Actual command exits are recorded in [implementation progress](../implementation-progress.md); ordinary fixture-free Go tests skip these external-service cases.

The dispatch, protected profile and acquisition-enrollment components now exist under ADR-069–071. Still required: authenticated token delivery/control mediation, protected issuer bootstrap, production lifecycle cleanup, general large-file readers, public browser/MCP/relay composition and Helm startup. There is no new public endpoint and no enabled collection. These separately tested proof and ledger components do not establish a complete end-to-end deployment.

[ADR-069 dispatch](download-worker-dispatch.md) now supplies a durable SQL worker binding, a restricted Job driver and `NewDispatchedDownloadPeerAttester`. The latter uses that registry and current immutable control-source checks; it supersedes the test-pinned identity input for this composition. [Protected profile enrollment](worker-configuration.md) and [audited acquisition issuance](worker-enrollment.md) now provide those component paths. Control/runtime/bootstrap and full operational qualification remain pending.
