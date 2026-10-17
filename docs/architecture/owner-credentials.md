# Process-owned hub credentials

[ADR-084](../decisions/084-process-owned-owner-credentials.md) connects [audited enrollment](owner-registration.md) to process key custody and renewal. C-04 owns `OwnerCredentialEnrollment`, `OwnerCredentialClient`, `OwnerCredentialSupervisor` and transient `OwnerCredentialStatus`. C-21 owns `mtls.OwnerCredentials`; existing C-24 binding/certificate values remain unchanged. SQL remains migration 30; no public or private wire schema is added.

## Credential ownership and installation

Protected bootstrap supplies the exact installation/hub-cluster/issuer/Pod binding with a fresh process epoch, explicit issuer roots, audited enrollment operation and independently pool/source-pinned active registry. Construct separate server/client instances. Each creates its own P-256 key and identity-free signed CSR. It never accepts an external private key or exports serialized keys. The CSR survives retries and renewals; restarting requires a fresh epoch and keys. Durable enrollment rejects another key for a retained process/purpose identity.

`Enroll` allows one attempt at a time, at least one second between attempted calls and one original thirty-second deadline. Recheck caller cancellation after acquiring the owner lock, before returning a cached identity or invoking enrollment. It copies the CSR for the coordinator, then validates the bounded public result: leaf at most 16 KiB, at most three chain certificates, and at most 32 KiB total. Parse copied DER; verify the generated SPKI, strict purpose/URI/DNS profile, binding, actual metadata digest and pinned roots. The leaf must end at the fixed UTC window at either request start or completion, accommodating one renewal-boundary crossing. Its maximum lifetime is twenty-two minutes including renewal advance/backdating; a shorter root cannot silently change the advertised leaf expiry.

Independently read active registration for that certificate. Require the exact certificate, immutable enrollment key and original current configuration interval. Reverify under accepted roots as well as constructor roots. Check cancellation, clock rollback, the original thirty-second limit, certificate validity and registry/configuration deadlines before installation. No freshness is renewed locally. Failed renewal preserves only the original leaf until its original expiry.

An already installed valid current-window certificate avoids another enrollment call. This only means the credential exists. Retirement, root removal, Pod deletion, readiness and request authority remain mandatory in [current peer authentication](owner-authentication.md) and forwarding, including on existing connections. A callback never substitutes for those checks.

## TLS snapshots and shutdown

`GetCertificate` serves only the server purpose, exact deterministic SNI and a TLS 1.3-capable hello. `GetClientCertificate` serves only the client purpose under TLS 1.3. Both require a supported certificate and return copied DER plus reparsed public state. Runtime configurations must pin TLS 1.3, avoid static-certificate fallback and preserve current peer checks. Runtime transport qualification must also cover session resumption and socket cancellation.

The private key field contains a restricted `crypto.Signer`, not the ECDSA private key. `Public` reparses an independently owned public-key snapshot. `Sign` accepts only P-256 SHA-256, uses the standard random source, and checks the original snapshot expiry before and after signing. Caller mutation and renewal cannot extend that snapshot. A caller-supplied blocking random reader cannot hold the shutdown lock.

`Close` is idempotent, cancels enrollment, removes key/certificate references and disables all retained signers. It promises neither physical heap zeroization nor established-socket termination. Runtime owners must close their listeners, transports and active requests. No key or CSR persistence is added.

## Pair supervision

The supervisor owns independent server/client credentials for the same binding. Initial enrollment lasts at most ninety seconds. It validates both and publishes a nonblocking process-local notification; this grants neither readiness nor authority to adopt requests.

Schedule renewal one minute before the earlier original leaf expiry. Each round makes at most eight attempts, delaying one, two, four, eight, sixteen and then at most thirty seconds, with 0–500 ms jitter and clipping to that deadline. Attempts retain their thirty-second bound. One side's successful renewal cannot extend the other side's deadline. Both leaves must outlive the earlier previous expiry before success. Cancellation, expiry or exhausted retries closes both owners; blocked notification receivers cannot prevent closure. SQL signing budgets remain independent and never reset on retry.

## Verification scope

Synthetic tests cover actual mutual TLS through these callbacks, independently owned keys, key reuse through renewal, invalid registry/root/certificate results, concurrent enrollment/cancellation, snapshot mutation/expiry and eight hours of accelerated pair scheduling. This is not eight hours of native provider operation.

The native fixture adds these keys to real Kubernetes pre-Ready proof, protected accepted configuration, scoped OpenBao signing and Transit/S3 audit, SQL activation and separately credentialed registry. A replacement key for an existing process is rejected before signing. Actual TLS snapshots undergo current Ready-route/root checks. The pause Pod runs no hub executable; protected installation/recovery and token provisioning remain fixture boundaries. [Implementation progress](../implementation-progress.md) records actual results. Protected bootstrap, transport/listener composition, live-provider renewal endurance, forwarding and the complete user workflow remain pending.
