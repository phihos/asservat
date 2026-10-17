# Audited bootstrap issuance

C-04, C-08 and C-21 implement the issuance portion of REQ-FED-001. The application accepts only a name, region, configured delivery-profile name and idempotency-key digest. Identity, actor, authority, quotas, installation and issuer epoch come from the protected enrollment authorizer. Public ingress and production trust/recovery composition remain separate prerequisites.

The bounded coordinator reserves immutable IDs and a five-minute deadline, stores the credential through the configured channel, records its digest, publishes an encrypted issuance-intent audit, acknowledges its exact verified object receipt, reauthorizes the same operator and atomically creates the claimable SQL bootstrap. It has a thirty-second request bound; each authority or provider operation retains its shorter original bound. A retry preserves the original IDs, credential and expiry. Audit recovery never creates another credential or grants new time.

The frozen audit contains the original actor/client, identity and fleet-settings revisions, request digest, display metadata, binding, original dates, delivery profile and credential digest/version. It explicitly records issuance intent; it does not falsely assert successful delivery or final activation. Its object key is `bootstrap-issue/v1/<installation>/<bootstrap>/record`, its envelope purpose is `asservat-bootstrap-issue-intent-audit/v1`, and limits are 64 KiB plaintext and 128 KiB encoded object. Conditional creation, authenticated exact-record verification and an immutable receipt prevent conflicting audit replacement. The secret itself remains only in the configured secret channel.

SQL locks installation trust before issuance intent. Activation checks current authority and the original deadline after blocking operations and again after writes, binds the exact actor/key/request/audit, and commits the issued marker and claimable token together. A missing credential, unacknowledged audit, suspended or recovering installation, changed settings/epoch, expired authority or revoked token denies activation. Replaying an issued request validates its existing token; it cannot clear revocation or change the CSR claim.

Recording an already-observed credential and publishing its historical audit may finish after authority expires or is suspended. Those operations explain a past provider effect and cannot activate it. The credential, audit and issued receipts are immutable database transitions. Independent SQL roles own reservation, credential recording, audit acknowledgement and activation; none can clear installation recovery, update a secret or enable a peer. Peer activation still requires the separate claim, PKI, certificate audit and registration pipeline.

## Verification status

Race-enabled application/codec tests passed in `test/results/bootstrap-issuance-unit.log`. They cover authority changes after provider I/O, interrupted audit recovery without another credential, exact actor/credential/time binding, wrong audit purpose, corruption and key-service failure. Real PostgreSQL/S3/OpenBao qualification passed with exit 0 in `test/results/bootstrap-issuance-integration-check.log`. The environment report records unchanged source hashes and complete owned-fixture cleanup. It covers audit gates, eight simultaneous activation retries, immutable credential/audit receipts, current authority after row-lock waits, role separation and historical audit without activation. The composed provider test now creates and audits the actual credential through KV, retrieves it through the operator channel, then claims, signs, audits and activates a certificate that passes a real TLS handshake. Revocation denies a reused connection and enrollment replay. Protected human authority and SQL trust remain synthetic in that provider fixture.

Still required for production: protected trust/recovery production, current IdP qualification, the actual authenticated browser/connector command, request/outcome audit and rate controls, credential destruction/metadata cleanup, and installation/provider backup-retention qualification. These components do not enable evidence collection or disclosure.

## Retained issuance versions

New acknowledgements and current activation require the full original issuance
receipt, including a nonempty, non-`null` immutable version. The activation
transaction validates the already-locked row; it introduces no query or role
grant. Initial claim and later signing/activation additionally check the issued
row's retained key, version and authority/ciphertext digests under their existing
locks. That issued row stores only minimized audit provenance, not the full
receipt. The full receipt is checked by the separate issuance activation step.

Historical credential/issuance/claim records remain structurally readable and
can explain already performed effects. No decoder invents a version or upgrades
old immutable history. Invalid historical provenance cannot mint a claim or a
signing attempt. The certificate registry keeps its independently audited
activation contract; it does not acquire a new dependency on an expired bootstrap
credential. Original expiry, current recovery and post-lock checks are unchanged.

Component and real-service qualification are tracked in implementation progress.
These checks do not enable a public collection or connector-enrollment route.
