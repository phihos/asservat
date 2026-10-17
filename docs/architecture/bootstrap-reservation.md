# Bounded bootstrap issuance reservations

C-04/C-21 under TASK-03, REQ-FED-001 and the protected fleet-administration contract. Migration 00010 adds `fleet_bootstrap_intent`: an accepted issuance request, not a usable token, certificate or active cluster. Issuance audit and finalization are still separate work.

## Current acceptance and identity

`ReserveBootstrap` consumes a current internal enrollment-authority result from [protected administration](fleet-administration.md). It locks installation trust and verifies the original authority interval, exact installation/issuer epoch/settings revision, current trust freshness and suspension/recovery state. It checks time after blocking work and before returning. These are trusted application inputs; caller-created structs and fixture authority do not establish operator eligibility. Production ingress must use the authorizer and protected trust/recovery producer.

The idempotency index is installation, complete actor identity (issuer, subject, client and human/workload kind), and request-key digest. A request digest binds the exact display name, region and configured delivery profile. A matching retry returns the original bootstrap, cluster and peer IDs and original five-minute deadline. The current short channel-operation interval may be revalidated inside that original deadline; it cannot renew the bootstrap. A conflicting body under the same key fails. The database trigger rejects changes to original actor, identity/settings revisions, request, scope, display metadata and dates.

## Independent finite limits

Under that same installation lock, admission checks three administrator ceilings:

- Active bootstrap slots include pending intents and already-issued bootstrap records until their original expiry; uncertainty or revocation does not silently refund the slot early.
- Retained bootstrap history includes expired records. Reaching this ceiling stops new reservations until qualified cleanup can retire records; it does not delete history implicitly.
- Registered/reserved cluster identity includes retained peer registrations and unexpired bootstrap/intention identities. A disabled or expired peer certificate does not silently remove the cluster registration.

Intent and issued-token records with the same bootstrap UUID count once. Pre-existing tokens without a new intent row still count, so adoption or partial historical state cannot enlarge capacity. Names/regions are bounded UTF-8 control metadata; there are no secrets, evidence bytes or provider responses in this table. SQL storage and backups still require the installation's encrypted finite metadata policy.

The reservation role can read the relevant counters, lock the trust row and insert intents. It cannot create a claimable bootstrap, enable a peer, clear recovery, delete history or extend deadlines. Actual credential generation occurs later through the [configured channel](bootstrap-channel.md); it never occurs during preview.

## Verification

Initial real PostgreSQL races, idempotent restart, state/expiry rejection and role checks passed. Additional tests reproduced an omission of pre-existing token rows from all three counters; `test/results/bootstrap-existing-quota-regression-test.log` and its environment report preserve that failure. The corrected query counts both intents and tokens and deduplicates by UUID. The pinned sqlc tool required a named CTE rather than its unsupported subquery/filter alias combination; no count was weakened to accommodate generation.

The corrected fleet and full custody suites passed with exit 0 in `test/results/bootstrap-reservation-fixed-integration-check.log`. Both environment reports record unchanged source hashes and complete owned-fixture cleanup. They test the final available slot under eight competing requests, preserved original IDs/deadlines under eight identical requests, expired history, existing registrations/tokens, suspended/recovering/changed trust and authority expiring behind a row lock. No public issuance or collection path is enabled by these tests.

Still required: binding the exact credential receipt, encrypted issuance audit, current atomic creation of `fleet_bootstrap`, secret-channel cleanup/retention, global request-rate limits, protected trust/recovery production and browser/connector ingress. The tested raw actor/settings values are synthetic; they do not replace real identity and configuration validation.

[Audited bootstrap issuance](bootstrap-issuance.md) now composes reservations, credential delivery, encrypted issuance-intent audit and current atomic activation, with real PostgreSQL/S3/OpenBao tests. This supersedes the issuance-producer gap stated above; protected trust/recovery, provider lifecycle qualification and public ingress remain pending.
