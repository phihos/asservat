# Protected owner configuration and route resolution

[ADR-077](../decisions/077-protected-owner-configuration.md) extends [hub owner discovery](hub-owner-discovery.md) under REQ-FED-001, REQ-DEP-003, REQ-DLD-003 and REQ-CAP-003. [ADR-078](../decisions/078-owner-configuration-acceptance.md) adds durable acceptance under migration 29. C-04 owns `OwnerConfigurationReader`, `OwnerConfigurationLedger`, observation and route composition; C-08 owns the separate encrypted audit writer/acknowledgement ports. C-21 owns Kubernetes, SQL, object and X.509 adapters; C-24 owns observations. The [private schema](../../specs/contracts/owner-configuration.schema.json) belongs to C-20. Public browser/MCP/worker interfaces remain unchanged.

## Independently protected source

Installation selects one control namespace and `owner-pool.json` ConfigMap by name and immutable UID, with an independently pinned installation and hub cluster. The JSON selects no alternate source. Its fields are installation/cluster/issuer epoch, explicit revision, suspension, namespace/Service/Deployment/account name-UID pairs, the private target port and one to four public DER CA anchors. There are no administrator declarations, endpoint URLs, private keys, provider tokens, evidence grants or personal credentials.

`ConfigMapAdministration` describes a separately configured protected object and allowed Kubernetes administrator users/groups. `WorkerAdministration` remains a source-compatible alias, and the worker admission contract is preserved. `OwnerConfigurationAdmission` generates a fail-closed native ValidatingAdmissionPolicy/binding covering create/update/delete for the named ConfigMap in the exact namespace. This is private installation configuration, not a replacement for workload permission CRDs.

`OwnerConfigurationProtection` and the worker variant share the internal proof engine. It checks namespace identity, exact policy UID/generation/spec, current type-check status and exact binding UID/resource version/spec. A distinct probe authenticates through SelfSubjectReview, must not match an allowed administrator, and must have update RBAC for this object. It resubmits the existing object using `dryRun=All`; only the exact pinned policy/binding denial cause is accepted. Check policy/binding again afterward. The observer has read rights; the probe has no Secret, certificate-signing, workload or SQL authority. Bootstrap must restrict the probe credential to its intended use and protect the admission objects themselves.

The probe sends no persistent mutation. If admission is missing, its dry-run may succeed, but qualification then fails and the configuration remains unavailable. RBAC rejection alone is insufficient because it says nothing about what another RBAC-authorized writer can do. An installation administrator can change or suspend the source without an additional developer approval.

## Read and bind

`OwnerConfigurationSource` requires the separately constructed protection object for the exact client/source. It reads at most 64 KiB of closed JSON. Canonical re-encoding rejects unknown fields, duplicate/aliased/missing keys, trailing values and implicit zero-value substitutions; formatting changes preserve the digest. Object names and nonzero UUID pins match Kubernetes and ADR-076 constraints.

The configuration revision includes the immutable ConfigMap UID, explicit revision and SHA-256 of canonical content. This is an observation identity; this reader alone does not prove monotonic acceptance across restarts or that a value was durably audited. Such acceptance and current recovery remain prerequisites for certificate activation/effects.

Public anchors are parsed with Go X.509: one to four distinct CA certificates, at most 16 KiB each and 32 KiB total, valid CA constraints and signing usage, no unhandled critical extensions and current validity. There is no system-root fallback. `OwnerTrustRoots` returns a new pool and the earliest configured anchor expiry. These checks establish usable configured trust material, not authority to issue a certificate. Root replacement/retirement cannot silently override outstanding recovery and evidence obligations.

Read the configuration twice, require identical values and recheck admission before returning. The observation carries the protection digest and the earliest of its original five-second deadline, protection deadline and configured root expiries. Suspension remains visible in a valid observation so operators can diagnose it; route resolution refuses it. Parsing roots does not start a capture, contact a key service, sign a certificate or reveal evidence.

## Durable acceptance and current recovery

The production route reader consumes the accepted SQL projection, refreshed independently from the admission-qualified source. One `(installation, hub cluster)` head pins a source UID; it cannot be replaced through ordinary observation. Immutable revision records retain exact bounded configuration and an independently acknowledged encrypted audit receipt. The observer can advance the head but cannot acknowledge audit. The audit role can acknowledge only an existing exact revision and cannot change its content or freshness. The reader has SELECT plus only the immutable-identity UPDATE privileges required for PostgreSQL row locking. Database triggers preserve identity, monotonic progress, original deadlines, immutable snapshots/receipts and the 1024-revision bound.

`OwnerConfigurationObserver` reads/validates the source, commits the observation, writes and rereads/verifies its encrypted object, then acknowledges that exact receipt through the separate audit facet. A new generation invalidates the old projection immediately; it is not usable before audit. Reobserving an acknowledged revision returns its stored receipt and avoids repeated encryption. Failed audit leaves the new head unusable. Late audit acknowledgement never changes the head or its observation time.

An unavailable source creates or advances an unavailable watermark even when no successful observation exists. Delayed positive results cannot pass it. Older failure cleanup cannot invalidate a later valid observation. A same-generation content/protection mutation or generation rollback commits a denial watermark before reporting conflict. Equal observation timestamps cannot extend deadlines; all source timestamps are normalized down to PostgreSQL microseconds before comparison. A same-time observation cannot revive a fenced head. A later observation of exact accepted content can restore availability. Failure persistence uses a separate bounded cancellation-independent cleanup context; if SQL is unreachable, the existing original freshness ceiling still applies.

Observer/current-reader transactions lock the current fleet recovery row before the owner head. They retain source deadlines through lock waits and reject suspended/recovery-blocked/expired trust or issuer mismatch. Reading never clears recovery, reselects historical revisions or renews time. Audit object/key operations remain outside SQL locks. Suspension itself may be observed and audited but cannot produce a current usable projection. Root validity remains capped by the qualified source observation, not by parsing SQL bytes as a new trust grant.

Source replacement, historical revision retirement beyond the finite bound and issuer/root recovery need independently qualified administrator workflows. No public endpoint or additional developer approval is added by this internal configuration lifecycle.

## Compose a route

`OwnerRoutes.CurrentOwnerRoute` starts a finite five-second operation, reads current unsuspended configuration, and checks the expected installation/cluster/issuer before endpoint lookup. ADR-076 resolves the exact Pod/process expectation under that pool. The endpoint's complete pool and binding must match. Repeat configuration observation after discovery and require unchanged revision/content/roots/protection and current validity.

The returned route retains the first configuration observation and the endpoint's original observation. Its deadline is no later than either configuration read, endpoint freshness or operation deadline. A fresh cached observation can be consumed without extending its original lifetime; already-expired input fails. Copy public roots and addresses when retaining them so a reader's mutable buffers cannot alter the established result. No partial route escapes an unavailable or changed source.

The route does not authenticate the network peer or confer effect authority. A future forwarder must verify TLS against this observed trust and exact expected process before sending credentials, then recheck current configuration/recovery, active certificate registration and the exact SQL/local request fence. Current human scope, connector-origin proof and original operation deadlines remain mandatory. Missing/changed trust is unavailable, not an invitation to choose another pool or process.

## Verification and open work

Unit/race tests cover closed/canonical source parsing, scope and name/UID bounds, invalid/duplicate/expired roots, configuration/protection/root changes around discovery, suspension, endpoint substitution, cancellation and original deadlines including bounded cached observations. The shared guard continues through the existing worker tests.

The owned Kubernetes fixture composes actual protected configuration with the restricted owner Deployment and controller-generated endpoints. It verifies a separate read/probe role, exact admission rejection, no dry-run persistence, administrator suspension/resume, missing-binding rejection and a negative control where dry-run succeeds after protection is removed. Root issuance and the process epoch remain explicit synthetic fixture inputs. Results and cleanup are in [implementation progress](../implementation-progress.md); no production owner issuer, network relay or public download is claimed.

The SQL/S3 acceptance tests additionally cover encrypted audit gating, restart/replay, source replacement, role/trigger enforcement, negative observations, revision rollback/mutation, recovery changes and expiry after a proven blocking lock. The Kubernetes route fixture now composes its real protected source through the SQL observer and encrypted audit before route use. Actual exits and remaining fixture inputs are recorded in [implementation progress](../implementation-progress.md).

[Owner issuance](owner-issuance.md) now implements the provider boundary and exact CSR/current-root verification. Next are protected recovery/workload/issuer bootstrap and durable owner enrollment/activation, then private forwarding, connector proof mediation and native delivery. Helm must eventually create and qualify these installation references automatically; the current development chart does not yet install this service path.

All recognized active worker input formats require nonempty, non-`null` immutable versions for owner configuration audit. Exact acknowledged replay and the accepted SQL read apply the same owner-specific receipt check before returning current configuration. Historical JSON remains readable, but an unversioned acknowledgement cannot supply current authority, cause a replacement audit write, or acquire a fabricated version. The original receipt and observation bounds remain unchanged.

## Historical physical inventory

The concrete object-store inventory reader binds one original owner configuration,
its exact derived audit key and the configured StoreID. Independent provider
inspection credentials permit historical inspection after the original source or
issuer observation expires. This does not make that configuration current again.

One caller-bounded operation lasts at most five seconds and makes three bounded
first-page reads: versions and delete markers, unfinished multipart uploads, and
current keys. Each page admits at most 128 rows. Exact key matching excludes
neighboring decimal generations such as 10 and 11 when inspecting generation 1;
truncation remains incomplete even if all returned rows are neighbors. Actual
version IDs, explicit historical `null` versions, zero-byte objects, markers and
upload IDs remain distinct. An upload has no invented measured byte size. A
current key without a matching version is reported as inconsistent rather than
converted into a guessed version. Complete version inventory reporting a latest
data version while complete current LIST omits that key is also inconsistent;
incomplete listings cannot establish that mismatch.

Validated earlier findings survive later read or row-validation failures with an
error and incomplete flags. Completion describes each individual bounded LIST;
the three sequential reads do not establish an atomic absence snapshot. The
reader neither deletes objects nor releases quota, accepts configuration or
resumes an uncertain writer. Full pagination, durable physical accounting,
writer quiescence and retirement remain separate work. Component qualification
is recorded in [implementation progress](../implementation-progress.md).

The [owned native fixture](../../test/integration/owner_audit_inventory_test.go)
qualifies a narrow inspection profile on the pinned SeaweedFS 4.48 image. Its
coarse bucket-scoped `List` role first produces versions 200, multipart uploads
403 and no current LIST, retaining the validated version facts. An independent
fixture administrator then grants only `s3:ListBucketMultipartUploads` through a
bucket policy for the exact principal, bucket and original `s3:prefix`. The same
reader's new bounded operation completes all three LISTs. This uses the pinned
provider's [exact S3 action mapping](https://github.com/seaweedfs/seaweedfs/blob/530be3e37337488ecc34d58441e0bc476e121c93/weed/s3api/s3_action_resolver.go),
not a broad `Read` permission.

All six required native test names pass. Missing/neighbor prefixes and the foreign
bucket deny multipart listing; part listing, ordinary/version GET and mutations
remain denied. Independent exact-version reads confirm unchanged historical
zero-byte/null copies, non-null versions, marker, neighboring generations and
unfinished upload/part. The original failed LIST run and later test-transport
constructor failure remain recorded in
[implementation progress](../implementation-progress.md). This qualification
covers the inspection profile and bounded historical reader; production policy
provisioning, complete pagination, backing, writer closure and physical
retirement remain pending.

## Finite audit epoch foundation

[ADR-156](../decisions/156-finite-owner-audit-epochs.md) defines independently
audited full-snapshot epochs for automatic rollover under one protected finite
policy. The integrated typed foundation separates new admission from an exact
original dependency, requires explicit overlap and enough charged slots, and
retains uncertain copies. Its [component qualification](../../test/results/owner-audit-epoch-package/component-1/result.json)
passes 144 top-level race tests (807 named passes), affected compilation and vet,
and specification, architecture and design gates. Strict original dependency-end
checks include the exact expiry boundary; the deliberately retained failing
predecessor is an unshipped draft.

The [separate encrypted snapshot codec](../../test/results/owner-epoch-codec-integration.json)
also passes component qualification: 42 top-level framed race tests, 99 named
passes, compilation, vet and canonical gates with synthetic key providers. It
binds the complete original epoch and bounded key/envelope operations; it grants
no object write, version acceptance or current authority.

The foundation remains unselected and does not change current SQL29 v1
configuration receipts, raw observations or runtime selection. Actual reserve
and independent checkpoint producers, one-use SQL/provider
effects, accepted/admitted SQL readers, complete consumer wiring and positive
physical retirement are still required before installed use.
