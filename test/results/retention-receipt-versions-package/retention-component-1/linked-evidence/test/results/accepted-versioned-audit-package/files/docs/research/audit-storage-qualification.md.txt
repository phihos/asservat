# Audit storage permission qualification

This is measured provider research from 2026-10-13. It does not enable a runtime
profile or establish general evidence-store support.

## Conditional writes and their permission enforcement differ

The owned [policy diagnostic](../../test/results/audit-s3-scope-probe-1/result.json)
used the existing pinned SeaweedFS image
`chrislusf/seaweedfs@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d`.
Image labels identify 4.48 and upstream revision
`530be3e37337488ecc34d58441e0bc476e121c93`.

With synthetic prefix-scoped credentials, ordinary `If-None-Match: *` creation
succeeds and a subsequent conditional replacement returns 412. Foreign-prefix
writes and anonymous reads return 403. A separately administered bucket policy
successfully denies the runtime writer object deletion, and that writer cannot
replace or remove the bucket policy.

However, the standard policy condition requiring `s3:if-none-match` denies even
a correctly conditional first write. The observed response is 403, so the
current policy configuration **does not qualify** the required usable append-only
audit writer. A successful diagnostic exit means the experiment completed;
its `qualificationPassed` result is explicitly false. Container, volume and
network cleanup completed without failures.

AWS documents the condition key as a way to enforce conditional writes. The
pinned SeaweedFS request-context extractor exposes `x-amz-*` request headers but
does not expose this key. That source inspection explains the observed denial;
it does not establish that every possible backend configuration is infeasible.
[AWS conditional-write enforcement](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html),
[pinned SeaweedFS context extraction](https://github.com/seaweedfs/seaweedfs/blob/530be3e37337488ecc34d58441e0bc476e121c93/weed/s3api/policy_engine/engine.go#L414).

## Boundaries and next qualification

This experiment uses a private HTTP fixture, synthetic bytes and temporary
credentials. It does not qualify TLS topology, durable persistence, concurrent
creation, production IAM administration, version inventory or deletion.
Previous product S3 roundtrip tests remain evidence for their recorded
operations; they never established this permission restriction.

Keep the installation artifacts backend-neutral and preserve their explicit
backend-qualification requirement. Neither a declared boolean nor normal client
use of conditional PUT proves that the credential cannot overwrite records.
Investigate supported immutable-version or enforced conditional-write
configurations before selecting a production writer. Any alternative must retain
exact committed identities, finite accounting, complete version cleanup and
independent retirement authority; no object-lock fallback may defeat required
early erasure or maximum retention.


## Immutable-version candidate

A [second owned diagnostic](../../test/results/audit-s3-scope-probe-2/result.json)
enables bucket versioning and denies runtime deletion. A conditional creation
returns a non-null version ID; a repeated conditional write returns 412.
Unconditional PUT creates a new version, including when a caller supplies the
old version ID. Reading the original version still returns its exact original
bytes. The runtime writer cannot delete the key, delete a version, suspend
versioning or read a foreign prefix; anonymous version reads also fail.

This distinguishes immutable committed versions from the mutable latest-key
pointer. It supports the existing version-pinned receipt format. The maintainer has
now selected versioned audit storage; complete accounting, concurrent creation,
restart/restore and independent deletion still require qualification.
The diagnostic records successful version behavior and explicitly leaves overall
qualification false. Teardown completed without failures. On 2026-10-13 the maintainer explicitly chose required versioned audit
storage without an extra gateway, including tracking and deleting every
version. This acceptance selects the design; it does not change the diagnostic
qualification verdict or waive unfinished runtime checks.

## Concurrent creation, restart and exact deletion

The [third diagnostic](../../test/results/audit-s3-scope-probe-3/result.json)
sent twelve conditional creates through four concurrent clients. Exactly one
succeeded and eleven returned 412. The complete version inventory contained
four versions: the three intentional versions of the original record and the
single concurrent winner. Independent administrator credentials deleted all
four by exact version ID; a new complete inventory was empty and reading the
original version returned 404.

Its restart check failed: bucket listing returned 200 while the first read of
the original version returned 500. The writer's delete denial still returned
403. This completed diagnostic reports `immutableVersionCandidateChecksPassed:
false`; its exit zero is not a successful qualification verdict.

The [fourth diagnostic](../../test/results/audit-s3-scope-probe-4/result.json)
retained the same assertions and added bounded, read-only sampling after an
initial 500, without retrying any write or changing product deadlines. In that
fresh run, the first version read succeeded immediately, so no recovery samples
were needed. All candidate checks passed, including the concurrent create and
complete deletion. Both labs cleaned up without failures.

The later successful restart does not explain the earlier failure or establish
a recovery duration. Bucket-list readiness alone is insufficient evidence of
readable retained records. The installation profile still requires actual TLS,
runtime credential separation, version-pinned product receipts, complete
accounting/cleanup and restart/restore qualification. These private HTTP
diagnostics do not establish persistent power-loss behavior or select a backend.

## Concrete product adapter and encrypted audit

`objectstore.NewVersionedAudit` now adds an explicit constructor whose successful
write, reconciliation and pinned-read receipts require nonempty, non-`null`
version IDs. Existing `New` consumers retain their qualified backend contract.
Neither constructor establishes IAM restrictions or storage quota by inspecting
an object response. Failed or unacknowledged writes may leave physical copies;
their reservations and cleanup obligations remain intact.

The [real-store product test](../../test/results/versioned-audit-native-test.log)
uses the existing owned SeaweedFS fixture and adapter-facing TLS, including its
private plaintext fixture hop. Eight concurrent `WriteOwnerConfiguration`
operations resolve to one encrypted object version and the same receipt. An
unconditional replacement changes the latest object, while full verification
of the original pinned version succeeds. Reconciliation against malformed
latest content fails. Writes before versioning and after suspension fail
acknowledgement while retaining their actual null copies. Independent fixture
administration inventories and deletes all four versions, verifies an empty
inventory and confirms the original is unreadable. Actual test time is 0.32
seconds, with 1,927 unchanged sources and complete lab teardown.

This test uses synthetic administrator credentials and an in-process wrapping
key. It does not qualify runtime IAM, SQL accounting, production key service,
restore or installation. The earlier restart-read failure remains unresolved.

The accepted design makes immutable audit versions intrinsic to the original
fresh worker2/owner2 selection, as required by [the evidence contract](../../specs/evidence.md#req-evd-002--commit-protocol-and-partial-artifacts).
The maintainer confirmed this choice on 2026-10-13; runtime profile enablement
and remaining qualification are still separate. Runtime permissions must include version-specific
GET and deny object/version deletion and versioning changes. Independent
retirement still needs complete inventory and physical deletion.

Conditional application writes bound legitimate retries to the original key;
prefix IAM alone cannot bound a compromised writer creating arbitrary additional
keys or versions. Versioning protects a committed version's identity, not its
allocation's physical quota. Backed audit capacity, conservative uncertain-copy
charges and complete cleanup remain separate requirements; no object-lock
configuration may defeat early erasure.

## Scoped runtime credentials and independent retirement

The [scoped product run](../../test/results/scoped-audit-storage-first/scoped-audit-storage.log), reproduced
with `make audit-storage-integration`, supplies three separate non-administrator
identities in the pinned backend. Configuration writes are confined to the exact
installation/cluster/source prefix; owner writes are confined to that
installation's enrollment and certificate prefixes. Prefix Read/Write is
combined with an independently administered explicit denial of object and
version deletion. Retirement has separate prefix read/delete and bucket-list
permissions, with an explicit denial of object writes. These are fixture
permission recipes, not automatic installation provisioning.

The actual SDK/TLS/encrypted audit composition passes concurrent creation,
version-specific retrieval after a runtime latest-key replacement, rejected
malformed reconciliation, deletion/configuration denials, cross-service access
denials and anonymous denial. Retirement removes five physical versions
including one unacknowledged null copy and one deletion marker across four
bounded inventory pages, then independently observes empty inventories. The
actual test takes 2.15 seconds; all 1,931 sources remain unchanged and owned
resources are removed without failures. The
[report](../../test/results/scoped-audit-storage-first/scoped-audit-storage-environment.json) records exact
images and selected cases.

The test uses synthetic administrator provisioning and wrapping keys, plus an
adapter-facing TLS bridge whose backend hop is private HTTP. It qualifies this
credential separation and version/delete-marker behavior, not installed TLS,
SQL capacity backing, uncertain-copy accounting, multipart retirement, restore
or persistent power-loss behavior. The earlier restart readiness failure
remains open. Versioning is still the stated implementation assumption for the
fresh worker2/owner2 pair, not a user-confirmed preference or enabled profile.

The [multipart follow-up](../../test/results/scoped-audit-multipart-test.log)
fails the complete test: retirement can list the exact incomplete upload and is
denied adding a part, but its abort receives 403. Earlier audit/version/access
checks pass again; the later version-deletion phase is not reached. All 1,931
sources are unchanged and owned resources are removed. This is a remaining
permission qualification failure, not permission to omit multipart cleanup or
grant the retirement identity administrator access.

## Corrected multipart retirement permissions

The [corrected SDK/TLS run](../../test/results/scoped-audit-retirement.log)
passes the entire matrix, including multipart abort, complete version/marker
retirement and new retirement isolation checks. The initial base Write permission
and explicit PutObject denial are removed from the retirement identity. It has
prefix Read and bucket List plus an independently installed policy granting only
`DeleteObject`, `DeleteObjectVersion` and `AbortMultipartUpload` under the three
exact audit prefixes. It cannot create an object/upload, upload a part, read or
delete a foreign object, or modify policy/versioning. Runtime writer deletion
denials remain unchanged; no administrator credential is supplied to retirement.

The pinned policy engine includes abort in its multipart action set and falls
back to matching `s3:PutObject` when evaluating both Allow and Deny statements.
That explains the previous explicit-deny failure. The positive exact-action
recipe avoids that alias without granting base Write. This is provider-specific
qualification, not a claim that AWS IAM has identical action matching.
[Pinned policy matching](https://github.com/seaweedfs/seaweedfs/blob/530be3e37337488ecc34d58441e0bc476e121c93/weed/s3api/policy_engine/engine.go#L171),
[pinned multipart action set](https://github.com/seaweedfs/seaweedfs/blob/530be3e37337488ecc34d58441e0bc476e121c93/weed/s3api/policy_engine/types.go#L41).

The actual named test takes 5.28 seconds; its
[report](../../test/results/scoped-audit-retirement-environment.json) records ten
named passes, 1,934 unchanged sources and complete cleanup. The harness takes
39.678 seconds including setup/build/teardown. The earlier failing run remains
separate evidence. This qualifies the fixture's permission and cleanup behavior;
installed provisioning, physical quota/accounting, writer quiescence and the
earlier restart-readiness issue remain open.
