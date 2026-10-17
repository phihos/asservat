# ADR-151: Required versions for initial installation audit

Status: component implementation and original fresh-bootstrap native qualification pass. Applies to REQ-EVD-002, TASK-02/03 and the
protected installation prerequisite of S-01/S-02. Qualification is recorded in
[implementation progress](../implementation-progress.md); component checks do not
establish complete runtime or physical-version retirement.

## Problem and decision

The selected provider-installed runtime requires immutable audit versions, but
the initial installer previously constructed a version-optional store. Enabling
bucket versioning in a fixture did not enforce the same requirement in product
code. A missing or `null` version could therefore produce an initial receipt.

Every active initial-installer storage adapter requires nonempty, non-`null`
immutable versions. This also applies when loading a recognized older input
format. Retaining an older immutable plan must never select a weaker runtime
backend. Missing versions fail after an uncertain write with no fallback,
replacement attempt or automatic adoption of the latest key. Reads and
verification remain pinned to the original acknowledged version.

Fresh original bootstrap selects `asservat-initial-bootstrap/v4` only after
its existing complete absence checks. Its immutable projection selects
`asservat-initial-preparation-services/v2`, which produces
`asservat-initial-installer/v2`. There is no user-selectable versioning switch,
provider-response detection, extra gateway or change to encrypted object bytes.
The credential binder accepts only the exact installer format derived from the
original service profile. The service-intent and installer-plan digests bind
that choice before effects; a later downgrade cannot rewrite either claim.

Known v2/v3 bootstrap roots retain their original format, guards, public/private
provenance and passive replay. Unknown, incomplete or changed history is never
upgraded. Known older installer documents keep their canonical bytes, but any
new audit effect or authority-bearing read requires a valid pinned version.
Unversioned historical receipts do not become current activation or restore
authority. No migration fabricates a version, rewrites an old receipt or clears
an already consumed witness/recovery fence.

## Ownership and implications

C-20 owns the closed format values and schemas; C-21 retains original protected
bootstrap/namespace/input production. Bootstrap selects the version-required
object-storage adapter when composing the private installer. SQL and encrypted
initial-activation audit contracts remain unchanged. Test backends must enable
versioning before the first product effect using fixture administration; that
fixture privilege is never given to the runtime writer.

This adapter enforces receipt/read identity, not backend IAM or versioning
administration. Scoped writer denial of object/version deletion and versioning
changes needs the separate actual-provider tests. Complete physical-copy
reservation/inventory/retirement, unacknowledged writes, old versions and delete
markers remain mandatory. Initial success does not qualify restart/restore,
provider refresh, owner startup or an installed debugging workflow.

## Verification

Require meaningful missing/null-version failures against the version-optional
constructor, actual TLS PUT/pinned GET tests for both recognized installer
formats, immutable-plan and service-downgrade regressions, original-profile
routing/replay, affected legacy suites and canonical schema checks. Then run the
fresh original bootstrap chain against actual Kubernetes, SQL, key and object
services, asserting the committed initial audit version and exact cleanup.
Actual results, including interrupted checks, remain in the progress record.

The [original native run](../../test/results/initial-versioned-audit-native-1/result.json)
passes all four selected cases with 2,142 unchanged source hashes and complete
owned cleanup. Both runtime Deployments stay at zero replicas. The [combined
component gate](../../test/results/initial-owner-integration-1/result.json) also
passes; neither result establishes all-copy accounting, independent restore or
a public investigation workflow.

## Acknowledged-version readback

A successful initial audit PUT already supplies the version to verify. The
readback now requests that exact version with its original ETag and validates
the complete byte count and ciphertext digest before encrypted-record verification.
A changed latest pointer cannot substitute a different receipt even when its
envelope encodes the same valid record. The existing HTTP 412 reconciliation
protocol remains separate; unknown PUT replies neither trigger readback nor
create positive writer completion. Existing SQL acknowledgement still determines
the retained original receipt.

Public-operation and download-stop positive writers and deletion-certificate
verifiers use the same exact-receipt read. This adds no claim, retry, authority
or storage request and preserves full post-lock/deadline checks. The [component
regression](../../test/results/audit-version-pinning-integration.json) reproduces
the initial substitution with the prior writer; 57 object/framing plus four
installer top-level race tests pass. Actual backend composition of this follow-up
is recorded separately from the preceding fresh-bootstrap run.

The same acknowledged-PUT rule now applies to reconciling authority, enrollment,
configuration, acceptance, capture-intent, verification, lifecycle, worker,
delete-audit, legacy operation and legacy download-stop writers. Definite HTTP
412 still enters their original decrypted semantic comparison: randomized
ciphertext from an earlier attempt need not equal freshly sealed bytes. An
unknown write does not trigger GET. Separate Find calls remain read-only and
cannot create positive completion. Download-window writes select the known
version before their existing complete receipt/envelope and completion checks.
The private helper supplies no authority or writer-completion fact. This change
does not migrate generic stores to version-required construction or establish
retirement coverage for additional audit families.

The [broader correction](../../test/results/audit-create-pinning-integration.json)
reproduces the original owner-version substitution and download-window availability
failure. Corrected object/framing races pass 60 top-level / 185 named cases and
audit-application races pass 34 top-level / 75 named cases with no skips; whole
compilation and affected vet pass with 3,023 unchanged dependencies. Real-service
qualification of these additional writers remains separate from the earlier
initial/operation/stop native results.

The initial receipt predicate also requires a nonempty, non-`null` version.
This applies at SQL acknowledgement, activation, historical observation and
post-activation runtime-bridge construction, so a previously stored empty/null
receipt cannot bypass the new-write constructor. Existing bytes remain untouched;
there is no automatic migration or synthesized version. The [history regression](../../test/results/initial-audit-history-version-integration.json)
reproduces two direct and four persisted-history acceptance failures with the old
predicate. Corrected component races pass 10 top-level / 66 named entries with
no skips; compilation and affected vet pass with 3,025 unchanged dependencies.
The new actual-SQL negative acknowledgement cases await native qualification.
