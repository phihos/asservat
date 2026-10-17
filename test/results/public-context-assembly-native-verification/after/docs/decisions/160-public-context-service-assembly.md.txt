# ADR-160 — Purpose-separated context service assembly

Status: implemented; component and native role checks pass, installed workflow pending.

The shared HTTP boundary already expects complete capture, case and download
operations, but installation has no single constructor joining those use cases.
Its compiled SQL inventory also lacks the preview writer and request-resolution
writer that the existing application service needs. Using capture admission's
credential for those operations would conflate passive review, resolution and
new evidence admission.

Add `capture-preview` at permanent ordinal 46 and `capture-resolution` at 47.
Existing ordinals, including cleanup 43–45 and capacity 70–71, retain their
meaning. The installer inventory has 33 purposes and the hub projection 28.
Both new roles retain the existing five-connection hub envelope; each runtime
pool remains one connection. This adds ten possible role connections to the
complete installation budget, not a larger per-role or per-process pool. Total
installation connection planning must account for them before public startup.
No PostgreSQL migration or new runtime DDL authority is introduced.

The preview credential constructs `postgres.ContextPreviews`: schema/version
read, permission-root lock, passive preview/fence reads, immutable preview
INSERT and expired preview/fence DELETE. It cannot close a preview, install a
resolution fence, accept a capture or reserve evidence storage.

The resolution credential constructs `postgres.ContextRequestResolutions` with
the existing root-bound recovery transaction guard. It reads current recovery,
permission projections and accepted captures before resolving the original
actor/client/key. Its only writes are the three existing one-way preview
closure columns, INSERT of the existing missing-preview fence, and expired
preview/fence deletion. Recovery SHARE precedes the permission-root UPDATE
lock. It has no capture, custody, permission-source or audit writes. SQL33/36
still enforce immutable original fields, first closure and live-deletion denial.
These database roles provide purpose separation; the existing root/current-
identity checks remain mandatory and are not replaced by a claim of SQL RLS.

`bootstrap.NewPublicContextOperations` assembles accepted installation services
into the existing presentation operation set. It uses `ContextSubmission`, so
first admission includes acknowledged intent and regional start, while explicit
Continue remains an accepted-only path. It binds the existing regional router,
shared capability/recovery readers, verified case navigation, native download
coordinator and Stop owner. Missing dependencies, foreign root/installation
scope, separate active-download ownership and overrides of assembly-owned ports
are errors. Construction performs no provider I/O, invents no authority or
observation, and opens no listener.

Browser and MCP continue through `NewPublicContextHandler` and the same audited
operation registry. Disabling acquisition retains resolution, existing cases,
downloads and Stop. Original caller identity, cancellation, deadlines, retained
scope, managed encryption and local-download behavior remain with the existing
use cases. This decision adds no API, route, approval or public configuration.

The source-owned layout digest incorporates both purposes, grants and projection
filenames. Old 31-purpose installer states and 26-purpose hub manifests cannot
satisfy the new complete inventory. Different layout digests also reject.
Preserve historical receipts for inspection; do not silently add credentials,
reissue claims or reinterpret old state as the new layout.

The [component gate](../../test/results/public-context-assembly-component-1/result.json)
passes 300 top-level race tests, compilation, vet and canonical checks. It tests
assembly bindings and original identity denial, not a positive complete journey.
Actual generated-role SQL checks pass in the unchanged first-installation
fixture: all 87 named tests pass with owned PostgreSQL/S3/OpenBao services.
The wrapper omitted four existing test names and retains exit 1; the
[independent verification](../../test/results/public-context-assembly-native-verification/result.json)
checks the source-derived complete inventory, original limits and cleanup.
Protected installed observation/configuration producers, credentials and backing
for every downstream download role, regional entrypoint, owned supervision and
the complete browser/MCP capture-to-download journey remain necessary before
public or Helm runtime enablement. Component assembly does not complete S-02.
