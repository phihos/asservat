# Profile comparison composition proposal

Status: integrated candidate; service and installed qualification pending. Scope: REQ-PRF-005 /
SC-PRF-005, S-05 increment 8. ADR-295 governs the current implementation. The
[component checkpoint](s05-profile-comparison-component.md) covers the prepared
parser and authenticated two-reader adapter; it supplies no public authority.

## Smallest supported composition

Use one existing regional worker, one admitted comparison query, one compound
read batch and one bounded result. Keep exactly two ordered sources: baseline
ordinal 0 and incident ordinal 1. Reuse the existing single-source authorizer
independently for each pprof source, including ordinary rights, original
audience, client, retention, recovery and processing. Metadata-share fallback
remains unavailable for raw profiles. Do not obtain two public summaries and
subtract their truncated top-N rows.

The two independently permitted paths must reach the same existing reader:
same installation/root, store ID, storage region, acquisition cluster/region,
connector cluster/region, hub cluster/region, worker configuration and hub
configuration. Compare these physical fields; **do not require equal Path.ID or
TargetClusterID**. Those identify each source's distinct accepted route and
target and must remain independently checked. The current worker has one
`CustodyStore`, store credential, key scope and endpoint; different stores or
worker configurations cannot be made compatible by taking a union of roots or
credentials. Report the unsupported placement without moving raw bytes through
the hub. This initial placement boundary needs specification coverage.

Keep each original source version, route and full authority. Recheck the first
after blocking work on the second; derive all operation/result bounds from the
earliest original caller, source, permission, retention, recovery, processing,
worker and query bounds. Current checks around SQL, keys and delivery must cover
both sources. Neither historical publication nor a successful first read is
authority for the other source or the eventual comparison.

## Atomic accounting and key identity

- Reserve 10 existing conservative profile-query units per source: 20 total,
  including a typed semantic mismatch after authenticated reads. Same workload:
  aggregate both charges into one 20-unit allocation update. Different
  workloads: lock both allocations in stable UUID order and charge 10 each in
  the same SQL transaction. Charge the principal/root total once. Unknown
  commit remains spent; replay cannot partially admit or refill either source.
- A nullable second-allocation reference on the existing `context_query` row is
  sufficient for this fixed pair. Extend admission triggers and current fences
  to check both accepted plans and workload allocations. No general source-set
  engine or new storage service is needed.
- The one physical worker counts once globally and per principal, and once
  against **each distinct covered workload's** existing two-worker ceiling.
  `AcquisitionWorkerCapacity` currently sees only its primary allocation; that
  query and the worker reservation checks must consume the second allocation
  too. Two references to one workload still represent one physical slot.
- Extend the existing key-binding table with immutable child identity and
  source ordinal, unique per `(batch_id, ordinal)`. Atomically create two
  three-role children under the one batch; preserve each child's existing
  monotonic data/index/manifest mask. Keep the batch claim identity distinct
  from the key child's authority UUID. Legacy child identity remains its batch
  ID, with the old encoding retained.
- Pass each stored child UUID to the existing remote opener. Bind child,
  ordinal, exact version, artifact AAD, pair/query, batch, worker and original
  bounds in provider validation. A failed/unknown first-source unwrap cannot
  consume the other child's slot as a retry. Six key uses are prepaid.
  Baseline and incident may name the same artifact: still two independently
  authorized opens and six slots. Their identical AAD is why one six-bit mask
  selected only by AAD would be ambiguous.

Comparison children should store compact references, not duplicate the complete
pair authority and query in each row: child/query/batch/claim IDs, source ordinal
and version, artifact-binding/AAD identity, key scope, exact worker/process and
certificate references/digests, immutable parent query/authority digests and
original creation/expiry bounds. The resolver already reads the immutable
parent query, batch/native authority, admitted worker and published source;
derive the full current check from those records before consuming a role bit.
The compact child is never authority on its own. Keep the legacy key binding's
bytes and validation branch unchanged.

Preserve comparable immutable scopes: use closed value fields/fixed pairs,
without borrowed slices, maps or pointer-identity equality. Omit the entire
comparison branch for legacy queries and scopes. Ordinal order is semantic;
allocation/retention lock order is separate and must never swap source labels.
Rollback must refuse retained comparison scopes/children it cannot interpret.

## Exact extension map

| Area | Existing files/functions to extend |
| --- | --- |
| Fixed query values | `internal/domain/analysis/projection.go`, `context_query.go`, `context_worker.go`, `projection_result.go`: closed pair scope/authority/plans, exact equality, minimum deadlines, comparison tool/result, one compound batch and two key children. Preserve the existing individual scope values for source checks. |
| Admission/current request | `internal/application/analysis/context_query.go`, `context_query_ports.go`, `profile_summary.go`: a typed comparison facet on the same owner/coordinator; bind both source IDs and normalization in invocation/audit. `internal/application/authorization/projection.go` (`ResolveProjectionCurrent`, `CheckProjectionCurrent`) and `projection_environment.go` (`ProjectionEnvironment`) remain the per-source authority producers. |
| Placement | `internal/application/authorization/projection_policy.go` (`ContextProjectionPolicy`) selects each accepted path; compose the physical compatibility check after both independent results. Do not replace their individual paths with an invented combined placement policy. |
| Plans and SQL fences | `internal/adapters/postgres/context_query_capacity.go` (`ContextQueryPlan`), `context_query.go` (`current`, `fence`, `AdmitQuery`), `context_query_batch.go`: resolve two plans; one recovery/permission transaction; check both retention topologies, processing snapshots, publication versions and current allocations before/after effects. Lock distinct allocations consistently. |
| Durable charge/worker coverage | One additive migration plus `migrations/queries/context_query_capacity.sql`, `context_queries.sql`, `download_workers.sql`; update closed scope/tool/unit/audit triggers. `context_projection_worker.go` (`ReserveProjectionWorker`, `ProjectionWorkerRoom`) and `AcquisitionWorkerCapacity` must cover both workloads while retaining one Job. |
| Sources/private operation | `internal/adapters/postgres/context_projection_native.go` (`ReadProjectionSource`, `projectionNativeRecord`) and `internal/application/evidence/context_projection_runtime.go` (`ReadProjection`): carry both verified sources and proofs in one registration/operation. Existing `NativeOperation` currently binds one version/path/processing proof, so it needs a closed pair branch, not an unchecked second JSON payload. |
| Keys | `internal/adapters/postgres/context_projection_keys.go` (`BindProjectionNativeKeys`, `ProjectionKeys.Resolve`), `internal/application/evidence/context_projection_keys.go` and domain `ContextProjectionKeyBinding.Valid`: two atomic children, ordinal-specific AAD and six irreversible uses; current fences cover the pair. |
| Regional read/protocol | `internal/contracts/native_exchange.go`, `internal/domain/authorization/native_exchange.go`, `internal/transport/native/worker.go` and approved-result codec; `internal/application/evidence/native_projection.go`, `context_projection.go`; `internal/adapters/objectstore/native_projection.go`, `context_projection_read.go`: typed pair command and one bounded comparison result. Open each source with its own stored key child and call prepared `ReadProfileComparison`; close both on every exit. |
| Protected/public assembly | `internal/bootstrap/public_projection.go`, `public_context_operations.go`, `download_worker_native.go`: install the typed facet and fixed interpreter through the current protected worker only. Extend canonical MCP schemas, browser/console result handling and two-source provenance/audit together. |

Acquisition type, mode and forced-GC facts already live in independently pinned
`NativeContextSource.Expectation.Profile`, returned by `ReadProjectionSource`
and matched against the authenticated manifest. No new manifest method is
needed for those facts. `FramedNativeSource.CaptureWindow` supplies authenticated
capture dates if a presentation requirement needs them; it does not replace
native sample duration when calculating rates.

## Complexity gate and remaining proof

| Gate | Numeric or yes/no answer |
| --- | --- |
| 1. Observed benefit | 1 specified public operation remains absent; every comparison has exactly 2 inputs. No measured runtime defect is asserted here. |
| 2. Accepted risk | Yes: bounded regional Go analyzers and ordinary approved profile inspection are accepted. No additional raw-disclosure approval is proposed. |
| 3. Typical path | Yes: two saved profiles served by a common installed reader. Other placements explicitly remain unavailable. |
| 4. Precedent | Existing installed pprof summary/query/key/worker composition is reused. No claim of external-project research is made. |
| 5. Added exposure | 0 services, Jobs beyond the existing one, credentials, key roots, RBAC permissions or public network endpoints. Existing SQL tables gain fixed pair references/children. |
| 6. Additional fallback states | 0. Existing unavailable and specified semantic-mismatch outcomes apply. |
| 7. Machinery configuration | 0 new settings. |
| 8. External dependence | 0 new dependencies; current PostgreSQL, Kubernetes, key service and object store remain required. |
| 9. Aggregate work | 2 complete native inputs, at most 64 MiB each; 6 unwraps; 20 conservative units; 1 physical worker; 0 watches/background loops; comparison output at most 24 KiB. New shared workers declare 384 MiB physical/transient memory and 500m CPU (+128 MiB per active worker versus the previous installer profile; +256 MiB at the existing two-worker workload ceiling). Existing accepted profiles and legacy admission floors remain unchanged. Full-worker peak/CPU and provider/SQL time remain unqualified. |
| 10. Rollback/disable | Planned: omit typed facet to disable new admission; legacy bytes stay unchanged; rollback refuses retained new pair state. Not yet tested. |
| 11. Smaller alternative | Two independently admitted summaries fail full-function comparison, atomic charging and one-worker ownership. The prepared parser/reader alone does not satisfy the public feature. |

The retained complete two-source process probe peaked at 252.363 MiB RSS in
1.202s without real SQL/KMS or a cgroup. ADR-295 selects 384 MiB for the new
shared installer profile, retaining the legacy summary floor. The versioned
`shared-query/v3` qualification digest records the changed resource declaration.
Still qualify actual framing, parsing, aggregation and providers together. Test
atomic cross-workload refusal/unknown commit, same-artifact child separation,
either source's deny/expiry/revocation, mismatch after both final hashes, closed
delivery and positive worker retirement. Complete native comparison against
both authenticated downloaded profiles and browser/MCP parity before claiming
REQ-PRF-005 or SC-PRF-005 complete.

## Paired SQL and encoding review, 2026-11-03

The implemented C-03 pair uses one owned
`Baseline *ContextProjectionAuthority`, rejects a second nesting level and
retains comparable value scopes. The proposed query adds
`BaselinePlan ContextQueryPlan` **by value**, omitted when zero. Extend
`ContextQuery.Equal` to normalize all six baseline-plan observation/horizon
times, as it already does for the incident plan. A pointer is appropriate for
the exactly one optional authority, but existing `sameProjectionAuthority`
helpers must compare/clone that child's values rather than pointer addresses.

The plan reader must choose one proposed principal-account UUID for both
source-plan reads. `SharedContextQueryPlans.ContextQueryPlan` currently creates
a new UUID per call, and `read_shared_context_query_plan` returns that proposal
when the principal has no account yet. Calling it twice unchanged can produce
two account IDs for one new principal. Reuse the existing SQL function twice
with one proposal in one plan-read transaction; do not rewrite a resolved plan
afterward. Both accepted plans keep their own workload allocation/path facts.

Observed pure encoding results, not SQL admission or installed qualification:

| Structurally valid maximum-shape preparation | Go JSON bytes | Conservative JSONB spacing ceiling |
| --- | ---: | ---: |
| Pair scope | 19,265 | 19,422 |
| Pair authority | 91,034 | 92,851 |
| Existing full key-binding-shaped envelope with pair authority | 116,329 | 118,709 |
| One independent plan | 22,575 | 22,943 |
| Proposed query with value `BaselinePlan` | 65,548 | 66,522 |

The authority/plan validity checks passed; the compound query/key envelopes are
not activated. The spacing calculation retains Go escaping and is an upper
bound, not observed PostgreSQL JSONB output. The focused maximum-shape test
passed with race detection in 1.024 s. Its log is
`/home/phil/.cache/asservat-build/profile-comparison-authority-maxencoding.log`.
The selected design permits **comparison-only** 96 KiB query envelopes and
128 KiB pair-authority envelopes; legacy 64 KiB limits remain unchanged.
Actual PostgreSQL JSONB round-trip/constraint proof remains required.

`download_worker.intent_json` is bytea capped at 64 KiB, and the worker intent
contains the whole query plus the physical worker profile. Its comparison
branch must use the corresponding measured, bounded envelope too; updating
only `context_query.query` would leave dispatch/enrollment/cleanup unreadable.
Audit `context_projection_worker.go` (`projectionWorkerState`,
`ReserveProjectionWorker`), `context_projection_cleanup.go` (`cleanupState`) and
`context_projection_enrollment.go` (`auditTransaction`) together. The certificate
attempt's separate 64 KiB limit does not contain the full query and needs no
automatic expansion. Keep batch/request, native-operation and result limits
unless their own measured fixed shapes require a separate change.

### Full source transfer fits the existing command path

The private **command** ceiling is already 640 KiB (655,360 bytes), not the
64 KiB limit used for other control/result frames. The unchanged pure
`TestNativeCommandAcceptsMaximumExistingSource` passed in 0.078 s and reported
569,446 source bytes, 3,898 operation bytes and 573,983 command bytes. That test
constructs a conservative domain superset, not a source accepted by current SQL
capture admission. Concatenating two such supersets would exceed the command
ceiling and is not the proposed transfer contract.

The actual `capture.go` admission producer marshals the complete expectation
and rejects more than 65,536 bytes; migration 00004 independently preserves
that immutable bytea bound. `ReadProjectionSource` reads precisely that
published capture record. Re-establish the **same canonical re-encode bound**
when assembling each full source; retain all audience, retention, composition
and acquisition provenance. A raw SQL JSON byte count alone would not prove
the size after Go escaping. `GoProfileAcquisition.Valid` alone also does not
bound its optional `Composition`; `ProfileContextFor`'s separate 64 KiB input
ceiling does not replace the smaller whole-expectation admission contract.

Four copy receipts each have two strings of at most 1,024 bytes, a bounded
integer and a fixed digest. Six-byte escaping plus fixed fields gives a
conservative receipt-array allowance below 50,100 bytes. Complete sources are
therefore below 115,700 bytes each under the existing producer contract. Two
full sources, the measured pair scope, a native operation within its existing
16 KiB bound and a 2 KiB command envelope remain below 270 KiB. This is derived
bound arithmetic; the new two-source maximum-shape command regression is still
required. Reuse the existing command/read ports, without new chunking states,
endpoints or discarded provenance. Result/native-control frames stay 64 KiB;
the comparison remains bounded to 24 KiB.

### Additive migration contract

1. Add nullable `baseline_allocation_id` with a same-root allocation foreign
   key to `context_query`; retain primary incident allocation identity. An
   absent comparison requires SQL NULL and an omitted zero baseline plan.
2. Replace the closed comparison scope/tool/unit/audit predicates **in the same
   migration as** both-source current fences and atomic accounting. Validate
   both full plans, common physical placement and the one principal account;
   lock distinct allocation IDs in stable order, then charge 20 once for the
   same allocation or 10 to each, with principal/root total 20. Do not enable
   comparison scope acceptance in a preliminary SQL helper-only change.
3. Extend shared acquisition capacity matching to both distinct workload
   allocations, counting one worker globally/per principal. Update source,
   retention, processing, publication and recovery fences around every effect;
   preserve originals across waits and unknown commit.
4. Add immutable key-child UUID and ordinal columns to the existing key table,
   retaining the batch/query foreign key and three role bits per child. Backfill
   legacy child UUIDs from their batch IDs; enforce one child per source ordinal
   and atomically insert the comparison's two compact children. Preserve the
   original batch claim ID instead of treating the new child UUID as a claim.
5. Add only the typed envelope branches described above, update matching Go
   producers/decoders and account for the extra row/WAL/backup work in existing
   conservative units. Refuse downgrade with retained pair state. Prove the
   final migration/role/JSONB behavior before public composition.

No resolver privilege addition is needed for the compact children:
`public_runtime_projection_grants.go` already grants `key-acquisition` SELECT
on the query, call, worker, batch and key-binding tables plus the existing
fence-lock and `used_roles` updates. `ProjectionKeys.Resolve` already calls
`withBatch` and reads the native parent, admitted worker and published source.
Extend those existing sqlc reads/lookups by child ID and ordinal; do not give
the worker SQL credentials or the key consumer child-insertion permission.
