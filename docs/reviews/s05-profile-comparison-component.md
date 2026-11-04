# Profile comparison component

Scope: REQ-PRF-005 / SC-PRF-005, S-05 increment 8. This isolated preparation
adds no public route, SQL authority, worker dispatch or collection capability.
The syscall integration candidate remains frozen during its native checks.

The maintained pprof parser consumes both complete inputs sequentially. Shared
aggregation preserves signed cumulative values over every function before
selecting differences; subtracting two truncated top-N summaries is incorrect.
Rows rank by absolute incident-minus-baseline change, then function name. Raw
deltas and duration-normalized interval/delta rates are distinct selections.
Selected sample type and unit must match. Heap and allocation handlers may
expose the same selected counter family; a handler-name change alone does not
establish incompatibility. State totals cannot be compared with window deltas.

Results retain each acquisition's type, mode and forced-GC setting, native
duration, signed total, sampling period and symbol status. Build identities are
reduced to bounded internal digests; only same/different/unknown leaves the
parser. Labels, paths, addresses, comments and raw build IDs remain excluded.
Build hashing spends at most the existing 16 MiB decompression ceiling, with
cancellation checks within long identifiers. Exhausting that optional work
leaves build identity unknown rather than rejecting an otherwise valid result.
These are implementation work bounds, not measured whole-worker memory limits.

The regional `ReadProfileComparison` component reuses the authenticated native
stream reader independently for both sources. Acquisition facts come from
their protected expected manifests. Both complete native hashes must pass
before an aggregate or semantic-mismatch result is accepted. A swallowed read
error, partial parser, malformed tail, cancellation or failed final hash cannot
yield a comparison. Every supplied source closes on every exit. The component
does not grant permission to open either source or deliver its result.

Focused checks at this preparation checkpoint:

- Application reader race tests: passed, 1.372 s; both source positions cover
  mismatched versions/types/selection, byte limits, missing authentication,
  partial/swallowed reads, changed acquisition output and cancellation.
- Real encrypted frame/manifest plus pinned TLS-range/parser composition:
  passed, 1.376 s, six cases. Both inputs perform three synthetic unwraps each;
  either ciphertext/final-hash failure refuses, and cancellation during the
  second input joins and closes both readers. Provider authority remains
  synthetic; this is not SQL, native worker or installed qualification.
- Repeated build-ID amplification reproduced before the fix; focused comparison
  race tests passed after bounded hashing, 1.535 s. Rate precision regressions also reproduced before their fix; final focused
  races passed (diagnostics 1.550 s, domain 1.007 s). Rates and deltas now round
  independently after exact arithmetic on bounded integer native ratios. A
  limitation explains why subtracting displayed rounded rates can differ.
  Symbol-side consistency checks reject contradictory values. Inline/recursive
  cumulative-value fixtures passed in 1.019 s.

Before integration, complete the two-source authority/plan/transaction/key and
private worker protocol design. Independently authorize both ordinary readers,
original audiences, clients, retention, recovery and regional processing before
returning semantic details. Use one existing regional worker where both
accepted paths permit it; do not invent cross-region access or proxy plaintext
through the hub. Fund both complete native reads and six one-use key operations,
with atomic workload/principal/root accounting and conservative uncertain spend.
Retain exact baseline/incident provenance and original minimum deadlines through
public result delivery. Existing metadata-only shares grant no raw-profile read.

The public schema, console/MCP parity, maximum-shape resource measurements,
independent deny/expiry/revocation, same-artifact behavior, native comparison
against downloaded profiles and positive worker retirement remain unfinished.
The existing profile preflight now selects comparison/parser/reader tests too;
no new harness, service or external fixture is introduced.

The combined `make profile-preflight` passed, including existing acquisition,
summary, authority, worker and integration-helper regressions. Go architecture
passed with 69 packages / 433 internal import edges. Final reader review then
reproduced same-format opened-source substitution and cancellation during source
closure. The helper now checks existing `ValidNativeSourceMetadata`, joins both
sources before final cancellation checks, and closes each supplied handle once.
Focused races after that change passed: evidence 1.554 s and objectstore 1.421 s,
including seven real encrypted/TLS cases and swapped opened sources. The combined
preflight predates this last helper change; the two affected packages were
rechecked, and unrelated preflight evidence is unchanged.

A local 10,000-function-per-source parser benchmark after precise normalization
used 41.18 ms/op and 39.96 MB total allocations. Total allocations are not peak
RSS, worker residency or composed provider cost. No public activation or physical
worker qualification is inferred.


The fixed-pair scope/request/result and public contracts are now prepared under
ADR-295. Legacy source/candidate JSON stays identical. One compound comparison
has fixed role order, exact versions, one batch and twenty read-work units; typed
incompatible-profile results carry no content. Affected domain races passed in
1.025 s, plus the strict mismatch-union follow-up in 1.011 s. Canonical browser/MCP
contracts preserve both case/artifact IDs, versions, acquisition/configuration
facts and original query times. The new example normalizes a 30-second baseline
and 10-second incident to equal rates. The old contract rejected its missing
provenance/configuration fields; the amended spec/OpenAPI/schema gates passed
13,530 assertions. None of this registers a runtime comparison tool.

The opt-in encrypted process probe now measures both complete sources, including
native framing, manifest checks and pinned TLS ranges. Each accepted source has
100,000 functions/locations/samples and 1,048,576 frame visits. The heavy shape
adds sixteen sample types/values and 32,768 numeric labels with units, exactly
662,144 shared structural units, with protobuf 56 bytes below 16 MiB. It does not
simultaneously maximize every independent string/inline dimension.

With the final immutable binary, the original pair peaked at 191.266 MiB RSS and
the heavy pair at 252.363 MiB; both took 1.202s wall and returned twenty valid rows,
six synthetic unwraps and closed both sources. A single unchanged-heavy replay
with standard GOMEMLIMIT=224MiB observed 246.152 MiB RSS and similar wall time.
This small improvement does not establish deployed 256 MiB feasibility. No
product memory setting changed. Source inventory scope is tracked/untracked Go,
go.mod/go.sum and internal JSON (3,814 files), not the whole repository/module
cache; each final phase matches its build inventory. Earlier cancellation data
belongs to a separately identified binary and is retained as such. Exact hashes,
CPU values, inputs and caveats are in test/results/profile-comparison-memory.
Real cgroup/CPU-quota/SQL/KMS and public/native qualification remain pending.


Paired C-03 authorization is implemented as an internal component: independent
ordinary source checks, then an exact-version baseline recheck under the first
source's original deadline. The shared request adapter still calls current
identity on every read; original groups/scopes and earliest expiry remain pinned.
The owned baseline proof is one level only; nested/cyclic authorities fail before
recursion. The combined decision binds both source decisions and the full fixed
scope, with minimum original access/deletion/validity dates. Global permission
and recovery revisions must agree with the same root stream used by SQL effects.
A successful pair performs nine identity, six permission, three catalog, six
retention and six environment port reads; no additional watches/credentials.
Affected C-03/domain races passed in 2.076s / 1.123s and independent review found
no blocking issue. A regional comparison regression reproduced pointer-based
baseline inequality after decoding; value comparison now passes (1.207s), keeps
mandatory decisions and ignores only existing observation/diagnostic fields.
Paired SQL/plan/native/public composition is still not enabled.
