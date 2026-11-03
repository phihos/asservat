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
