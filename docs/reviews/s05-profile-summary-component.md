# Bounded pprof summary component

Scope: REQ-PRF-003/005 and ADR-286, after profile acquisition. Implement a pure
selection/result contract and maintained-library analyzer; do not activate a
public query, add a projection source, change query funding, or admit raw reads.
The caller must later supply exact artifact authority and the qualified worker.

Implementation limits (not measured resource qualification): native gzip input
64 MiB; decompressed protobuf 16 MiB, shared with publication; at most 100,000
samples, locations and functions each; 4,096 mappings; 4,096 frame visits per
sample and 1,048,576 total frame visits. Top-N defaults to 20 and is at most 100.
Names are bounded UTF-8 without control characters: sample type/unit 64 bytes,
function 512 bytes. Aggregation preserves exact signed integer values within the
JSON interoperable integer range; overflow refuses the result. Output is at most
24 KiB of JSON; an oversized selected result is refused rather than truncated.

Parse with the existing google/pprof dependency. Share publisher validation
without a second decompression/parse. Check context before/after each input read,
before/after parsing and during bounded aggregation. A blocking underlying reader
must implement its owner's deadline. The third-party parse is synchronous and
cannot be interrupted by context cancellation; table limits are post-parse
work bounds, not a promise that allocations were capped before parsing. Worker
memory/CPU qualification and uncertain-parser retirement remain ADR-286 work.
No goroutine, child process, filesystem or network access is added by the analyzer.

Aggregate flat values at the leaf frame and cumulative values once per function
name per sample, including inline frames and recursive stacks. Group unresolved
frames into a null-name bucket, never fabricate symbols from paths or addresses.
Sort by absolute cumulative contribution, then absolute flat contribution, then
name for deterministic signed-delta behavior. Omit labels, comments, paths,
addresses, mapping names and build IDs from the result. Preserve units; perform
no rate normalization in a summary. Missing duration is null.

Concrete contract issue: Go's net/http/pprof delta handler scales its initial
profile by -1 and merges it with the final profile. A heap delta can therefore
contain +10/-10 in-use bytes: a zero signed total with nonzero functions. The
previous canonical fraction field required a number in [0,1]. Minimal contract
amendment: retain signed totals and make fraction nullable; provide flat /
total only for a nonnegative sample set with positive total, otherwise null.
Do not invent an absolute-value normalization or a fraction-basis field.

Verification: deterministic CPU/heap/mixed-unit/inline/recursion/stripped-symbol
fixtures, signed and zero totals, secret-bearing omitted fields, malformed gzip,
parser bounds, cancellation and output limits; fuzz smoke against arbitrary
compressed/protobuf inputs. Component tests do not qualify maximum-shape memory,
CPU, provider authority, browser/MCP delivery or installed worker retirement.

Complexity gate: required ordinary summaries, no observed parser exploit; approved
ADR-286 worker reuse; zero extra Jobs, credentials, API calls, watches or network
destinations. One existing parser call and bounded in-memory aggregation per query.
No persistent states or tuning options. Native downloads remain the fallback for
unsupported shapes; public summary integration is a separate unfinished step.

Component check results are recorded after implementation below. Public query
funding, approved-projection authority for a raw source, full worker memory/CPU
and failure qualification, browser/MCP activation and full installed delivery
remain pending. The component adds no source to LookupProjectionSource and no
branch to the existing ProjectionResult wire union.

Verification at this component checkpoint:

- `go test -race -count=1 ./internal/adapters/diagnostics ./internal/domain/analysis`
  passed (15.398 s / 1.014 s); targeted `go vet` passed.
- `go test ./internal/adapters/diagnostics -run '^$' -fuzz '^FuzzPprofSummary$'
  -fuzztime=15s -parallel=2` passed with 236,182 executions; actual output is in
  [the fuzz log](../../test/results/pprof-summary-component-fuzz.log).
- `make spec-check architecture-check go-architecture-check
  investigation-schema-check design-check` passed: 13,464 specification
  assertions, 1,330 architecture checks, 69 Go packages/427 internal edges,
  explicit embedded registration and 61 browser/MCP schema pairs.
- The architectural gate initially rejected JSON encoding in the domain package;
  encoding/byte-budget enforcement was moved into the diagnostics adapter. Domain
  validation remains pure structural/value checking. No gate was weakened.

Broader Go/Kubernetes groups and installed query qualification are deferred to
the combined query increment; these results establish only this component.
