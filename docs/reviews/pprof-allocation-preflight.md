# Pprof allocation preflight

Scope: REQ-PRF-002, REQ-PRF-003 and REQ-EVD-005; measured follow-up to
ADR-284/286. This changes supported input shape at publication and subsequent
parsing. It does not activate profile queries or change grants, evidence already
stored, worker resources or the native evidence byte limits.

## Observed problem and selected limits

The old capped decompression followed by `pprof.ParseUncompressed` allocates the
full protobuf object graph before semantic checks or analyzer table bounds.
A valid one-sample profile with one million repeated labels (6,000,169 bytes)
exhausted a 256 MiB process; a 512 MiB process accepted it with 439 MiB peak RSS.
Two million labels (12,000,169 bytes) exhausted both process limits. Compact
malformed sample/function tables also exhausted both limits. Raising every
worker to 512 MiB would add 256 MiB per worker without resolving the failure.
The before report
retains terminal OOM exits, process/cgroup measurements and input hashes.

One fixed, nonrecursive preflight scan now counts allocation-bearing fields
before pprof allocates its object graph. It uses the already pinned
`google.golang.org/protobuf/encoding/protowire`. No fork, alternate semantic
parser or library change is introduced. The maintained pprof parser and
`CheckValid` still check references, IDs, strings and profile semantics.
Unknown ordinary fields remain ignored as before. Groups are refused as in the
pinned pprof parser. Packed, unpacked and split repeated numeric fields are all
counted; duplicate fields cannot reset counts. No input is truncated.

| Allocation-bearing shape | Fixed limit |
| --- | ---: |
| Samples, locations, functions | 100,000 each |
| Mappings | 4,096 |
| Sample types; period-type allocations | 16 each |
| Labels, including numeric labels and units | 64 per sample; shared object allowance below |
| Shared expensive-object allowance | `2*samples + locations + functions + 8*labels <= 662144` |
| String-table entries | 300,000 |
| Sample location references | 1,048,576 total; 4,096 per sample |
| Inline line records | 1,048,576 total; 4,096 per location |
| Sample values | 16 per sample |
| Comment indices | 4,096 |
| Decompressed bytes | existing 16 MiB |

String payload bytes remain bounded by the whole decompressed input. Fixed
message scalar fields do not create variable arrays; their semantics stay in
pprof. Preflight uses bounded counters and borrowed byte slices; its allocation
regression observes zero heap allocations. Shape excess returns `ErrLimit`;
malformed wire returns `ErrNotProfile` or the unchanged parser's refusal.

The table allowance supports the measured 100,000-distinct-table profile while
leaving room for nested data. The initial independent label limit was selected
after a combined
100,000-label numeric/unit shape reached about 258 MiB RSS and 253 MiB cgroup
usage: too little margin for a 256 MiB worker. Reducing aggregate labels to
32,768 brought the combined near-16-MiB maximum below 191 MiB process RSS,
including the explicitly modeled 16 MiB buffer reserve. This is a supported
shape decision, not an asserted universal Go allocation formula. The shared
allowance below supersedes that independent 32,768-label ceiling.

The old 330,000-table publisher experiment remains a real historical component
result. The new 100,000-table allowance intentionally refuses that shape.
The publisher's synthetic memory test now exercises the current supported
shape; prior evidence was not rewritten as a passing qualification of it.

## Native heap intersection and shared allowance

Go's `runtime/pprof` heap writer (`src/runtime/pprof/protomem.go`) emits a
numeric `bytes` label for each sample. An independent 32,768-label ceiling
therefore unnecessarily rejects a heap with more than that many allocation
buckets even if its other tables are small. A fresh owned Go process generated
40,007 actual heap samples/bytes labels, 20 locations, 14 functions and 760,054
location references: only 1,401,571 decompressed bytes (127,059 gzip bytes).
The native generator report
and generator retain its exact
hashes and Go version. This deliberately dense synthetic allocation-stack case
shows native writer behavior; it is not a claim about deployment frequency.

Use one common expensive-object allowance rather than separate publisher/query
profiles: charge two units per sample, one per location/function and eight per
label, capped at 662,144 units. These are fixed empirical structural units,
**not heap bytes or a hard Go allocation guarantee**. The sample structure holds
several slices/maps; labels add temporary records and up to three postdecode
maps plus value/unit arrays. The larger label weight covers the observed numeric
label overhead conservatively. Byte, strings, primitive array and per-record
limits remain unchanged. No unit is discounted based on evidence contents or
whether the analyzer displays a label.

The ceiling is `2*100000 + 100000 + 100000 + 8*32768`: it retains the measured
full-table shape without pretending every small-table heap has those other
costs. The 40,007-sample native heap uses 400,104 units and now passes actual
`inuse_space` summary analysis at 70.4 MiB peak RSS. The earlier full-table,
100,000-label shape costs 1,200,000 units and is refused before object parsing.
A native-shaped 40,000-sample regression failed with the old flat label cap,
then passed with the shared allowance; the 100,000-sample/all-labeled shape
still refuses. All caps intersect: neither 100,000 samples nor a label-count
maximum is an independent acceptance promise.

The mixed-shape report
measures two additional near-ceiling combinations under the same 256 MiB process
limit and modeled 16 MiB buffer reserve: 64,000 samples plus 64,000 numeric labels
(640,257 units), and 100,000 samples plus 57,000 numeric labels (656,257 units).
Both also contain approximately one million lines/references, 300,000 strings
and nearly 16 MiB input. They pass at 181.7 and 183.4 MiB peak RSS. The
native heap summary report
returns a valid typed result; the refusal report
keeps the original dense-sample, dense-function, two-million-label and expensive
full-table failures below 60 MiB RSS with no OOM. These are a bounded empirical
qualification corpus, not proof of every possible permitted combination or an
installed worker qualification.

This replaces one counter with a weighted counter, adding no purpose selector,
parser fork, resource increase, configuration, I/O or fallback. The alternative
was a fixed 100,000-label publisher limit under its existing 512 MiB process
while keeping a smaller query limit. It preserves native downloads but would
still reject this inexpensive heap summary, so the measured common allowance
is the smaller usable contract. Process memory containment remains mandatory.

One generator invocation continued after its helper compile failed and used the
previous executable. Its unqualified report
is retained explicitly; the final native measurements use the rebuilt helper
and matching source/binary hashes. No stale-build observation is claimed as the
final source qualification. The measurement harness is retained in the isolated
analyzer branch at commit `b992ae9d`, extending `bcacb89a`; it is not required
by the publication parser. Reports bind the exact helper/runtime source hashes.

## Verification and practical limits

The shared-allowance follow-up passed the full diagnostics race suite (12.127 s),
affected `go vet`, and the same spec/architecture gates (13,475 assertions,
1,330 architecture checks, 69 Go packages/426 edges). Its retained
fuzz log records 81,778
executions in a 15-second two-worker smoke, with no failure.

The red valid-label regression initially returned success. With preflight, the
same valid oversized profile returns `ErrLimit` before the allocating parser.
Tests cover every table boundary, aggregate/per-record nested boundaries,
packed/unpacked/split values and references, malformed wire, groups, unknown
fields, unchanged semantic refusals and zero preflight allocations.

The final isolated publication branch passed `go test -race
./internal/adapters/diagnostics -count=1` (11.292 s), affected `go vet`,
`make spec-check` (13,467 assertions), `architecture-check` (1,330 checks)
and `go-architecture-check` (69 packages, 426 edges). The retained
fuzz log records the final
15-second, two-worker malformed-input smoke. These are component/static gates,
not installed qualification.

The after publisher report
contains 23 fresh process runs under a 256 MiB memory limit with no swap. All
previous OOM cases now return a bounded refusal; combined supported profiles
are accepted. The largest measured combined numeric-label shape has 100,000
samples/locations/functions, 32,768 labels with units, 16 values/sample,
one million lines and references, 300,000 strings and nearly 16 MiB input.
It peaks at 190.5 MiB process RSS / 186.2 MiB cgroup memory, in 0.183 seconds.
An additional summary component report
retains the analyzer's independent aggregate frame-visit refusal: parser
acceptance does not promise every profile query can traverse every shape.

The native-byte regression
accepts the exact CPU loopback and heap Pod-IP pprof files from native run
41592789877, with hashes and provenance retained. This replays existing
synthetic native bytes through the guarded parser; it is not a fresh installed
qualification or a rerun of acquisition/Stop/download.

Measurements use Go 1.27.3, the pinned pprof revision `1facf8f91b50`, fresh local
processes, GOMAXPROCS=2/GOGC=100 and a streaming reader. They include 16 MiB of
explicitly held modeled frame/crypto buffers, not actual remote transport or
worker composition. Configured CPU quota is 500m, but short runs report no
throttling and sometimes more CPU time than elapsed time; the elapsed values
must not be presented as 500m runtime qualification. Peak RSS and cgroup memory
have different accounting. Source hashes stayed unchanged during each final
campaign; no transient unit remains. Before/after harness work is isolated from
the acquisition candidate, initially committed as `3bed1688` and extended for
the combined-shape cases. The guard itself has no analyzer/domain dependency.

A 256 MiB query worker is a candidate pending actual verified-reader/crypto,
concurrent-work, CPU and cancellation/join qualification. The process memory
limit remains the hard boundary; there is no per-query heap guarantee. OOM or
unjoined work stays charged and does not authorize a retry or replacement.
The synchronous parser is still not interruptible by context cancellation.

## Complexity gate

1–4: synthetic but valid data reproduced a process-killing problem in the actual
maintained parser; decompressed byte bounds alone and doubling process memory
both failed. The pinned parser's decoder shows variable sample/label/string/
line arrays; its existing semantic validation remains in place. This protects
ordinary publication and the planned summary path without broadening access.
5: zero new privileges, credentials, network calls or dependencies. 6: zero new
outcome states; reuse invalid/over-limit refusal. 7: zero new configuration.
8: same maintained parser and already pinned protobuf wire package. 9: one scan
of at most 16 MiB, fixed counters, zero measured scan heap allocations; no new
watch, API, background task or Job. 10: no schema migration or persisted-state
reinterpretation; rollback would restore the known amplification risk.
11: merely raising memory does not fix the reproduced case, and a 2 MiB byte
ceiling would exclude the measured 100,000-table valid profile. A bounded shape
scan is the smaller adequate change.
