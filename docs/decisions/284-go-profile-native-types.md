# ADR-284 — Go pprof and execution-trace native types (S-05 increment 1)

Date: 2026-11-02. Status: accepted (agent decision).
Requirements: REQ-PRF-002, REQ-PRF-003, REQ-EVD-005, REQ-DLD-001; ADR-244
(native types), ADR-248/279/282 (publisher stream checks);
S-05 plan (`docs/reviews/s05-plan-2026-11-02.md`, branch
`docs/s05-plan`) §3 S5, §4 row 1, §7.1 F5.

## Context

The Go acquisition component streams a `net/http/pprof` response into the
encrypted format but nothing could store, verify or describe it: the native
type registry had no profile entries, the manifest's `profile` block required
semantic facts (sample types, period, symbol coverage) that the wrapping
producer cannot know without parsing hostile input, and the publisher had no
check for either format.

## Decision

1. Two registered native types, both data class `raw`, manifest kind
   `profile`, evidence type `profile` and media type
   `application/octet-stream` (what `net/http/pprof` serves with `debug=0`):
   `pprof` (format `pprof`, gzip-compressed protobuf, `.pb.gz`, at most
   64 MiB) and `goTrace` (format `go-trace`, `.trace`, at most 128 MiB). The
   maxima are REQ-PRF-002's; the installed download path still serves at most
   one 8 MiB frame (`DownloadLimit`).
2. The expectation carries `Profile` (`GoProfileAcquisition`: source ref,
   endpoint digest, type, mode, duration, forced GC; omitted otherwise, so
   existing digests are unchanged). A profile is a finite onTrigger raw
   artifact with a composed action ID; its native type follows the profile
   type (`runtimeTrace` is `goTrace`, every other type `pprof`). The
   type/mode/duration rule is shared with the acquisition component
   (`artifact.ValidGoProfile`).
3. F5 resolved: the manifest records acquisition facts only (format, runtime
   `go`, profile type, mode, requested duration, mechanism `endpoint`, source
   ref, endpoint digest, forced GC, `settingsKnown: false`).
   `profile.schema.json` no longer requires sample types, period, lost
   samples or symbol coverage; a producer that builds the profile itself (the
   eBPF sampler, increment 5) may still record them. Semantic facts come from
   the publisher's verification and from query-time analysis (S4).
4. Producer check (in the connector, no decompression): a pprof stream must
   start with one gzip member header (deflate, no reserved flags), be at
   least 19 bytes and declare at most 16 MiB in its trailer length; a trace
   must start with a version 2 header (`go 1.22` or later). Constant memory.
5. Publisher check (`internal/adapters/diagnostics`, run in the same
   authenticated verification read as the other stream checks):
   - pprof: exactly one gzip member, CRC/length verified, decompressed to at
     most 16 MiB (`artifact.MaxPprofDecompressedBytes`), then
     `github.com/google/pprof/profile.ParseUncompressed` and `CheckValid`;
     1–16 named sample types with named units, duration 0–24 h, non-negative
     time and period, a named period type when present, at most 4,096
     mappings each with `Start <= Limit`.
   - Go trace: version 2 header, then `golang.org/x/exp/trace` reads every
     event to EOF, at most 2^25 events, and at least one non-Sync event.
     Version 1 traces (Go 1.21 and older) are refused rather than converted.
   - A parser panic is a refusal, not a publisher crash. Over-bound input is
     `ErrLimit`, never truncated.
6. Historical bound measurement: parsing a 15.4 MB table-heavy synthetic
   profile (330,000 distinct functions and locations) peaked at about
   190 MiB of sampled live heap in 0.23 s; 30 MB peaked at about 377 MiB.
   This informed the original 16 MiB decompression limit. The follow-up
   below supersedes the assumption that this byte limit alone keeps all
   profiles inside the publisher's 512 MiB process limit. The measured
   330,000-table experiment remains historical evidence; that shape is no
   longer supported by the preallocation limits.
7. Dependencies: `github.com/google/pprof` pinned at
   `v0.0.0-20261016150608-1facf8f91b50` (upstream main, 2026-10-16; the
   project publishes no tags; Apache-2.0), only its `profile` package is
   compiled, which imports the standard library only. Upstream main
   shows continued profile-package fixes (2026-08-25, 2026-08-30,
   2026-10-12). `golang.org/x/exp` moves from indirect
   to direct at the already locked `v0.0.0-20260824195058-e88cd73687aa`; its
   `trace` package supports trace versions up to Go 1.26, which Go 1.27.2
   still writes.

## Not changed

No grant, migration, SQL or wire change. `ServedClass` still excludes the
profile types, so SQL publication and download refuse them until increment 3
adds the node work kind, the ad hoc grant result-access child and download
evidence type `profile`. No query or analyzer reads profiles (increments 7/8).

## Complexity gate

1–3: profiles are a specified first-release feature; without verification no
profile could be published. 4: pprof's own parser and Go's trace reader are
the reference implementations. 5: no new privilege, network access or
credential; the checks run in the existing publisher. 6: one refusal state
per format (invalid, over bound). 7: no configuration. 8: two maintained Go
team libraries. 9: one bounded parse per published profile, ~12x the
decompressed size in transient heap. 10: code-only registry; rollback removes
the types. 11: a smaller check (header only) would publish unverifiable
bytes from a hostile endpoint, contrary to ADR-244.

## Follow-up: measured protobuf allocation amplification (2026-11-03)

A valid synthetic profile with one sample and two million labels is only
12,000,169 decompressed bytes, but the maintained parser exhausted both 256
and 512 MiB bounded processes before semantic validation. Panic recovery does
not catch process OOM. This observed case, plus dense table records, justifies
one fixed preallocation shape check shared by publication and analysis.

The [allocation preflight review](../reviews/pprof-allocation-preflight.md)
records the supported bounds, maintained wire-library reuse, red regression,
process measurements and qualification limits. The pprof library remains the
semantic parser. New unsupported shapes return the existing limit refusal,
without truncation or mutation of old evidence/grants. No worker resource,
query authority, privilege, migration or public activation changes here.

The first fixed 32,768 aggregate-label limit was subsequently replaced by a
shared structural allowance after an actual Go heap with 40,007 allocation
buckets showed that the runtime emits one numeric `bytes` label per sample.
The common preflight charges samples=2, locations/functions=1 and labels=8,
with at most 662,144 empirical units plus the unchanged independent array/byte
bounds. It accepts that native heap while refusing the measured expensive
full-table shape; no separate publisher/query policy or memory increase is
introduced. The review above records native-shaped regression and mixed-shape
process measurements. Units are not a heap guarantee.
