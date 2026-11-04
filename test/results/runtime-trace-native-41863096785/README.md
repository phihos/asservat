# Installed runtime trace partial failure at c6

Run [41863096785](https://github.com/phihos/asservat/actions/runs/41863096785),
source `c6cfe2509d898c49529df49b118b0f97be9e8dc9`, actual Go/harness exit1 after
498.465s. Final direct REST subsequently settled completed/failure. Full combined
original workflow logs preserve the actual step exit1, No kind clusters found and
successful artifact upload. This is not a native trace download/tool qualification.

Actual command (full build/test invocation in original ci log/environment):

```
env ASSERVAT_JOURNEY_FOCUS=manual-profile ASSERVAT_PROFILE_VARIANT=trace python3 scripts/test-context-storage.py --initial-bootstrap-chain --runtime-provider-pair --installer-continuation
```

The immutable namespace profile requested runtimeTrace/interval5s, forceGCfalse,
32MiB action/output bound and10s action timeout through existing collection review.
Capture, semantic publication and get_case profile/go-trace checks passed; the
case metadata validated the exact original Pod,5000ms and verified timing, without
inventing clock/process attribution. The initial SQL guard confirmed the pinned
catalog source, no context queries/workers and allocated query backing0 before
attempting a summary.

First fatal is context-storage.log96: trace summary refusal unavailable; no replay,
tools/call transport ServiceUnavailable; installed_runtime_trace_native_test.go78.
The expected closed ordinary-read-only pprof summary NotAvailable response did not
arrive. No cause beyond that actual transport boundary is inferred. Second/third
SQL zero-query checks, authenticated native filename/SHA/bytes, finite local
`go tool trace -pprof=sched`, and fresh history repeat were NOT reached. No.trace
file exists in the actual artifact. The32MiB admitted bound is not a measurement
of downloaded native size. No implicit acquisition, retry or native rerun is made.

## Provenance and workflow status

All4128 submitted source SHA-256 values independently matched frozen c6 Git
blobs. sourceUnchangedDuringTest=true, cleanupFailures=[], buildScratchRemoved=true.
These are actual test/environment facts, distinct from the delayed workflow API.
The original environment contains the complete source inventory and build hashes;
derived verification.json records the audit against git cat-file --batch c6:path.
Logs retain actual commands, Go exits and elapsed results. No new run, retry,
production edit or qualified-tree source change occurred while archiving.

The initial gh run view poll responses continued to report queued/empty steps even
after terminal artifacts were uploaded. Original initial metadata is retained where
available; no missing initial snapshot is reconstructed as original. Direct REST
was subsequently consulted. Current metadata snapshots are retained verbatim;
an in_progress/absent conclusion is not promoted to a successful outer workflow.
The actual immutable Go/harness result is reported separately. Per-artifact API
metadata supplies exact creation timestamp, source head and artifact archive digest.

Every archived payload's original cache path, source/stored size and SHA-256 is
listed in archive-manifest.json. Reports/logs/metadata use deterministic gzip
(level9,mtime0); native gzip files retain exact original bytes. Readback checks
every cache byte, hash, inflation and deterministic recompression. For the heavy suite, native hashes
also match the prepared heavy manifest. Downloaded artifact/workflow ZIP duplicates,
binaries and private fixture files are excluded. When full workflow logs are
available, original combined per-job text is retained without duplicate per-step
copies; unsuccessful log requests and explicit availability gaps remain recorded.

Artifact created at 2026-11-04T16:12:58Z; outer REST snapshot: {"conclusion": "failure", "run_attempt": 1, "run_started_at": "2026-11-04T15:58:55Z", "status": "completed", "updated_at": "2026-11-04T16:21:04Z"}.
