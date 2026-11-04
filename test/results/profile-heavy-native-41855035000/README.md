# Accepted-heavy run41855035000: separate infrastructure and test outcomes

[Run41855035000](https://github.com/phihos/asservat/actions/runs/41855035000)
used frozen source `02e62a8931f1041733988c26b3226859ff8de21a`. It was dispatched once
at15:10:51Z on2026-11-04. The parent retried only the failed job once with
`gh run rerun 41855035000 --failed` after the demonstrated setup infrastructure
failure. No new workflow dispatch, source change, timeout change or second retry
occurred. Both attempts and their distinct evidence are preserved below. The
workflow is failed; passing comparisons/probes are not a green whole-workflow claim.

## Attempt1: runner disk exhaustion before native testing

Heavy job126661349905 ran15:11:06Z–15:12:27Z and failed while
`.github/actions/setup` was in progress. GitHub's check annotation reports
`System.IO.IOException: No space left on device` while writing
`/home/runner/actions-runner/cached/2.338.2/_diag/Worker_20261104-151106-utc.log`,
with Runner.Worker/HostTraceListener stack and an unhandled exception.

The actual native test step remained pending, with no Go exit or elapsed result,
no source inventory, no fixture cleanup proof, and zero uploaded artifacts.
The heavy job log was unavailable: `gh run view ... --log` exited1 with log not
found and the direct jobs/logs API returned404. The available workflow log contains
only the successful select job. Its contents are not a substitute heavy-test log.
`attempt1` retains the exact check, full annotation, job/workflow metadata, artifact
count0 and failed log-retrieval response/stderr; derived verification records null
Go result and explicit evidence gaps.

## Attempt2: both comparisons and live worker probes completed

Failed-job retry readback15:15:15Z matched the same02e commit. Heavy job126663888513
ran15:15:15Z–15:33:26Z. Native testing executed (step started15:16:43Z); actual Go
exit1 after673.948s, harness exit1, successful artifact upload. This is a later
fixture assertion failure, not another setup failure or outer job timeout.

The first ordinary-read-only MCP comparison returned ok after10.696625664s on its
second result poll; the second actual installed React comparison joined after
rendered-row, source/version, independent native aggregation and mobile viewport
checks. Each native/batch owner joined and closed, active=false, uncertain=false,
with two independent source children at used_roles7 (six roles per query).
The separate20-unit queries retained cumulative root20 then40. The final second
query SQL readback also recorded principal/workload/root totals40.

| Exact live-worker fact | MCP cross-case | React same-artifact |
| --- | --- | --- |
| QueryID | afb9432e-266a-4a7c-ae11-253b4b2f8999 | bd1b180c-1582-450f-b794-fccf6a9e4fdf |
| WorkerID | 2418592f-3466-4ed2-a5b0-d873271ff2a3 | ab586e57-5a58-44c9-9d1e-793b029ad6a0 |
| PodUID | a3a8af95-9522-49dd-8b47-393d69532caf | fabe41f9-bd61-4a77-a042-b618494e51de |
| Probe UTC | 15:31:46.840367244Z | 15:32:27.614946747Z |
| Probe exec wall seconds | 0.232940135 | 0.215469216 |
| Query created→probe seconds | 38.535534 | 37.876165 |
| memory.max | 402653184B(384MiB) | 402653184B(384MiB) |
| memory.peak | 275722240B(262.94921875MiB) | 242057216B(230.84375MiB) |
| memory.current | 99639296B | 237961216B |
| swap.max / swap.current | 0 / 0 | 0 / 0 |
| memory.events high / max / oom / oom_kill | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| cpu.max | 50000/100000(500m) | 50000/100000(500m) |
| CPU usage/user/system microseconds | 4024008/3677857/346151 | 3677704/3371392/306311 |
| periods/throttled periods | 107/68 | 101/67 |
| throttled microseconds | 1241477 | 2962152 |

Both original Pod/container/image bindings were checked before and after finite
exec. Probe SHA matches the prepared helper, and each observed image matches the
actual worker build. Both records say resourceQualified=true for this one accepted
heavy shape. Source Pod UID98a5a7ac-c18f-4ec5-8bde-b264cae22ce3 is retained on both
sides. These are whole-worker cumulative counters through each live snapshot,
including credentials, native processing and the probe itself. They exclude the
later output/idle lifetime and are not analyzer-only memory/CPU, universal parser
maxima,64MiB native coverage or sampled application overhead. CPU throttling is
observed, beyond merely a configured quota. No OOM/swap was observed at either
snapshot; current/future terminal exit/OOM outcomes are not inferred from a live
Running state or absent LastTerminationState.

## Original request cutoffs and remaining fixture failure

The repaired policy and browser paths preserve the almost20s original read request:

| UTC field | MCP | React |
| --- | --- | --- |
| Query created | 15:31:08.304833Z | 15:31:49.738781Z |
| WorkerUntil/query deadline | 15:32:08.304833Z | 15:32:49.738781Z |
| Request started | 15:31:32.664889Z | 15:32:14.059179Z |
| RequestUntil/AuthorityValidUntil/BatchUntil/OperationUntil | 15:31:52.650033Z | 15:32:33.959061Z |
| Authority checked | 15:31:32.783339329Z | 15:32:14.163416028Z |
| Operation started | 15:31:33.684103Z | 15:32:15.404694Z |
| Request seconds | 19.985144 | 19.899882 |
| Native operation seconds | 18.965930 | 18.554367 |

After both probes and React completion, the terminal proof cohort invoked the
first query's verifier again. At context-storage.log line118 it failed:
`comparison actual exact384MiB Pod ... not found`. The unconditional live Pod GET
is in installed_profile_comparison_sql_native_test.go87, called from the deferred
cohort at installed_profile_comparison_native_test.go115. First WorkerUntil
15:32:08.304833Z was already past before the second probe15:32:27.614946747Z;
normal cleanup can remove that first Pod before the final lookup. The first live
probe already checked its exact original Pod/resources/container independently.
The late404 does not erase that earlier observation, but it aborts the remaining
first-query terminal child-binding readback; a complete workflow pass is not
claimed. The second final SQL proof succeeded (log119). No runtime request expiry
or probe error caused this failure. A subsequent fixture repair/qualification is
outside this archive.

## Native inputs, build/source provenance and cleanup

Both approved10s CPU captures were encrypted/published; authenticated native
downloads matched the prepared inputs and official Go pprof opened each original:

- Baseline9394862B, SHA-256 `853f5ed2f0a6afa8c64dcef9d0715e49b9435966406cde3b108f599a63084a9d`,100000 samples, total700000ns.
- Incident9392922B, SHA-256 `efd5dac937c228106a344b5bbd9b7340035f761a979bbca010b8fa6a676fae6f`,100000 samples, total1100us.

The exact two native files appear once each in attempt2. No duplicate artifact ZIPs
are added. The accepted synthetic shape has100000 functions/locations/samples,
1048576 frame visits,16 values/types,32768 numeric-label records,662144 shared object
units and16777160 protobuf bytes per source. Native payloads are input fixtures,
not measured sampled workloadCPU/capture overhead.

The separate producer exited0, timedOut=false,4.018589208s elapsed,491740KiB peakRSS,
4.091620s userCPU and0.484850s systemCPU outside workload/worker cgroups. These are
this run's build observations, not universal memory cost. The original manifest and
environment retain exact generator/worker/probe binaries and image digests.

All4123 submitted source SHA-256 values independently matched frozen02e Git blobs;
sourceUnchangedDuringTest=true, cleanupFailures=[], buildScratchRemoved=true.
Workflow says No kind clusters found; terminal upload succeeded. Attempt1 has no
such fixture proof and remains separate. No new run or source change was performed
during this archive task.

## Archive encoding and readback

`archive-manifest.json` maps every exact cache source, source/stored size and
SHA-256. Reports/logs/metadata are deterministic gzip(level9,mtime0); two native
files preserve original bytes. Readback checks every cache byte, stored/source
hash, inflation/deterministic recompression and native hashes against the prepared
manifest. Derived `verification.json.gz` files label scope and gaps; other payloads
preserve downloaded originals. Actual commands/exits are retained in workflow/ci
logs and reports; failed-job retry command is recorded above. No green workflow,
new production authority or unrestricted resource claim is inferred.
