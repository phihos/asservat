# Fourth accepted-heavy installed run: first MCP pass, later browser failure

Run [41846328376](https://github.com/phihos/asservat/actions/runs/41846328376)
used frozen source `4552bfd0e6500842facf297d91de9a15d8dd1394`, dispatched once at
14:19:01Z on2026-11-04. Heavy job14:19:14Z–14:37:09Z failed; actual Go exit1 after
666.969s and harness exit1. Artifact upload succeeded; this was not an outer
job timeout. This archive preserves the partial installed result and full failure,
not a successful two-query/browser workflow.

## First actual MCP comparison and whole-worker snapshot

The MCP comparison admitted query `e4f8b0ee-e941-465c-b56a-7bf7641f52de`, worker
`012f852e-4073-44db-b19f-45abd87cfddd`,20units. One pending poll was followed by an
ok result in10.5021782s. Existing production comparison parity assertions passed.
Both source children (ordinals0/1) consumed used_roles7 (six roles total).
NativeClosed=true, closed=true, active=false, uncertain=false; rootUnits20.

The live finite probe ran before deferred worker cleanup, through the exact stored
Pod UID `4804caef-cacb-4425-9fe0-ab367f11e822` and container
`containerd://f159327d0a1b8aa604ae33731fb750960135a79854f1227423a4a9ee697adecd`.
Pod/image/container binding was checked around exec. The image digest matches the
actual worker build; the probe SHA matches the prepared helper SHA. Original source
Pod UID `1e61df86-35f6-4b51-acfb-0b8ddbdc9892` is pinned independently on both sides.

Probe elapsed0.299852183s; snapshot14:35:47.723891084Z,38.454678s after query
creation. Its observed counters are cumulative for the whole worker container,
including credentials/native work and the probe itself, through this live snapshot.
They are not analyzer-only costs or the later output/idle lifetime:

| Observed cgroup fact | Value |
| --- | --- |
| memory.max | 402653184B (384MiB), finite |
| memory.peak | 276090880B (263.30078125MiB) |
| memory.current | 100990976B (96.3125MiB) |
| swap.max / swap.current | 0 / 0 |
| memory.events high / max / oom / oom_kill | 0 / 0 / 0 / 0 |
| cpu.max | 50000 / 100000 (500m), finite |
| CPU usage / user / system | 4263251 / 3955464 / 307787 microseconds |
| periods / throttled periods | 119 / 76 |
| throttled time | 3971457 microseconds |

The actual CPU throttling counters provide installed enforcement observations;
this is not merely the earlier local Docker configured-quota check. This one
accepted-heavy source pair and first MCP worker passed resourceQualified=true.
It does not qualify all parser maxima,64MiB inputs, every workload or the failed
second/browser worker.

## Original cutoffs and second browser failure

The first read request retained its original nearly20s interval and completed:

| First/MCP fact | UTC time |
| --- | --- |
| Query created | 14:35:09.269213Z |
| Query deadline / WorkerUntil | 14:36:09.269213Z |
| Request started | 14:35:33.588595Z |
| RequestUntil / AuthorityValidUntil / BatchUntil / OperationUntil | 14:35:53.581144Z |
| Authority checked | 14:35:33.766442936Z |
| Operation started | 14:35:34.859190Z |

The first operation received18.721954s; the policy I/O subcall no longer truncated
its read interval to about5s. The later browser comparison used a separate20-unit
query `f696fe94-b77f-40d8-acbd-d38293e42738`, worker
`d86c28e2-87ca-4488-b099-29dba350e2d2`, raising rootUnits to40. Both three-role
children were consumed, but its result did not complete. The browser's second
get_query_result returned HTTP503 after about4.816s; stage=get_query_result,
pageErrors0. Owner14:36:20.888756629Z names
`result/until-request/prepare/projection`; browser14:36:20.927684463Z reports
`call-no-outcome/request-expired`. Worker result read was refused at
14:36:20.888748314Z, about1.2ms after the original operation cutoff.

| Second/browser fact | UTC time |
| --- | --- |
| Query created | 14:35:51.784460Z |
| Query deadline / WorkerUntil | 14:36:51.784460Z |
| Request started | 14:36:16.208050Z |
| RequestUntil / AuthorityValidUntil / BatchUntil / OperationUntil | 14:36:20.887547Z |
| Authority checked | 14:36:16.420633762Z |
| Operation started | 14:36:17.557425Z |

Thus the browser read request had4.679497s, with only3.330122s left at native
operation start. Its limiting bound is the original request, not the fixed policy
I/O interval. NativeClosed=false, closed=false, active=true, uncertain=false;
resourceQualified=false. Both consumed children do not prove source completion.
No second live probe or resource counters were reached. Its failure snapshot was
Running/Ready with no restarts; subsequent default LastTerminationState exit0
would not establish actual current terminal exit. Second terminal exit/reason,
memory peak, OOM/swap and CPU counters remain unknown. The later diagnostic's
first Pod-not-found is after its completed/retired query and does not erase the
first live probe evidence.

## Native inputs, builds, cleanup and readback

Both approved10s CPU captures were published and authenticated native downloads
matched the prepared files; official Go pprof opened each (top20 of100000):

- Baseline9394862B, SHA-256 `853f5ed2f0a6afa8c64dcef9d0715e49b9435966406cde3b108f599a63084a9d`, total700000ns.
- Incident9392922B, SHA-256 `efd5dac937c228106a344b5bbd9b7340035f761a979bbca010b8fa6a676fae6f`, total1100us.

The two exact original native files appear once each; no artifact ZIP duplicate.
The manifest fixes100000 functions/locations/samples,1048576 frame visits,
16 sample types/values,32768 numeric-label records,662144 shared object units and
16777160 protobuf bytes per source. This synthetic input is not sampled workload
CPU or measured capture overhead. The separate producer exited0, timedOut=false,
4.635833911s elapsed,473836KiB peakRSS,4.769226s userCPU and0.457942s systemCPU,
outside worker/workload cgroups; this per-run build observation is not universal.

The environment retains exact generator/worker binary/image/probe digests. All4123
submitted source SHA-256 values independently matched frozen Git blobs;
sourceUnchangedDuringTest=true, cleanupFailures=[], buildScratchRemoved=true.
Workflow reports No kind clusters found and successful artifact upload. No retry,
VM rerun or production edits occurred during the audit.

`archive-manifest.json` maps every original cache path and source/stored SHA/size.
Reports/logs/metadata use deterministic gzip(level9,mtime0); native files retain
original bytes. Readback verifies every cache byte, hash, gzip inflation and
recompression, and native hashes against the prepared manifest.
`verification.json.gz` is derived audit evidence; other payloads preserve original
artifact/metadata bytes. This archive supports first installed MCP resource proof
and a separate browser request-expiry failure; the complete workflow remains failed.
