# Third accepted-heavy installed diagnostic failure

Run [41841610822](https://github.com/phihos/asservat/actions/runs/41841610822)
used frozen source `f7eaa6f41db402d648b712af3abf75d44016b8f0`. It was dispatched once
at13:49:22Z on2026-11-04. The heavy job ran13:49:36Z–14:06:37Z and failed;
actual Go exit1 after631.429s, harness exit1. This was an actual test failure,
not an outer job timeout or artifact-upload failure. Original workflow metadata,
full workflow log and terminal artifact files are preserved here.

## Observed limiting deadline

The first comparison admitted one20-unit query and one worker. The first result
poll was pending; the second received HTTP503/ServiceUnavailable with an unknown
operation outcome, so the fixture did not replay it. Owner log14:05:49.026254055Z
names `result/until-authority/comparison/baseline/environment/policy/prepare/projection`.
Worker result read was refused at14:05:49.026019016Z; the worker later reported
`native/conversation/read/approved` unavailable at14:05:49.039446538Z.

The original failure JSON records these UTC instants without renewal:

| Fact | Time |
| --- | --- |
| Query created | 14:05:19.287603Z |
| Query deadline / worker Until | 14:06:19.287603Z |
| Read request started | 14:05:43.591158Z |
| Read request Until | 14:06:03.581638Z |
| Authority checked | 14:05:43.759953903Z |
| Authority ValidUntil / batch Until | 14:05:49.025030570Z |
| Batch started | 14:05:44.519283Z |
| Native operation started | 14:05:44.708001Z |
| Native operation Until | 14:05:49.025030Z |

Thus the operation received4.317029s, although worker lifetime still had34.579602s
and the read request almost20s. Refusal followed the operation cutoff by about1ms.
The diagnostic identifies the limiting baseline environment/policy deadline; it
does not establish why that producer supplied this remaining interval or qualify
a production fix. The plan/baseline hard cutoff remained2026-11-05T14:02:42.925111Z.

Query `f96e9c5f-ecc7-4e35-8967-9eab555b5f47` used worker
`a0fa80b1-9c65-4809-8824-c20fc054c936`; two source children (ordinals0/1) both have
used_roles7, six roles total. NativeClosed=false, closed=false, active=true,
uncertain=false. Consumed key roles do not establish complete payload delivery.

## Completed earlier steps and unmeasured resources

Both approved10s CPU captures were encrypted/published and authenticated native
downloads matched the prepared inputs. Local official Go pprof opened both with
top20 of100000 functions, baseline700000ns total and incident1100us total:

- Baseline9394862 bytes, SHA-256 `853f5ed2f0a6afa8c64dcef9d0715e49b9435966406cde3b108f599a63084a9d`.
- Incident9392922 bytes, SHA-256 `efd5dac937c228106a344b5bbd9b7340035f761a979bbca010b8fa6a676fae6f`.

The two exact original native files are retained once each; artifact ZIPs are not
copied. This accepted synthetic input is not sampled application CPU or measured
runtime overhead. Its manifest fixes100000 functions/locations/samples,
1048576 frame visits,16 sample types/values,32768 numeric-label records,
662144 shared object units and16777160 protobuf bytes per source.

No comparison result, browser comparison or live cgroup resource probe was reached.
The failure JSON says resourceQualified=false. Its Pod snapshot was Running,
Ready=true, restarts0, configured384Mi/500m. No actual memory peak, CPU counter,
swap, OOM status or effective quota enforcement was measured. The later diagnostic
prints phaseFailed and `last "" exit0`, but that exit is a default from absent
LastTerminationState, not the current container's terminal exit. Actual terminal
exit/reason and OOM counters remain unknown.

The separate prebuilt-input producer exited0, timedOut=false,3.618290874s elapsed,
453104KiB peakRSS,3.751406s userCPU and0.375240s systemCPU. These are this build
process's observations outside workload/worker cgroups, not worker measurements
or a universal generator cost. The manifest and environment retain exact generator,
worker binary, image and resource-probe build hashes; the probe was not executed.

## Source, cleanup and archive readback

All4123 submitted SHA-256 source values independently matched the exact frozen
Git commit blobs. sourceUnchangedDuringTest=true; cleanupFailures=[];
buildScratchRemoved=true. The workflow log reports No kind clusters found after
fixture cleanup and successful terminal artifact upload. No VM/native rerun or
production change was made during this audit.

`archive-manifest.json` gives each original cache path, original/stored size and
SHA-256. Logs, reports and metadata use deterministic gzip (level9,mtime0); the
two native files preserve original bytes. Readback verified every stored hash,
every cache byte, inflation/recompression, prepared-input native hashes and source
provenance. `verification.json.gz` is derived audit evidence; remaining files
preserve original downloaded artifacts/metadata. This failure is not installed
comparison or384Mi/500m resource qualification.
