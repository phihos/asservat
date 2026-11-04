# Second installed heavy-profile run: first comparison failure

Run [41834018171](https://github.com/phihos/asservat/actions/runs/41834018171)
used exact source `b5d42f9557897b40ca5d6506ffc3c9bd4946f373`. Go exited **1**
after **627.902 seconds**; the harness and workflow also failed. Artifact upload
completed. This was not an outer job timeout or upload failure.

Both approved captures, encrypted publications, authenticated native downloads
and local CPU pprof checks passed. The original synthetic ten-second inputs are
retained once each, byte-for-byte:

| Input | Native bytes | SHA-256 |
| --- | --- | --- |
| Baseline | 9,394,862 | `853f5ed2f0a6afa8c64dcef9d0715e49b9435966406cde3b108f599a63084a9d` |
| Incident | 9,392,922 | `efd5dac937c228106a344b5bbd9b7340035f761a979bbca010b8fa6a676fae6f` |

The hashes match the prepared manifest. Local pprof showed bounded CPU rows from
100,000 functions, with totals 700,000 ns and 1,100,000 ns respectively. These
were prebuilt synthetic inputs through the approved acquisition path, not
sampled application CPU or collector-overhead measurements.

The first `compare_profiles` returned pending; one `get_query_result` poll also
returned pending. The next poll received HTTP 503/ServiceUnavailable and the
fixture stopped without replay (`context-storage.log` line 107). The worker
reported `serve/result/read/refused` and stopped at
`native/conversation/read/approved` at 13:15:08.337Z. The underlying cause is
unproven by these logs.

Independent later SQL readback showed one admitted worker, two polls,
generation 1, two fully consumed three-role children with source ordinals 0/1,
20 units spent, `native_closed=false`, zero closed batches, active batch and
`uncertain=false`. Original native-download retirement checks had passed. No
comparison result, second browser comparison or resource probe was reached.

The private failure record identifies the original query/worker/Pod and source
Pod pins and shows a Running container with configured 384 MiB/500m limits.
Its image matches the harness's node-image digest. A later diagnostic reports
the Pod phase Failed, but prints only `LastTerminationState` (default empty
reason/exit 0), **not its current termination state**. The actual current exit
code/reason and cgroup memory, CPU, swap and OOM counters are unknown. The record
has `resourceQualified=false`; it is not evidence of an OOM, absence of an OOM,
effective CPU throttling or successful worker containment.

All **4,123** submitted source hashes independently match exact Git blobs.
The environment reports unchanged sources, `cleanupFailures=[]` and build
scratch removal. The workflow's later Kind read-back says no clusters remain.
The separate producer recorded exit 0, 469,952 KiB peak RSS and 3.924913 seconds
outside the worker cgroup; these are per-run producer observations only.

`archive-manifest.json` records original/stored sizes and SHA-256 values. Full
original workflow, metadata, Go/timing/provider logs, pprof outputs, prepared
manifest and private failure JSON are retained. Text and JSON use deterministic
gzip (mtime 0, no filename). Both native files retain their original bytes
without recompression; no artifact ZIP or extra native copy is included. Every
payload was read back against its cache original. No rerun, source fix or new
qualification is part of this archive.
