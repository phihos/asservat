# Runtime trace native success before later fresh-preview failure on6eff

Run [41872236223](https://github.com/phihos/asservat/actions/runs/41872236223),
frozen `6effd250a4d8c114d6815da1a422dfee3bbec716`, outer failure and actual Go/harness
exit1 after525.298s. Trace capture/refusal/native/offline boundaries passed; the
complete workflow failed later at fresh history preview readiness.

```
env ASSERVAT_JOURNEY_FOCUS=manual-profile ASSERVAT_PROFILE_VARIANT=trace python3 scripts/test-context-storage.py --initial-bootstrap-chain --runtime-provider-pair --installer-continuation
```

The immutable namespace definition requested runtimeTrace/interval5s, action32MiB,
10s action timeout and forceGCfalse. Independently reviewed capture, semantic
publication/get_case and exact original target/acquisition metadata passed. The
ordinary read-only pprof-summary request returned the intended closed NotAvailable,
without a query worker or analyzer. All three real SQL zero-query/backing0 guards
ran successfully by control flow before the later failure (before summary,
after refusal and after native opening).

Authenticated raw download metadata/size/SHA/filename checks completed. The exact
original is retained once, and the existing finite local go tool trace -pprof=sched
emitted a valid pprof parsed/checked by the fixture:

| Retained file | Bytes | SHA-256 |
| --- | --- | --- |
| manual-runtime-trace.trace | 76500 | 3f0d6b0981ae3d1538866ba379e712579f826549c604a0b526b2e71b2d5374a0 |
| manual-runtime-trace-sched.pb.gz | 508 | be328790fd3ccc0adafdd92c499b483b046e3c1b16a8089541f4299fd27daf98 |

This establishes these exact native/tool boundaries, not every Go trace version,
32MiB maximum resource behavior, CPU/heap summary, forcedGC, busy or Stop behavior.
No symbol server/browser trace service or acquisition retry was used.

The later fresh history path get_capture_settings in820.856603ms, then its one
preview_capture attempt returned NotAvailable after4.530477361s. Owner UTC
17:08:19.415448174Z names facts/storage/expired/readiness-tail. Original numeric
request/identity deadlines were not logged; they are not reconstructed from buckets.

The trace has an actual early storage hint read error and demand acknowledgement
both<100ms. Buckets: target<2s,review<100ms,profiles<2s,recorder<1s,
await-storage<3s,storage<2s. Capacity demand at17:08:18.644853318Z reports
guarded-read unavailable after2.01s/readleft0, with c-post<2s and o-claim<2s;
other listed stages are<250ms. Independently logged regional native cycle opened
17:08:17.421996507Z, reads1/2/3 at17:08:17.427800552Z/17:08:17.469585136Z/17:08:17.640634781Z,
and read4 at17:08:18.562585015Z all reported ok. Those regional observations do
not substitute successful owned demand readiness. No timeout increase, source
renewal or precise unlogged cutoff is inferred. The successful fresh repeat
preview was NOT reached, so the workflow remains failed.

## Frozen source, commands, cleanup and preservation

All4132 SUBMITTED source SHA-256 values independently match exact frozen6eff Git
blobs (git cat-file --batch for the exact6eff head/path and SHA-256,
compared against every original sourceHashes entry). This is the submitted
inventory, including JS helpers/generated validators and other files, not a claim
that4132 Go files were checked. sourceUnchangedDuringTest=true;
cleanupFailures=[]; buildScratchRemoved=true. Full original workflow logs show
No kind clusters found, actual process exit1 and successful artifact upload.
Both direct REST run/job snapshots settled completed/failure. No outer timeout,
new test, retry, dispatch or qualified source modification occurred during audit.

Original ci-native and environment logs retain exact build/test commands, package
selection, Go version, worker/source hashes and actual exits. The suite command is
shown above. Metadata timestamps are preserved in UTC as supplied; no local-time,
original-deadline or clock-offset values are inferred from elapsed buckets.

archive-manifest.json maps exact cache sources, source/stored sizes and SHA-256.
Reports/logs/metadata use deterministic gzip(level9,mtime0). The original trace and
its scheduler gzip derivative retain original bytes once each in the trace archive;
no duplicate ZIP, binary or private temporary file is added. Combined original
per-job workflow texts preserve full logs without duplicate per-step copies.
Readback verifies every cache byte and hash, gzip inflation/deterministic
recompression, and committed Git bytes. verification.json.gz is derived audit
evidence; other payloads preserve original downloaded artifacts/metadata.
