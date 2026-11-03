# Streamed pprof summary component

The next query increment composes the existing `ContextVerifier.OpenNative`,
`FramedNativeSource.ReadNext`, `ReadProfileSummary` and `SummarizePprof` with
actual Tink frame/manifest encryption and pinned local TLS range reads. Test
source authority, key wrapping and HTTP receipts remain synthetic; this is no
SQL, native S3, private key-service or installed worker qualification.

`TestProfileSummaryEncryptedStream` creates a valid pprof larger than one 8 MiB
storage frame using an omitted random comment. The returned hotspot remains a
small named synthetic function. It proves:

- the whole encrypted stream verifies before a valid typed result returns;
- ciphertext corruption and an authenticated manifest with a false native
  whole-file hash both prevent a result;
- caller cancellation and explicit source closure while a range read is
  blocked terminate the read, join the wrapper and retain no source reader or
  carry buffer.

These checks do not prove SQL charge retirement or permission revocation. The
existing operation owner must retain uncertain/unjoined spend; no retry or
replacement is introduced by this test.

The explicit `TestProfileSummaryEncryptedProcess` modes prepare encrypted
fixture files in one process and consume them in a fresh measured process.
Generation is excluded from the read's peak RSS. The selected large profile has
100,000 distinct sample/location/function tables, 16 values/sample, 32,768
labels and one million inline lines. Actual TLS, object checks, crypto and
streaming replace the earlier modeled 16 MiB buffers. Under a 256 MiB memory
cgroup/no swap, GOMAXPROCS=2/GOGC=100, the read returned a valid summary with
176.4 MiB peak process RSS and 156 MiB cgroup peak in 254.5 ms. See the
[terminal report](../../test/results/pprof-streamed-summary-process.json).
The configured 500m CPU quota did not establish throttled execution on this
host; elapsed time is not an installed 500m guarantee. No service remained.

Reproduction uses a separately compiled objectstore test binary:

```sh
TMPDIR=/path/with/space go test -c -o /path/objectstore.test ./internal/adapters/objectstore
ASSERVAT_PROFILE_STREAM_GENERATE=/owned/fixture ASSERVAT_PROFILE_STREAM_NATIVE=/synthetic/profile.pb.gz /path/objectstore.test -test.run '^TestProfileSummaryEncryptedProcess$' -test.v
systemd-run --user --wait --pipe --collect -p MemoryMax=256M -p MemorySwapMax=0 -p RuntimeMaxSec=30s -p LimitCORE=0 --setenv=GOMAXPROCS=2 --setenv=ASSERVAT_PROFILE_STREAM_FIXTURE=/owned/fixture /path/objectstore.test -test.run '^TestProfileSummaryEncryptedProcess$' -test.v
```

Public enablement, query funding, actual worker resource/CPU/concurrency and
cancellation/retirement qualification remain separate acceptance work. The
native Go heap label-count intersection is being assessed separately; this
stream component does not widen parser limits.
