# Sustained live cohort delivery without recorder backpressure

PR #209 code commit: `cb6e1905`.

Focused race-enabled qualification run on 2026-11-10:

```bash
TMPDIR=/home/phil/.cache/asservat-build/tmp \
CGO_CFLAGS='-I/home/phil/.cache/asservat-build/libpcap-1.11.0/include' \
CGO_LDFLAGS='-L/home/phil/.cache/asservat-build/libpcap-1.11.0/lib' \
GOFLAGS=-p=2 go test -race -tags libpcap ./internal/bootstrap \
  -run '^TestLiveExistingSourceTapDoesNotCollectPinOrBorrowRaw$' -count=20
```

Result: all 20 runs passed (73.412 seconds). The complete `make pre-push` gate
also passed, including affected libpcap/integration tests and all 611 console
tests.

The actual existing-source cohort receives 2,000 timestamped frames in bounded
batches. Reads reactivate the cohort as real node reads do. Cursor and loss
counters must be monotonic, at least one approved batch must be delivered, and
empty/sampled batches under the 100 ms live CPU ceiling are valid rather than
being mislabeled lossless. A further 1,000-frame reader-lag burst must retain
bounded rows and explicit loss.

All 3,001 source frames remain charged to the original recorder, the ring stays
unpinned, and synthetic payload bytes never enter approved metadata. Closing the
cohort leaves the original source active with its original permit.

This is component qualification, not installed/native or operator-metrics
qualification. Earlier attempts with exact batch-size/zero-loss assumptions were
invalid under intentional replay and CPU-budget shedding. Reusing initial frame
timestamps also correctly expired the one-second source ring; fresh timestamps
fixed the fixture rather than the product lifecycle.
