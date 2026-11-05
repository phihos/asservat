# Cancellation regression and interrupted-run diagnostics

The CI storage cancellation fixture assumed its1s caller skipped readiness.
With750ms scheduling reserve that caller permits a hint, racing the intended
first authoritative read. Baseline race repetition reproduces29 failures/50;
the original single run passed and is retained accurately despite its log name.
The test now uses half the reserve. All original cancellation, deadline, joined
read, one-read/zero-demand/zero-admission assertions remain. Corrected50/50
and full application/capture races pass (42.847s); production is unchanged.

The harness lost small output because its files were buffered and its report
was written only after cleanup. Two existing log writes are now unbuffered.
Atomic setup/running source checkpoints leave exits null and cleanup incomplete;
only actual terminal finalization supplies the finished report. No signal
supervisor, deadline extension or different Go/pass predicates were added.

The synchronized real-process cancellation regression fails against a cache copy
with only the two unbuffered arguments removed, then passes on final sources.
It waits for exact log/timing bytes before killing the fixture-owned group.
A separate child-exit7 control preserves status and exact output. All38 harness
regressions pass with ResourceWarnings treated as errors. Root required local
pre-push checks pass, including552 console tests. Original syntax failure,
unsynchronized earlier experiments and complete final inputs are retained.

These results do not explain the installed20-minute overrun or establish query,
Repeat, Stop, native cleanup or whole-workflow success. The next fresh installed
campaign must retain actual stages within the same original limit. Independent
reviews are preserved with the source-bound originals.
