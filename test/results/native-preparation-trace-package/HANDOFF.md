# Native preparation trace — frozen fixture-only package

Two payload paths; one existing base and one new helper. The package changes no product file, authority, deadline, SQL, wire format or retry. Native/external qualification remains parent-owned and unrun for this trace.

## Scope

The one-line `traceNativePreparation(t, cfg)` hook is immediately before the existing actual runtime constructor in `test/integration/context_native_content_test.go`. The new `native_preparation_trace_test.go` decorates existing runtime ports and the actual C03 authority's permission/catalog/retention/environment ports. It records dispatch reserve, intent receipt, claim, exact Job create/find/observe, record, bind and read boundaries; attachment and owner admission; preparation batch/audit/acknowledgements; native fence/owner/origin/key calls and original registration callbacks, wait and commit.

Original contexts, arguments, results and errors pass through unchanged, with exactly one underlying call. Only returned interface handles gain forwarding decorators. No new context, authority check, cached permission, I/O, goroutine or retry is added. The original first-context marker is forwarded from the original concrete facet rather than conferred on an arbitrary port.

At most 512 fixed-label events plus the first returned error are retained. Output contains durations, original context deadlines, relevant input/result expiry and closed error/context categories. No raw errors, scope/actor/SQL arguments, credentials or evidence are logged. Test output is deferred to fixture cleanup; unfinished entries are explicitly `not-joined`. This timing diagnostic is not a performance qualification.

## Actual verification

Handle **13383**, terminal **exit 0**, total 11.226s. Integration package compiled and the two `^TestNativePreparationTrace` tests passed with the race detector (package 1.054s). Tests cover exact original context/result/error/invocation forwarding, unchanged deadlines, canceled-call forwarding, closed error labels and bounded recording with first-error retention after overflow. Both payloads, original base/new-path absence and all 1,309 source/module dependency hashes matched before and after. Exact command/exits/hashes are in `evidence/trace-focused.json`; output in `evidence/trace-focused.log`.

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/planning/native-preparation-trace-20261012/tmp go test -overlay /home/phil/.cache/asservat-build/planning/native-preparation-trace-20261012/overlay.json -race ./test/integration -run '^TestNativePreparationTrace' -count=1 -timeout=60s
```

No separate full vet/repository gate or native result is claimed. Existing native preparation failed at original `ContinueContextDownload` after source resolution in `native-retry-range-supervised-fixture.log`; its connector timings do not locate the failed runtime boundary. Source duplication exists but is not yet proven the cause. This trace is intended to identify the earliest failed boundary before any production optimization.

## Guarded integration and next step

Check manifest base/new-path absence, both payload hashes and dependency object before copying. Parent owns integration and the selected `TestContextAdmissionWithRealServices/download-worker-native-content-resume` actual SQL/S3/native run using the existing harness. Preserve original source/hash/cleanup reporting and prior failure logs. Archive any copied Go source as `.go.txt` outside package paths.

Do not reorder origin SQL/catalog access ahead of current eligibility: origin recheck reads catalog state. Any later optimization must preserve deny-before-evidence-lookup, original five-second/session/source deadlines, current locked SQL guards and unknown spend. No cached authority across effects or unknown-effect replay is included here.
