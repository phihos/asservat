# ADR139 staged checks

All Go commands used GOMAXPROCS=2, GOFLAGS=-p=2, the stage overlay and the dedicated stage/tmp. No external/native fixture was run for this package.

| Handle | Command scope | Actual terminal result |
| --- | --- | --- |
| 54336 | Original owner_runtime.go plus new TestOwnerRuntimeJoinsBlockedChildAfterCancellation, race | exit 1, intended failing-before at 6.01s: Run returned while the positively observed child was still blocked |
| 89440 | go test ./test/integration -run '^$' | exit 0, integration source compiles |
| 21302 | selected bootstrap/native races | exit 1 overall; corrected bootstrap passed 9.716s, native fixture failed at a client frame context longer than the allowed five seconds |
| 75303 | go test -race ./internal/transport/native -run '^(TestNativeServe|TestNativeSharedPort|TestNativePurpose)' -count=1 -timeout=90s | exit 0, 13.585s, after fixture-only four-second child read context correction |
| 96865 | go vet ./internal/bootstrap ./internal/transport/native ./test/integration | exit 0 |
| synchronous | PYTHONPATH=<live>/scripts PYTHONDONTWRITEBYTECODE=1 python changes/scripts/test-regional-context-selection.py | exit 0, four tests |
| synchronous | exact live/base comparison, gofmt -l, Python AST parsing | exit 0, seven bases, seven absent new paths, eleven formatted Go files, two parsed Python sources |

Evidence logs preserve both failures and passing reruns. The listener fixture's parent sixteen-second context, server operation four-second bound and accepted socket ten/thirty-second bounds were unchanged; only its NativeClientStream.Receive child was narrowed to four seconds. The production frame validation was unchanged.

No Go process remains owned by this stage. Actual SQL/S3 owner discovery, both signed regional exchange modes, integrated full repository gates and installed runtime qualification remain unrun. Ordinary Serve coverage in the selected native tests passed; the shared H2 test proves a standby beyond ten seconds plus a separately admitted native conversation using synthetic current authority.
