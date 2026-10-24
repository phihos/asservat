# Native58 preflight corrections

Read against integrated base bc94a1885ddcfe16825dbf8571934d288a050f44. No external fixture was run for this review.

1. The regional bootstrap fixture still requested four removed credential files. It now uses the compiled hub-runtime credential through one helper-owned MaxConns=1 pool, retaining the four typed facets and closing before regional installation.
2. Installed owner input validation still calculated six individually sized owner pools. It now matches the installed loader's fixed six-connection pool; legacy calculation and the 32-connection governor stay unchanged. Existing promotion tests failed in the parent's full Go gate and pass in the focused result here.
3. The new approved query and two later native sessions share the existing two-worker quota. The fixture now reads the exact original query worker, waits for its original interval and positive natural Job/Pod termination, and requires product-retained termination/retirement after the successful distinct Stop preparation, before Stop. No failed prepare is retried; no dates, charges, limits or worker objects are mutated by this fixture wait.

The predicate table covers replaced identities, original interval still live, missing/running/unknown container state and exact positive completion/failure. It is new coverage, not claimed genuine RED. Natural Kubernetes termination, asynchronous foreground deletion and installed SQL retirement remain unqualified until the native journey.

Focused command, environment, actual terminal exit and before/after six-source hashes are in focused-result.json; raw stdout/stderr is focused.log. Wrapper 25.120126183s; bootstrap 0.047s and integration 0.014s. Actual terminal tool session38581/chunkd604f3 exit0. No tests or source changes beyond this scoped task are claimed.

Independent read-only source review by ci_change_detection found no blockers in the six-file candidate: installed pool math matches the loader, the regional facets share and close one pool, and query cleanup observes exact natural termination followed by product-persisted retirement. Reviewer ran no tests. An explicit post-Pod-GET cancellation check was added after the focused pass; final-source.json distinguishes its final hash from the tested snapshot. Parent final gates remain pending.
