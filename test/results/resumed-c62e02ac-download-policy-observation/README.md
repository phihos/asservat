# Download-only policy observations: focused RED/GREEN

The regression first composed the existing raw policy port directly, before the new observation owner. Actual RED exit **1** (`red.log`, package 0.002s): repeated reads, concurrent reads, canceled waiter, mutable return ownership and clock rollback assertions failed; no-stale-fallback passed. `red-test.go.txt` preserves that exact test checkpoint. The baseline does not claim a concrete Kubernetes source aliasing defect.

The implementation adds one synchronous live read shared by concurrent callers. Only a completed strict five-second protected observation can be retained, until its original `ObservedAt + 60s`. Returned slices are owned copies. Waiting callers retain cancellation/deadlines; failed refreshes do not retry implicitly or reuse expired results. There is no background worker, watch, sliding expiry or configuration knob.

Download-specific validation and path selection consume this observation. Administrative `Valid`, `Select` and `Operator` remain strict five-second consumers. The composed download environment retains current recovery/processing reads and the original request, catalog, retention and proof deadlines. These synthetic tests do not qualify installed authorization or native delivery.

The first focused race GREEN exited **0** (authorization 1.038s, privacy 1.007s). The final focused race GREEN, after adding failed-flight/no-retry and source-alias assertions, exited **0** (authorization 1.035s, privacy 1.008s). Exact commands and raw outputs are retained. `final-green.json` includes the unchanged before/after hashes of all five owned source files. `result.json` distinguishes measured command results from test scope. The RED environment is copied from the actual invocation because its original JSON recorder omitted those fields.

No full package suite or external fixture ran. The independent composed test results are in [download-composed-budget](../resumed-c62e02ac-download-composed-budget/README.md); they expose a remaining identity read budget failure despite the policy-cache pass. No production or test source was changed while creating this archive.

The subsequent specification, architecture and design gates exited **0** in 10.542 seconds. `contract-gates.log` and `contract-result.json` preserve their exact command/output. They validate documents and declared contracts, not installed runtime behavior.

## Follow-up: near-expiry headroom

The initial implementation could leave a new request only the last fraction of a cached observation. [The separate headroom RED/GREEN phase](headroom/README.md) reproduces and corrects this without extending an existing request or sliding cached timestamps. The original evidence above remains unchanged.
