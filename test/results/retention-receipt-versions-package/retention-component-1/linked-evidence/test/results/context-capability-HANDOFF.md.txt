# First context capability and exact intent checkpoint

Frozen source checkpoint; no live repository changes and no public enablement.

Manifest: `manifest.json`, SHA256 `aa870495d51a5f6b8f463c09362eff379bc4cf440deda2a6a4f33b58b3ca9763`.
All 14 payload hashes and the three existing live-file base hashes were checked when packaging. Files under `files/` are immutable. Parent owns integration, final repository gates and native qualification.

## Implemented scope

The closed immutable ConfigMap reader implements both existing capability ports and requires independently installed image/projection/version pins, current recovery and independent native guard proof. It retains the earliest original deadline through final guard and source rereads. The canonical private schema is included; provisioning and native admission qualification remain pending.

The private SQL facet selects only the exact capture ID. Its decoder validates the original minimized intent and complete acknowledgement, rejecting partially populated pending receipts. The application publication reader has no write/KMS port and only reuses an independently acknowledged exact receipt. It cannot publish a pending legacy intent.

The still-live submission adapter connects the actual C09 admission to exact acknowledged intent and a narrow start port. The bootstrap start adapter calls the existing APIContextRunner without a new transport. It preserves current caller cancellation and original response authority; downstream failure returns the already accepted value plus an error. Accepted replay is passive and never starts acquisition. Tests use a synthetic start port, not a deployed runner.

## Validation actually completed

SQLc generation against the isolated SQL snapshot exited 0; only `capture.sql.go` changed.

Focused command (actual exit 0, log `../first-check.log`):

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp go test -overlay=/home/phil/.cache/asservat-build/planning/first-context-runtime-20261012/overlay.json -run 'TestContextCapability|TestExactCaptureIntent|TestContextSubmission' -count=1 ./internal/application/audit ./internal/application/capture ./internal/adapters/kubernetes ./internal/adapters/postgres ./internal/bootstrap
```

Audit, capture, Kubernetes and PostgreSQL selected tests passed; bootstrap compiled and selected no tests. Meaningful negatives cover strict projections/source changes, short current authority, wrong/pending intent, lost start response and preservation of accepted receipts. No failing-before run is claimed for previously absent APIs.

After that passing run, a small source review correction moved the last capability source read after the final guard, made accepted replay explicitly passive, rejected partially populated pending receipt fields, and added the pending-receipt assertion. These final changes were formatted but have not been rerun under the parent's current native build hold. Final race/vet, schema/spec/architecture gates and all native tests remain unrun for this exact frozen payload.

## Required next work and limits

No installed command constructs this bridge, no regional capture transport is invented, and public collection remains disabled. The old conditional-PUT writer is not a one-use lifecycle. ADR132/migration52 must add a qualified typed audit layout, atomic admission/backing, irreversible write claims, original cutoffs, bounded reconciliation and positive joined completion/cleanup before enabling this bridge.

Historical accepted replay must stay passive. Runtime composition needs an explicit fresh-current same-key continuation to resume an admitted but not started capture after a lost first-start reply. Current capture metadata/progress and existing resolve/retry UX must retain the original receipt; an error must not imply non-admission or leave an unqualified accepted-forever state.

Planned native tests: exact immutable capability/VAP scope and source replacement; SQL exact lookup with unrelated pending rows and scoped write denial; then C09-to-actual-runner acquisition only after ADR132 and regional routing qualify. Existing test harnesses should run only under parent source freeze with terminal hash and cleanup verification.
