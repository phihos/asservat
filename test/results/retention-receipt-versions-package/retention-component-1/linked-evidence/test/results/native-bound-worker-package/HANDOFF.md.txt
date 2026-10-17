# Bound-worker native continuation — frozen two-path package

## Scope and contracts

`ContextNativeRuntime.ContinueContextDownload` now distinguishes a currently bound original worker from an unbound launch. The existing first current C03 check still precedes the SQL attachment/catalog read. For a bound worker, the code calls the original `Jobs.ObserveDownloadWorker` with the exact original intent and Job receipt. The production Kubernetes adapter still reads current accepted configuration, protected namespace/account/control/priority sources, exact nonterminal Job and bounded Pod list. The observed complete worker must equal the original binding. Fresh ordinary authority then precedes a second current SQL attachment read; a further current identity/authority check runs after that possibly blocking SQL call. Original parent, source, attachment, worker and five-second request bounds can only shorten.

Only replayed completed launch operations are omitted: reserve, intent receipt lookup, claim, separate Job lookup, record, bind and final launch lookup. SQL attachment independently verifies the acknowledged original intent and rejects termination/retirement. Busy/uncertain state, a missing/changed binding, pending after already being bound, changed/deleting/extra Pods and current denial do not fall back to launch or stored authority. Actual enrollment registration, native peer/Pod proof, per-frame checks, SQL effect fences, preparation admission and key work remain unchanged. Unbound/unknown launch recovery still calls the existing full `ensureChecked` path.

No public wire/schema/SQL migration, capacity, retry, approval or authority-lifetime contract changes. This is not a permission cache, preparation retry or completed-worker revival.

## Actual verification and preserved failures

- Handle **67757**: terminal exit 1. BEFORE meaningful regression failed against the unchanged original runtime: it replayed reserve, intent receipt, claim, Find, Record, Bind and Read on an already bound worker. Original context reached bounded enrollment wait; this is not a setup failure. Command 6.058 seconds.
- The initial AFTER phase in the same handle failed only because the new test incorrectly applied the disclosure/source deadline to the existing separately bounded restrictive owner release. All new negative/deadline cases and existing recovery cases passed. This test defect and initial test source are retained (`after.log/json`, `initial-test.go.txt`). Vet was not reached.
- Handle **35836**: corrected affected race test command exit 0, 3.813 seconds (Go package 1.172 seconds), **22 top-level / 76 named passing entries**; affected evidence vet exit 0, 0.199 seconds. The corrected assertion retains the original effect bounds and independently checks the already joined restrictive release against its five-second cleanup ceiling.
- All 1,210 internal-source/embed/module dependency hashes, original bases and respective frozen payload hashes matched before/after each phase. Integration fixture paths are deliberately outside this closure, so parent-owned pool-lifecycle fixture changes did not overlap these checks.

Commands (GOMAXPROCS=2, GOFLAGS=-p=2, TMPDIR set to this stage's `tmp`):

```sh
go test -overlay /home/phil/.cache/asservat-build/planning/native-bound-worker-20261012/overlay-before.json -race ./internal/application/evidence -run '^TestContextRuntimeBoundWorkerAvoidsCompletedLaunchReplay$' -count=1 -timeout=60s -v
go test -overlay /home/phil/.cache/asservat-build/planning/native-bound-worker-20261012/overlay-after.json -race ./internal/application/evidence -run '^Test(ContextRuntime|WorkerCurrent|WorkerPending)' -count=1 -timeout=90s -v
go vet -overlay /home/phil/.cache/asservat-build/planning/native-bound-worker-20261012/overlay-after.json ./internal/application/evidence
```

Tests exercise actual continuation orchestration with explicitly synthetic current authority, SQL and Kubernetes port observations. The positive case reaches and joins one original enrollment registration with zero repeated launch effects. Negative cases cover deny before any catalog/Pod lookup, revocation during Pod/SQL reads, Job/Pod/SQL replacement, multi-Pod and termination port errors, missing binding, busy/uncertain state, cancellation, original five-second expiry and shorter caller deadline after blocking observations. The actual Kubernetes multi-Pod/termination implementation is unchanged; these port-error tests do not independently qualify that API. Existing lost-CREATE, pending startup, current-identity and locator-shortening regressions are included.

## Remaining qualification and next task

No native timing/availability verdict is claimed. Retained trace measured about 285 ms in replayed dispatch work; the new path still performs its required independent reads, and savings must be measured by the actual fixture. The separate real fixture connection exhaustion (48-server-connection limit and recursive phase resource overlap) is not changed here. Parent owns its fixture correction and any native run.

After exact manifest/base/dependency verification, parent should integrate and run the selected real SQL/S3/native/HTTPS ordinary, intentional range and actual interrupted-client paths with frozen source and full cleanup/hash verification. No authority deadline extension or automatic attempt retry is authorized by this package. No build remains active; copied Go evidence outside product paths has `.go.txt` suffix.
