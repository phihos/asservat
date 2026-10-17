# ADR-134 explicit accepted capture continuation

Frozen source package: 32 paths, 28 changed existing files and four new files. All existing payload bases matched the live tree when packaged. No live source was changed. No SQL migration, schema-head, table-inventory, grants or generated sqlc changes belong to this payload.

## Behavior and outward contract

`request_capture` accepts optional `continue_acquisition: true` only in its preview/idempotency-key input branch. Absent keeps accepted replay passive; false, null, wrong types, extra fields and the expanded legacy branch with the field reject. Browser uses the existing exact matching Idempotency-Key header. Response DTO stays unchanged. Collection enablement, evidence:capture, same actor/client and current response deadlines remain required. No new endpoint/tool or automatic polling action.

Continue directly looks up the exact original accepted request, never creates admission/preview/IDs. It uses a fresh actual CurrentIdentity and recovery observation, monotonically carries all known shorter deadlines, requires exact original acknowledged intent, then invokes the original runner and final current check. Missing optional continuation implementation denies rather than falling back to Request. Started/stored runner replay is passive. Only the positively acknowledged first execution-preparation winner may call PrepareContext; an existing prepared or uncertain reply cannot create/wrap keys again. Original registration, scope, executor/process and attempt/start intervals stay immutable.

Console action appears only for Pending work with the in-memory original receipt and current capture rights. Poll, reload, pasted URLs and session refresh do not continue. Unknown results retain the original key; known closed/uncertain preparation blocks further continuation and explains checking the original capture before deliberately starting another investigation. No replacement capture or extra consent is automatic.

## Shared paths requiring explicit merge review

- Canonical contracts: `specs/contracts/mcp-tools.json`, `docs/interfaces/browser-openapi.yaml`, `specs/mcp.md`.
- Schema generation: `scripts/investigation-schemas.py`; generated `internal/contracts/investigation-schemas/request_capture.json`, `web/src/generated/capture.d.ts`, `web/src/generated/validate-capture.js`. Only existing request_capture input changes; outputs stay identical.
- Common dispatch/audit input: `internal/transport/presentation/context_operations.go` adds optional facet and normalized omitempty field. Historical absent serialization remains unchanged. Browser/MCP route implementations are unchanged; their tests include the new branch.
- Existing regional runner/start bridge: `internal/application/execution/api_context.go`, `internal/bootstrap/context_submission.go` and typed error domain files; no signature change to APIContextRunner.Execute.
- Existing shared native helper: `test/integration/api_execution_native_test.go` now composes actual C09 submission and current52 publication instead of legacy direct admission. New setup is isolated in `context_continuation_native_test.go`; current52 implementation/roles are dependencies, not replaced files.
- Existing browser fixture: `test/integration/console_test.go`, `web/scripts/browser-test.mjs`. Synthetic service only; no synthetic transfer/execution success is claimed.
- Parent adds ADR-134 to its decision index/progress and updates `docs/reviews/first-context-integration.md` after integration. This payload contains the new ADR and architecture note, not those shared indexes.

`paths.txt` and manifest enumerate every replacement. `base_sha256` null means a new absent path. Verify bases and payloads before applying. Review changes.patch, then regenerate/check derived contracts against the combined source rather than overwrite another agent's changes blindly. No SQL generation is necessary for this patch.

## Verification and actual results

All checked source used the isolated Go overlay or validation tree, GOMAXPROCS=2 and GOFLAGS=-p=2 with TMPDIR=/home/phil/.cache/asservat-build/tmp. Evidence is copied unchanged under evidence/.

- Before regression exit 1: `preparation-before.log` and `preparation-before-complete.log` reproduce two key preparations on concurrent replay and unintended StoredPendingVerification after a lost preparation reply.
- Separate meaningful deadline before regression exit 1: `preparation-deadline-before.log` shows a valid original binding expired before keys yet old code called key provider/capture once. Fixture explicitly checks binding validity.
- After affected full six-package races exit 0, handle 48098: application/capture, application/execution, presentation, browser, MCP, contracts. See affected-race.log.
- Final execution regressions plus bootstrap/integration compilation exit 0, handle 89481. Integration compile reports no tests to run: no external fixture was executed. See final-execution-fixture-compile.log.
- Affected eight-package vet exit 0, handle 11650, affected-vet.log.
- Web contracts/native ESM/TypeScript and 125 tests exit 0, then Vite build exit 0, handle 41828. See web-check-final.log/web-build.log. Existing Vite large-chunk warning remains; no dependency changes. Earlier preserved failed web logs show missing isolated examples, then a test assertion before its passive asynchronous read settled; both corrected without weakening product checks.
- OpenAPI 3.1.1 validation and exact browser/MCP input/output parity for all 49 tools PASS, handle 69741 exit 0. Both independent logs inspected: openapi.log/parity.log.
- Following checks, only the architecture note's exact native-selector/provenance text and the one static UI helper sentence were corrected. Parent requested the helper wording; no behavior/type/test change and no further builds during native hold.

Useful reproduction commands after integration: `go test -race -count=1 ./internal/application/capture ./internal/application/execution ./internal/transport/presentation ./internal/transport/browser ./internal/transport/mcp ./internal/contracts`; `go vet` on those plus bootstrap/integration; `npm --prefix web run check`; `npm --prefix web run build`; repository contract/schema and architecture gates. Full combined repository gates remain parent-owned.

## Native and browser qualification pending

Exact native selector is `TestContextAdmissionWithRealServices/native-api-runner`, using the existing context harness (not custody):

`python scripts/test-context-storage.py --run '^TestContextAdmissionWithRealServices$/^native-api-runner$'`

The actual outer function and branch are in `capture_admission_test.go`; context fixture mode initializes Kubernetes/S3/SQL and selects that branch. Parent runs it with frozen combined sources. The staged test now starts with real C09 Preview/Request and separate current52 SQL/S3 intent acknowledgement. It injects one unavailable start BEFORE execution preparation, cancels the old current request, checks ordinary replay remains passive and explicitly continues with a fresh actual request handle into the real API runner. It then preserves the previous exact-byte, one SQL execution/local CAS, immutable binding/process, deletion-before-publication and custody-charge assertions. Target/API objects are real; human/capability/retention/recovery/bootstrap/key qualification inputs remain explicitly synthetic. This does not qualify an installed regional route, capability producer, real SSO or public activation.

Parent reported current52 corrected native qualification passed separately (11 entries, original role/read path), including narrow UPDATE(source_uid) lock privilege. The continuation helper consumes those current roles; it does not broaden grants. integration-dependency-hashes.json records those dependencies, not source-matched ADR134 native evidence.

The built-browser journey asserts no automatic continuation, explicit original pair, no new preview/request and passive reload with accessibility checks. Source compiles; actual parent loopback browser run remains pending. No external fixture or browser lab was run by this agent.

## Next

Parent integrates/rechecks this package, qualifies exact native API selector and actual console browser flow, records evidence, and keeps collection disabled until the installed end-to-end slice passes. ADR136 actual native GET/download composition is the next assigned source-only design. No pending/unknown original audit or key effect receives renewed authority from continuation.
