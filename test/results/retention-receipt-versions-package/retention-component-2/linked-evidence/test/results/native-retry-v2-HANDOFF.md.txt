# Native download retry and interrupted-client qualification

V2 supersedes the immutable package/ checkpoint; v1-to-v2.json records the three
UI-only changes and unchanged Go scope. Seventeen isolated paths over integrated
ADR136/137/138. No migration, protocol
version, refill, original authority deadline or runtime enablement change. The
payload is now frozen. All builds/readers are joined; parent owns integration,
combined gates and every external fixture.

## Resulting behavior

A closed local response/native owner no longer makes a failed or unknown first
context response eligible for reuse. Under the existing original session lock,
the actual admission/metadata path reads at most two exact window rows and
requires one valid matching successful, final-verified, independently acknowledged
window. This is a bounded read, not another reservation, refund or state rewrite.
Missing outcomes while the original handler finishes remain temporarily unavailable;
a later acknowledged result can satisfy a fresh read. Known failed outcomes deny.
The read-only download-worker facet additionally needs SELECT on download_window;
no write privilege is added. Console ADR140 has recorded that inventory change.

A successful output receipt is still not proof that the remote worker received
the last hub marker. A real h2/mTLS regression drops that final marker before worker
consumption: the hub positively acknowledges while the worker reports Uncertain.
Any otherwise eligible retry still needs the existing exact fresh worker Hello
before key/read effects, and consumes unchanged finite original allowances. No
partition-proof completion, worker revival or new acknowledgement protocol is claimed.

The console now offers **Start a new download** after the user requests the
native browser transfer, including when status remains Ready and the browser
failure never reaches React. Interrupted/error transfer recovery is also supported.
Before the first native link click, Ready alone does not offer this action.
It first confirms restrictive Stop for the exact old session, then prepares one new
session for the same saved artifact. Lost Stop and new-prepare replies retain their
respective original keys in the existing page/session receipt. Pending or foreign
Stop replies never dispatch new work. The browser restarts its file from the
beginning; no JavaScript Blob, partial-file append, new approval or recapture is
introduced. Old uncertain spend remains charged. Compatible authenticated clients
can use the explicitly new path with their retained Range/If-Match and checksum.

## Two distinct compiled native cases

Both source cases use actual PostgreSQL, S3, encrypted window/preflight audit,
remote three-slot A-KEY, worker/connector/hub h2 and final HTTPS sink. Human/session,
issuer, protected bootstrap and Pod/serving authority remain explicit fixture inputs.
They are not installed SSO, deployed acquisition, browser-file-save or large-artifact
qualification. Neither new selector has run.

1. `download-worker-native-content-resume` intentionally completes two 206 ranges
   on one original session. It joins actual HTTP/worker completion, crosses the
   actual earlier identity expiry, obtains fresh authority, denies wrong If-Match
   without response/key spend, reconstructs the original SHA and denies a third
   depleted response. Each partial result remains Interrupted; client hash verification
   is separate from a whole-file server completion.
2. `download-worker-native-content-interrupted` delivers a real h2 prefix, then
   cancels the actual client while its native write is blocked. It joins the HTTP
   handler and Uncertain worker, verifies conservative old accounting, and denies
   independent old-session metadata/response admission. One explicit audited prepare
   creates a different session/worker for the same immutable artifact using remaining
   original capacity. The new HTTPS Range/If-Match yields the suffix for exact client
   reconstruction. It never replaces/refunds the old worker or extends the original
   fixture/request context; a third admission must deny depleted capacity.

Both cases configure sufficient backing before the first effect: 12 MiB per-session
read ceiling, 8192 output, two original response/window/native-key rows and ten
native updates where relevant. The fixture's existing independent allocations
cover the two explicitly admitted sessions. These synthetic backing values are not
measured backend/WAL capacity. Preparation uses three separate unwrap slots; each
content window uses another three. SQL used_roles=7 is a three-bit mask, not seven
keys. ADR140 owns practical installed default headroom and protected qualification.

The earlier cookie/join fixture correction is already integrated/qualified by
parent 47877. Its helper is an unchanged dependency, excluded from this payload.
The context-native fixture mutation here contains only new mode/role/branch changes.
There is no capture_admission_test.go mutation.

## Actual evidence

All Go checks used GOMAXPROCS=2 GOFLAGS=-p=2 and dedicated stage TMPDIRs. checks.json
records exact terminal handles and evidence paths, including setup/compile failures.
No native lab was run by this agent.

- 56709 exit 1: pre-fix closed-owner uncertainty predicate regression fails. This is
 a focused pure admission regression, not the unrun real SQL before/after case.
- 73334 exit 0: corrected Postgres and native focused races, including actual h2
 final-marker loss and existing lost-final/positive-retirement protocol cases.
- cdc3d4 exit 0: isolated sqlc generation after correcting its stage-relative input
 path. The earlier wrong-path failure remains archived. Only the changed query
 binding is delivered; no models or other generated output changed.
- 12699 exit 0: combined integration source compilation and existing exact cookie/
 joined-handler helper tests. The new external selectors were compiled, not run.
- 18561 exit 0: 37 affected UI tests, including lost Stop/new-prepare replies,
 unchanged keys, pending/foreign Stop, scope cancellation, terminal status race
 and explicit full-restart wording/order. Earlier missing stage examples dependency
 failure remains archived; fixing the stage link changed no product assertions.
- 80963 exit 0: initial TypeScript noEmit on the v1 staged web files.
- 69180 exit 1: meaningful native-link/stale-Ready regression before correction.
- 71175 exit 0: final v2 affected UI tests,38 passing; the new case clicks the
 actual anchor and requires the action without another status call or synthetic
 operation error. It then verifies positive Stop before fresh preparation.
- 5200 exit 0: final v2 TypeScript noEmit. Helper copy now reads:
 "Starts the browser download from the beginning and stops the previous request.
 Both attempts count toward your download limit."
- 47785 exit 0: final focused vet for Postgres, native transport and integration.

Reproduction commands against the retained stage overlays:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/planning/context-native-outcome-20261012/tmp go test -race -count=1 -overlay=/home/phil/.cache/asservat-build/planning/context-native-outcome-20261012/overlay.json ./internal/adapters/postgres ./internal/transport/native -run 'TestFirstContext|TestNativePositiveContentAcknowledgementDoesNotProveRemoteJoined|TestNativeLostFinalAcknowledgementNeverReturnsJoined|TestNativeContentFinalMarkerSurvivesOwnPositiveRetirement'
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/planning/context-native-resume-20261012/tmp go test -count=1 -overlay=/home/phil/.cache/asservat-build/planning/context-native-resume-20261012/combined-overlay.json ./test/integration -run '^TestNativeContentFixture'
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/planning/context-native-resume-20261012/tmp go vet -overlay=/home/phil/.cache/asservat-build/planning/context-native-resume-20261012/combined-overlay.json ./internal/adapters/postgres ./internal/transport/native ./test/integration
```

In `native-download-restart-20261012/work/web`, the affected test invocation is
`./node_modules/.bin/vitest run src/evidence/evidence.test.ts src/evidence/EvidenceWorkspace.test.tsx`,
and typecheck is `./node_modules/.bin/tsc --noEmit`. The four work-tree source files
were byte-identical to delivered changes for these final checks.

## Integration and next qualification

Verify manifest.json base/payload hashes and new-path absence, then apply changes/.
Dependencies are a path-to-SHA object, not a list. Parent integrated ADR139 after the initial Go/UI checks joined; the narrow v2
UI checks then ran against the same isolated web sources. No Go check was repeated. dependency-transition139.json and the preserved parent
manifest record each exact old/new dependency: none overlaps a payload. Current
post139 Go/query/web dependencies are pinned, but no Go check is presented as
retested against that new source. Parent's next integrated gates must cover the composition.

Run each selector in its own owned source-frozen lab, retaining all terminal source
hash and cleanup evidence:

```sh
python3 scripts/test-custody.py --run '^TestContextAdmissionWithRealServices$/^download-worker-native-content-resume$'
python3 scripts/test-custody.py --run '^TestContextAdmissionWithRealServices$/^download-worker-native-content-interrupted$'
```

Then run affected/integrated Go, SQL, web, spec and architecture gates and the
relevant baseline under parent sequencing. UI built-browser qualification and both
new actual-service selectors remain pending; compile/unit evidence does not close
them. Native139 listener changes also remain independently subject to their own
qualification. Public installed runtime prerequisites remain with ADR140.
