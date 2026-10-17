# ADR120 gated preparation checkpoint

Frozen outside the live repository. Seventeen paths, thirteen Go files; no module,
SQL migration, generated database model, fixture role or public-runtime change.
All eight existing-file base hashes matched live immediately before packaging.
ADR118 is already integrated; the historical dependency package is not reapplied.

## Implemented scope

- Explicit new-installation continuation capability, included in the immutable
  plan digest and compiled continuity guard. Old roots cannot silently acquire it.
- Actual private `initial-prepare` command reaches the closed inert scheduling-gated
  Pod producer. Exact original Namespace/account/RBAC identities remain required.
  Only known optional Kubernetes defaults are normalized; injected execution,
  volume/token/account/privilege changes, scheduling or known-UID replacement deny.
- Separate per-HTTP-request claim before each actual Pod CREATE, fixed sixteen
  requests, original <=5-second interval, same root UID/resource-version CAS.
  A recorded Pod receipt closes further CREATE claims. Only the local invocation's
  own joined matching 201 or structured 409 AlreadyExists can complete its record.
  GET, another request's 409, cancellation or expiry never proves old completion.
- Local owner shutdown cancels and joins the entire preparation call through final
  root handling. Healthy drain preserves original dates and can acknowledge a
  retained local completion after an uncertain completion-journal write. Unknown
  prior owners remain unresolved and retain occupied names; no DELETE authority.
- Concrete final-input credential binder: original private material Secret UID,
  actual gated Pod UID/spec, final native workload guard and immutable startup
  ConfigMap UID/hash precede one original fifteen-minute interval. CAS replay,
  loser and lost reply cannot replace material, full startup identity or dates.
- Closed private schema additions preserve omitted legacy JSON fields/bytes.
  No private credential or secret-payload digest is persisted in the public root.

## Actual validation

`TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -race -p 2
-overlay=<stage>/overlay.json ./internal/adapters/kubernetes ./internal/bootstrap
./test/integration -run 'TestInitialPrepar' -count=1`

Terminal0: Kubernetes61.934s; bootstrap1.052s; integration1.053s. External cases
skip without their owned fixture. The final narrowed request tests are terminal0,
6.066s, adding exhaustion and local completion acknowledgement after the original
request deadline. The final native-fixture source compile is terminal0,1.050s.
Focused `go vet -p 2` for those packages and contracts is terminal0.
Two staged private JSON schemas plus continued/legacy positives and five negatives
passed with the repository's format-capable specification environment.

Logs: qualification-first.log (initial gated tests), qualification-second.log
(binder/gated tests), qualification-third.log (preserved failing-before shutdown
regression plus incorrect test counter path), qualification-fourth.log (corrected
full selection), qualification-request-final.log, qualification-native-compile.log,
vet.log and schema-check.log. The shutdown defect was real: Close originally joined
only the POST and allowed outer handling to continue. Whole-call ownership fixes it.
A sibling read-only review found no concrete blocking authority defect.

## Required parent native selection

`^TestInitialPreparationActivationWithRealKubernetes$` through the existing owned
context harness. No special initial-installer environment toggle is required;
ASSERVAT_CONTEXT_FIXTURES supplies the fixture. The top-level test runs sequential
healthy and uncertain subfixtures, each with its original120-second context.
Healthy checks actual native201 completion/drain; uncertain checks delayed first
POST, second winner, known UID, DELETE denial and late original409 after an explicit
fixture-admin final-guard/staging transition. Both retain all original declaration,
retirement and attack regressions. The Pod stays gated; no image is executed.
The transition is fixture authority, explicitly not product handover qualification.
No ADR120 native test has been run or claimed passed by this package.

## Remaining required implementation

The current command stops at a gated Pod with healthy request drain. The binder
consumes final inputs; it does not create them. Next is the typed final public
source/witness/guard/input producer, original private/provider one-use effects,
then actual staging handover and original-UID ungating, activation reconciliation,
credential retirement and the healthy drain-to-Pod-retirement composition.
Unknown request recovery still needs qualified reconciliation; sixteen exhausted
claims do not authorize a reset or fresh name. The earlier nine inert declarative
names remain retained per installation; this ledger covers the executable Pod key.
Root retention is not a completed installer, historical activation is not current
RecoveryReady, and no Helm or public workflow is enabled.

Shared files with guarded full diffs: contracts/initial_preparer.go, bootstrap
initial_preparer.go, the existing adapter and native initial_preparer_test.go, and
two private schemas. Parent owns shared indexes/progress/AGENTS. Continue the next
producer slice in a separate stage; this package stays immutable.
