# ADR137 Helm bootstrap packaging — frozen handoff

Frozen against current live SQL52 + integrated ADR135. All 58 payload/base paths
and 21 dependencies were checked; dependencies.json lists their exact hashes. No live edits or native lab were performed by this agent.
Native Helm/private-registry qualification remains pending for the parent.

## Payload boundary

This package adds the fixed four-command Helm hook and static trusted installer
RBAC, immutable revision-named public input, the nonauthorizing PEM/audience
compiler, local terminal-only resume CLI, exact public provider recipe, and
explicit private-registry propagation using the original provider Secret and
positive cleanup. Omitted registry fields preserve legacy bytes. The optional
bootstrap mode remains off by default; runtime stays rejected.

The new actual qualification selector packages the chart, builds the exact
product, gives it empty PostgreSQL and real TLS OpenBao/S3, and uses an owned
TLS/authenticated Distribution registry plus two fresh owned Kind nodes. It
requires image/manifest absence before both relevant pulls, anonymous denial,
exact authenticated manifest GET evidence for each node, real original manager,
schema, encrypted activation, positive manager/copy closure, setup-free replay,
terminal-only failed-hook resume through its original public revision and
uninstall preservation. Its source compiles; the native test has not executed.

Parent integration should add ADR137 and architecture links to shared indexes
and record this checkpoint in progress; this package deliberately does not
replace the parent's actively edited indexes/progress. No SQL migration or
module update is involved. ADR135 source must remain preserved.

## Earlier decisive checks

- Expected failing-before: handle33180 exit1, registry-before.log,
  TestInitialRegistryRequestedActivationPullIsNotSilentlyOmitted.
- First affected race handle80858 exit0, first-race.log: Kubernetes,
  providerconfig, KMS, bootstrap plus contracts/cmd compile. PublicCompiler name
  was not selected by that regex and was run separately below.
- First Helm fixture check11133 failed because its synthetic subject was a
  string instead of the existing typed IdentitySubject. Only that fixture input
  changed; helm-second.log handle63331 exit0.
- Public compiler race and affected vet handle93383 exit0; compiler-race.log
  explicitly records PASS, first-vet.log is clean.
- Spec/layer checks51837 exit0: spec-first.log (87 schemas/49 MCP operations/
  9,936 assertions), architecture-first.log (51 packages/269 edges).
- One initial shell invocation could not create its relative evidence path;
  no Go test ran in it. It is not failing-before product evidence.

Final job25854 exited0: native integration-source compile (`-run '^$'`),
focused six-package race selection and seven-package vet. Final offline job65603
exited0: five selector tests, Helm4.3.0 render/schema/package, spec91 schemas /
9,961 assertions, architecture1,205 positive /120 rejection checks, and design
73 browser /49 MCP pairs. The subsequent Python-only cleanup refinement passed
three new selector/registry/cleanup tests (exec chunk d239ca, exit0). No Go source
changed after job25854. Exact commands/results are in checks.json and
final-check.sh; native compilation is not execution. Earlier Go layer check is
preserved; the final offline layer gate is the design/catalog checker.

manifest.json pins every original/payload hash; dependencies.json pins consumed
unchanged sources. adr137.patch is an optional unified patch. Apply only after
matching each original; new paths must be absent. Evidence includes the exact
failing-before test source with a .go.txt suffix so it cannot become a Go package.
All inputs in changes/ are immutable after this handoff.

## Parent-owned actual qualification

With all sources frozen and no concurrent Go/sqlc builds:

```sh
python scripts/test-context-storage.py --helm-bootstrap
```

Use the repository's qualified Python environment as for existing context
fixtures. This is a new explicit selector, not `make helm-integration`'s old
foundation CRD lifecycle case. The test requires Helm, Docker, Kind, kubectl,
OpenSSL and the already qualified local Go/tool environment. It installs no new
host package, changes no host Docker auth/trust, publishes nothing externally
and never loads the exact product image into either Kind node. The harness
records sourceHashes before effects and compares them again after test/registry
evidence. It includes go.mod/go.sum, itself, all Go integration and
product sources, canonical embedded JSON/SQL/fixture sources, the registry helper
and every chart file. The packaged .tgz has a separate SHA-256; the actual binary,
Docker configuration and pulled manifest identities remain separate evidence.
Missing exact selector PASS or changed sources forces failure.

The harness owns all clusters/network/registry/service containers. Removal first
checks the original fixture label and uses acknowledged Docker removal. The new
registryCleanup check independently lists containers/networks to establish the
exact owned names are absent, then removes and verifies the private TLS/auth
fixture directory before writing the report. Any unknown lookup/removal fails
cleanup and the process. Upstream official image caches remain explicitly
outside fixture removal; no physical sanitization is claimed. Its Go process
bound is twelve minutes; individual original product bounds are unchanged. Archive actual environment/log plus image/binary identities.

Official fixture registry provenance checked 2026-10-12: registry:3,
Distribution3.1.2, index SHA256
ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8.
See NATIVE-PLAN.md for primary URLs. This pin is not a passing pull result.

Native metadata-only API tracing remains separately qualified by ADR131/133.
This new command test is designed to prove setup-free compiled replay without enlarging
product RBAC or adding production tracing. Lost API create replies and original
schema-incarnation denial retain their prior separate tests; this selector does
not inject every prior failure. Helm rollback is never recovery.

## Explicit remaining scope

See INSTALLED-PREREQUISITES.md and architecture/helm-bootstrap.md. Public runtime
requires installed protected sources/accepted policy and qualification, actual
storage/retention/audit/capture/Stop/processing backing, peer/trust/key provisioning,
ongoing joined supervision, public HTTPS composition and its end-user native
qualification. Internal/bundled provider alternatives remain separate work.
Successful hook completion establishes an initial checkpoint and starts no
service, collector or public route.

Nonsecret public revision snapshots are retained until positive unreferenced
cleanup is qualified. Never remove one referenced by a retained/running/unknown
hook. Operator registry credentials remain an image-distribution dependency.
Managed copy cleanup does not claim upstream credential revocation, operator
input deletion, node-cache deletion or etcd/backup erasure. Original installer
image/bundle remains pinned; no application upgrade/recovery protocol is added.
