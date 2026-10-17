# ADR128 provider preparation checkpoint

Frozen isolated payload: 25 paths in `changes/`; original/live and payload hashes
in `manifest.json`; unified `initial-provider-provisioning.patch`. No live file,
SQL migration/model/role fixture, dependency, chart, shared index/progress or public
transport changes. Parent owns integration and all external qualification.

## Implemented scope

The actual private `initial-prepare` loader/supervisor accepts an optional explicit
provider profile. Before declaration it reads one immutable pinned bootstrap
material Secret, validates endpoints and exact finite OpenBao issuer/roles/JSON
ACLs. After original SQL/probe preparation it persists separate one-use private
wrap/unwrap claims, sends each provider POST only after its acknowledged first CAS,
privately retains/independently verifies positive original replies, and persists
exactly seven immutable `initial-install` files into one original target Secret.
No bootstrap issuer or SQL maintenance credentials enter that projection.

The existing maintained OpenBao client is reused with no retry/redirect/ambient
proxy. Service tokens must be nonorphan, nonrenewable and nonperiodic. Role cap is
900 seconds; original parent expiry must fit the original SQL interval. Requested
child TTL uses the original claim completion bound, not a later clock. Unknown
responses never repeat issuance; token accessors/GET do not reconstruct missing
positive secret responses. A same-process positive response may finish a lost CAS;
process closure joins calls and clears the bounded two-response map.

Managed S3 keys are supplied input. Their `storageUseUntil` is a local bound,
not provider revocation or credential expiry. The final immutable projection has
exactly the three scoped SQL files, storage file, encrypt/decrypt tokens and the
original probe token; writer token remains the kubelet projection. Legacy absent
provider DTO fields are omitted, and existing policy bytes remain unchanged.

Exact provider revocation is implemented for retained positive child responses,
requiring invalid original accessor plus actual original-token authentication
denial. It does not establish quiescence of earlier provider/SQL/storage effects.
The supervisor does not automatically activate or retire: the original Pod stays
gated. Full handover/activation/retirement continues in a separate checkpoint.

## Measured checks

Environment for Go: TMPDIR=/home/phil/.cache/asservat-build/tmp, GOMAXPROCS=2,
-p 2, stage `overlay.json`. No external fixture was started.

- `go test -race ... ./internal/adapters/kms ./internal/adapters/kubernetes
  ./internal/adapters/providerconfig ./internal/bootstrap ./internal/contracts
  ./test/integration -run 'TestInitialProvider|TestInitialPreparationProviders'`:
  exit 0; kms1.378s, Kubernetes19.931s; all packages compiled (`focused-race.log`).
- Final `go test -race ...` same six packages with
  `-run '^TestInitial(Provider|Preparer|Private(Continuation|State)|Preparation(Providers|RejectsStaticProvider))' -count=1`:
  exit 0; kms1.478s, Kubernetes44.803s, bootstrap1.050s, contracts1.025s,
  integration1.055s (`final-race.log`). This includes old continuity-policy golden
  checks and preparer concurrency/retirement/uncertainty regressions. External
  native test only compiled and skipped without its explicit owned fixture input.
- `go vet -p 2 -overlay=overlay.json` over those six packages: exit 0 (`vet.log`).
- Repository spec-venv `python check-schemas.py`, offline registry and actual
  FormatChecker: exit 0 (`schema-check.log`). New private progression/material/
  public profile/selection prerequisites and legacy private SQL states validate;
  malformed dates, secret overflows, extra fields and missing dependencies deny.
  The initial sliced prerequisite test omitted the canonical dependentRequired
  and failed (`schema-check-fragment-before.log`). The test fragment now includes
  that actual clause; canonical schema was unchanged.

New tests cover broader role/ACL/issuer profiles, missing explicit safety fields
(including false/zero values that Go decoding alone would accept), one POST after
lost/late/broader/oversized provider replies, original dates, exact live revocation,
private CAS losses, same-owner positive recovery, concurrent owners, changed
parent, final deadline expiry, bounded worst-case private size and immutable
seven-file projection. No entire-tree/native gate is claimed by these checks.

## Parent native qualification

Exact owned context selection:
`^TestInitialPreparationProvidersWithRealServices$`
No extra initial-installation env flag. Fresh real PostgreSQL/OpenBao/Kubernetes
are required; the fixture executes actual fixed-file
`NewInitialPreparationDeployment` and `.Run`, then repeats through the loader.
It uses an explicitly scoped bootstrap ServiceAccount rather than the fixture
administrator token in product files. The only shared helper hunk makes staging
admission use the explicit `plan.Administrators`; defaults are preserved and the
fixture cleanup actor remains explicit. Fixture-admin role/provider setup stays
separate from product authority. No container image or intended activation binary
execution is claimed here.

The fixture checks exact seven-file names, immutable original UID/RV on replay,
absence of the actual issuer token and actual SQL maintenance username/password,
separate actual encrypt/decrypt purpose denials, still-gated original Pod, then
exact child revocation/replay after both Run owners joined. This last check is
provider cleanup evidence with no activation process; it is not full installed
retirement. Externally managed fixture S3 credentials are not least-privilege
backend credential qualification. The existing helper has a 120-second aggregate
budget; actual runtime/native result remains unmeasured until parent runs it.

## Integration / next continuation

All ten existing bases match current live hashes at freeze. The other fifteen
paths are new. `test/integration/initial_preparer_test.go` has the parent-approved
shared administrator-list hunk and should be merged as such if the base changes.
No shared SQL/generated files need merging. Parent should register ADR128 and the
new architecture document in its owned indexes, then run integrated contract/
architecture gates and actual provider qualification.

Continue with an explicit new immutable plan capability for kubelet writer
TokenRequest and guarded staging-to-final handover, preserving every old policy
shape. Current continuity policy correctly denies kubelet writer requests; the
new capability must allow only the qualified request intersected with the final
actual Pod UID guard. Join original CREATE owners, launch only original recorded
Pod UID once, observe actual activation/history and compose SQL/provider/probe
retirement plus irreversible private clearing. Unknown prior CREATE/provider
writes and expired issuer credentials keep uncertainty; no root/witness/claim
reset, renewed SQL interval or invented no-effect. Helm/runtime collection remains
disabled until those continuations qualify.
