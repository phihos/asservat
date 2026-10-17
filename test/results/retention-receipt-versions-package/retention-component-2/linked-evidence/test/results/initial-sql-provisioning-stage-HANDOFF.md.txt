# ADR123 original SQL preparation continuation

Frozen isolated payload: 18 paths in `changes/`, exact live base and new hashes
in `manifest.json`, unified `initial-sql-provisioning.patch`. No live files,
SQL migration/generated models, modules, catalog/index/progress, public transport
or Helm templates were edited. Parent owns integration and external qualification.

## Concrete behavior

The actual private `initial-prepare` deployment has an optional protected
`sqlMaterial` reference. Before irreversible setup it validates that exact immutable
bootstrap material, fixed SQL maintenance projection and supported TLS/CREATEROLE
profile. After original public inputs and positive probe issuance it composes the
existing native credential binder, one target Secret persistence and actual
InitialSQLRoles.Provision. Original passwords, actual Pod/startup digest and
fifteen-minute interval remain immutable; maintenance authority stays outside the
activation Pod. Every SQL effect retains the original current Kubernetes lease
through final checks. No token or secret payload/hash enters the public journal.

`ReadPreparedInputs` is a read-only current nine-object/Pod observation with
independent returned slices. The private document gains only an optional closed
SQL intent and immutable Secret reference. One acknowledged CAS admits one CREATE;
unknown/replayed claims get GET-only exact-content resolution, not another CREATE.
The original state is not reset after expiry or failure. New DTO fields are
omitempty; absent fields preserve legacy encoded shapes/policy bytes.

This adds one bootstrap material Secret supplied by the protected input and one
product-created fixed `<credentials>-sql` Secret; no extra public journal entry or
arbitrary resource engine. SQLMaterial selection is frozen by the existing
original credential binding; it does not rewrite the declared root plan.

## Measured checks

All executed with TMPDIR=/home/phil/.cache/asservat-build/tmp, GOMAXPROCS=2, -p 2,
and this stage's overlay. No external fixtures were started.

- Focused race selection `TestInitial(SQLPreparation|SQLMaterialPreflight|PreparedInput|CredentialStateNativeGuard)`:
  Kubernetes36.853s, bootstrap/contracts compiled; exit0 (`focused-race.log`).
- Wider race `go test -vet=off -race -p 2 -overlay=overlay.json
  ./internal/adapters/kubernetes ./internal/bootstrap ./internal/contracts
  ./test/integration -run '^TestInitial' -count=1`: Kubernetes148.708s,
  bootstrap1.115s, contracts1.024s, integration1.050s; exit0 (`initial-race.log`).
  External fixture cases skip without their explicit environment; this is not
  native qualification. Existing Initial* policy golden checks were included.
- Final new integration source compile/skip: exact TestInitialPreparationSQLWithRealKubernetesPostgres,
  race1.049s, exit0 (`native-source-final.log`).
- `go vet -p 2 -overlay=overlay.json` on those four packages: exit0 (`vet.log`).
- Repository spec-venv JSON Schema validation with FormatChecker: four private
  states and fourteen rejected private shapes; explicit SQL material clause and
  four rejected prerequisite/reference shapes; exit0 (`schema-check-final.log`).
  Initial system-python attempt lacked jsonschema; the successful rerun uses the
  repository environment, not a weakened fallback.

Tests cover current input replacement/expiry, material errors before effects,
concurrent persistence, lost claims/creates/receipts, exact UID/content recovery,
changed original material and elapsed original credential interval. The wider
legacy tests also cover original binding CAS loser/lost reply and unchanged timing.

## Parent native run

Run the context fixture with exact selector:
`^TestInitialPreparationSQLWithRealKubernetesPostgres$`
against its own fresh migrated SQL state. No extra initial-installation env flag
is needed. The new file is isolated; no shared fixture hook or script edit is
included. It composes actual native public inputs/probe/binder/Secret plus scoped
SQL roles, verifies unchanged role verifiers/expiry on replay and irreversible
role retirement, and requires a still-gated Pod/no activation.

Trusted fixture inputs: original private/material roots, API audience selection,
SQL maintenance grants and TLS bridge. Unused public provider endpoints are
explicitly synthetic. It is component composition, not a deployed initial-prepare
command or provider/handover qualification. Runtime is expected to fit the existing
120s helper budget, but no actual native time is claimed. No authority deadline
was increased.

## Remaining required continuation

Actual scoped OpenBao issuance/revocation and qualified object-store credentials;
immutable final target provider projection; independent final native guard proof
and one-use staging handover/ungating; historical activation reconciliation;
joined writers, credential retirement and private in-place clearing. SQL role
retirement primitives exist/tested, but this command does not automatically retire
or erase setup state. Unknown provider writes and expired original credentials
must retain uncertainty, never reset witness/root or mint a new interval.

The command still reports a preparation checkpoint, not installed/runtime readiness.
Public acquisition/Helm runtime remain disabled. Parent should add the new architecture
file to its owned indexes and record actual native results after qualification.
