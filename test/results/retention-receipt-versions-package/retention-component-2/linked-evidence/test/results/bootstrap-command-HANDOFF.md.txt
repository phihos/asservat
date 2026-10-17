# Frozen ADR131 bootstrap command/passive-history package

Payload is frozen in `changes/`; `manifest.json` has every original and payload SHA-256. `bootstrap-command.patch` is the equivalent unified patch. There are 28 paths: 11 modified originals and 17 new files. All 11 originals match the live schema50 tree at freeze; no new-path collisions. `dependencies.json` pins ten unchanged source dependencies. No SQL migration, generated SQL, chart runtime or public endpoint changes are included.

- Patch SHA-256: `0dc05200ce9368446f92fbd27fe9d8679c4c0666a0b38d321c1d0a8ea6dc9794`
- Manifest SHA-256: `e0d269df61e50a04bbd722923724418e4affb9ed526dba137e4449cb7d402fde`

## Scope and ordering

The four private commands are `initial-bootstrap`, `initial-bootstrap-schema`, `initial-bootstrap-prepare` and `initial-bootstrap-retire`. Fixed memory-backed projections separate the DDL-only phase from manager/provider preparation and trusted final manager closure. Concrete observation-only token refresh uses retained public pins, native identity/guard checks, original process cancellation, finite attempt limits and joined shutdown. It does not reopen setup authority or refresh the one-use target credential.

The installer selects persisted `asservat-initial-bootstrap/v2`, adds one fixed immutable history-only Secret, and rejects adoption of an existing v1 seed/guard. Its public seed locator is read using an exact PartialObjectMetadata request with no full-Secret fallback. The retained bundle contains only the original SELECT-only history login and public configuration/observation. Missing/unknown routing cannot fall back to the broad seed after either preparation root or target namespace exists.

Production ordering is explicit: original public prelude/guard → original private seed/manager → immutable public projection → original passive-history create claim → exact immutable history Secret → receipt and metadata locator in one seed CAS → phase projection files → later schema/preparation commands. The producer does not create the preparation root or target namespace. It writes no usable phase files before the history Secret and locator are acknowledged. Thus a crash before the locator leaves no command-produced route to those effects. A restart before that point can read the original seed only after independently establishing both effect roots are absent. A lost committed CREATE response recovers the same operation/object by exact lookup; a lost committed locator-CAS response immediately enters metadata/history-only replay. Neither case creates a replacement identity or repeats POST.

A genuinely unknown create whose object cannot be independently found remains the original spent pending claim, as required by the existing one-use creation contract. It is not described as successful or automatically repaired; this package adds no absent=closed rule or fresh attempt. A failed read or unsupported metadata negotiation never selects broad fallback.

The new private copy can be claimed/created only within the original manager setup interval. Receipt recovery for an already-created copy cannot renew that interval or perform another CREATE. The regression below demonstrates this temporal boundary.

Completed producer replay classifies protected handover and independent SQL history before broad seed/setup material. First actual retirement may then load the exact original manager closure material, use the separate trusted administrator, and require positive manager privilege/session/password closure. Already-retired replay uses metadata/history only and returns before broad seed or setup credentials. No seed field alone globally revokes credentials. Completed schema is only a no-effect DDL scheduling result; the independently integrated active-loader and final SQL incarnation checks remain mandatory.

## Actual checks

All commands ran with `GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp` against the live tree through the absolute `overlay.json`. Native fixtures were not run.

1. Meaningful before: `go test -overlay overlay-before-setup-bound.json ./internal/adapters/kubernetes -run '^TestInitialBootstrapPassiveNewCopyCannotOutliveOriginalSetup$' -count=1` exited **1** (handle 96260). It failed with `expired setup created another managed private copy`. The preceding source is retained in `before-original-setup-bound.go`; log `evidence/passive-setup-before.log`.
2. Corrected final: `go test -race -overlay overlay.json ./internal/adapters/kubernetes ./internal/bootstrap ./internal/contracts ./cmd/asservat ./test/integration -run '^TestInitialBootstrap(Passive|Observer|Schema|Projection)' -count=1` exited **0** (handle 91541): Kubernetes 18.418s, bootstrap 1.073s, integration 1.051s. Native integration source compiled and skipped without its fixture. Log `evidence/passive-final-race.log`. This includes lost CREATE/restart, lost locator-CAS reply, no broad seed reads, v1 adoption rejection, replaced UID, missing/unknown metadata, original setup expiry, observer cancellation/deadlines and fixed projection limits.
3. `go vet -overlay overlay.json` on the same five packages exited **0** (58728), `evidence/passive-final-vet.log`.
4. Earlier full `go test -race -overlay overlay.json ./internal/bootstrap -count=1` exited **0** (41895; 4.532s), `evidence/passive-bootstrap-full-race.log`. Those bootstrap sources are unchanged in the final payload.
5. Staged `check-specs.py` through `check-source-overlay.py` exited **0** (73820): 84 schemas, 49 MCP tools, 173 examples, 176 requirements/scenarios, 608 rejected invalid examples, 9,814 assertions. Log `evidence/passive-final-spec-check.log`. The wrapper redirects writes outside live and supplies staged reads only.
6. Staged Go architecture and design architecture gates exited **0**: 51 packages/268 internal edges; 1,201 positive/120 rejected design cases. Logs `evidence/passive-go-architecture.log`, `evidence/passive-architecture.log`. Subsequent changes add no package/import/design edges.
7. Offline canonical/reference checks exited **0**, `evidence/passive-schemas.log`: 84 schemas including five staged files, all local references resolve, installed date-time/URI/UUID format checking, locator positive/four negative cases.

`evidence/passive-final-exits.json` records final exit/handle values. Earlier failed diagnostics remain preserved: a fake API omitted server-provided TypeMeta, then a staged spec wrapper lacked Python's `case_sensitive` forwarding. Neither correction weakened production validation. The original file-size before/after evidence is also retained.

## Native selectors and limits

The new compiled-but-UNRUN actual API case is:

```sh
python scripts/test-context-storage.py --run '^TestInitialBootstrapPassiveWithRealKubernetes$'
```

It uses an owned actual API/prelude/guard, lost committed CREATE/restart, metadata-only replay, native locator immutability/history mutation denial and exact-UID cleanup. It intentionally supplies a **synthetic SQL manager receipt/OID** only to reach projection; it makes no SQL/provider call and establishes no activation or manager retirement. It does not need `--fleet`. The prior manager component qualification is a separate real SQL/OpenBao/fleet result with synthetic Kubernetes authority; neither result may be combined into an unrun command-chain claim.

Still unqualified/unimplemented: full fixed-command chain through the original product Pod and real passive producer/retire replay; actual long-phase observation-token replacement; official Helm runner; qualified final deletion of Asservat-managed SQL/provider Secret copies. The new v2 admission transitions require the native selector above; the earlier native v1 guard result does not qualify them. Local API assertions prove the adapter never receives broad Secret.data on passive replay, but do not substitute for the full completed command/SQL integration.

The managed private copies remain retained in this slice. Their future deletion must require actual reader/writer/credential closure, original UID/RV and occupied names that cannot be recreated, while preserving operator originals/upstream credential ownership. No runtime enablement is authorized by this package.

Next: parent guarded integration and selected native passive API test; then compose/qualify fixed commands with original schema-to-handover and manager retirement. Keep source-copy cleanup as a separate explicit bounded transition.
