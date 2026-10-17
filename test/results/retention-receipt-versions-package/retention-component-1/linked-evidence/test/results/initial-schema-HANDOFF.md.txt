# ADR130 frozen implementation handoff

Payload: `changes/`, 23 paths, schema remains 48. No live edits or external fixture runs. `manifest.json` SHA256 `036037ce01c183f56ee590b35b4f4f9be51265dc82056193c5ae35cea3feec6b`; `payload.patch` SHA256 `55b40586897e61ab85c31aae74e619d35b994b4b11bdc51fd60f7146497624b8`. All existing bases were compared byte-for-byte against live immediately before freeze. New-path absence was checked. Sources under changes are frozen.

## Scope and contracts

- Private `initial-schema` CLI and fixed mounted loader, separate DDL credential. Uses actual Kubernetes preparation-root guard/admin observations, original same-root CAS claim/completion and exact embedded migration bundle. No new migration/control table, Down, arbitrary directory or SQL, recovery activation, runtime enablement or Helm deployment.
- Explicit `schemaInitialization: asservat-initial-schema/v1` requires the existing handover profile. Old omitted fields preserve bytes. Root.Schema binds original attempt, bundle/head, database OID/postmaster, DDL identity, separately pinned manager, and original claim/completion. Declaration cannot start before completion; subsequent root mutations preserve the record.
- Transactional upward Goose Provider.ApplyVersion, strict version0/ordered-up history and exact pristine table inventory. Metadata creation belongs to the original protected transaction, not Goose retry. Busy session lock refuses takeover. Unknown replies stop and retain the original prefix/instance/attempt.
- Every root read, claim and completion narrows the original deadline, including cancellation of a context already passed into Goose before its lock callback. Detached context only releases advisory lock. No authority extension.
- Installs only the existing preparation/audit/activation grant union WITH GRANT OPTION on an independently pinned active setup manager. No creation/reset/password mutation. Active manager checks reject child-role membership; after schema completion, interrupted preparation uses separate VerifyInitialSchemaCompletion(ctx, managerConfig, root), which is read-only and permits legitimate later creator ADMIN membership and operational rows. Fully completed bootstrap must branch to passive historical replay before active setup constructors; ADR131 owns this composition and actual manager provisioning/retirement.

## Actual verification

All Go commands used GOMAXPROCS=2, -p 2, TMPDIR=/home/phil/.cache/asservat-build/tmp, -modfile=<stage>/changes/go.mod and -overlay=<stage>/overlay.json.

- Initial four-package compile: exit 0 (`compile-first.log`).
- First selected race: exit 1 because an existing migration contains an optional Down source section (`race-first.log`). Corrected bundle inspection permits that existing inert source section while the runner never exposes Down. Unsupported transaction/annotation controls remain rejected.
- Controlled before-fix deadline regression: exit 1, `shorter root deadline discarded` (`before-deadline.log`). Production fix retains/narrows the context through root reads, claims, completion and already-passed Goose calls.
- `go test -race ... ./internal/adapters/postgres ./internal/adapters/kubernetes ./internal/bootstrap ./test/integration -run '^(TestInitialSchema|TestInitialPrepar)'`: exit 0 (`race-final.log`); Kubernetes 94.500s, PostgreSQL 1.070s, bootstrap 1.053s, integration compile/skip 1.051s. Integration tests without owned service environment skipped, not native passes.
- Additional root-CAS preservation test first failed because its synthetic fixture omitted required provider/service input (`race-schema-cas.log`). Fixture now supplies the same complete closed inputs used by existing tests. `go test -race ... ./internal/adapters/kubernetes -run '^TestInitialSchema'`: exit 0, 1.386s (`race-schema-cas-after.log`). No production check was relaxed.
- `go vet ... ./internal/adapters/postgres ./internal/adapters/kubernetes ./internal/bootstrap ./cmd/asservat ./migrations`: exit 0 (`vet-final.log`).
- Stage schema checker using spec-venv Python: exit 0, 16 valid/invalid capability/claim/completion cases, offline canonical references and date-time FormatChecker (`schema-final.log`). System Python lacks jsonschema; it was not counted as a passed gate.
- Stage import-architecture wrapper executes the repository checker with staged catalog + Go overlay: exit 0, 51 packages/264 edges (`go-architecture.log`). Parent still runs full integrated gates.
- Runtime `go list -deps ./cmd/asservat`: exit 0 (`runtime-deps.log`); Goose library/database/lock/parser packages only, no Goose command or unrelated SQLite/MySQL/ClickHouse driver package.

## Dependency changes

New direct github.com/pressly/goose/v3 v3.28.0, the existing pinned tool version. Runtime helper additions: mfridman/interpolate v0.0.2, sethvargo/go-retry v0.4.0, uber/multierr v1.11.0. MVS upgrades required by that graph: go-logr/logr 1.4.3→1.4.4; segmentio/asm 1.1.3→1.2.1; protobuf prerelease v1.36.12-0.20260120151049-f2248ac996af→stable v1.36.12. pgx5.11.0 and other existing direct pins unchanged. Exact diffs retained as go.mod.diff/go.sum.diff. Parent owns shared technology/dependency prose corrections at integration.

## Native qualification pending

1. Selected ordinary custody fixture `^TestInitialSchemaWithRealPostgres$` creates its own isolated fresh database, avoiding shared fixture mutation. Actual Goose execution/prefix resume/root-ack loss/exact grants/foreign history/lock and read-only completed replay remain unrun. Synthetic root is explicitly not native authority. The finite test context is 100s; no special long fixed waits.
2. Parent owns the separate fresh-database schema→existing handover context mode, compiled against the earlier immutable 23-file review snapshot. It invokes the real mounted schema loader before preparation/actual activation Pod/audit/cleanup/passive reopening. It must verify Root.Schema identity survived all stages. It does not establish in-Pod initial-schema CLI execution unless actually run there.
3. Parent owns context/custody migration-Go hash additions; this package changes identity/permission source inventories only. Parent merges catalog package-root addition and new module files before native image build. Embedded source head is48: subsequent49/50 integration changes the bundle and must retain head matching and reject resume of an older bound bundle rather than silently upgrading the attempt.

## Remaining work

Native results, actual trusted manager/input producer (ADR131), DDL credential removal by the owning trusted installer, then deployed installation/runtime packaging. Supplied DDL credentials remain externally owned; this facet does not claim their revocation. Restart/restore reconciliation remains separate. No public capture/disclosure or runtime readiness follows from schema completion.
