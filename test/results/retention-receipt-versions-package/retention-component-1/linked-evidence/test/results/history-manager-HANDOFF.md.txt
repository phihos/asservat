# Pinned original history manager correction

Frozen correction, thirteen scoped existing paths, no migration/dependency/public runtime enablement. Every original base hash matches the current repository. Parent owns the two actual handover fixture edits and must include its pre-declaration manager pin before the native Kind run.

## Measured defect and correction

Parent-owned selected PostgreSQL run confirmed exact creator grant before_count=1 / before_exact=true and after_count=1 / after_exact=true after the non-superuser creator's REVOKE. Production then failed history-role-privileges, sqlstate=none, expired=false. Native result terminal1, one diagnostic subcase passed, 1,143 source hashes unchanged, cleanup empty. This was the platform mismatch, not an expiry or permission fallback.

The explicit handover plan now requires `HistoryManager *contracts.InitialSQLHistoryManager` (`historyManager:{name,oid}`). The original protected plan/root digest pins this public identity before effects. All old non-handover omitted fields remain unchanged; unresolved new-profile roots lacking the pin require separate reconciliation. No automatic replacement/pin discovery.

The loader checks the actual original non-superuser maintenance identity before Declare, and ProvisionHistory repeats it under its bounded original transaction. Completed passive startup still returns before maintenance/provider material is opened. Creation and current passive verification allow exactly one incoming grant from PostgreSQL bootstrap-superuser OID10 to the independently pinned original manager: ADMIN true, INHERIT false, SET false. No outgoing history membership or extra incoming grant/privilege is accepted. Manager identity must remain unchanged; disabling its LOGIN/CREATEROLE does not prevent passive reads. The trusted manager can deliberately re-grant access; false SET/INHERIT flags are not a security boundary against trusted SQL administration.

API signatures now append contracts.InitialSQLHistoryManager to ProvisionHistory and CheckInitialSQLHistoryRole. The fixed history credential bytes/file remain unchanged. New CheckHistoryManager is read-only preflight, never effect authority.

## Checks actually run

- Focused Go races: `TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -p 2 -race -overlay <stage>/overlay.json ./internal/adapters/postgres ./internal/adapters/kubernetes ./internal/bootstrap ./test/integration -run 'TestInitial(History|PreparationHistoryManager|PreparationHandoverClosedProfiles|SQLHistoryDiagnostic)'`: terminal0; PostgreSQL/Kubernetes tests passed, bootstrap/integration compile only. See race.log and race-final.log.
- Affected contracts/PostgreSQL/Kubernetes/bootstrap/integration vet with the same overlay, `go vet -p 2`: terminal0, vet-final.log.
- `spec-venv/bin/python <stage>/check-schema.py`: terminal0; complete legacy and handover plan schema clauses, eleven invalid identity/capability cases, Draft202012+FormatChecker and offline references. See schema.log.
- No external fixture or full repository gate run by this agent. Parent native selected test remains `^TestInitialSQLHistoryRoleWithRealPostgres$` on a fresh database. Normal full custody regex excludes it.

## Native regression scope awaiting parent run

Original creator CREATE/REVOKE catalogue behavior remains recorded and transactionally rolled back. Corrected original history creation/replay; independent manager preflight/pin negatives before history effects; exact SELECT-only read and denied writes; INHERIT/SET/ADMIN changes, missing original grant, extra incoming/outgoing grants, additional manager-attributed grant, extra UPDATE privilege, replacement manager name/OID, and passive reads after manager LOGIN/CREATEROLE retirement. Fixture administrative changes are explicit and restored. Product code never gains those fixture privileges. Original five-second operation bounds and setup lifetime remain unchanged.

Next: qualify selected real PostgreSQL correction, then parent actual-loader handover/image/cleanup/passive replay. Continue bounded exact-409 recovery separately; no uncertain request may become a retry or new interval.
