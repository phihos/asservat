# Initial handover loader preflight correction

Three frozen paths; all base hashes match integrated ADR129. No live source edits, no native fixture by this agent. Parent owns the standalone native admission fixture correction separately.

The actual fresh-database native run failed in the loader's sql-material phase before Run. ADR129 compared its fourth history password using ReadInitialSQLMaterial, whose deliberate original-root binding requires a declared journal. Earlier pre-seeded fixtures masked this ordering error. The correction adds CheckInitialSQLHistoryPassword: a current exact pinned immutable-material preflight that returns no credentials, root binding or provisioning authority, and checks the fourth canonical password is distinct from all three setup passwords. The loader selects this preflight instead of the bound read. ReadInitialSQLMaterial and all issuance requirements remain unchanged.

Other constructor checks were inspected: ReadInitialProviderMaterial intentionally supports pre-declaration and reads no journal/private state; provider Check is observation only; SQL maintenance constructor qualifies its actual role without journal dependency; initial history pool construction is lazy. No second pre-declaration root dependency was found.

Focused race command (external TMPDIR, GOMAXPROCS=2, -p 2, overlay.json): go test -race ./internal/adapters/kubernetes ./internal/bootstrap -run 'TestInitial(SQLMaterial|SQLHistoryPreflight|Preparer)'. Terminal exit0; Kubernetes27.414s/bootstrap1.056s. Cases include root absent/no mutation, duplicate with each setup password, malformed history password, changed source UID and bound issuance read still denied. Affected Kubernetes/bootstrap vet also exit0. Logs race.log/vet.log retained. The actual earlier native failure is parent-owned initial-handover-first report; no after-fix native result is claimed.

Next: parent integrates these three paths plus its independent native admission fixture fix, reruns the same actual fresh-database handover qualification. Separate definite409 continuation remains staged design only and is not part of this correction.
