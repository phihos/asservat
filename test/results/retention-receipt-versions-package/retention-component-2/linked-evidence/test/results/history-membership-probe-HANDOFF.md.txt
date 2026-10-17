# Exact creator membership diagnostic

One isolated native fixture edit; no production behavior changes. Frozen after integration compile terminal0; no test selected/external lab run here. Command: TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -p 2 -overlay ./overlay.json ./test/integration -run '^$' (run from live repository with absolute overlay path). See compile.log.

Parent selected native test remains ^TestInitialSQLHistoryRoleWithRealPostgres$ on a fresh owned database. New subcase uses the original non-superuser maintenance login to CREATE a synthetic NOLOGIN role, inspect exact original creator membership, perform the same REVOKE, inspect again, and ROLLBACK. Logs contain only counts/booleans. It expects the documented bootstrap-superuser grant to remain; the later production history-role path is still expected to fail pending the actual observation.

The source-backed hypothesis is not yet native-confirmed. No manager pin/grant correction is included. No credentials, names, queries, catalogue rows or provider errors are printed. The test role is transactionally rolled back, never permanently adopted.
