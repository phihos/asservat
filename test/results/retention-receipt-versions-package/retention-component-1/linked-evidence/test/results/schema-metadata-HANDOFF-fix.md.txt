# ADR130 PostgreSQL18 metadata constraint correction

Three-path frozen payload selected by fix-manifest.json; all bases verified against integrated diagnostic live source. Manifest SHA256 cacb234f1676892c9e78da8c44b41e8e52ac79e443d30be876fe0cf2c496284d. Patch SHA256 fb846e06661ed0261c3293a4d0a147a3b99632910a7eca40d6ff00424ffd1328. Do not copy unrelated unchanged files under changes/.

Parent's actual failing-before native diagnostic (61496, terminal1, source1157 unchanged, cleanup[]) confirms phase=inspection, version0, head0, claims1, root_reads1, primary1/not_null4/other0. The original predicate incorrectly expected one total pg_constraint row. PostgreSQL18 records NOT NULL in pg_constraint: https://www.postgresql.org/docs/18/catalog-pg-constraint.html. Goose3.28.0 creates id plus version_id/is_applied/tstamp all NOT NULL, matching the measured five rows.

The production correction requires exactly that shape: one immediate PK on id, four unique single-column NOT NULL keys1..4, all enforced/validated/local, no foreign kind/deferral/inheritance. Existing owner, ordinary persistent table, no RLS/user triggers, exact four column types/nullability/identity/default and strict version0/ordered-up history checks remain. No migration or identity/deadline/recovery rule changed.

The native fixture adds actual SQL hostile shape tests: extra CHECK, missing NOT NULL and PK on version_id. Each must deny completed replay without repair; restoring the original shape in the fixture must make read-only replay succeed. Existing bounded phase/head diagnostics and abort-after-prerequisite-failure remain intact. These actual SQL cases are not run by the agent; parent owns the next selected native fixture.

Actual staged checks: GOMAXPROCS2/TMPDIR dedicated build cache, go test -race -p2 -overlay=overlay-fix.json ./internal/adapters/postgres ./test/integration -run '^TestInitialSchema' terminal0 (Postgres1.070s/integration source compile+skip1.050s, race-fix.log). go vet same two packages/overlay terminal0 (vet-fix.log). No external labs or live edits. Production/source payload is now frozen; no active build remains.
