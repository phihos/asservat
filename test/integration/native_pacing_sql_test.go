package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Owned-fixture measurements only. Counts are statements, not wire attempts;
// execution time excludes planning by default. No SQL text, parameters, role
// names or credentials enter the report. The snapshot reader's role is excluded.
type nativeSQLCounters struct {
	Calls, Rows, Statements int64
	ExecutionMilliseconds   float64
}

type nativeSQLSnapshot struct {
	StartedAt, FinishedAt, ResetAt time.Time
	Deallocations                  int64
	Roles                          map[uint32]nativeSQLCounters
}

// Install only after the real initial schema/role workflow has finished. An
// extension before bootstrap would violate its pristine-schema requirement.
// This owned fixture schema is inaccessible to all product roles; the existing
// fixture administrator alone reads numeric aggregates.
const nativePacingStatisticsSetup = `BEGIN;
CREATE SCHEMA fixture_native_statistics;
CREATE EXTENSION pg_stat_statements WITH SCHEMA fixture_native_statistics;
REVOKE ALL ON SCHEMA fixture_native_statistics FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA fixture_native_statistics FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA fixture_native_statistics FROM PUBLIC;
COMMIT;`

// Only the owned fixture administrator calls this once after completed
// bootstrap, strictly before its first measurement edge. Never rearm a phase.
const nativePacingStatisticsReset = `SELECT fixture_native_statistics.pg_stat_statements_reset()`

func nativePacingSQLSnapshot(ctx context.Context, admin *pgxpool.Pool) (nativeSQLSnapshot, error) {
	s := nativeSQLSnapshot{StartedAt: time.Now().UTC(), Roles: make(map[uint32]nativeSQLCounters)}
	if ctx == nil || ctx.Err() != nil || admin == nil {
		return s, errors.New("SQL measurement unavailable")
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	const info = `SELECT stats_reset,dealloc FROM fixture_native_statistics.pg_stat_statements_info`
	if err := admin.QueryRow(call, info).Scan(&s.ResetAt, &s.Deallocations); err != nil {
		return s, errors.New("SQL measurement extension unavailable")
	}
	// This fixture database belongs to one installation. Include every other
	// role, including background services, rather than guessing attribution
	// from query text. Numeric deltas and an idle baseline remain separate.
	rows, err := admin.Query(call, `SELECT userid,sum(calls)::bigint,sum(rows)::bigint,
 sum(total_exec_time)::double precision,count(*)::bigint
 FROM fixture_native_statistics.pg_stat_statements WHERE userid<>(current_user::regrole)::oid
 AND dbid=(SELECT oid FROM pg_database WHERE datname=current_database())
 GROUP BY userid ORDER BY userid LIMIT 513`)
	if err != nil {
		return s, errors.New("SQL counters unavailable")
	}
	for rows.Next() {
		var id uint32
		var c nativeSQLCounters
		if err := rows.Scan(&id, &c.Calls, &c.Rows, &c.ExecutionMilliseconds, &c.Statements); err != nil || !c.valid() || len(s.Roles) == 512 {
			rows.Close()
			return s, errors.New("SQL counter snapshot exceeds its finite shape")
		}
		s.Roles[id] = c
	}
	rows.Close()
	if rows.Err() != nil {
		return s, errors.New("SQL counter read failed")
	}
	var reset time.Time
	var deallocations int64
	if err := admin.QueryRow(call, info).Scan(&reset, &deallocations); err != nil || !reset.Equal(s.ResetAt) || deallocations != s.Deallocations {
		return s, errors.New("SQL counters reset or evicted during snapshot")
	}
	s.FinishedAt = time.Now().UTC()
	return s, nil
}

func (c nativeSQLCounters) valid() bool {
	return c.Calls >= 0 && c.Rows >= 0 && c.Statements >= 0 && c.ExecutionMilliseconds >= 0 && !math.IsInf(c.ExecutionMilliseconds, 0) && !math.IsNaN(c.ExecutionMilliseconds)
}

// Reject lost statistics instead of reporting a negative/zero invented cost.
// Snapshot edges span actual reads while background work continues; these are
// background-inclusive intervals, not an atomic trace of one HTTP request.
func nativePacingSQLDelta(before, after nativeSQLSnapshot) (map[uint32]nativeSQLCounters, error) {
	if before.ResetAt.IsZero() || after.ResetAt.IsZero() {
		return nil, errors.New("SQL snapshot reset timestamp missing")
	}
	if !before.ResetAt.Equal(after.ResetAt) {
		return nil, errors.New("SQL snapshot reset timestamp changed")
	}
	if before.Deallocations < 0 || after.Deallocations < 0 {
		return nil, errors.New("SQL snapshot deallocation count invalid")
	}
	if before.Deallocations != after.Deallocations {
		return nil, errors.New("SQL snapshot entries evicted")
	}
	if before.StartedAt.After(before.FinishedAt) || after.StartedAt.Before(before.FinishedAt) || after.StartedAt.After(after.FinishedAt) {
		return nil, errors.New("SQL snapshot time intervals overlap or moved backwards")
	}
	if len(before.Roles) > 512 || len(after.Roles) > 512 {
		return nil, errors.New("SQL snapshot role count exceeds bound")
	}
	for id := range before.Roles {
		if _, ok := after.Roles[id]; !ok {
			return nil, errors.New("SQL role counters disappeared")
		}
	}
	out := make(map[uint32]nativeSQLCounters, len(after.Roles))
	for id, current := range after.Roles {
		old := before.Roles[id]
		d := nativeSQLCounters{Calls: current.Calls - old.Calls, Rows: current.Rows - old.Rows, Statements: current.Statements - old.Statements, ExecutionMilliseconds: current.ExecutionMilliseconds - old.ExecutionMilliseconds}
		if !old.valid() || !current.valid() || !d.valid() {
			return nil, errors.New("SQL counters moved backwards")
		}
		out[id] = d
	}
	return out, nil
}

func TestNativePacingSQLDeltaRejectsLostOrResetStatistics(t *testing.T) {
	now := time.Now().UTC()
	before := nativeSQLSnapshot{StartedAt: now, FinishedAt: now.Add(time.Millisecond), ResetAt: now.Add(-time.Hour), Roles: map[uint32]nativeSQLCounters{42: {Calls: 3, Rows: 7, Statements: 2, ExecutionMilliseconds: 1.25}}}
	after := nativeSQLSnapshot{StartedAt: now.Add(time.Second), FinishedAt: now.Add(time.Second + time.Millisecond), ResetAt: before.ResetAt, Roles: map[uint32]nativeSQLCounters{42: {Calls: 5, Rows: 10, Statements: 2, ExecutionMilliseconds: 1.75}, 43: {Calls: 1, Rows: 1, Statements: 1, ExecutionMilliseconds: .1}}}
	d, err := nativePacingSQLDelta(before, after)
	if err != nil || d[42].Calls != 2 || d[42].Rows != 3 || d[42].ExecutionMilliseconds != .5 || d[43].Calls != 1 || before.Roles[42].Calls != 3 {
		t.Fatal("valid numeric deltas changed or mutated their baseline", d, err)
	}
	for _, mode := range []string{"reset", "eviction", "missing role", "backwards", "overlap", "nonfinite"} {
		t.Run(mode, func(t *testing.T) {
			bad := after
			bad.Roles = map[uint32]nativeSQLCounters{42: after.Roles[42]}
			switch mode {
			case "reset":
				bad.ResetAt = bad.ResetAt.Add(time.Second)
			case "eviction":
				bad.Deallocations++
			case "missing role":
				delete(bad.Roles, 42)
			case "backwards":
				bad.Roles[42] = nativeSQLCounters{Calls: 1}
			case "overlap":
				bad.StartedAt = before.StartedAt
			case "nonfinite":
				bad.Roles[42] = nativeSQLCounters{ExecutionMilliseconds: math.NaN()}
			}
			if _, err := nativePacingSQLDelta(before, bad); err == nil {
				t.Fatal("incomplete measurement accepted", mode)
			}
		})
	}
}

// Explicit owned SQL fixture only; ordinary integration runs do not enable
// this measurement extension. This verifies the real query, pgx types and
// exclusion of the fixture administrator, not installed runtime attribution.
func TestNativePacingSQLWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned numeric SQL measurement fixture not selected")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("SQL measurement fixture unavailable")
	}
	var f struct {
		Postgres            string
		NativeSQLStatistics bool
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("SQL measurement fixture is invalid")
	}
	if !f.NativeSQLStatistics {
		t.Skip("numeric SQL measurement is not enabled in this fixture")
	}
	if f.Postgres == "" {
		t.Fatal("owned SQL measurement fixture has no connection")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal("SQL measurement administrator unavailable")
	}
	// The standalone test owns a fresh measurement fixture. The installed
	// journey invokes the same setup only after completing actual bootstrap.
	if _, err := admin.Exec(ctx, nativePacingStatisticsSetup); err != nil {
		admin.Close()
		t.Fatal("private SQL statistics setup failed", err)
	}
	var reader, otherDatabase *pgxpool.Pool
	created := false
	defer func() {
		if otherDatabase != nil {
			otherDatabase.Close()
		}
		if reader != nil {
			reader.Close()
		}
		if created {
			cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
			defer end()
			if _, err := admin.Exec(cleanup, `DROP ROLE fixture_native_pacing_statistics`); err != nil {
				t.Error("owned measurement role cleanup failed")
			}
		}
		admin.Close()
	}()
	if _, err := admin.Exec(ctx, `CREATE ROLE fixture_native_pacing_statistics LOGIN PASSWORD 'synthetic-only'`); err != nil {
		t.Fatal("owned measurement role creation failed")
	}
	created = true
	var exposed bool
	if err := admin.QueryRow(ctx, `SELECT has_schema_privilege('fixture_native_pacing_statistics','fixture_native_statistics','USAGE')
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='fixture_native_statistics' AND has_table_privilege('fixture_native_pacing_statistics',c.oid,'SELECT'))
 OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='fixture_native_statistics' AND has_function_privilege('fixture_native_pacing_statistics',p.oid,'EXECUTE'))`).Scan(&exposed); err != nil || exposed {
		t.Fatal("fixture statistics exposed to an ordinary runtime login", err)
	}
	var role uint32
	if err := admin.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname='fixture_native_pacing_statistics'`).Scan(&role); err != nil {
		t.Fatal("measurement role identity unavailable")
	}
	// A saturated preloaded library survives extension creation. Synthetic SET
	// utilities exercise default-capacity eviction without adding relations or
	// changing statistics capacity. This is a deliberate qualification fault,
	// not proof of which condition ended an earlier installed run.
	var maximum int
	if err := admin.QueryRow(ctx, `SHOW pg_stat_statements.max`).Scan(&maximum); err != nil || maximum != 5000 {
		t.Fatal("statistics capacity differs from the pinned default", maximum, err)
	}
	flood := func(ordinal int) {
		t.Helper()
		var statements strings.Builder
		for i := 0; i <= maximum; i++ {
			fmt.Fprintf(&statements, "SET application_name = 'fixture_bootstrap_%d_%d';\n", ordinal, i)
		}
		if _, err := admin.Exec(ctx, statements.String()); err != nil {
			t.Fatal("synthetic bootstrap utility batch failed", err)
		}
	}
	initial, err := nativePacingSQLSnapshot(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	flood(1)
	inherited, err := nativePacingSQLSnapshot(ctx, admin)
	if err != nil || inherited.Deallocations <= initial.Deallocations {
		t.Fatal("utility prefill did not reproduce inherited saturation", initial.Deallocations, inherited.Deallocations, err)
	}
	flood(2)
	evicted, err := nativePacingSQLSnapshot(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nativePacingSQLDelta(inherited, evicted); err == nil || err.Error() != "SQL snapshot entries evicted" {
		t.Fatal("eviction inside measured interval was accepted", inherited.Deallocations, evicted.Deallocations, err)
	}
	// This reset starts the first positive baseline only after the entire
	// synthetic bootstrap. Lost preflight coverage was refused above, not
	// represented as zero or retried within one measurement interval.
	if _, err := admin.Exec(ctx, nativePacingStatisticsReset); err != nil {
		t.Fatal("pre-baseline statistics reset failed", err)
	}
	before, err := nativePacingSQLSnapshot(ctx, admin)
	if err != nil || before.Deallocations != 0 || !before.ResetAt.After(inherited.ResetAt) {
		t.Fatal("first positive baseline retained pre-bootstrap statistics", before.Deallocations, err)
	}
	t.Logf("default entries=%d inherited deallocations=%d then midphase=%d; first positive baseline reset deallocations=%d", maximum, inherited.Deallocations, evicted.Deallocations, before.Deallocations)
	cfg, err := pgxpool.ParseConfig(f.Postgres)
	if err != nil {
		t.Fatal("SQL fixture connection configuration invalid")
	}
	cfg.ConnConfig.User = "fixture_native_pacing_statistics"
	cfg.ConnConfig.Password = "synthetic-only"
	cfg.MaxConns = 1
	reader, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("measurement role connection failed")
	}
	for range 2 {
		var count int
		if err := reader.QueryRow(ctx, `SELECT count(*) FROM generate_series(1,3)`).Scan(&count); err != nil || count != 3 {
			t.Fatal("synthetic measured statement failed")
		}
	}
	// The same login can have instance-wide statistics in another database.
	// Its statement must not inflate this database's measured workflow.
	if cfg.ConnConfig.Database != "postgres" {
		other := cfg.Copy()
		other.ConnConfig.Database = "postgres"
		otherDatabase, err = pgxpool.NewWithConfig(ctx, other)
		if err != nil {
			t.Fatal("second fixture database connection failed")
		}
		var value int
		if err := otherDatabase.QueryRow(ctx, `SELECT 7`).Scan(&value); err != nil || value != 7 {
			t.Fatal("second database synthetic statement failed")
		}
	}
	after, err := nativePacingSQLSnapshot(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := nativePacingSQLDelta(before, after)
	if err != nil || delta[role].Calls != 2 || delta[role].Rows != 2 || delta[role].Statements != 1 {
		t.Fatal("actual SQL counters did not isolate two role statements", err, delta)
	}
	var administrator uint32
	if err := admin.QueryRow(ctx, `SELECT (current_user::regrole)::oid`).Scan(&administrator); err != nil {
		t.Fatal("fixture administrator identity unavailable")
	}
	if _, ok := delta[administrator]; ok {
		t.Fatal("fixture SQL snapshot counted its own reader")
	}
	if _, err := admin.Exec(ctx, nativePacingStatisticsReset); err != nil {
		t.Fatal(err)
	}
	reset, err := nativePacingSQLSnapshot(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nativePacingSQLDelta(after, reset); err == nil || err.Error() != "SQL snapshot reset timestamp changed" {
		t.Fatal("midphase reset did not refuse coverage", err)
	}
	t.Log("actual PostgreSQL numeric role counters isolate two statements; no query text or parameters exported")
}
