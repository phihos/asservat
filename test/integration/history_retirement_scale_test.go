package integration

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type historyScaleQuery struct {
	*pgx.Conn
	sql  string
	args []any
}

func (q *historyScaleQuery) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.sql = sql
	q.args = args
	return q.Conn.Query(ctx, sql, args...)
}

// Independent reference retained from the pre-optimization candidate query.
// Effect authority is separately checked; this test compares only due hints.
const historyRetirementReferenceSQL = `SELECT h.capture_id,a.cluster_id,h.state FROM capture_history_parameter h JOIN custody_attempt a ON a.id=h.attempt_id
WHERE h.root_id=$1 AND ($2::uuid IS NULL OR h.capture_id>$2::uuid) AND (((h.visible OR h.state='deleted') AND h.summary_expires_at<=$3::timestamptz) OR (h.state IN('reserved','available','deleting') AND (a.effective_expires_at<=$3::timestamptz OR NOT h.visible OR (h.state='reserved' AND a.write_until<=$3::timestamptz))))
ORDER BY h.capture_id LIMIT 16`

// Query-cost evidence only: TEMP synthetic rows on one owned session shadow
// production names. No accepted capture, guard, ciphertext, quota or authority
// row is created or bypassed. Minimal columns understate real row-width costs.
func TestCustodyHistoryRetirementQueryScaleWithRealSQL(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run owned custody fixture")
	}
	var fixture struct{ Postgres string }
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &fixture) != nil {
		clear(raw)
		t.Fatal("owned SQL fixture missing", err)
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, fixture.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			t.Fatal("synthetic query setup", err)
		}
	}
	for _, sql := range []string{
		`CREATE TEMP TABLE capture_history_parameter(root_id uuid NOT NULL,capture_id uuid PRIMARY KEY,attempt_id uuid NOT NULL UNIQUE,state text NOT NULL,visible boolean NOT NULL,summary_expires_at timestamptz NOT NULL)`,
		`CREATE INDEX synthetic_history_summary ON capture_history_parameter(root_id,summary_expires_at,capture_id)`,
		`CREATE TEMP TABLE custody_attempt(id uuid PRIMARY KEY,cluster_id uuid NOT NULL,state text NOT NULL,effective_expires_at timestamptz NOT NULL,write_until timestamptz NOT NULL)`,
		`CREATE INDEX synthetic_custody_due ON custody_attempt(effective_expires_at,id) WHERE state<>'deleted'`,
		`INSERT INTO custody_attempt SELECT md5('synthetic-attempt-'||n)::uuid,'10000000-0000-4000-8000-000000000004','stored_unpublished',clock_timestamp()+interval '1 day',clock_timestamp()+interval '30 seconds' FROM generate_series(1,100000)n`,
		`INSERT INTO capture_history_parameter SELECT '10000000-0000-4000-8000-000000000001',md5('synthetic-capture-'||n)::uuid,md5('synthetic-attempt-'||n)::uuid,'available',true,clock_timestamp()+interval '1 day' FROM generate_series(1,100000)n`,
		`ANALYZE capture_history_parameter`, `ANALYZE custody_attempt`,
	} {
		exec(sql)
	}
	var root pgtype.UUID
	_ = root.Scan("10000000-0000-4000-8000-000000000001")
	args := custodydb.ListHistoryRetirementCandidatesParams{RootID: root, Through: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}}
	query := &historyScaleQuery{Conn: conn}
	useAdapter := false
	actual := func() []custodydb.ListHistoryRetirementCandidatesRow {
		t.Helper()
		var rows []custodydb.ListHistoryRetirementCandidatesRow
		var err error
		if useAdapter {
			rows, err = postgres.ReadHistoryRetirementHints(ctx, query, args)
		} else {
			rows, err = custodydb.New(query).ListHistoryRetirementCandidates(ctx, args)
		}
		if err != nil {
			t.Fatal("generated candidate query", err)
		}
		return rows
	}
	reference := func() []custodydb.ListHistoryRetirementCandidatesRow {
		t.Helper()
		rows, err := conn.Query(ctx, historyRetirementReferenceSQL, args.RootID, args.AfterID, args.Through)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []custodydb.ListHistoryRetirementCandidatesRow
		for rows.Next() {
			var row custodydb.ListHistoryRetirementCandidatesRow
			if err = rows.Scan(&row.CaptureID, &row.ClusterID, &row.State); err != nil {
				t.Fatal(err)
			}
			out = append(out, row)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if len(actual()) != 0 {
		t.Fatal("idle generated query returned candidates")
	}
	var explain func(string, string, []any) map[string]any
	explain = func(name, sql string, params []any) map[string]any {
		t.Helper()
		var plan json.RawMessage
		if err = conn.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+sql, params...).Scan(&plan); err != nil {
			t.Fatal("candidate explain", err)
		}
		var result []struct {
			ExecutionTime float64 `json:"Execution Time"`
			Plan          map[string]any
		}
		if json.Unmarshal(plan, &result) != nil || len(result) != 1 {
			t.Fatal("invalid explain")
		}
		t.Logf("history query %s: syntheticRows=100000 explainExecutionMS=%.3f plan=%s", name, result[0].ExecutionTime, plan)
		return result[0].Plan
	}
	fullScans := func(plan map[string]any) int {
		total := 0
		var visit func(map[string]any)
		visit = func(node map[string]any) {
			if slices.Contains([]any{"Seq Scan", "Index Scan", "Index Only Scan", "Bitmap Heap Scan"}, node["Node Type"]) {
				rows, _ := node["Actual Rows"].(float64)
				removed, _ := node["Rows Removed by Filter"].(float64)
				loops, _ := node["Actual Loops"].(float64)
				if (rows+removed)*loops >= 100000 || loops >= 100000 {
					total++
				}
			}
			if children, ok := node["Plans"].([]any); ok {
				for _, child := range children {
					visit(child.(map[string]any))
				}
			}
		}
		visit(plan)
		return total
	}
	explain("old-idle", historyRetirementReferenceSQL, []any{args.RootID, args.AfterID, args.Through})
	before := explain("union-idle-without-active-indexes", query.sql, query.args)
	// Measure the exact reservation->available->evicted index transitions on
	// 1000 TEMP rows. This is warm synthetic SQL cost, not a workflow benchmark.
	churn := func(name string, start int) {
		t.Helper()
		began := time.Now()
		exec(`INSERT INTO custody_attempt SELECT md5('synthetic-attempt-'||n)::uuid,'10000000-0000-4000-8000-000000000004','reserved',clock_timestamp()+interval '1 day',clock_timestamp()+interval '30 seconds' FROM generate_series($1::int,$1::int+999)n`, start)
		custodyInserted := time.Since(began)
		began = time.Now()
		exec(`INSERT INTO capture_history_parameter SELECT '10000000-0000-4000-8000-000000000001',md5('synthetic-capture-'||n)::uuid,md5('synthetic-attempt-'||n)::uuid,'reserved',true,clock_timestamp()+interval '1 day' FROM generate_series($1::int,$1::int+999)n`, start)
		inserted := time.Since(began)
		began = time.Now()
		exec(`UPDATE capture_history_parameter SET state='available' WHERE capture_id IN(SELECT md5('synthetic-capture-'||n)::uuid FROM generate_series($1::int,$1::int+999)n)`, start)
		available := time.Since(began)
		began = time.Now()
		exec(`UPDATE capture_history_parameter SET visible=false WHERE capture_id IN(SELECT md5('synthetic-capture-'||n)::uuid FROM generate_series($1::int,$1::int+999)n)`, start)
		hidden := time.Since(began)
		t.Logf("history index churn %s: rows=1000 custodyInsert=%s historyInsert=%s availableUpdate=%s hiddenUpdate=%s (TEMP minimal rows/no WAL; not production workflow latency)", name, custodyInserted, inserted, available, hidden)
		exec(`DELETE FROM capture_history_parameter WHERE capture_id IN(SELECT md5('synthetic-capture-'||n)::uuid FROM generate_series($1::int,$1::int+999)n)`, start)
		exec(`DELETE FROM custody_attempt WHERE id IN(SELECT md5('synthetic-attempt-'||n)::uuid FROM generate_series($1::int,$1::int+999)n)`, start)
	}
	churn("without-active-indexes", 100001)
	// The plans must demonstrate the need before these proposed active-only
	// indexes are accepted into migration101; no model/state change is needed.
	if fullScans(before) == 0 {
		t.Fatal("active-index proposal has no demonstrated scan benefit; remove unnecessary indexes")
	}
	exec(`CREATE INDEX synthetic_history_hidden ON capture_history_parameter(root_id,capture_id) WHERE NOT visible AND state IN('reserved','available','deleting')`)
	exec(`CREATE INDEX synthetic_history_reserved ON capture_history_parameter(root_id,capture_id) INCLUDE(attempt_id) WHERE state='reserved'`)
	exec(`ANALYZE capture_history_parameter`)
	exec(`ANALYZE custody_attempt`)
	after := explain("union-idle-with-active-indexes", query.sql, query.args)
	if fullScans(after) != 0 {
		t.Fatal("indexed idle hint still scans full history/custody")
	}
	for n := 0; n < 8; n++ {
		began := time.Now()
		if len(actual()) != 0 {
			t.Fatal("idle prepared candidate query changed")
		}
		t.Logf("actual pgx idle execution%d elapsed=%s", n, time.Since(began))
	}
	var genericPlans, customPlans int64
	if err = conn.QueryRow(ctx, `SELECT COALESCE(sum(generic_plans),0)::bigint,COALESCE(sum(custom_plans),0)::bigint FROM pg_prepared_statements WHERE statement=$1`, query.sql).Scan(&genericPlans, &customPlans); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual pgx prepared candidate decisions after repeated idle reads: genericPlans=%d customPlans=%d", genericPlans, customPlans)
	var preparedName string
	if err = conn.QueryRow(ctx, `SELECT name FROM pg_prepared_statements WHERE statement=$1 LIMIT 1`, query.sql).Scan(&preparedName); err != nil {
		t.Fatal(err)
	}
	// Values are closed fixture UUID/time types; quote the server-owned
	// statement identifier. This EXPLAIN executes the actual cached statement,
	// rather than showing a separately planned custom EXPLAIN SELECT.
	preparedSQL := "EXECUTE " + pgx.Identifier{preparedName}.Sanitize() + "('" + args.RootID.String() + "',NULL,'" + args.Through.Time.Format(time.RFC3339Nano) + "')"
	cached := explain("actual-pgx-cached-idle", preparedSQL, nil)
	t.Logf("default cached hint large-read nodes=%d", fullScans(cached))
	var cachedBefore int64
	if err = conn.QueryRow(ctx, `SELECT generic_plans FROM pg_prepared_statements WHERE name=$1`, preparedName).Scan(&cachedBefore); err != nil {
		t.Fatal(err)
	}
	useAdapter = true
	for n := 0; n < 10; n++ {
		began := time.Now()
		if len(actual()) != 0 {
			t.Fatal("actual adapter idle hint changed")
		}
		t.Logf("production adapter idle execution%d elapsed=%s", n, time.Since(began))
	}
	var cachedAfter int64
	if err = conn.QueryRow(ctx, `SELECT generic_plans FROM pg_prepared_statements WHERE name=$1`, preparedName).Scan(&cachedAfter); err != nil {
		t.Fatal(err)
	}
	if cachedAfter != cachedBefore {
		t.Fatal("production adapter still executed the named generic plan")
	}
	adapterPlan := explain("production-adapter-idle", query.sql, query.args)
	if fullScans(adapterPlan) != 0 {
		t.Fatal("production adapter idle hint still reads100k rows")
	}
	churn("with-active-indexes", 101001)
	for _, name := range []string{"synthetic_history_summary", "synthetic_history_hidden", "synthetic_history_reserved"} {
		var size int64
		if err = conn.QueryRow(ctx, `SELECT pg_relation_size($1::regclass)`, "pg_temp."+name).Scan(&size); err != nil {
			t.Fatal(err)
		}
		t.Logf("history index bytes after1000transition churn: %s=%d", name, size)
	}
	// Fixed original cutoff: do not make correctness depend on how long the
	// preceding planner measurements took on this host.
	past := args.Through.Time.Add(-time.Second)
	exec(`UPDATE custody_attempt SET effective_expires_at=$1 WHERE id=(SELECT attempt_id FROM capture_history_parameter ORDER BY capture_id DESC LIMIT 1)`, past)
	if got, want := actual(), reference(); !slices.Equal(got, want) || len(got) != 1 {
		t.Fatal("one-due candidate equivalence", got, want)
	}
	explain("union-one-due", query.sql, query.args)
	// Overlapping branches and all valid paired states, including expired
	// summaries of unknown writers and settled tombstones. First-page failures
	// are simulated by advancing the same cursor without changing those rows.
	exec(`CREATE TEMP TABLE synthetic_due AS SELECT capture_id,row_number() OVER(ORDER BY capture_id) n FROM capture_history_parameter ORDER BY capture_id LIMIT 80`)
	exec(`UPDATE capture_history_parameter h SET state=CASE d.n%6 WHEN 0 THEN 'deleted' WHEN 1 THEN 'write_claimed' WHEN 2 THEN 'reserved' WHEN 3 THEN 'deleting' ELSE 'available' END,visible=d.n%6 NOT IN(0,3,4),summary_expires_at=CASE WHEN d.n%6 IN(0,1) THEN $1::timestamptz ELSE $1::timestamptz+interval '2 days' END FROM synthetic_due d WHERE h.capture_id=d.capture_id`, past)
	exec(`UPDATE custody_attempt a SET state=CASE h.state WHEN 'reserved' THEN 'reserved' WHEN 'write_claimed' THEN 'reserved' WHEN 'deleting' THEN 'deleting' WHEN 'deleted' THEN 'deleted' ELSE 'stored_unpublished' END,effective_expires_at=CASE WHEN d.n%6=5 THEN $1::timestamptz ELSE $1::timestamptz+interval '2 days' END,write_until=CASE WHEN h.state='reserved' THEN $1::timestamptz ELSE $1::timestamptz+interval '1 day' END FROM capture_history_parameter h JOIN synthetic_due d ON h.capture_id=d.capture_id WHERE a.id=h.attempt_id`, past)
	seen := map[pgtype.UUID]bool{}
	pages := 0
	for {
		got, want := actual(), reference()
		if !slices.Equal(got, want) || len(got) > 16 {
			t.Fatal("old/new keyset candidate mismatch", pages, got, want)
		}
		for _, row := range got {
			if seen[row.CaptureID] {
				t.Fatal("duplicate candidate across bounded pages")
			}
			seen[row.CaptureID] = true
		}
		pages++
		if len(got) < 16 {
			break
		}
		if pages > 10 {
			t.Fatal("keyset did not terminate")
		}
		args.AfterID = got[len(got)-1].CaptureID
	}
	if len(seen) != 81 || pages < 5 {
		t.Fatal("mixed valid states/failing first page starved candidates", len(seen), pages)
	}
	t.Logf("old/new candidate equivalence: %d unique IDs across%d bounded pages, overlap deduplicated and failed-page cursor advanced", len(seen), pages)
}
