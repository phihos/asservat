package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

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

// Query-cost evidence only: temporary synthetic rows on one owned fixture
// session shadow the production names. No accepted capture, SQL guard,
// ciphertext, quota or authorization row is created or bypassed.
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
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, fixture.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	for _, sql := range []string{
		`CREATE TEMP TABLE capture_history_parameter(root_id uuid NOT NULL,capture_id uuid PRIMARY KEY,attempt_id uuid NOT NULL,state text NOT NULL,visible boolean NOT NULL,summary_expires_at timestamptz NOT NULL)`,
		`CREATE INDEX synthetic_history_summary ON capture_history_parameter(root_id,summary_expires_at,capture_id) WHERE state<>'deleted'`,
		`CREATE TEMP TABLE custody_attempt(id uuid PRIMARY KEY,cluster_id uuid NOT NULL,state text NOT NULL,effective_expires_at timestamptz NOT NULL,write_until timestamptz NOT NULL)`,
		`CREATE INDEX synthetic_custody_due ON custody_attempt(effective_expires_at,id) WHERE state<>'deleted'`,
		`INSERT INTO custody_attempt SELECT md5('synthetic-attempt-'||n)::uuid,'10000000-0000-4000-8000-000000000004','stored_unpublished',clock_timestamp()+interval '1 day',clock_timestamp()+interval '30 seconds' FROM generate_series(1,100000)n`,
		`INSERT INTO capture_history_parameter SELECT '10000000-0000-4000-8000-000000000001',md5('synthetic-capture-'||n)::uuid,md5('synthetic-attempt-'||n)::uuid,'available',true,clock_timestamp()+interval '1 day' FROM generate_series(1,100000)n`,
		`ANALYZE capture_history_parameter`, `ANALYZE custody_attempt`,
	} {
		if _, err = conn.Exec(ctx, sql); err != nil {
			t.Fatal("synthetic scale setup", err)
		}
	}
	var root pgtype.UUID
	_ = root.Scan("10000000-0000-4000-8000-000000000001")
	query := &historyScaleQuery{Conn: conn}
	args := custodydb.ListHistoryRetirementCandidatesParams{RootID: root, Through: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}}
	measure := func(name string, want int) {
		t.Helper()
		start := time.Now()
		rows, err := custodydb.New(query).ListHistoryRetirementCandidates(ctx, args)
		elapsed := time.Since(start)
		if err != nil || len(rows) != want {
			t.Fatal("actual generated candidate query", name, len(rows), err)
		}
		var plan json.RawMessage
		if err = conn.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.args...).Scan(&plan); err != nil {
			t.Fatal("actual candidate explain", err)
		}
		var result []struct {
			ExecutionTime float64 `json:"Execution Time"`
			Plan          map[string]any
		}
		if json.Unmarshal(plan, &result) != nil || len(result) != 1 {
			t.Fatal("invalid explain")
		}
		t.Logf("history query %s: syntheticRows=100000 returned=%d elapsed=%s explainExecutionMS=%.3f rootLocalHitBlocks=%v rootSharedHitBlocks=%v plan=%s", name, len(rows), elapsed, result[0].ExecutionTime, result[0].Plan["Local Hit Blocks"], result[0].Plan["Shared Hit Blocks"], plan)
	}
	measure("idle", 0)
	if _, err = conn.Exec(ctx, `UPDATE custody_attempt SET effective_expires_at=clock_timestamp()-interval '1 second' WHERE id=(SELECT attempt_id FROM capture_history_parameter ORDER BY capture_id DESC LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	measure("one-due", 1)
}
