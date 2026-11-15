package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func (f *capacitySQLFixture) waitBlocked(t *testing.T, role string, ctx context.Context) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.admin.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND cardinality(pg_blocking_pids(pid))>0)`, role).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("intended SQL lock was not reached")
		case <-ticker.C:
		}
	}
}

func capacitySQLState(err error) string {
	var p *pgconn.PgError
	if errors.As(err, &p) {
		return p.Code
	}
	if err != nil {
		return "none"
	}
	return "success"
}

func capacityProjectionUUID(t *testing.T, text string) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	if err := id.Scan(text); err != nil || !id.Valid {
		t.Fatal("invalid projection fixture identity", err)
	}
	return id
}

// historicalRowJSON copies a row with bounded historical freshness.
func historicalRowJSON(table string) string {
	if table == "permission_stream" {
		return "to_jsonb(t)||jsonb_build_object('fresh_until',LEAST(t.fresh_until,t.observed_at+interval '5 seconds'))"
	}
	return "to_jsonb(t)"
}

func capacityWaitUntil(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("original-time wait cancelled")
	}
}
