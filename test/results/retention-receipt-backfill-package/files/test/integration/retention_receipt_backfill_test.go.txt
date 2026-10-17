package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type retentionReceiptIndexOriginal struct {
	name, statement, definition string
	oid                         uint32
}

// Fixture-only populated backfill measurement. The surrounding transaction
// owns all synthetic rows, admits no runtime effect, and rolls back the exact
// original indexes together with those rows. These timings do not qualify a
// production-sized migration or a live deployment's lock acquisition time.
func qualifyRetentionReceiptIndexBackfill(t *testing.T, ctx context.Context, tx pgx.Tx, syntheticHistory int) []retentionReceiptIndexOriginal {
	t.Helper()
	raw, err := os.ReadFile("../../migrations/00057_retention_receipt_versions.sql")
	if err != nil {
		t.Fatal("authored receipt index migration", err)
	}
	names := []string{"retention_checkpoint_invalid_receipt", "retention_decision_invalid_receipt"}
	indexes := make([]retentionReceiptIndexOriginal, len(names))
	read := func(name string) (string, int64, uint32) {
		t.Helper()
		bounded, end := context.WithTimeout(ctx, 5*time.Second)
		defer end()
		var definition string
		var size int64
		var oid uint32
		var valid, ready, unique bool
		err := tx.QueryRow(bounded, `SELECT pg_get_indexdef(c.oid),pg_relation_size(c.oid),c.oid,i.indisvalid,i.indisready,i.indisunique FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_index i ON i.indexrelid=c.oid WHERE n.nspname='public' AND c.relname=$1`, name).Scan(&definition, &size, &oid, &valid, &ready, &unique)
		if err != nil || !valid || !ready || unique {
			t.Fatal("exact ready nonunique receipt index unavailable", name, err)
		}
		return definition, size, oid
	}
	for i, name := range names {
		prefix := "CREATE INDEX " + name + "\n"
		if strings.Count(string(raw), prefix) != 1 {
			t.Fatal("authored fixed index statement missing or repeated", name)
		}
		_, tail, _ := strings.Cut(string(raw), prefix)
		body, _, found := strings.Cut(tail, ";")
		if !found || !strings.HasPrefix(body, "ON public.retention_") {
			t.Fatal("authored fixed index statement malformed", name)
		}
		definition, _, oid := read(name)
		indexes[i] = retentionReceiptIndexOriginal{name, prefix + body + ";", definition, oid}
	}
	var checkpoints, decisions int64
	bounded, end := context.WithTimeout(ctx, 5*time.Second)
	err = tx.QueryRow(bounded, "SELECT (SELECT count(*) FROM retention_checkpoint),(SELECT count(*) FROM retention_decision)").Scan(&checkpoints, &decisions)
	end()
	if err != nil || checkpoints < int64(syntheticHistory) || decisions < int64(syntheticHistory) {
		t.Fatal("actual populated index input unavailable", err)
	}
	for _, index := range indexes {
		bounded, end := context.WithTimeout(ctx, 5*time.Second)
		_, err := tx.Exec(bounded, "DROP INDEX public."+index.name)
		end()
		if err != nil {
			t.Fatal("transaction-owned receipt index drop", index.name, err)
		}
	}
	for _, index := range indexes {
		bounded, end := context.WithTimeout(ctx, 5*time.Second)
		started := time.Now()
		_, err := tx.Exec(bounded, index.statement)
		elapsed := time.Since(started)
		end()
		if err != nil {
			t.Fatal("populated exact receipt index build", index.name, elapsed, err)
		}
		definition, size, _ := read(index.name)
		if definition != index.definition {
			t.Fatal("authored backfill changed original index definition", index.name)
		}
		t.Logf("index-backfill synthetic_history=%d checkpoint_rows=%d lifecycle_rows=%d index=%s elapsed=%s bytes=%d; synthetic receipts are canonical versioned values, no runtime effects or production migration latency claim", syntheticHistory, checkpoints, decisions, index.name, elapsed, size)
	}
	return indexes
}

func checkRetentionReceiptIndexesRestored(ctx context.Context, admin *pgxpool.Pool, originals []retentionReceiptIndexOriginal) error {
	for _, original := range originals {
		var definition string
		var oid uint32
		var valid, ready bool
		err := admin.QueryRow(ctx, `SELECT pg_get_indexdef(c.oid),c.oid,i.indisvalid,i.indisready FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_index i ON i.indexrelid=c.oid WHERE n.nspname='public' AND c.relname=$1`, original.name).Scan(&definition, &oid, &valid, &ready)
		if err != nil {
			return fmt.Errorf("original index %s was not restored: %w", original.name, err)
		}
		if definition != original.definition || oid != original.oid || !valid || !ready {
			return fmt.Errorf("original index %s identity, definition or readiness was not restored", original.name)
		}
	}
	return nil
}
