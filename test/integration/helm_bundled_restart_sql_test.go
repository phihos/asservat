package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The ordinary custody harness applies the actual schema to an empty owned
// PostgreSQL instance. Missing IDs exercise real SQL name/function resolution,
// without inventing an installation, authority or committed evidence fixture.
func TestBundledRestartSQLShapeWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run test-custody.py --run '^TestBundledRestartSQLShapeWithRealPostgres$'")
	}
	var fixture struct{ Postgres string }
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &fixture) != nil || fixture.Postgres == "" {
		clear(raw)
		t.Fatal("owned PostgreSQL fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(fixture.Postgres)
	if err != nil {
		t.Fatal("owned PostgreSQL configuration unavailable")
	}
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("owned PostgreSQL pool unavailable")
	}
	defer pool.Close()
	var head int64
	if err := pool.QueryRow(ctx, "SELECT version_id FROM goose_db_version ORDER BY id DESC LIMIT 1").Scan(&head); err != nil || head != postgres.CompiledSchemaVersion {
		t.Fatal("restart SQL preflight requires the actual compiled schema head")
	}
	const absent = "f4a25164-5ad5-43f4-bf6c-2701bd61a8f7"
	if err := pool.QueryRow(ctx, bundledRestartArtifactSQL, absent, absent, absent).Scan(); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("original artifact SELECT failed real PostgreSQL shape check: %v", err)
	}
	if _, err := readBundledPostgresSQL(ctx, pool, absent); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("PostgreSQL incarnation SELECT failed real PostgreSQL shape check: %v", err)
	}
	t.Logf("both restart SELECTs resolved against real PostgreSQL schema %d with no installation/artifact rows; typed populated data and restart behavior remain unqualified", head)
}
