package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The manager is a separately provisioned fixture input. It has no application
// grants: only the actual schema loader may install the compiled grant union.
func initialEmptySchemaManager(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, roots *tls.Config) *pgxpool.Pool {
	t.Helper()
	var empty bool
	if err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')`).Scan(&empty); err != nil || !empty {
		t.Fatal("schema qualification requires an actually empty owned database")
	}
	name := "initial_schema_manager_" + strings.ReplaceAll(custodyID(), "-", "")
	until := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	if _, err := admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" LOGIN NOINHERIT NOSUPERUSER CREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD 'synthetic-operator' VALID UNTIL '"+until+"'"); err != nil {
		t.Fatal("fixture schema manager unavailable")
	}
	c, err := pgxpool.ParseConfig("postgres://" + name + ":synthetic-operator@" + address + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal("fixture manager configuration unavailable")
	}
	c.ConnConfig.TLSConfig = roots.Clone()
	c.ConnConfig.Fallbacks = nil
	c.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal("fixture manager pool unavailable")
	}
	t.Cleanup(pool.Close)
	return pool
}

func initialSchemaHandoverSame(a, b contracts.InitialPreparationSchema) bool {
	x, ex := json.Marshal(a)
	y, ey := json.Marshal(b)
	return ex == nil && ey == nil && bytes.Equal(x, y)
}
