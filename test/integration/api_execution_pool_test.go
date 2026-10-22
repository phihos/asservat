package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// All three typed execution ports use this actual compiled login and one cold
// pool. Other fixture privileges remain separate; cleanup joins the pool before
// the role is removed. The setup-only pool supplies TLS endpoint configuration.
func compiledAPIExecutionPool(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool) (*pgxpool.Pool, string) {
	t.Helper()
	const purpose = "api-execution"
	const password = "synthetic-shared-api-execution"
	role := narrowRole(t, ctx, admin, "api_shared_", password, func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL(purpose, role)
		if !ok {
			t.Fatal("missing compiled shared execution grants")
		}
		return grants
	})
	limit, ok := contracts.PublicRuntimeRoleConnectionLimit(purpose)
	if !ok || limit != 13 {
		t.Fatal("unexpected execution login envelope")
	}
	if _, err := admin.Exec(ctx, "ALTER ROLE "+pgx.Identifier{role}.Sanitize()+" CONNECTION LIMIT 13"); err != nil {
		t.Fatal(err)
	}
	seed := poolFor(role, password)
	config := seed.Config()
	seed.Close()
	config.MaxConns, config.MinConns = 3, 0
	governor, err := postgres.NewSQLConnectionGovernor(32, 0)
	if err != nil || governor.Govern(config, false) != nil {
		t.Fatal("execution pool governor unavailable", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, role
}

func qualifyAPIExecutionPoolBound(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for round := 0; round < 2; round++ {
		var held []*pgxpool.Conn
		release := func() {
			for _, conn := range held {
				conn.Release()
			}
			held = nil
		}
		defer release()
		for range 3 {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				t.Fatal("shared execution pool cannot acquire former three slots", err)
			}
			held = append(held, conn)
		}
		if pool.Stat().AcquiredConns() != 3 || pool.Stat().TotalConns() != 3 {
			t.Fatal("shared execution concurrency changed")
		}
		wait, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		if round == 1 {
			cancel()
		}
		extra, err := pool.Acquire(wait)
		cancel()
		if extra != nil {
			extra.Release()
		}
		want := context.DeadlineExceeded
		if round == 1 {
			want = context.Canceled
		}
		if !errors.Is(err, want) {
			t.Fatal("fourth execution acquisition escaped original caller bound", err)
		}
		release()
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal("shared execution pool failed after joined cancellation", err)
	}
	conn.Release()
}
