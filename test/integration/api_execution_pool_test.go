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

// All three typed execution ports use the compiled ordinary hub login and its
// shared 20-connection pool. Other fixture processes stay separate; cleanup joins it before
// the role is removed. The setup-only pool supplies TLS endpoint configuration.
func compiledOrdinaryHubPools(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool) (*pgxpool.Pool, string) {
	t.Helper()
	const purpose = "hub-runtime"
	const password = "synthetic-shared-api-execution"
	role := narrowRole(t, ctx, admin, "api_shared_", password, func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL(purpose, role)
		if !ok {
			t.Fatal("missing compiled shared execution grants")
		}
		return grants
	})
	limit, ok := contracts.PublicRuntimeRoleConnectionLimit(purpose)
	if !ok || limit != 81 {
		t.Fatal("unexpected execution login envelope")
	}
	if _, err := admin.Exec(ctx, "ALTER ROLE "+pgx.Identifier{role}.Sanitize()+" CONNECTION LIMIT 81"); err != nil {
		t.Fatal(err)
	}
	seed := poolFor(role, password)
	config := seed.Config()
	seed.Close()
	return governedOrdinaryHubPools(t, ctx, config), role
}

// This subset keeps the public group's 20 physical connections. Independent
// owner/capture/reader pools and their credentials are qualified separately.
func governedOrdinaryHubPools(t *testing.T, ctx context.Context, config *pgxpool.Config) *pgxpool.Pool {
	t.Helper()
	governor, err := postgres.NewSQLConnectionGovernor(32, 20)
	if err != nil {
		t.Fatal(err)
	}
	c := config.Copy()
	c.MaxConns, c.MinConns = contracts.PublicRuntimeHubOrdinaryConnections, 0
	if err := governor.Govern(c, true); err != nil {
		t.Fatal("public pool governor unavailable", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func qualifyOrdinaryHubPoolBound(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
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
		for range contracts.PublicRuntimeHubOrdinaryConnections {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				t.Fatal("shared execution pool cannot acquire 20 ordinary slots", err)
			}
			held = append(held, conn)
		}
		if pool.Stat().AcquiredConns() != contracts.PublicRuntimeHubOrdinaryConnections || pool.Stat().TotalConns() != contracts.PublicRuntimeHubOrdinaryConnections {
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
			t.Fatal("twenty-first ordinary acquisition escaped original caller bound", err)
		}
		release()
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal("shared execution pool failed after joined cancellation", err)
	}
	conn.Release()
}
