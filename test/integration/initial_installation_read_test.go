package integration

import (
	"context"
	"crypto/tls"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Current Kubernetes administrator/protection is explicitly synthetic here;
// native input/guard checks belong to the separate Kubernetes qualification.
type initialHistoryAuthorityFixture struct {
	mu         sync.Mutex
	until      time.Time
	deny       bool
	calls      int
	delayFinal time.Duration
}

func (f *initialHistoryAuthorityFixture) CheckInitialInstallationRead(ctx context.Context, _ value.InstallationWitnessScope, _ artifact.Digest) (time.Time, error) {
	f.mu.Lock()
	f.calls++
	calls, delay, deny, until := f.calls, f.delayFinal, f.deny, f.until
	f.mu.Unlock()
	if deny {
		return time.Time{}, value.ErrDenied
	}
	if calls == 2 && delay > 0 {
		time.Sleep(delay)
	}
	return until, nil
}
func (f *initialHistoryAuthorityFixture) reset(d time.Duration, deny bool, delay time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.until = time.Now().Add(d)
	f.deny = deny
	f.delayFinal = delay
	f.calls = 0
}

func initialHistoryPool(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config) (*pgxpool.Pool, string) {
	t.Helper()
	username := "initial_history_" + strings.ReplaceAll(custodyID(), "-", "")
	role := pgx.Identifier{username}.Sanitize()
	if _, e := admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'synthetic-history'; GRANT USAGE ON SCHEMA public TO "+role+"; GRANT SELECT ON goose_db_version,fleet_initial_activation TO "+role+";"); e != nil {
		t.Fatal(e)
	}
	c, e := pgxpool.ParseConfig("postgres://" + username + ":synthetic-history@" + address + "/custody_test?sslmode=disable")
	if e != nil {
		t.Fatal(e)
	}
	c.ConnConfig.TLSConfig = tlsConfig
	c.ConnConfig.Fallbacks = nil
	c.MaxConns = 2
	pool, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	return pool, username
}
