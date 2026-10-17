package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

type initialHistoryFixture struct {
	reader    *postgres.InitialInstallationReader
	pool      *pgxpool.Pool
	authority *initialHistoryAuthorityFixture
	username  string
}

func newInitialHistoryFixture(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope value.InstallationWitnessScope, plan artifact.Digest) *initialHistoryFixture {
	t.Helper()
	pool, username := initialHistoryPool(t, ctx, admin, address, tlsConfig)
	authority := &initialHistoryAuthorityFixture{}
	authority.reset(time.Second, false, 0)
	reader, e := postgres.NewInitialInstallationReader(ctx, pool, scope, plan, authority)
	if e != nil {
		t.Fatal(e)
	}
	return &initialHistoryFixture{reader, pool, authority, username}
}
func (f *initialHistoryFixture) expect(t *testing.T, ctx context.Context, want app.InitialInstallationDisposition, record *audit.InitialInstallation) {
	t.Helper()
	f.authority.reset(time.Second, false, 0)
	got, e := f.reader.ObserveInitialInstallation(ctx)
	if e != nil || got.Disposition != want || !time.Now().Before(got.ValidUntil) || got.ValidUntil.After(f.authority.until) {
		t.Fatal("historical disposition", got.Disposition, e)
	}
	if record == nil {
		if got.Record != nil || got.AuditReceipt != nil {
			t.Fatal("missing observation exposed a record")
		}
		return
	}
	if got.Record == nil || got.Record.Scope != record.Scope || !got.Record.Claim.Same(record.Claim) {
		t.Fatal("historical identity changed")
	}
}
func (f *initialHistoryFixture) qualifyBoundsAndRole(t *testing.T, ctx context.Context, admin *pgxpool.Pool, installation string) {
	t.Helper()
	t.Run("historical-reader-role-is-select-only", func(t *testing.T) {
		for _, sql := range []string{"UPDATE fleet_initial_activation SET singleton=true", "DELETE FROM fleet_initial_activation WHERE false", "INSERT INTO fleet_initial_activation(singleton) VALUES(true)", "UPDATE fleet_trust SET recovery_blocked=false"} {
			_, e := f.pool.Exec(ctx, sql)
			var pg *pgconn.PgError
			if !errors.As(e, &pg) || pg.Code != "42501" {
				t.Fatal("read role mutation did not fail privilege check", e)
			}
		}
	})
	t.Run("historical-denial-before-sql", func(t *testing.T) {
		f.authority.reset(time.Second, true, 0)
		got, e := f.reader.ObserveInitialInstallation(ctx)
		if !errors.Is(e, value.ErrDenied) || got.Record != nil {
			t.Fatal("current denied operator read historical metadata", e)
		}
	})
	t.Run("historical-final-check-keeps-original-bound", func(t *testing.T) {
		f.authority.reset(50*time.Millisecond, false, 80*time.Millisecond)
		got, e := f.reader.ObserveInitialInstallation(ctx)
		if e == nil || got.Record != nil {
			t.Fatal("final native recheck renewed original disclosure bound")
		}
	})
	t.Run("historical-blocked-sql-keeps-original-bound", func(t *testing.T) {
		tx, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(context.Background())
		if _, e = tx.Exec(ctx, "LOCK TABLE fleet_initial_activation IN ACCESS EXCLUSIVE MODE"); e != nil {
			t.Fatal(e)
		}
		f.authority.reset(250*time.Millisecond, false, 0)
		done := make(chan error, 1)
		go func() {
			r, e := f.reader.ObserveInitialInstallation(ctx)
			if r.Record != nil {
				done <- errors.New("metadata after expired blocked read")
				return
			}
			done <- e
		}()
		observed := false
		until := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(until) {
			var n int
			e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock'", f.username).Scan(&n)
			if e != nil {
				t.Fatal(e)
			}
			if n > 0 {
				observed = true
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !observed {
			t.Fatal("test did not observe blocked historical SQL read")
		}
		if e = <-done; e == nil {
			t.Fatal("blocked SQL returned expired metadata")
		}
		if e = tx.Rollback(ctx); e != nil {
			t.Fatal(e)
		}
	})
	var blocked bool
	if e := admin.QueryRow(ctx, "SELECT recovery_blocked FROM fleet_trust WHERE installation_id=$1", installation).Scan(&blocked); e != nil || !blocked {
		t.Fatal("historical reader changed current recovery", e)
	}
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
func qualifyNativeInitialHistoricalRead(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, authority app.InitialInstallationReadAuthority, scope value.InstallationWitnessScope, plan artifact.Digest) {
	t.Helper()
	pool, _ := initialHistoryPool(t, ctx, admin, address, tlsConfig)
	reader, e := postgres.NewInitialInstallationReader(ctx, pool, scope, plan, authority)
	if e != nil {
		t.Fatal(e)
	}
	result, e := reader.ObserveInitialInstallation(ctx)
	if e != nil || result.Disposition != app.InitialInstallationActivated || result.Record == nil || result.Record.Scope != scope || result.Record.Claim.PlanDigest != plan || !time.Now().Before(result.ValidUntil) {
		t.Fatal("native historical read after original Pod terminated", e)
	}
}
