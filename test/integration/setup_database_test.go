package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// `asservat setup`'s database path on a fresh owned database: migrations
// from empty, runtime roles from the compiled plans with grant
// reconciliation, the trust seed, and idempotent reruns.
func TestCustodySetupDatabaseWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run the owned custody fixture")
	}
	var f fixture
	raw, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
		t.Fatal("fixture unavailable")
	}
	ctx, end := context.WithTimeout(context.Background(), 4*time.Minute)
	defer end()
	admin, e := pgxpool.New(ctx, f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Close)
	installation := custodyID()
	name := "setup_" + strings.ReplaceAll(installation, "-", "")
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	roles, e := postgres.RuntimeRoles(installation)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if _, e := admin.Exec(bounded, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error("owned database cleanup failed", e)
		}
		for _, r := range roles {
			if _, e := admin.Exec(bounded, "DROP ROLE IF EXISTS "+pgx.Identifier{r.Name}.Sanitize()); e != nil {
				t.Error("owned role cleanup failed", r.Name, e)
			}
		}
	})
	endpoint, e := url.Parse(f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	address, roots := pgTLSBridge(t, endpoint.Host)
	host, portText, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	port, _ := strconv.Atoi(portText)
	config := admin.Config().ConnConfig.Copy()
	config.Host, config.Port, config.Database = host, uint16(port), name
	config.TLSConfig = roots.Clone()
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.Fallbacks = nil

	// P1: an empty database is migrated to the compiled head, then a rerun
	// is a no-op.
	schema, e := postgres.NewUpgradeSchema(config)
	if e != nil {
		t.Fatal(e)
	}
	defer schema.Close()
	if from, to, e := schema.Run(ctx); e != nil || from != 0 || to != postgres.CompiledSchemaVersion {
		t.Fatal("fresh migration", from, to, e)
	}
	if from, to, e := schema.Run(ctx); e != nil || from != postgres.CompiledSchemaVersion || to != from {
		t.Fatal("rerun", from, to, e)
	}

	// Provision the hub and federation roles from their mounted credentials.
	hub, _ := postgres.PublicRuntimeRoleName(installation, "hub-runtime")
	fleetRole, _ := postgres.ConfigurationRuntimeRoleName(installation, "configuration-fleet")
	password := strings.Repeat("Setup-0", 7)
	federation, _ := postgres.PublicRuntimeRoleName(installation, "connector-owner-read")
	logins := map[string]string{hub: password, fleetRole: password, federation: password}
	report, e := postgres.EnsureRuntimeRoles(ctx, config, installation, logins)
	if e != nil || len(report.Created) != 3 || len(report.Updated) != 0 || len(report.Missing) != len(roles)-3 {
		t.Fatal("first role reconciliation", report, e)
	}
	// Two serving federation replicas and one rolling replacement each need a
	// persistent listener and an independent session for ordinary work.
	t.Run("federation overlap", func(t *testing.T) {
		login := config.Copy()
		login.User, login.Password = federation, password
		var listeners, queries []*pgx.Conn
		for i := range 6 {
			conn, err := pgx.ConnectConfig(ctx, login)
			if err != nil {
				t.Fatal("federation session", i, err)
			}
			defer conn.Close(ctx)
			if i%2 == 0 {
				if _, err = conn.Exec(ctx, "LISTEN asservat_connector_work"); err != nil {
					t.Fatal(err)
				}
				listeners = append(listeners, conn)
			} else {
				queries = append(queries, conn)
			}
		}
		for _, q := range queries {
			if _, err := q.Exec(ctx, "SELECT pg_notify('asservat_connector_work','ready')"); err != nil {
				t.Fatal(err)
			}
		}
		for _, l := range listeners {
			for range queries {
				n, err := l.WaitForNotification(ctx)
				if err != nil || n.Payload != "ready" {
					t.Fatal("work dispatch", err)
				}
			}
		}
	})
	// Drift: an extra grant is revoked again and the password follows the
	// mounted credential.
	owned, e := pgx.ConnectConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer owned.Close(context.Background())
	if _, e = owned.Exec(ctx, "GRANT DELETE ON public.fleet_trust TO "+pgx.Identifier{hub}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	logins[hub] = strings.Repeat("Rotate-1", 6)
	if report, e = postgres.EnsureRuntimeRoles(ctx, config, installation, logins); e != nil || len(report.Created) != 0 || len(report.Updated) != 3 {
		t.Fatal("second role reconciliation", report, e)
	}
	var extra bool
	if e = owned.QueryRow(ctx, "SELECT has_table_privilege($1,'public.fleet_trust','DELETE')", hub).Scan(&extra); e != nil || extra {
		t.Fatal("extra grant survived reconciliation", e)
	}
	login := config.Copy()
	login.User, login.Password = hub, logins[hub]
	login.RequireAuth = "scram-sha-256"
	pc, e := pgxpool.ParseConfig("")
	if e != nil {
		t.Fatal(e)
	}
	pc.ConnConfig, pc.MaxConns = login, 1
	pool, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	if e = postgres.VerifySessionRole(ctx, pool, hub); e != nil {
		t.Fatal("runtime login", e)
	}
	if e = postgres.VerifySessionRole(ctx, pool, fleetRole); !errors.Is(e, cfg.ErrDenied) {
		t.Fatal("another role name accepted", e)
	}
	if head, e := postgres.ReadSchemaHead(ctx, pool); e != nil || head != postgres.CompiledSchemaVersion {
		t.Fatal("runtime schema head", head, e)
	}

	// P3: the trust seed activates once; a rerun keeps it, another
	// installation is refused.
	epoch := custodyID()
	if e = postgres.SeedInstallation(ctx, config, installation, epoch); e != nil {
		t.Fatal("seed", e)
	}
	var activated bool
	if e = owned.QueryRow(ctx, "SELECT activated_postmaster_at IS NOT NULL FROM public.fleet_trust WHERE installation_id=$1", installation).Scan(&activated); e != nil || !activated {
		t.Fatal("seeded trust not activated", activated, e)
	}
	if e = postgres.SeedInstallation(ctx, config, installation, epoch); e != nil {
		t.Fatal("seed rerun", e)
	}
	if e = postgres.SeedInstallation(ctx, config, custodyID(), epoch); !errors.Is(e, cfg.ErrChanged) {
		t.Fatal("second installation accepted", e)
	}
	var stale int
	if e = owned.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('capacity_setup_original_valid','capacity_audit_reader_pin_valid') AND pg_get_functiondef(p.oid) LIKE '%fleet_initial_activation%'`).Scan(&stale); e != nil || stale != 0 {
		t.Fatal("capacity checks still require the first-installation record", stale, e)
	}
	// A version this binary does not know is refused, not skipped.
	if _, e = owned.Exec(ctx, "INSERT INTO goose_db_version(version_id,is_applied) VALUES($1,true)", postgres.CompiledSchemaVersion+1); e != nil {
		t.Fatal(e)
	}
	if _, _, e = schema.Run(ctx); e == nil {
		t.Fatal("unknown newer history accepted")
	}
}
