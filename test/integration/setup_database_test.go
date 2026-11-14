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
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
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

	// P2: two runtime roles with mounted credentials; the rest are missing.
	hub, _ := postgres.PublicRuntimeRoleName(installation, "hub-runtime")
	fleetRole, _ := postgres.ConfigurationRuntimeRoleName(installation, "configuration-fleet")
	password := strings.Repeat("Setup-0", 7)
	logins := map[string]string{hub: password, fleetRole: password}
	report, e := postgres.EnsureRuntimeRoles(ctx, config, installation, logins)
	if e != nil || len(report.Created) != 2 || len(report.Updated) != 0 || len(report.Missing) != len(roles)-2 {
		t.Fatal("first role reconciliation", report, e)
	}
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
	if report, e = postgres.EnsureRuntimeRoles(ctx, config, installation, logins); e != nil || len(report.Created) != 0 || len(report.Updated) != 2 {
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
	if state, e := postgres.ReadSchemaState(ctx, pool); e != nil || !state.Compatible(postgres.CompiledSchemaVersion) {
		t.Fatal("runtime schema state", state, e)
	}

	// P3: the trust seed activates once; a rerun keeps it, another
	// installation is refused.
	now := time.Now()
	a := value.Administration{InstallationID: installation, IssuerEpoch: custodyID(), Issuer: "https://id.example.test", Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: [32]byte{1}},
		Clients: []string{"console"}, Groups: []string{"operators"}, DeliveryProfiles: []string{"ops"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	if e = postgres.SeedInstallation(ctx, config, a); e != nil {
		t.Fatal("seed", e)
	}
	var blocked, suspended bool
	if e = owned.QueryRow(ctx, "SELECT recovery_blocked,suspended FROM public.fleet_current_trust WHERE installation_id=$1", installation).Scan(&blocked, &suspended); e != nil || blocked || suspended {
		t.Fatal("seeded trust not current", blocked, suspended, e)
	}
	if e = postgres.SeedInstallation(ctx, config, a); e != nil {
		t.Fatal("seed rerun", e)
	}
	other := a
	other.InstallationID = custodyID()
	if e = postgres.SeedInstallation(ctx, config, other); !errors.Is(e, cfg.ErrChanged) {
		t.Fatal("second installation accepted", e)
	}
	var stale int
	if e = owned.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('capacity_setup_original_valid','capacity_audit_reader_pin_valid') AND pg_get_functiondef(p.oid) LIKE '%fleet_initial_activation%'`).Scan(&stale); e != nil || stale != 0 {
		t.Fatal("capacity checks still require the first-installation record", stale, e)
	}
}
