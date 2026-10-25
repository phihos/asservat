package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// ADR-227 phase 1: an installed database one migration behind is upgraded by
// the schema owner; the upgrade is idempotent, records the compatibility floor
// and refuses a history it does not know.
func TestCustodyUpgradeSchemaWithRealPostgres(t *testing.T) {
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
	name := "upgrade_" + strings.ReplaceAll(custodyID(), "-", "")
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, e := admin.Exec(bounded, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error("owned database cleanup failed", e)
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

	// An installation at the previous head, with an activated trust root.
	db := stdlib.OpenDB(*config)
	defer db.Close()
	p, e := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if e != nil {
		t.Fatal(e)
	}
	sources := p.ListSources()
	head := sources[len(sources)-1].Version
	if _, e = p.UpTo(ctx, head-1); e != nil {
		t.Fatal("migrate to previous head", e)
	}
	conn, e := pgx.ConnectConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(context.Background())
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, e = conn.Exec(ctx, `INSERT INTO fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until,activated_postmaster_at,activated_database_oid)
 VALUES($1,$2,'synthetic-upgrade',1,$3,$4,$5,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()))`, custodyID(), custodyID(), make([]byte, 32), now, now.Add(time.Second)); e != nil {
		t.Fatal("synthetic activated installation", e)
	}

	upgrade, e := postgres.NewUpgradeSchema(config)
	if e != nil {
		t.Fatal(e)
	}
	defer upgrade.Close()
	from, to, e := upgrade.Run(ctx)
	if e != nil || from != head-1 || to != head {
		t.Fatal("upgrade", from, to, e)
	}
	var floor string
	if e = conn.QueryRow(ctx, "SELECT obj_description('public.goose_db_version'::regclass,'pg_class')").Scan(&floor); e != nil || !strings.HasPrefix(floor, "asservat:oldest-binary-schema=") {
		t.Fatal("compatibility floor not recorded", floor, e)
	}
	if from, to, e = upgrade.Run(ctx); e != nil || from != head || to != head {
		t.Fatal("repeated upgrade was not a no-op", from, to, e)
	}
	// A version this binary does not know is refused, not skipped.
	if _, e = conn.Exec(ctx, "INSERT INTO goose_db_version(version_id,is_applied) VALUES($1,true)", head+1); e != nil {
		t.Fatal(e)
	}
	if _, _, e = upgrade.Run(ctx); e == nil {
		t.Fatal("unknown newer history accepted")
	}
	t.Logf("upgrade schema: %d to %d by the schema owner, idempotent, floor %q, unknown history refused", head-1, head, floor)
}
