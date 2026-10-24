package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// initialFreshDatabase returns an administrator pool on a new, fully migrated
// database on the fixture server. Initial SQL provisioning refuses any
// database with existing installation rows (no rebootstrap after use), so it
// cannot share the suite database that earlier tests have written to.
func initialFreshDatabase(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
	t.Helper()
	server, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "initial_" + strings.ReplaceAll(custodyID(), "-", "")
	if _, err = server.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		server.Close()
		t.Fatal("owned database", err)
	}
	t.Cleanup(func() {
		defer server.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, e := server.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error("owned database not removed", e)
		}
	})
	config := server.Config().Copy()
	config.ConnConfig.Database = name
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	migrationDB.SetMaxOpenConns(1)
	provider, err := goose.NewProvider(goose.DialectPostgres, migrationDB, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err == nil {
		_, err = provider.Up(ctx)
	}
	if e := migrationDB.Close(); err == nil {
		err = e
	}
	if err != nil {
		t.Fatal("owned database schema", err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	return admin
}

func initialSQLMaintenance(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config) *pgxpool.Pool {
	t.Helper()
	operator := "initial_operator_" + strings.ReplaceAll(custodyID(), "-", "")
	_, err := admin.Exec(ctx, strings.ReplaceAll(`CREATE ROLE initial_role_operator LOGIN CREATEROLE PASSWORD 'synthetic-operator';
 GRANT USAGE ON SCHEMA public TO initial_role_operator WITH GRANT OPTION;
 GRANT SELECT,MAINTAIN ON ALL TABLES IN SCHEMA public TO initial_role_operator WITH GRANT OPTION;
 GRANT INSERT ON fleet_initial_activation TO initial_role_operator WITH GRANT OPTION;
 GRANT INSERT(installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,activated_database_oid,observed_at,fresh_until) ON fleet_observation TO initial_role_operator WITH GRANT OPTION;
 GRANT UPDATE(singleton,audit_receipt_json,activated_at) ON fleet_initial_activation TO initial_role_operator WITH GRANT OPTION;
 GRANT INSERT(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until) ON fleet_trust TO initial_role_operator WITH GRANT OPTION;
 GRANT UPDATE(suspended,recovery_blocked,activated_postmaster_at,activated_database_oid,observed_at,fresh_until) ON fleet_trust TO initial_role_operator WITH GRANT OPTION;`, "initial_role_operator", operator))
	if err != nil {
		t.Fatal(err)
	}
	// The operator's grants above belong to the administrator pool's database.
	c, err := pgxpool.ParseConfig("postgres://" + operator + ":synthetic-operator@" + address + "/" + admin.Config().ConnConfig.Database + "?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	c.ConnConfig.TLSConfig = tlsConfig.Clone()
	c.ConnConfig.TLSConfig.MinVersion = tls.VersionTLS13
	c.ConnConfig.Fallbacks = nil
	c.MaxConns = 4
	op, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	return op
}

func qualifyInitialSQLRoles(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config) {
	t.Helper()
	op := initialSQLMaintenance(t, ctx, admin, address, tlsConfig)
	c := op.Config()
	plan, err := postgres.NewInitialSQLCredentials(custodyID(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := postgres.NewInitialSQLRoles(ctx, op, plan.InstallationID)
	if err != nil {
		t.Fatal("maintenance role", err)
	}
	if err = manager.Provision(ctx, plan); err != nil {
		t.Fatal("initial role provisioning", err)
	}
	var verifier string
	var originalExpiry time.Time
	if err = admin.QueryRow(ctx, "SELECT rolpassword,rolvaliduntil FROM pg_authid WHERE rolname=$1", plan.Preparation.Username).Scan(&verifier, &originalExpiry); err != nil || !strings.HasPrefix(verifier, "SCRAM-SHA-256$") {
		t.Fatal("SCRAM verifier not stored")
	}
	if err = manager.Provision(ctx, plan); err != nil {
		t.Fatal("exact role replay", err)
	}
	var unchanged bool
	if err = admin.QueryRow(ctx, "SELECT rolpassword=$2 AND rolvaliduntil=$3 FROM pg_authid WHERE rolname=$1", plan.Preparation.Username, verifier, originalExpiry).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("replay changed credential/expiry")
	}
	other, err := postgres.NewInitialSQLCredentials(plan.InstallationID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrong := plan
	wrong.Preparation.Password = other.Preparation.Password
	if err = manager.Provision(ctx, wrong); err == nil {
		t.Fatal("adopted role without matching secret")
	}
	// This administrator mutation is a fault injection. Product replay must
	// reject unexpected privileges rather than silently adopting/removing them.
	if _, err = admin.Exec(ctx, "GRANT UPDATE ON public.custody_pool TO "+pgx.Identifier{plan.Preparation.Username}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if err = manager.Provision(ctx, plan); err == nil {
		t.Fatal("overprivileged role accepted")
	}
	if _, err = admin.Exec(ctx, "REVOKE UPDATE ON public.custody_pool FROM "+pgx.Identifier{plan.Preparation.Username}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if err = manager.Provision(ctx, plan); err != nil {
		t.Fatal("exact privileges not restored", err)
	}
	// PUBLIC grants do not appear in this role's direct ACL. They must not
	// silently bypass the purpose-specific permission boundary.
	for _, injection := range []struct{ grant, undo string }{
		{"GRANT UPDATE ON public.custody_pool TO PUBLIC", "REVOKE UPDATE ON public.custody_pool FROM PUBLIC"},
		{"GRANT UPDATE(recovery_blocked) ON public.fleet_trust TO PUBLIC", "REVOKE UPDATE(recovery_blocked) ON public.fleet_trust FROM PUBLIC"},
		{"GRANT CREATE ON SCHEMA public TO PUBLIC", "REVOKE CREATE ON SCHEMA public FROM PUBLIC"},
		{"CREATE FUNCTION public.unsafe_initial_test() RETURNS void LANGUAGE sql SECURITY DEFINER AS 'UPDATE public.fleet_trust SET recovery_blocked=false'", "DROP FUNCTION public.unsafe_initial_test()"},
	} {
		if _, err = admin.Exec(ctx, injection.grant); err != nil {
			t.Fatal(err)
		}
		denied := manager.Provision(ctx, plan)
		if _, err = admin.Exec(ctx, injection.undo); err != nil {
			t.Fatal(err)
		}
		if denied == nil {
			t.Fatalf("accepted ambient privilege: %s", injection.grant)
		}
	}
	runtime := c.ConnConfig.Copy()
	runtime.User, runtime.Password, runtime.RequireAuth = plan.Activation.Username, plan.Activation.Password, "scram-sha-256"
	conn, err := pgx.ConnectConfig(ctx, runtime)
	if err != nil {
		t.Fatal("scoped runtime authentication failed")
	}
	defer conn.Close(context.Background())
	if err = manager.Retire(ctx, plan); err != nil {
		t.Fatal("credential retirement", err)
	}
	if err = manager.Retire(ctx, plan); err != nil {
		t.Fatal("retirement replay", err)
	}
	if err = manager.Provision(ctx, plan); err == nil {
		t.Fatal("retired credentials resurrected")
	}
	_, err = conn.Exec(ctx, "SELECT * FROM fleet_trust")
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("existing connection kept table privileges", err)
	}
	if later, err := pgx.ConnectConfig(ctx, runtime); err == nil {
		later.Close(ctx)
		t.Fatal("retired login accepted")
	}
	if err = admin.QueryRow(ctx, "SELECT NOT rolcanlogin AND rolpassword IS NULL AND rolvaliduntil=$2 FROM pg_authid WHERE rolname=$1", plan.Activation.Username, originalExpiry).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("retirement incomplete")
	}
	t.Log("non-superuser maintenance provisioned exact purpose roles with client-derived SCRAM; exact replay preserves password/expiry, wrong secrets and excess grants deny, retirement revokes existing/new sessions' authority")
}
