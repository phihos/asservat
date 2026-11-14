package integration

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
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
