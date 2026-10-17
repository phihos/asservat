package integration

import (
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

// Uses real role provisioning and the original completed embedded schema. The
// witness/source are explicitly synthetic; only SQL binding and rollback are
// qualified here. Stale expected dates model the old incarnation carried across
// a restart, without restarting a shared provider or claiming recovery support.
func initialSchemaActivationBinding(t *testing.T, ctx context.Context, config *pgx.ConnConfig, admin *pgx.Conn, manager string, completed contracts.InitialPreparationSchema) {
	t.Helper()
	scope := value.InstallationWitnessScope{InstallationID: custodyID(), IssuerEpoch: custodyID(), ClusterID: custodyID(), Namespace: "control", NamespaceUID: custodyID(), Name: "witness", UID: custodyID(), WriterAccount: "installer", WriterAccountUID: custodyID()}
	pool := func(login postgres.InitialSQLLogin) *pgxpool.Pool {
		t.Helper()
		c, e := pgxpool.ParseConfig("postgres://synthetic.invalid/synthetic?sslmode=disable")
		if e != nil {
			t.Fatal("fixture pool configuration unavailable")
		}
		c.ConnConfig = config.Copy()
		c.ConnConfig.User, c.ConnConfig.Password = login.Username, login.Password
		c.MaxConns = 4
		p, e := pgxpool.NewWithConfig(ctx, c)
		if e != nil {
			t.Fatal("fixture scoped pool unavailable")
		}
		return p
	}
	managerPool := pool(postgres.InitialSQLLogin{Username: manager, Password: "synthetic-schema-manager"})
	defer managerPool.Close()
	roles, e := postgres.NewInitialSQLRoles(ctx, managerPool, scope.InstallationID)
	if e != nil {
		t.Fatal("actual manager unavailable", e)
	}
	credentials, e := postgres.NewInitialSQLCredentials(scope.InstallationID, time.Now())
	if e != nil {
		t.Fatal("synthetic role material unavailable")
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		// The scoped pool's later defer has already joined it. Revoke through
		// the actual original manager grantor: administrative DROP OWNED did
		// not remove this grant chain in the real PostgreSQL fixture.
		if e := roles.Retire(bounded, credentials); e != nil {
			t.Errorf("scoped role retirement unavailable sqlstate=%s", initialSchemaCleanupSQLState(e))
		}
		for _, login := range []postgres.InitialSQLLogin{credentials.Preparation, credentials.Audit, credentials.Activation} {
			name := pgx.Identifier{login.Username}.Sanitize()
			if _, e := admin.Exec(bounded, "DROP ROLE IF EXISTS "+name); e != nil {
				t.Errorf("scoped role cleanup unavailable sqlstate=%s", initialSchemaCleanupSQLState(e))
			}
		}
	}()
	if e = roles.Provision(ctx, credentials); e != nil {
		t.Fatal("actual bounded role provisioning failed", e)
	}
	prepPool := pool(credentials.Preparation)
	defer prepPool.Close()
	expected := contracts.InitialSchemaExpectation{BundleDigest: completed.BundleDigest, Head: completed.Head, DatabaseOID: completed.DatabaseOID, PostmasterAt: completed.PostmasterAt}
	inputs := func() (value.InstallationWitness, value.Administration) {
		w, _ := (&initialWitnessFixture{scope: scope}).ReadInstallationWitness(ctx)
		a, _ := (&initialAdminFixture{a: value.Administration{InstallationID: scope.InstallationID, IssuerEpoch: scope.IssuerEpoch, Issuer: "https://id.example.test", Revision: identity.Revision{UID: "initial-fleet", Generation: 1, Digest: artifact.Digest{1}}, Clients: []string{"console"}, Groups: []string{"operators"}, DeliveryProfiles: []string{"ops"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}}).FleetAdministration(ctx)
		return w, a
	}
	for _, mode := range []string{"changed-database", "changed-postmaster"} {
		t.Run(mode, func(t *testing.T) {
			old := expected
			if mode == "changed-database" {
				old.DatabaseOID++
			} else {
				old.PostmasterAt = old.PostmasterAt.Add(-time.Second)
			}
			facet, e := postgres.NewInitialInstallationsForSchema(ctx, prepPool, scope, artifact.Digest{2}, old)
			if e != nil {
				t.Fatal("static bound facet unavailable", e)
			}
			w, a := inputs()
			if _, e = facet.PrepareInitialInstallation(ctx, w, a); e == nil {
				t.Fatal("fresh activation claim bypassed original completed schema")
			}
			var count int
			if e = admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM public.fleet_initial_activation)+(SELECT count(*) FROM public.fleet_trust)").Scan(&count); e != nil || count != 0 {
				t.Fatal("rejected old incarnation left activation state")
			}
		})
	}
	facet, e := postgres.NewInitialInstallationsForSchema(ctx, prepPool, scope, artifact.Digest{2}, expected)
	if e != nil {
		t.Fatal("original facet unavailable", e)
	}
	w, a := inputs()
	record, e := facet.PrepareInitialInstallation(ctx, w, a)
	if e != nil || record.Claim.Database.DatabaseOID != expected.DatabaseOID || !record.Claim.Database.StartedAt.Equal(expected.PostmasterAt) {
		t.Fatal("original incarnation failed scoped claim", e)
	}
	// Claim remains recovery-blocked and unaudited. No synthetic success proof is
	// supplied to activate this isolated database.
	var blocked bool
	if e = admin.QueryRow(ctx, "SELECT recovery_blocked AND activated_postmaster_at IS NULL FROM public.fleet_trust WHERE installation_id=$1", scope.InstallationID).Scan(&blocked); e != nil || !blocked {
		t.Fatal("claim activated without independently acknowledged audit")
	}
}

// Fixture diagnostics retain only the standardized code, never SQL text,
// credentials, role names or the provider's message/detail fields.
func initialSchemaCleanupSQLState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && len(pg.Code) == 5 {
		for _, c := range pg.Code {
			if !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') {
				return "unavailable"
			}
		}
		return pg.Code
	}
	return "none"
}
