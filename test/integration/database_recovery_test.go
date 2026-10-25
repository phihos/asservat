package integration

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The owned Python harness actually restarts PostgreSQL and restores pg_dump
// into a new database between invocations. Only initial/repeated activation is
// synthetic; all configuration observation and authority reads use real roles.
func TestDatabaseRecoveryAfterRestartAndRestore(t *testing.T) {
	phase := os.Getenv("ASSERVAT_DATABASE_RECOVERY_PHASE")
	if phase == "" {
		t.Skip("run make database-recovery-integration")
	}
	if phase != "initial" && phase != "restarted" && phase != "restored" {
		t.Fatal("unknown owned fixture phase")
	}
	var f fixture
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CUSTODY_FIXTURES"))
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	u, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	u.Host, u.User = address, url.UserPassword("fleet_observe_runtime", "synthetic-fleet-observe")
	c, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		t.Fatal(err)
	}
	c.ConnConfig.TLSConfig, c.ConnConfig.Fallbacks, c.MaxConns = tlsConfig, nil, 4
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := value.Administration{
		InstallationID: "4a748d72-85e9-4305-a737-3abfb22cf788", IssuerEpoch: "e7924388-979c-4620-944d-c4067c80c875",
		Issuer: "https://identity.example.test", Revision: identity.Revision{UID: "synthetic-recovery", Generation: 1, Digest: artifact.Digest{1}},
		ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Clients: []string{"console"}, Groups: []string{"operators"}, DeliveryProfiles: []string{"ops"},
		MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16,
	}
	observer, err := postgres.NewFleetObservation(ctx, pool, a.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := postgres.NewRecoveryReader(ctx, pool, a.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	// The restart/restore check reads the stored activation before any
	// observation pass, which may re-activate a lossless restart (ADR-226).
	if phase != "initial" {
		var storedBlocked, sameProcess, sameDatabase bool
		if err = admin.QueryRow(ctx, `SELECT recovery_blocked,
		 activated_postmaster_at=pg_catalog.pg_postmaster_start_time(),
		 activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
		 FROM fleet_trust WHERE installation_id=$1`, a.InstallationID).Scan(&storedBlocked, &sameProcess, &sameDatabase); err != nil {
			t.Fatal(err)
		}
		if storedBlocked || (phase == "restarted" && (sameProcess || !sameDatabase)) || (phase == "restored" && (!sameProcess || sameDatabase)) {
			t.Fatal("harness did not produce the expected real database change", phase, storedBlocked, sameProcess, sameDatabase)
		}
		// Even a separately cleared suspension flag cannot hide the mismatch.
		if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET suspended=false WHERE installation_id=$1", a.InstallationID); err != nil {
			t.Fatal(err)
		}
		if _, err = reader.RecoveryState(ctx); err == nil {
			t.Fatal("database served current authority before observation", phase)
		}
	}
	if err = observer.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, observer), a); err != nil && phase != "restored" {
		t.Fatal(err)
	}
	switch phase {
	case "initial":
		var unacceptedLegacy bool
		if err = admin.QueryRow(ctx, `SELECT recovery_blocked AND suspended AND activated_postmaster_at IS NULL AND activated_database_oid IS NULL
		 FROM fleet_trust WHERE installation_id=$1`, a.InstallationID).Scan(&unacceptedLegacy); err != nil || !unacceptedLegacy {
			t.Fatal("migration did not block legacy stored-flag readers without activating the root", err)
		}
		if _, err = reader.RecoveryState(ctx); err == nil {
			t.Fatal("unaccepted database served current authority", phase)
		}
		// Explicit fixture-only stand-in for the first-installation activation,
		// recording the same incarnation facts it does. Never copy this SQL
		// into a production startup hook.
		if _, err = admin.Exec(ctx, `UPDATE fleet_trust SET suspended=false,recovery_blocked=false,
		 activated_postmaster_at=pg_catalog.pg_postmaster_start_time(),
		 activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
		 activated_system_identifier=(pg_catalog.pg_control_system()).system_identifier::text,
		 activated_timeline=('x'||substr(pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()),1,8))::bit(32)::integer
		 WHERE installation_id=$1`, a.InstallationID); err != nil {
			t.Fatal(err)
		}
		if _, err := replaceSyntheticFleetObservationAfterActivation(ctx, admin, a.InstallationID); err != nil {
			t.Fatal("explicit synthetic recovery observation", err)
		}
		if _, err = reader.RecoveryState(ctx); err != nil {
			t.Fatal("synthetic accepted incarnation unavailable", err)
		}
	case "restarted":
		// ADR-226: the product observation pass re-activated the lossless
		// restart; no fixture activation is involved.
		if err = observer.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, observer), a); err != nil {
			t.Fatal("observation after re-activation", err)
		}
		if _, err = reader.RecoveryState(ctx); err != nil {
			t.Fatal("lossless restart was not re-activated", err)
		}
	case "restored":
		// A logical restore into a new database keeps the block.
		if _, err = reader.RecoveryState(ctx); err == nil {
			t.Fatal("restored database served current authority", phase)
		}
	}
	t.Log("verified database recovery phase:", phase)
}
