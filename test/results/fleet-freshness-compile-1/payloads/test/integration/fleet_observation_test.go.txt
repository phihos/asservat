package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEnrollmentFleetObservationWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run make fleet-integration or custody-integration")
	}
	var f fixture
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	ctx := context.Background()
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
	config, err := pgxpool.ParseConfig("postgres://fleet_observe_runtime:synthetic-fleet-observe@" + address + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.TLSConfig = tlsConfig
	config.ConnConfig.Fallbacks = nil
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	setup := func() (value.Administration, *postgres.FleetObservation) {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		a := value.Administration{InstallationID: uuid.NewString(), IssuerEpoch: uuid.NewString(), Issuer: "https://identity.example.test", Revision: identity.Revision{UID: "fleet-settings", Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Clients: []string{"console"}, Groups: []string{"operators"}, DeliveryProfiles: []string{"ops"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}
		observer, err := postgres.NewFleetObservation(ctx, pool, a.InstallationID)
		if err != nil {
			t.Fatal(err)
		}
		return a, observer
	}
	refresh := func(a *value.Administration) {
		a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
	}
	check := func(a value.Administration, wantSuspended, wantRecovery bool) {
		t.Helper()
		var suspended, blocked bool
		var observed, until time.Time
		var generation int64
		table := "fleet_trust"
		if !wantRecovery {
			table = "fleet_current_trust"
		}
		if err := admin.QueryRow(ctx, "SELECT suspended,recovery_blocked,observed_at,fresh_until,source_generation FROM "+table+" WHERE installation_id=$1", a.InstallationID).Scan(&suspended, &blocked, &observed, &until, &generation); err != nil {
			t.Fatal(err)
		}
		if suspended != wantSuspended || blocked != wantRecovery {
			t.Fatal("unexpected authority flags", suspended, blocked)
		}
		if !observed.Equal(a.ObservedAt) || !until.Equal(a.FreshUntil) || generation != a.Revision.Generation {
			t.Fatal("observation deadline or revision changed")
		}
	}
	t.Run("enabled-flag-alone-cannot-activate-database", func(t *testing.T) {
		a, o := setup()
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		// An old backup can carry both flags cleared. Configuration freshness
		// is not independent evidence that this database may serve authority.
		if _, err := admin.Exec(ctx, "UPDATE fleet_trust SET suspended=false,recovery_blocked=false WHERE installation_id=$1", a.InstallationID); err != nil {
			t.Fatal(err)
		}
		refresh(&a)
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		reader, err := postgres.NewRecoveryReader(ctx, pool, a.InstallationID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = reader.RecoveryState(ctx); err == nil {
			t.Fatal("restored enabled flags plus current configuration reactivated the database")
		}
	})
	t.Run("missing-root-starts-blocked-and-restart-cannot-clear", func(t *testing.T) {
		a, o := setup()
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		check(a, true, true)
		restarted, err := postgres.NewFleetObservation(ctx, pool, a.InstallationID)
		if err != nil {
			t.Fatal(err)
		}
		refresh(&a)
		if err = restarted.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, restarted), a); err != nil {
			t.Fatal(err)
		}
		check(a, true, true)
	})
	for _, field := range []string{"postmaster", "database"} {
		t.Run("stale-activation-"+field, func(t *testing.T) {
			a, o := setup()
			if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
				t.Fatal(err)
			}
			// Model independent activation with fixture-only administrator SQL.
			if _, err := admin.Exec(ctx, `UPDATE fleet_trust SET suspended=false,recovery_blocked=false,
			 activated_postmaster_at=pg_catalog.pg_postmaster_start_time(),
			 activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
			 WHERE installation_id=$1`, a.InstallationID); err != nil {
				t.Fatal(err)
			}
			if _, err := seedSyntheticFleetObservation(ctx, admin, a.InstallationID); err != nil {
				t.Fatal("explicit synthetic activation observation", err)
			}
			reader, err := postgres.NewRecoveryReader(ctx, pool, a.InstallationID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = reader.RecoveryState(ctx); err != nil {
				t.Fatal("current fixture activation unavailable", err)
			}
			change := "activated_postmaster_at=activated_postmaster_at-interval '1 microsecond'"
			if field == "database" {
				change = "activated_database_oid=0::oid"
			}
			if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET "+change+" WHERE installation_id=$1", a.InstallationID); err != nil {
				t.Fatal(err)
			}
			if _, err = reader.RecoveryState(ctx); err == nil {
				t.Fatal("stale activation remained current")
			}
			refresh(&a)
			if err = o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
				t.Fatal(err)
			}
			if _, err = reader.RecoveryState(ctx); err == nil {
				t.Fatal("configuration refresh renewed stale activation")
			}
		})
	}
	t.Run("current-observation-preserves-original-deadline", func(t *testing.T) {
		a, o := setup()
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		// Synthetic separate recovery authority; this observer has no such grant.
		if _, err := admin.Exec(ctx, "UPDATE fleet_trust SET activated_postmaster_at=pg_catalog.pg_postmaster_start_time(),activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),suspended=false,recovery_blocked=false WHERE installation_id=$1", a.InstallationID); err != nil {
			t.Fatal(err)
		}
		if _, err := seedSyntheticFleetObservation(ctx, admin, a.InstallationID); err != nil {
			t.Fatal("explicit synthetic activation observation", err)
		}
		refresh(&a)
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		check(a, false, false)
		a.Suspended = true
		a.Revision.Generation++
		a.Revision.Digest[0]++
		refresh(&a)
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		check(a, true, false)
		a.Suspended = false
		a.Revision.Generation++
		a.Revision.Digest[0]++
		refresh(&a)
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		check(a, false, false)
	})
	t.Run("equal-or-rounded-observation-cannot-extend-or-unfence", func(t *testing.T) {
		a, o := setup()
		a.FreshUntil = a.ObservedAt.Add(3 * time.Second)
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		for _, nanos := range []time.Duration{0, 500 * time.Nanosecond} {
			changed := a
			changed.ObservedAt = changed.ObservedAt.Add(nanos)
			changed.FreshUntil = a.ObservedAt.Add(4 * time.Second)
			if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), changed); err == nil {
				t.Fatal("equal SQL timestamp extended observation")
			}
			check(a, true, true)
		}
		if err := o.FenceAdministration(ctx, fleetBasisFixture(t, ctx, o), a.ObservedAt); err != nil {
			t.Fatal(err)
		}
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err == nil {
			t.Fatal("equal timestamp revived fenced root")
		}
	})
	t.Run("newer-success-wins-over-delayed-failure-and-old-observation", func(t *testing.T) {
		a, o := setup()
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		old := a
		started := time.Now().UTC().Truncate(time.Microsecond)
		time.Sleep(2 * time.Millisecond)
		refresh(&a)
		a.Revision.Generation++
		a.Revision.Digest[0]++
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		if err := o.FenceAdministration(ctx, fleetBasisFixture(t, ctx, o), started); err != nil {
			t.Fatal(err)
		}
		check(a, true, true)
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), old); err == nil {
			t.Fatal("old success overwrote newer snapshot")
		}
		check(a, true, true)
	})
	t.Run("failed-current-read-fences-without-clearing-recovery", func(t *testing.T) {
		a, o := setup()
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, "UPDATE fleet_trust SET suspended=false,recovery_blocked=false WHERE installation_id=$1", a.InstallationID); err != nil {
			t.Fatal(err)
		}
		started := time.Now().UTC().Truncate(time.Microsecond)
		if err := o.FenceAdministration(ctx, fleetBasisFixture(t, ctx, o), started); err != nil {
			t.Fatal(err)
		}
		var suspended, blocked bool
		if err := admin.QueryRow(ctx, "SELECT suspended,recovery_blocked FROM fleet_trust WHERE installation_id=$1", a.InstallationID).Scan(&suspended, &blocked); err != nil {
			t.Fatal(err)
		}
		if !suspended || blocked {
			t.Fatal("read failure changed recovery or left authority live")
		}
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err == nil {
			t.Fatal("pre-failure snapshot resurrected authority")
		}
	})
	for _, mode := range []string{"epoch", "source-uid", "regressed-generation", "same-generation-new-digest", "expired-lock"} {
		t.Run(mode, func(t *testing.T) {
			a, o := setup()
			a.Revision.Generation = 2
			if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
				t.Fatal(err)
			}
			original := a
			refresh(&a)
			switch mode {
			case "epoch":
				a.IssuerEpoch = uuid.NewString()
			case "source-uid":
				a.Revision.UID = "replacement"
			case "regressed-generation":
				a.Revision.Generation = 1
			case "same-generation-new-digest":
				a.Revision.Digest[0]++
			}
			if mode == "expired-lock" {
				a.FreshUntil = time.Now().Add(200 * time.Millisecond)
				tx, err := admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if _, err = tx.Exec(ctx, "SELECT installation_id FROM fleet_trust WHERE installation_id=$1 FOR UPDATE", a.InstallationID); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				basis := fleetBasisFixture(t, ctx, o)
				go func() { done <- o.ObserveAdministration(ctx, basis, a) }()
				time.Sleep(300 * time.Millisecond)
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err = <-done; err == nil {
					t.Fatal("expired observation refreshed trust")
				}
			} else if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err == nil {
				t.Fatal("unsafe observation refreshed trust")
			}
			check(original, true, true)
		})
	}
	t.Run("role-cannot-clear-recovery-rotate-epoch-or-activate-peer", func(t *testing.T) {
		a, o := setup()
		if err := o.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, o), a); err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{"UPDATE fleet_trust SET recovery_blocked=false WHERE installation_id=$1", "UPDATE fleet_trust SET issuer_epoch=gen_random_uuid() WHERE installation_id=$1", "UPDATE fleet_trust SET source_uid='replacement' WHERE installation_id=$1", "DELETE FROM fleet_trust WHERE installation_id=$1", "UPDATE fleet_peer SET enabled=true WHERE installation_id=$1", "UPDATE fleet_bootstrap SET revoked=false WHERE installation_id=$1"} {
			if _, err := pool.Exec(ctx, sql, a.InstallationID); err == nil {
				t.Fatal("observer exceeded purpose")
			}
		}
		if _, err := pool.Exec(ctx, `INSERT INTO fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until,recovery_blocked) VALUES($1,$2,'injected',1,$3,clock_timestamp(),clock_timestamp()+interval '1 second',false)`, uuid.NewString(), uuid.NewString(), a.Revision.Digest[:]); err == nil {
			t.Fatal("observer inserted unblocked root")
		}
		for _, mutation := range []struct{ sql, code string }{
			{"UPDATE fleet_trust SET activated_postmaster_at=pg_catalog.pg_postmaster_start_time() WHERE installation_id=$1", "42501"},
			{"UPDATE fleet_trust SET activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()) WHERE installation_id=$1", "42501"},
			{"UPDATE fleet_trust SET activated_postmaster_at=pg_catalog.pg_postmaster_start_time(),activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()) WHERE installation_id=$1", "42501"},
			// The CTE-backed view is structurally read-only before column ACLs.
			{"UPDATE fleet_current_trust SET recovery_blocked=false WHERE installation_id=$1", "55000"},
			{"UPDATE fleet_current_trust SET issuer_epoch=gen_random_uuid() WHERE installation_id=$1", "55000"},
		} {
			_, err := pool.Exec(ctx, mutation.sql, a.InstallationID)
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != mutation.code {
				t.Fatal("expected exact SQL rejection for recovery mutation", mutation.code, err)
			}
		}
	})
}
