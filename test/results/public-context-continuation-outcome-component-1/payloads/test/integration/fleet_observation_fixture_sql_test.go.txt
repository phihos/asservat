package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Test fixture helpers against real PostgreSQL. This qualifies only explicit
// synthetic authority, never production source observation or activation.
func TestEnrollmentSyntheticFleetObservationBinding(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		path = os.Getenv("ASSERVAT_FLEET_FIXTURES")
	}
	if path == "" {
		t.Skip("owned SQL fixture required")
	}
	var f fixture
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	pc, err := pgxpool.ParseConfig(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	pc.MaxConns = 1
	admin, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	setup := func(t *testing.T) (pgx.Tx, syntheticFleetBinding) {
		t.Helper()
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		id := custodyID()
		_, err = tx.Exec(ctx, `INSERT INTO public.fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,activated_postmaster_at,activated_database_oid,observed_at,fresh_until)
  VALUES($1,$2,'synthetic-binding-regression',1,decode(repeat('61',32),'hex'),false,false,pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),statement_timestamp(),statement_timestamp()+interval '30 seconds')`, id, custodyID())
		if err != nil {
			t.Fatal(err)
		}
		b, err := seedSyntheticFleetObservation(ctx, tx, id)
		if err != nil {
			t.Fatal(err)
		}
		return tx, b
	}
	t.Run("explicit-seed-retains-original-dates-and-binding", func(t *testing.T) {
		tx, b := setup(t)
		got, err := readSyntheticFleetObservationBinding(ctx, tx, b.installation)
		if err != nil || got != b {
			t.Fatal("seed lost exact original tuple", err)
		}
		var exact bool
		if err = tx.QueryRow(ctx, `SELECT o.observed_at=f.observed_at AND o.fresh_until=f.fresh_until FROM public.fleet_observation o JOIN public.fleet_trust f USING(installation_id) WHERE o.installation_id=$1`, b.installation).Scan(&exact); err != nil || !exact {
			t.Fatal("seed changed original interval", err)
		}
		if err = renewSyntheticFleetObservation(ctx, tx, b, 30*time.Second, true); err != nil {
			t.Fatal("positive current renewal", err)
		}
		after, err := readSyntheticFleetObservationBinding(ctx, tx, b.installation)
		if err != nil || after != b {
			t.Fatal("renewal replaced tuple", err)
		}
	})
	t.Run("duplicate-seed-is-not-renewal", func(t *testing.T) {
		tx, b := setup(t)
		if _, err := seedSyntheticFleetObservation(ctx, tx, b.installation); err == nil {
			t.Fatal("seed replaced original observation")
		}
	})
	for _, change := range []struct{ name, sql string }{
		{"version", "semantic_version=semantic_version+1"},
		{"issuer", "issuer_epoch=gen_random_uuid()"},
		{"source-uid", "source_uid='changed-source'"},
		{"source-generation", "source_generation=source_generation+1"},
		{"source-digest", "source_digest=decode(repeat('62',32),'hex')"},
		{"suspension", "suspended=true"},
		{"recovery", "recovery_blocked=true"},
		{"postmaster", "activated_postmaster_at=activated_postmaster_at-interval '1 microsecond'"},
		{"database", "activated_database_oid=0::oid"},
	} {
		t.Run("renew-rejects-"+change.name, func(t *testing.T) {
			tx, b := setup(t)
			var beforeStart, beforeEnd time.Time
			if err := tx.QueryRow(ctx, "SELECT observed_at,fresh_until FROM fleet_observation WHERE installation_id=$1", b.installation).Scan(&beforeStart, &beforeEnd); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "UPDATE fleet_trust SET "+change.sql+" WHERE installation_id=$1", b.installation); err != nil {
				t.Fatal(err)
			}
			if err := renewSyntheticFleetObservation(ctx, tx, b, 30*time.Second, false); err == nil {
				t.Fatal("renewal adopted changed or fenced authority")
			}
			var afterStart, afterEnd time.Time
			if err := tx.QueryRow(ctx, "SELECT observed_at,fresh_until FROM fleet_observation WHERE installation_id=$1", b.installation).Scan(&afterStart, &afterEnd); err != nil || !beforeStart.Equal(afterStart) || !beforeEnd.Equal(afterEnd) {
				t.Fatal("failed renewal modified observation", err)
			}
		})
	}
	t.Run("missing-observation-never-auto-seeded", func(t *testing.T) {
		tx, b := setup(t)
		if _, err := tx.Exec(ctx, "DELETE FROM fleet_observation WHERE installation_id=$1", b.installation); err != nil {
			t.Fatal(err)
		}
		if err := renewSyntheticFleetObservation(ctx, tx, b, 30*time.Second, false); err == nil {
			t.Fatal("renewal fabricated missing observation")
		}
	})
	t.Run("ongoing-expiry-denies-explicit-lifecycle-refresh-retains-binding", func(t *testing.T) {
		tx, b := setup(t)
		if _, err := tx.Exec(ctx, "UPDATE fleet_observation SET observed_at=statement_timestamp()-interval '2 seconds',fresh_until=statement_timestamp()-interval '1 second' WHERE installation_id=$1", b.installation); err != nil {
			t.Fatal(err)
		}
		if err := renewSyntheticFleetObservation(ctx, tx, b, 30*time.Second, true); err == nil {
			t.Fatal("ongoing source revived expired observation")
		}
		if err := renewSyntheticFleetObservation(ctx, tx, b, 30*time.Second, false); err != nil {
			t.Fatal("explicit lifecycle refresh failed", err)
		}
		got, err := readSyntheticFleetObservationBinding(ctx, tx, b.installation)
		if err != nil || got != b {
			t.Fatal("lifecycle refresh changed binding", err)
		}
	})
	t.Run("explicit-reactivation-cannot-be-hidden-in-renewal", func(t *testing.T) {
		tx, b := setup(t)
		if _, err := tx.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", b.installation); err != nil {
			t.Fatal(err)
		}
		if _, err := replaceSyntheticFleetObservationAfterActivation(ctx, tx, b.installation); err == nil {
			t.Fatal("replacement cleared recovery")
		}
		if _, err := tx.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=false WHERE installation_id=$1", b.installation); err != nil {
			t.Fatal(err)
		}
		if err := renewSyntheticFleetObservation(ctx, tx, b, 30*time.Second, false); err == nil {
			t.Fatal("old binding adopted explicit new activation")
		}
		current, err := replaceSyntheticFleetObservationAfterActivation(ctx, tx, b.installation)
		if err != nil || current.version != b.version+2 {
			t.Fatal("explicit administrator reactivation failed", err)
		}
		if err = renewSyntheticFleetObservation(ctx, tx, b, 30*time.Second, false); err == nil {
			t.Fatal("retained stale binding renewed new observation")
		}
		if err = renewSyntheticFleetObservation(ctx, tx, current, 30*time.Second, false); err != nil {
			t.Fatal("explicitly restored binding unavailable", err)
		}
	})
}
