package integration

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// recoveryEffectFixture seeds the installation's trust row and fleet observation.
type recoveryEffectFixture struct {
	installation string
	observation  syntheticFleetBinding
}

func newRecoveryEffectFixtures(t *testing.T, ctx context.Context, admin *pgxpool.Pool) func(*testing.T, string) *recoveryEffectFixture {
	return func(t *testing.T, root string) *recoveryEffectFixture {
		t.Helper()
		f := &recoveryEffectFixture{installation: custodyID()}
		if _, err := admin.Exec(ctx, "INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,'synthetic-recovery',1,$3)", f.installation, custodyID(), bytes.Repeat([]byte{97}, 32)); err != nil {
			t.Fatal(err)
		}
		var err error
		f.observation, err = readSyntheticFleetBinding(ctx, admin, f.installation)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
}

// fixtureIssuerEpoch reads the seeded installation's issuer epoch.
func fixtureIssuerEpoch(t *testing.T, ctx context.Context, admin *pgxpool.Pool, installation string) string {
	t.Helper()
	var epoch string
	if e := admin.QueryRow(ctx, "SELECT issuer_epoch::text FROM fleet_trust WHERE installation_id=$1", installation).Scan(&epoch); e != nil {
		t.Fatal(e)
	}
	return epoch
}
