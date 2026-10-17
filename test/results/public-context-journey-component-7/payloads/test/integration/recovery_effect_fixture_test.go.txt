package integration

import (
	"bytes"
	"context"
	"testing"

	"asservat.local/asservat/internal/adapters/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only completed protected recovery activation is synthesized. The ordinary
// read role and final effect checks must use the product adapters.
type recoveryEffectFixture struct {
	installation string
	observation  syntheticFleetBinding
	reader       *postgres.RecoveryReader
	guard        *postgres.RecoveryTransactionGuard
}

func newRecoveryEffectFixtures(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool) func(*testing.T, string) *recoveryEffectFixture {
	pool := poolFor("peer_read_runtime", "synthetic-peer-read")
	t.Cleanup(pool.Close)
	return func(t *testing.T, root string) *recoveryEffectFixture {
		t.Helper()
		f := &recoveryEffectFixture{installation: custodyID()}
		if _, err := admin.Exec(ctx, "INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,'synthetic-recovery',1,$3,false,false,statement_timestamp(),statement_timestamp()+interval '30 seconds')", f.installation, custodyID(), bytes.Repeat([]byte{97}, 32)); err != nil {
			t.Fatal(err)
		}
		var err error
		f.observation, err = seedSyntheticFleetObservation(ctx, admin, f.installation)
		if err != nil {
			t.Fatal(err)
		}
		f.reader, err = postgres.NewRecoveryReader(ctx, pool, f.installation)
		if err != nil {
			t.Fatal(err)
		}
		f.guard, err = postgres.NewRecoveryTransactionGuard(root, f.installation)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
}
