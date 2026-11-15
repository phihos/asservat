package integration

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// syntheticFleetBinding names a seeded installation's static trust row.
type syntheticFleetBinding struct{ installation, issuer string }

func readSyntheticFleetBinding(ctx context.Context, db *pgxpool.Pool, installation string) (syntheticFleetBinding, error) {
	b := syntheticFleetBinding{installation: installation}
	err := db.QueryRow(ctx, "SELECT issuer_epoch::text FROM public.fleet_trust WHERE installation_id=$1", installation).Scan(&b.issuer)
	return b, err
}
