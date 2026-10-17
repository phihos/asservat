package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only existing synthetic native-source fixtures use this convenience. Real
// TrustObserver selects the basis before its independent source read itself.
func fleetBasisFixture(t *testing.T, ctx context.Context, o *postgres.FleetObservation) fleet.ObservationBasis {
	t.Helper()
	b, err := o.ReadAdministrationBasis(ctx)
	if err != nil {
		t.Fatal("original SQL observation basis", err)
	}
	return b
}

// Explicit exclusive authority mutation stand-in, not a long-lived production
// bridge. Unchanged renewals no longer conflict with a retained bridge SHARE.
func withFleetExclusiveFixture(ctx context.Context, admin *pgxpool.Pool, installation string, fn func(context.Context) error) (result error) {
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := admin.Begin(call)
	if err != nil {
		return err
	}
	defer func() {
		clean, end := context.WithTimeout(context.Background(), time.Second)
		defer end()
		if err := tx.Rollback(clean); err != nil && !errors.Is(err, pgx.ErrTxClosed) && result == nil {
			result = err
		}
	}()
	if _, err = tx.Exec(call, "SELECT installation_id FROM public.fleet_trust WHERE installation_id=$1 FOR UPDATE", installation); err != nil {
		return err
	}
	return fn(call)
}
