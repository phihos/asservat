package integration

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/fleet"
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
