package integration

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// One fixed independently selected synthetic source, not a reader that refreshes
// time on access. SQL observation, original activation and bridge are actual.
type fixedContentionAdministration struct{ value fleet.Administration }

func (s fixedContentionAdministration) FleetAdministration(context.Context) (fleet.Administration, error) {
	return s.value, nil
}

type countedContentionProjection struct {
	actual               *postgres.FleetObservation
	fences               int
	lost                 *fleetObservationCommitLoss
	admin                *pgxpool.Pool
	expected             fleet.Administration
	committedBeforeFence bool
	basis                fleet.ObservationBasis
	fenceStarted         time.Time
}

func (p *countedContentionProjection) ReadAdministrationBasis(ctx context.Context) (fleet.ObservationBasis, error) {
	b, err := p.actual.ReadAdministrationBasis(ctx)
	p.basis = b
	return b, err
}
func (p *countedContentionProjection) ObserveAdministration(ctx context.Context, basis fleet.ObservationBasis, a fleet.Administration) error {
	return p.actual.ObserveAdministration(ctx, basis, a)
}
func (p *countedContentionProjection) FenceAdministration(ctx context.Context, basis fleet.ObservationBasis, started time.Time) error {
	p.fences++
	p.fenceStarted = started
	if p.lost != nil && p.lost.lost.Load() {
		// Read the committed actual row before applying the existing failure fence.
		// This is test evidence, never accepted authority or a retry of COMMIT.
		_ = p.admin.QueryRow(ctx, `SELECT NOT suspended AND observed_at=$2 AND fresh_until=$3 FROM public.fleet_current_trust WHERE installation_id=$1`, p.expected.InstallationID, p.expected.ObservedAt, p.expected.ObservedAt.Add(30*time.Second)).Scan(&p.committedBeforeFence)
	}
	return p.actual.FenceAdministration(ctx, basis, started)
}

// Unlike the historical fixed source above, this fixture samples native start
// inside Settings, after Reconcile and the actual SQL basis read have begun.
// Only the native source is synthetic; COMMIT loss and SQL fence are actual.
type nativeStartedContentionAdministration struct {
	value  fleet.Administration
	onRead func(fleet.Administration)
}

func (s nativeStartedContentionAdministration) FleetAdministration(context.Context) (fleet.Administration, error) {
	a := s.value
	a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
	s.onRead(a)
	return a, nil
}
