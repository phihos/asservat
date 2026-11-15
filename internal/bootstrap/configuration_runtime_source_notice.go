package bootstrap

import (
	"context"
	"crypto/sha256"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// This fixed wrapper forwards only the actual observer. Scheduling notices
// cannot supply accepted authority or stand in for the separate recovery read.
// It owns no SQL pool, source loop, retry, timestamp renewal or new lifetime.
type configurationRuntimeFleetProjection struct {
	actual    *postgres.FleetObservation
	admission *app.WorkerRuntimeAdmission
}

func (s *configurationRuntimeFleetProjection) ReadAdministrationBasis(ctx context.Context) (fleet.ObservationBasis, error) {
	if s == nil || s.actual == nil || s.admission == nil {
		return fleet.ObservationBasis{}, fleet.ErrUnavailable
	}
	basis, err := s.actual.ReadAdministrationBasis(ctx)
	if err != nil {
		s.admission.InvalidateFleetNotice()
	}
	return basis, err
}

func (s *configurationRuntimeFleetProjection) ObserveAdministration(ctx context.Context, basis fleet.ObservationBasis, a fleet.Administration) error {
	if s == nil || s.actual == nil || s.admission == nil {
		return fleet.ErrUnavailable
	}
	s.admission.NoteFleetObservation(a)
	return s.finishObservation(ctx, a, s.actual.ObserveAdministration(ctx, basis, a))
}

// Keep every failed SQL outcome on the same notice-invalidating path, including
// unchanged persistence contention. This private completion grants no authority.
func (s *configurationRuntimeFleetProjection) finishObservation(ctx context.Context, a fleet.Administration, err error) error {
	if err != nil || ctx.Err() != nil || !a.Valid(time.Now()) {
		s.admission.InvalidateFleetNotice()
		if err != nil {
			return err
		}
		return fleet.ErrUnavailable
	}
	s.admission.NoteFleetCommitted(ctx, a)
	return nil
}

func (s *configurationRuntimeFleetProjection) FenceAdministration(ctx context.Context, basis fleet.ObservationBasis, started time.Time) error {
	if s == nil || s.actual == nil || s.admission == nil {
		return fleet.ErrUnavailable
	}
	s.admission.InvalidateFleetNotice()
	return s.actual.FenceAdministration(ctx, basis, started)
}

// installationTrust is the fleet observer's source: the generated IDs alone.
type installationTrust struct{ installation, epoch string }

func (t installationTrust) FleetAdministration(ctx context.Context) (fleet.Administration, error) {
	if ctx.Err() != nil {
		return fleet.Administration{}, fleet.ErrUnavailable
	}
	return installationTrustAt(t.installation, t.epoch, time.Now()), nil
}

// installationTrustAt is the fleet trust observation that setup seeds and the
// hub-worker refreshes. Its source is the generated IDs alone, so its
// revision never changes for one installation.
func installationTrustAt(installation, issuerEpoch string, now time.Time) fleet.Administration {
	digest := sha256.Sum256([]byte("asservat-installation-trust/v1\x00" + installation + "\x00" + issuerEpoch))
	return fleet.Administration{InstallationID: installation, IssuerEpoch: issuerEpoch, Revision: identity.Revision{UID: installation, Generation: 1, Digest: digest}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
}
