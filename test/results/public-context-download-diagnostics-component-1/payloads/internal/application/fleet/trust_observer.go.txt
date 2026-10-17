package fleet

import (
	"context"
	"errors"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// FleetTrustProjection observes current protected configuration. It has no
// recovery-clear, epoch-rotation, enrollment, certificate or revocation port.
type FleetTrustProjection interface {
	ReadAdministrationBasis(context.Context) (value.ObservationBasis, error)
	ObserveAdministration(context.Context, value.ObservationBasis, value.Administration) error
	FenceAdministration(context.Context, value.ObservationBasis, time.Time) error
}

type TrustObserver struct {
	Settings   AdministrationReader
	Projection FleetTrustProjection
	Now        func() time.Time
}

// Reconcile refreshes only within the reader's original observation interval.
// A failed read fences prior observations; a newer successful read wins over a
// delayed failure. Recovery remains blocked until its separate protocol passes.
func (s TrustObserver) Reconcile(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.Settings == nil || s.Projection == nil || s.Now == nil {
		return value.ErrUnavailable
	}
	started := s.Now().UTC()
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	basis, err := s.Projection.ReadAdministrationBasis(readCtx)
	if err != nil || !basis.Current(s.Now()) || readCtx.Err() != nil {
		// No native read has started and no retained SQL version can bind a
		// failure fence. Existing finite expiry remains effective.
		return value.ErrUnavailable
	}
	readCtx, end := context.WithDeadline(readCtx, basis.FreshUntil)
	defer end()
	a, err := s.Settings.FleetAdministration(readCtx)
	if err == nil && !a.Valid(s.Now()) {
		err = value.ErrDenied
	}
	unchangedContention := false
	fenceStarted := started
	if err == nil {
		// Bind failure to this exact validated native observation, not an earlier
		// wrapper start that could mistake its own unknown commit for a new read.
		if a.ObservedAt.After(fenceStarted) {
			fenceStarted = a.ObservedAt
		}
		err = s.Projection.ObserveAdministration(readCtx, basis, a)
		// Only the persistence call may classify its exact aborted lock attempt.
		// A source reader returning this error still follows the original fence.
		unchangedContention = errors.Is(err, value.ErrObservationPersistenceContended) && readCtx.Err() == nil && basis.Current(s.Now()) && ctx.Err() == nil && !a.Suspended && a.Valid(s.Now())
	}
	if err != nil && !unchangedContention {
		// The read deadline is not reused for fencing. The parent cancellation is
		// still respected; an unreachable database leaves the old expiry in force.
		fenceCtx, done := context.WithTimeout(ctx, 5*time.Second)
		defer done()
		if fenceErr := s.Projection.FenceAdministration(fenceCtx, basis, fenceStarted); fenceErr != nil {
			return value.ErrUnavailable
		}
	}
	return err
}
