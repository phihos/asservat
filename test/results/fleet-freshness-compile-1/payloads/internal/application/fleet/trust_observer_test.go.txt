package fleet

import (
	"context"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

type trustObservationFixture struct {
	a                                   value.Administration
	readError, observeError, fenceError error
	basis                               value.ObservationBasis
	basisError                          error
	read                                bool
	observedBasis, fencedBasis          value.ObservationBasis
	observed, fenced                    bool
	fenceStarted                        time.Time
}

func (f *trustObservationFixture) FleetAdministration(context.Context) (value.Administration, error) {
	f.read = true
	return f.a, f.readError
}
func (f *trustObservationFixture) ReadAdministrationBasis(context.Context) (value.ObservationBasis, error) {
	return f.basis, f.basisError
}
func (f *trustObservationFixture) ObserveAdministration(_ context.Context, b value.ObservationBasis, _ value.Administration) error {
	f.observedBasis = b
	f.observed = true
	return f.observeError
}
func (f *trustObservationFixture) FenceAdministration(_ context.Context, b value.ObservationBasis, started time.Time) error {
	f.fenced = true
	f.fencedBasis = b
	f.fenceStarted = started
	return f.fenceError
}
func TestTrustObservationFencesUnavailableOrInvalidSource(t *testing.T) {
	for _, mode := range []string{"unavailable", "invalid", "fence-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			f := &trustObservationFixture{basis: trustObservationBasis(now)}
			if mode != "invalid" {
				f.readError = value.ErrUnavailable
			}
			if mode == "fence-unavailable" {
				f.fenceError = value.ErrUnavailable
			}
			observer := TrustObserver{Settings: f, Projection: f, Now: func() time.Time { return now }}
			if err := observer.Reconcile(context.Background()); err == nil || !f.fenced || f.observed || !f.fenceStarted.Equal(now) {
				t.Fatal("failed source did not fence prior trust", err)
			}
		})
	}
}

func trustObservationBasis(now time.Time) value.ObservationBasis {
	return value.ObservationBasis{InstallationID: "11111111-1111-4111-8111-111111111111", Database: value.DatabaseIncarnation{StartedAt: now.Add(-time.Hour).Truncate(time.Microsecond), DatabaseOID: 42, SchemaVersion: 59}, SemanticVersion: 7, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
}
func TestTrustObserverMissingBasisNeverStartsSourceOrUnboundFence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, mode := range []string{"missing", "expired", "error"} {
		t.Run(mode, func(t *testing.T) {
			f := &trustObservationFixture{}
			if mode == "expired" {
				f.basis = trustObservationBasis(now.Add(-5 * time.Second))
			}
			if mode == "error" {
				f.basis = trustObservationBasis(now)
				f.basisError = value.ErrUnavailable
			}
			err := (TrustObserver{Settings: f, Projection: f, Now: func() time.Time { return now }}).Reconcile(t.Context())
			if err == nil || f.read || f.observed || f.fenced {
				t.Fatal("unbound source/fence", err)
			}
		})
	}
}

type originalBasisFixture struct {
	basis                   value.ObservationBasis
	now                     time.Time
	phase                   int
	sourceErr               error
	sourceUntil, fenceUntil time.Time
	fenceBasis              value.ObservationBasis
	expiredSource           bool
}

func (f *originalBasisFixture) ReadAdministrationBasis(ctx context.Context) (value.ObservationBasis, error) {
	if f.phase != 0 || ctx.Err() != nil {
		return value.ObservationBasis{}, value.ErrUnavailable
	}
	f.phase = 1
	return f.basis, nil
}
func (f *originalBasisFixture) FleetAdministration(ctx context.Context) (value.Administration, error) {
	if f.phase != 1 {
		return value.Administration{}, value.ErrUnavailable
	}
	f.phase = 2
	f.sourceUntil, _ = ctx.Deadline()
	if f.expiredSource {
		f.now = f.basis.FreshUntil
	}
	return value.Administration{}, f.sourceErr
}
func (f *originalBasisFixture) ObserveAdministration(context.Context, value.ObservationBasis, value.Administration) error {
	f.phase = 99
	return value.ErrUnavailable
}
func (f *originalBasisFixture) FenceAdministration(ctx context.Context, b value.ObservationBasis, _ time.Time) error {
	if f.phase != 2 || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	f.phase = 3
	f.fenceBasis = b
	f.fenceUntil, _ = ctx.Deadline()
	return nil
}
func TestTrustObserverExpiredPositiveBasisStillFencesOriginalVersion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := &originalBasisFixture{basis: trustObservationBasis(now), now: now, sourceErr: value.ErrUnavailable, expiredSource: true}
	err := (TrustObserver{Settings: f, Projection: f, Now: func() time.Time { return f.now }}).Reconcile(t.Context())
	if err == nil || f.phase != 3 || f.fenceBasis != f.basis || f.basis.Current(f.now) || f.sourceUntil.After(f.basis.FreshUntil) || !f.fenceUntil.After(time.Now()) {
		t.Fatal("failure did not retain original expired basis and independent bounded fence")
	}
}
func TestTrustObserverBasisReadAndSourcePreserveCallerDeadline(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	callerUntil := now.Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), callerUntil)
	defer cancel()
	f := &originalBasisFixture{basis: trustObservationBasis(now), now: now, sourceErr: value.ErrUnavailable}
	err := (TrustObserver{Settings: f, Projection: f, Now: func() time.Time { return f.now }}).Reconcile(ctx)
	if err == nil || f.phase != 3 || !f.sourceUntil.Equal(callerUntil) || !f.fenceUntil.Equal(callerUntil) || f.fenceBasis != f.basis {
		t.Fatal("pre-read renewed or detached caller deadline")
	}
}
