package fleet

import (
	"context"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// Models SQL's exact original-version/start predicates, not a successful SQL
// commit or its transport. The dedicated native fixture exercises the latter.
type unknownCommitStartFixture struct {
	a             value.Administration
	basis         value.ObservationBasis
	now           time.Time
	storedStart   time.Time
	storedVersion int64
	mode          string
	fenced        bool
	attempted     bool
	suppliedStart time.Time
}

func (f *unknownCommitStartFixture) ReadAdministrationBasis(context.Context) (value.ObservationBasis, error) {
	return f.basis, nil
}
func (f *unknownCommitStartFixture) FleetAdministration(context.Context) (value.Administration, error) {
	f.now = f.a.ObservedAt.Add(time.Microsecond)
	return f.a, nil
}
func (f *unknownCommitStartFixture) ObserveAdministration(_ context.Context, b value.ObservationBasis, a value.Administration) error {
	f.storedStart = a.ObservedAt
	f.storedVersion = b.SemanticVersion
	if f.mode == "newer-observation" {
		f.storedStart = a.ObservedAt.Add(time.Microsecond)
	}
	if f.mode == "newer-semantic-version" {
		f.storedVersion++
	}
	return value.ErrUnavailable
}
func (f *unknownCommitStartFixture) FenceAdministration(_ context.Context, b value.ObservationBasis, started time.Time) error {
	f.attempted = true
	f.suppliedStart = started
	f.fenced = b.SemanticVersion == f.storedVersion && !started.Before(f.storedStart)
	return nil
}
func TestTrustObserverUnknownCommitRetainsItsActualNativeStart(t *testing.T) {
	for _, mode := range []string{"own-unknown-commit", "newer-observation", "newer-semantic-version"} {
		t.Run(mode, func(t *testing.T) {
			outer := time.Now().UTC().Truncate(time.Microsecond)
			a := workerSchedulingAdministration()
			a.ObservedAt = outer.Add(time.Millisecond)
			a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
			f := &unknownCommitStartFixture{a: a, basis: trustObservationBasis(outer), now: outer, mode: mode}
			originalUntil := a.FreshUntil
			err := (TrustObserver{Settings: f, Projection: f, Now: func() time.Time { return f.now }}).Reconcile(t.Context())
			if err == nil || !f.attempted || f.fenced != (mode == "own-unknown-commit") || !f.suppliedStart.Equal(a.ObservedAt) || f.a.FreshUntil != originalUntil {
				t.Fatal("own result mistaken for newer source, or newer root fenced")
			}
		})
	}
}
