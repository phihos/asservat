package bootstrap

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

// These are independent current observations of the same immutable registration.
// Only the first observation is short; this does not renew the native operation.
type phaseRegistrationFixture struct {
	app.OwnerCertificateRegistry
	firstUntil time.Time
	shortRead  int32
	fixed      bool
	delayRead  int32
	reads      atomic.Int32
	t          *testing.T
}

func (r *phaseRegistrationFixture) ReadOwnerRegistration(ctx context.Context, leaf value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	n := r.reads.Add(1)
	if r.t != nil {
		end, _ := ctx.Deadline()
		r.t.Logf("registration %d inputEnd=%s", n, end.Format(time.RFC3339Nano))
	}
	if n == r.delayRead {
		timer := time.NewTimer(time.Until(r.firstUntil.Add(100 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return value.OwnerRegistrationObservation{}, ctx.Err()
		case <-timer.C:
		}
	}
	v, err := r.OwnerCertificateRegistry.ReadOwnerRegistration(ctx, leaf)
	if (n == 1 && r.shortRead == 0 || n == r.shortRead || r.fixed) && v.FreshUntil.After(r.firstUntil) {
		v.FreshUntil = r.firstUntil
	}
	return v, err
}

type phaseCandidateFixture struct {
	app.OwnerObservationCandidateSource
	until time.Time
}

func (f phaseCandidateFixture) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	v, err := f.OwnerObservationCandidateSource.ReadOwnerObservationCandidates(ctx)
	if f.until.Before(v.ValidUntil) {
		v.ValidUntil = f.until
	}
	return v, err
}

type phaseReadyReader func(context.Context, value.APIContextOwnerCandidates) (kube.OwnerObservationDialCandidates, error)

func (f phaseReadyReader) ReadOwnerObservationDialCandidates(ctx context.Context, c value.APIContextOwnerCandidates) (kube.OwnerObservationDialCandidates, error) {
	return f(ctx, c)
}
