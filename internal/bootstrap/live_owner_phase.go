package bootstrap

import (
	"context"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/fleet"
)

// A phase owns at most the two exact local/remote certificate observations.
// OwnerAuthenticator's second registry read reuses the independently obtained
// first observation, including its original freshness, configuration and
// registration. A final admission creates a NEW phase and rereads the registry.
// This is neither a whole-command cache nor a renewable peer assertion.
type liveOwnerPhaseRegistry struct {
	base     app.OwnerCertificateRegistry
	now      func() time.Time
	mu       sync.Mutex
	observed map[fleet.OwnerCertificate]fleet.OwnerRegistrationObservation
}

func liveOwnerPhase(owners *app.OwnerAuthenticator) *app.OwnerAuthenticator {
	copy := *owners
	copy.Registry = &liveOwnerPhaseRegistry{base: owners.Registry, now: owners.Now, observed: make(map[fleet.OwnerCertificate]fleet.OwnerRegistrationObservation, 2)}
	return &copy
}
func (p *liveOwnerPhaseRegistry) ReadOwnerRegistration(ctx context.Context, c fleet.OwnerCertificate) (fleet.OwnerRegistrationObservation, error) {
	var zero fleet.OwnerRegistrationObservation
	if ctx == nil || ctx.Err() != nil {
		return zero, fleet.ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.observed[c]; ok {
		if !old.Valid(p.now()) || old.Certificate != c || ctx.Err() != nil {
			return zero, fleet.ErrUnavailable
		}
		old.Configuration.Configuration = old.Configuration.Configuration.Clone()
		return old, nil
	}
	if len(p.observed) >= 2 {
		return zero, fleet.ErrUnavailable
	}
	first, e := p.base.ReadOwnerRegistration(ctx, c)
	if e != nil || !first.Valid(p.now()) || first.Certificate != c || ctx.Err() != nil {
		return zero, fleet.ErrUnavailable
	}
	first.Configuration.Configuration = first.Configuration.Configuration.Clone()
	p.observed[c] = first
	out := first
	out.Configuration.Configuration = first.Configuration.Configuration.Clone()
	return out, nil
}
