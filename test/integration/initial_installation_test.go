package integration

import (
	"context"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// Explicit synthetic Kubernetes boundary. Native record/admission/UID tests are
// separate; this fixture never claims to attest an actual installation Pod.
type initialWitnessFixture struct {
	mu    sync.Mutex
	scope value.InstallationWitnessScope
	claim *value.InitialActivationClaim
}

func (f *initialWitnessFixture) ReadInstallationWitness(context.Context) (value.InstallationWitness, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := time.Now().UTC().Truncate(time.Microsecond)
	w := value.InstallationWitness{Scope: f.scope, ResourceVersion: "1", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	if f.claim != nil {
		c := *f.claim
		w.Claim = &c
	}
	return w, nil
}

type initialAdminFixture struct{ a value.Administration }

func (f *initialAdminFixture) FleetAdministration(context.Context) (value.Administration, error) {
	a := f.a
	a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
	return a, nil
}
