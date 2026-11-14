package bootstrap

import (
	"context"
	"sync/atomic"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

type localDirectInputs struct {
	owner         *observationForwardFixture
	mode          string
	addresses     map[string][]string
	tokens, lists atomic.Int32
}

func (f *localDirectInputs) ReadOwnerObservationDialCandidates(ctx context.Context, c value.APIContextOwnerCandidates) (kube.OwnerObservationDialCandidates, error) {
	f.lists.Add(1)
	groups, err := f.owner.ReadyOwnerObservationCandidates(ctx, c)
	if err != nil {
		return kube.OwnerObservationDialCandidates{}, err
	}
	addresses := map[string][]string{}
	for _, g := range groups.Groups {
		addresses[g.PodUID] = []string{"10.0.0.8"}
	}
	if f.addresses != nil {
		addresses = f.addresses
	}
	if f.mode == "wrong-address" {
		for k := range addresses {
			addresses[k] = []string{"10.0.0.9"}
		}
	}
	return kube.OwnerObservationDialCandidates{Groups: groups, Addresses: addresses}, nil
}
func (f *localDirectInputs) ReadClusterObservationToken(ctx context.Context) ([]byte, error) {
	f.tokens.Add(1)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return []byte(localObservationFixtureToken), nil
}

type localDirectRegistry struct {
	app.OwnerCertificateRegistry
	f     *localReceiverFixture
	mode  string
	reads atomic.Int32
	until time.Time
}

func (r *localDirectRegistry) ReadOwnerRegistration(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	r.reads.Add(1)
	if r.mode == "revoked-after-get" && r.f.get.Load() > 0 || r.mode == "revoked-after-post" && r.f.post.Load() > 0 {
		return value.OwnerRegistrationObservation{}, value.ErrUnavailable
	}
	v, err := r.OwnerCertificateRegistry.ReadOwnerRegistration(ctx, c)
	if !r.until.IsZero() {
		if v.FreshUntil.After(r.until) {
			v.FreshUntil = r.until
		}
	}
	return v, err
}
