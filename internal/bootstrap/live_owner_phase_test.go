package bootstrap

import (
	"context"
	"testing"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/domain/fleet"
	v "asservat.local/asservat/internal/domain/live"
)

func TestLiveOwnerPhasePreservesOriginalObservationAndFreshFinalPhase(t *testing.T) {
	old, source := newObservationForwardFixture(t, "valid", 0)
	certificate, e := old.client.ClientCertificate()
	if e != nil {
		t.Fatal(e)
	}
	// Independently obtain one valid observation, then freeze the original
	// interval. Reread must not manufacture a later observed/freshness time.
	first := liveOwnerPhase(old.owners)
	a, e := first.Registry.ReadOwnerRegistration(t.Context(), certificate)
	if e != nil {
		t.Fatal(e)
	}
	reads := source.registry.Load()
	b, e := first.Registry.ReadOwnerRegistration(t.Context(), certificate)
	if e != nil || !a.ObservedAt.Equal(b.ObservedAt) || !a.FreshUntil.Equal(b.FreshUntil) || source.registry.Load() != reads {
		t.Fatal("same phase renewed or reread registry", e)
	}
	// Caller-owned configuration mutations cannot change the retained original.
	b.Configuration.Configuration.Revision.Generation++
	c, e := first.Registry.ReadOwnerRegistration(t.Context(), certificate)
	if e != nil || c.Configuration.Configuration.Revision != a.Configuration.Configuration.Revision {
		t.Fatal("mutable phase proof", e)
	}
	source.mu.Lock()
	clear(source.identities)
	source.mu.Unlock()
	final := liveOwnerPhase(old.owners)
	if _, e = final.Registry.ReadOwnerRegistration(t.Context(), certificate); e == nil || source.registry.Load() != reads+1 {
		t.Fatal("final phase reused revoked registry", e)
	}
}
func TestLiveOwnerPhaseCannotRenewAfterBlockingPastOriginalBound(t *testing.T) {
	old, source := newObservationForwardFixture(t, "valid", 0)
	source.bound = time.Now().Add(200 * time.Millisecond)
	certificate, e := old.client.ClientCertificate()
	if e != nil {
		t.Fatal(e)
	}
	phase := liveOwnerPhase(old.owners)
	first, e := phase.Registry.ReadOwnerRegistration(t.Context(), certificate)
	if e != nil {
		t.Fatal(e)
	}
	timer := time.NewTimer(time.Until(first.FreshUntil) + time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	source.bound = time.Now().Add(5 * time.Second) // later provider freshness cannot renew this phase
	reads := source.registry.Load()
	if _, e = phase.Registry.ReadOwnerRegistration(context.Background(), certificate); e == nil || source.registry.Load() != reads {
		t.Fatal("expired original proof renewed", e)
	}
	// A separate final phase may independently read the current observation.
	if next, e := liveOwnerPhase(old.owners).Registry.ReadOwnerRegistration(t.Context(), certificate); e != nil || !next.FreshUntil.After(first.FreshUntil) {
		t.Fatal("fresh phase unavailable", e)
	}
	if _, e = phase.Registry.ReadOwnerRegistration(t.Context(), fleet.OwnerCertificate{}); e == nil {
		t.Fatal("foreign certificate reused original proof")
	}
}

type liveOwnerSlowRoute struct {
	base  fleetapp.OwnerRouteReader
	calls int
}

func (r *liveOwnerSlowRoute) CurrentOwnerRoute(ctx context.Context, b fleet.OwnerBinding) (fleet.OwnerRoute, error) {
	r.calls++
	if r.calls > 1 {
		if e := liveOwnerProofWait(ctx); e != nil {
			return fleet.OwnerRoute{}, e
		}
	}
	return r.base.CurrentOwnerRoute(ctx, b)
}

type liveOwnerSlowProtection struct {
	base fleetapp.OwnerProtectionReader
}

func (p liveOwnerSlowProtection) ReadOwnerProtection(ctx context.Context, pool fleet.OwnerPool) (fleet.OwnerProtection, error) {
	if e := liveOwnerProofWait(ctx); e != nil {
		return fleet.OwnerProtection{}, e
	}
	return p.base.ReadOwnerProtection(ctx, pool)
}
func liveOwnerProofWait(ctx context.Context) error {
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestLiveOwnerActualH2PhaseDoesNotRenewAcrossBlockedPeerProof(t *testing.T) {
	for _, mode := range []string{"route", "protection"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveOwnerH2Fixture(t, 1)
			f.peer.bound = time.Now().Add(100 * time.Millisecond)
			owners := *f.forward.owners
			if mode == "route" {
				owners.Routes = &liveOwnerSlowRoute{base: owners.Routes}
			} else {
				owners.Protection = liveOwnerSlowProtection{base: owners.Protection}
			}
			f.forward.owners = &owners
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			d, e := f.begin(ctx, liveapp.Command{Read: &v.Read{ID: f.watch.ID, Cursor: *f.watch.Cursor}})
			if e == nil {
				_ = d.Close(ctx)
				t.Fatal("blocked proof renewed original admission")
			}
			if f.facts.reads.Load() != 0 || len(f.forward.slots) != 0 {
				t.Fatal("expired peer reached source or leaked slot")
			}
		})
	}
}
