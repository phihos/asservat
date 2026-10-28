package bootstrap

import (
	"context"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

type localPendingNative struct{ *pendingOwnerNative }

func (n *localPendingNative) Claim(ctx context.Context, _ []byte, _ string) (time.Time, error) {
	if ctx.Err() != nil {
		return time.Time{}, ctx.Err()
	}
	return n.facts.FreshUntil, nil
}
func localPendingFixture(t *testing.T) (*pendingFixture, *ownerLocalObservationPending, *ownerLocalObservationPendingEntry, *localPendingNative, value.ClusterObservationLocator) {
	t.Helper()
	return localPendingFixtureIn(t, nil, nil, 1, 0)
}

func localPendingFixtureIn(t *testing.T, s *ownerLocalObservationPending, anchor *pendingFixture, maximum int, lifetime time.Duration) (*pendingFixture, *ownerLocalObservationPending, *ownerLocalObservationPendingEntry, *localPendingNative, value.ClusterObservationLocator) {
	t.Helper()
	var f *pendingFixture
	if anchor == nil {
		f = newPendingFixture(t)
	} else {
		cloned := *anchor
		f = &cloned
	}
	if lifetime > 0 {
		f.request.RequestedAt = time.Now()
		f.request.NotAfter = f.request.RequestedAt.Add(lifetime)
		var cancel context.CancelFunc
		f.get, cancel = context.WithDeadline(context.Background(), f.request.NotAfter)
		t.Cleanup(cancel)
	}
	if s == nil {
		var err error
		s, err = newOwnerLocalObservationPending(context.Background(), f.store.pin, f.server.Binding, maximum, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
	}
	// Every fixture retains independent operation identity in the shared store.
	if lifetime > 0 {
		f.request.ID = ownerRandomID()
		f.request.Challenge = ownerRandomID()
	}
	e, err := s.reserve(f.get, f.request.LocatorQuery(), observationForwardID(701), []byte(localObservationFixtureToken), f.server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.finishGET)
	request := value.OwnerObservationRequest{RootID: f.request.RootID, ID: f.request.ID, Challenge: f.request.Challenge, RequestedAt: f.request.RequestedAt, NotAfter: f.request.NotAfter}
	native := &localPendingNative{&pendingOwnerNative{facts: value.OwnerObservationNativeFacts{Request: request, Pin: s.pin, ObservedAt: time.Now(), FreshUntil: e.end, Peers: []value.OwnerObservationNativePeer{{Binding: f.server.Binding, Pod: "owner-" + f.server.Binding.PodUID, ReplicaSetUID: runtimeID, Addresses: []string{"10.0.0.8"}, WorkloadDigest: artifact.Digest{45}}}}}}
	registry := &ownerLocalObservationRegistry{root: e.work, pin: s.pin, server: f.keys, leaf: f.server, registry: f.registry, now: time.Now, end: e.end}
	op, err := mtls.NewOwnerObservationOperation(e.work, s.pin, request, f.keys, registry, native, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	locator := value.ClusterObservationLocator{RequestID: request.ID, Challenge: request.Challenge, RootID: request.RootID, ClusterID: f.request.ClusterID, Holder: f.server.Binding, ExchangeID: observationForwardID(814), Sequence: 1, Interval: value.ClusterObservationInterval{ObservedAt: time.Now(), FreshUntil: e.end}}
	// Isolate bookkeeping from the holder; actual reservation/stream/TLS is
	// exercised by TestLocalReceiverActualFramedClaimAndUncertainDelivery.
	e.mu.Lock()
	e.operation, e.native, e.registry, e.locator, e.phase = op, native, registry, locator, ownerLocalObservationPrepared
	e.mu.Unlock()
	return f, s, e, native, locator
}
func TestLocalPendingRetainsTokenAndOriginalGETLifetime(t *testing.T) {
	f, s, e, native, locator := localPendingFixture(t)
	if _, err := e.possibleDelivery(); err != nil {
		t.Fatal(err)
	}
	e.finishGET()
	f.cancelGet()
	if e.work.Err() != nil || native.closed.Load() != 0 {
		t.Fatal("GET completion killed retained proof")
	}
	call, cancel := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer cancel()
	input := value.ClusterObservationClaim{Request: f.request, Locator: locator}
	for _, changed := range []string{"token", "pod", "leaf", "sequence"} {
		token := []byte(localObservationFixtureToken)
		pod := observationForwardID(701)
		server := f.server
		v := input
		switch changed {
		case "token":
			token = []byte("replacement")
		case "pod":
			pod = observationForwardID(702)
		case "leaf":
			server.Digest[0]++
		case "sequence":
			v.Locator.Sequence++
		}
		if h, err := s.claim(call, v, pod, token, server); err == nil {
			h.Close()
			t.Fatal("changed original tuple admitted", changed)
		}
	}
	claim, err := s.claim(call, input, observationForwardID(701), []byte(localObservationFixtureToken), f.server)
	if err != nil {
		t.Fatal(err)
	}
	if end, _ := claim.call.Deadline(); !end.Equal(locator.Interval.FreshUntil) {
		t.Fatal("claim renewed original cutoff")
	}
	claim.Close()
	if native.closed.Load() != 1 || len(e.token) != 0 {
		t.Fatal("native/token not joined and cleared")
	}
	if _, err = s.claim(call, input, observationForwardID(701), []byte(localObservationFixtureToken), f.server); err == nil {
		t.Fatal("duplicate claim")
	}
	other := f.request.LocatorQuery()
	other.RequestID = observationForwardID(900)
	if _, err = s.reserve(call, other, observationForwardID(701), []byte(localObservationFixtureToken), f.server); err == nil {
		t.Fatal("completed or unknown output refunded original slot")
	}
}
func TestLocalPendingOneConcurrentClaim(t *testing.T) {
	f, s, e, native, locator := localPendingFixture(t)
	if _, err := e.possibleDelivery(); err != nil {
		t.Fatal(err)
	}
	e.finishGET()
	call, cancel := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer cancel()
	var joined sync.WaitGroup
	winners := make(chan *ownerLocalObservationPendingClaim, 8)
	for range 8 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			h, err := s.claim(call, value.ClusterObservationClaim{Request: f.request, Locator: locator}, observationForwardID(701), []byte(localObservationFixtureToken), f.server)
			if err == nil {
				winners <- h
			}
		}()
	}
	joined.Wait()
	close(winners)
	n := 0
	for h := range winners {
		n++
		h.Close()
	}
	if n != 1 || native.closed.Load() != 1 {
		t.Fatal("concurrent claim/native Close", n, native.closed.Load())
	}
}
func TestLocalPendingCancelledGETRetainsSpentMarker(t *testing.T) {
	f, s, e, native, _ := localPendingFixture(t)
	f.cancelGet()
	if _, err := e.possibleDelivery(); err == nil {
		t.Fatal("cancelled GET exposed locator")
	}
	e.finishGET()
	pendingWait(t, e.closed, "local cancelled GET")
	if native.closed.Load() != 1 || len(e.token) != 0 {
		t.Fatal("cancellation did not join/clear")
	}
	call, cancel := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer cancel()
	if _, err := s.reserve(call, f.request.LocatorQuery(), observationForwardID(701), []byte(localObservationFixtureToken), f.server); err == nil {
		t.Fatal("cancelled locator reopened")
	}
}

type localRegistryCutoffFixture struct {
	app.OwnerCertificateRegistry
	until time.Time
	calls int
	t     *testing.T
}

func (r *localRegistryCutoffFixture) ReadOwnerRegistration(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	r.calls++
	if r.calls > 1 {
		if end, ok := ctx.Deadline(); !ok || end.After(r.until) {
			r.t.Fatal("newly observed cap did not reach following SQL call")
		}
	}
	v, err := r.OwnerCertificateRegistry.ReadOwnerRegistration(ctx, c)
	if err == nil && v.FreshUntil.After(r.until) {
		v.FreshUntil = r.until
	}
	return v, err
}
func TestLocalRegistryOriginalCapAndChangedConfiguration(t *testing.T) {
	f := newPendingFixture(t)
	bound := time.Now().Add(time.Second)
	source := &localRegistryCutoffFixture{OwnerCertificateRegistry: f.registry, until: bound, t: t}
	r := &ownerLocalObservationRegistry{root: f.get, pin: f.store.pin, server: f.keys, leaf: f.server, registry: source, now: time.Now, end: f.request.NotAfter}
	first, err := r.ReadOwnerRegistration(f.get, f.server)
	if err != nil || !first.FreshUntil.Equal(bound) {
		t.Fatal("first original cap", err)
	}
	time.Sleep(time.Millisecond)
	second, err := r.ReadOwnerRegistration(f.get, f.server)
	if err != nil || !second.FreshUntil.Equal(bound) {
		t.Fatal("later read renewed cap", err)
	}
	f.registry.mode = "revision-after-get"
	f.registry.get.Store(1)
	if _, err = r.ReadOwnerRegistration(f.get, f.server); err == nil {
		t.Fatal("accepted revision change within original operation")
	}
	if _, err = r.until(f.get); err == nil {
		t.Fatal("known change did not permanently close private state")
	}
}
