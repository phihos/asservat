package bootstrap

import (
	"context"
	"net"
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

func TestDirectHolderCurrentRegistrationOwnsClaimPhase(t *testing.T) {
	c, f, inputs, native, _ := directHolderFixture(t, "joined")
	request := f.base.request()
	firstUntil := time.Now().Add(time.Second)
	c.registry = &phaseRegistrationFixture{OwnerCertificateRegistry: f.base.owner, firstUntil: firstUntil, delayRead: 4}
	f.receiver.registry = &phaseRegistrationFixture{OwnerCertificateRegistry: f.base.registry, firstUntil: firstUntil}
	result, err := c.ObserveCluster(f.base.root, request)
	native.mu.Lock()
	h := native.last
	native.mu.Unlock()
	f.native.mu.Lock()
	a := f.native.last
	f.native.mu.Unlock()
	if h != nil {
		t.Logf("H original native cutoff=%s request cutoff=%s", h.facts.FreshUntil.Format(time.RFC3339Nano), request.NotAfter.Format(time.RFC3339Nano))
	}
	if a != nil {
		t.Logf("receiver original native cutoff=%s", a.facts.FreshUntil.Format(time.RFC3339Nano))
	}
	if err != nil || result.RequestID != request.ID {
		t.Fatal("independently fresh same-registration claim refused while original request remains live", err)
	}
	if h == nil || a == nil || !h.facts.FreshUntil.Equal(request.NotAfter) || !a.facts.FreshUntil.Equal(request.NotAfter) {
		t.Fatal("native operation was constructed under a consumed SQL observation")
	}
	if inputs.tokens.Load() != 1 || f.get.Load() != 1 || f.post.Load() != 1 || len(c.sockets) != 0 {
		t.Fatal("phase transition replayed transport or failed to join")
	}
}

// Independent fresh proof for ordinal two must not be forced under ordinal
// one's SQL freshness. The same real regional conversation and four ordinals
// are exercised; SQL/native contents remain synthetic.
func TestDirectHolderNumberedProofUsesCurrentRegistration(t *testing.T) {
	c, f, _, _, _ := directHolderFixture(t, "joined")
	until := time.Now().Add(300 * time.Millisecond)
	r := &phaseRegistrationFixture{OwnerCertificateRegistry: f.base.registry, firstUntil: until, shortRead: 5, delayRead: 6, t: t}
	f.receiver.registry = r
	request := f.base.request()
	result, err := c.ObserveCluster(f.base.root, request)
	if err != nil || result.RequestID != request.ID || r.reads.Load() < 6 {
		t.Fatal("numbered proof retained earlier SQL cutoff", err, r.reads.Load())
	}
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
func phaseCandidates(t *testing.T, c *DirectHolderObservationClient, f *localReceiverFixture, until time.Time) {
	t.Helper()
	selected, err := app.NewOwnerObservationCandidateSelection(c.pin.Pool, phaseCandidateFixture{f.base.owner, until})
	if err != nil {
		t.Fatal(err)
	}
	c.candidates = selected
}

func TestDirectHolderDiscoveryConsumedBeforeLosingJoin(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined", true: "cancelled"}[cancelParent], func(t *testing.T) {
			c, f, inputs, native, _ := directHolderFixture(t, "joined")
			request := f.base.request()
			until := time.Now().Add(300 * time.Millisecond)
			phaseCandidates(t, c, f, until)
			original := f.base.owner.servers[0]
			other := original
			other.PodUID = observationForwardID(9)
			other.ProcessEpoch = observationForwardID(29)
			f.base.owner.servers = []value.OwnerBinding{other, original}
			inputs.addresses = map[string][]string{other.PodUID: {"10.0.0.7"}, original.PodUID: {"10.0.0.8"}}
			entered := make(chan struct{})
			joining := make(chan struct{})
			joined := make(chan struct{})
			c.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(address)
				if host == "10.0.0.7" {
					close(entered)
					<-ctx.Done()
					close(joining)
					time.Sleep(time.Until(until.Add(100 * time.Millisecond)))
					close(joined)
					return nil, ctx.Err()
				}
				select {
				case <-entered:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
			}
			ctx, cancel := context.WithCancel(f.base.root)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := c.ObserveCluster(ctx, request); result <- err }()
			<-joining
			if cancelParent {
				cancel()
			}
			err := <-result
			<-joined
			if (err != nil) != cancelParent {
				t.Fatal("discovery/parent phase ownership", err)
			}
			native.mu.Lock()
			last := native.last
			native.mu.Unlock()
			if last == nil || last.closed.Load() != 1 || len(c.sockets) != 0 {
				t.Fatal("losing join or selected native leaked")
			}
			if !cancelParent && (f.get.Load() != 1 || f.post.Load() != 1 || inputs.tokens.Load() != 1) {
				t.Fatal("joined discovery replayed")
			}
		})
	}
}

func TestDirectHolderFixedCurrentExpiryStillDenies(t *testing.T) {
	c, f, _, native, _ := directHolderFixture(t, "joined")
	until := time.Now().Add(3 * time.Second)
	registry := &phaseRegistrationFixture{OwnerCertificateRegistry: f.base.owner, firstUntil: until, fixed: true, delayRead: 4}
	c.registry = registry
	request := f.base.request()
	if _, err := c.ObserveCluster(f.base.root, request); err == nil {
		t.Fatal("expired independently current registration authorized claim")
	}
	if f.post.Load() != 0 || registry.reads.Load() != 4 || len(c.sockets) != 0 {
		t.Fatal("expiry replayed or leaked")
	}
	native.mu.Lock()
	last := native.last
	native.mu.Unlock()
	if last == nil || !last.facts.FreshUntil.Equal(request.NotAfter) || last.closed.Load() != 1 {
		t.Fatal("native lifetime rewritten or not joined")
	}
}

func TestDirectHolderShortParentStillDenies(t *testing.T) {
	c, f, _, _, _ := directHolderFixture(t, "joined")
	c.registry = &phaseRegistrationFixture{OwnerCertificateRegistry: f.base.owner, firstUntil: time.Now().Add(time.Second), delayRead: 4}
	ctx, cancel := context.WithTimeout(f.base.root, 100*time.Millisecond)
	defer cancel()
	if _, err := c.ObserveCluster(ctx, f.base.request()); err == nil || len(c.sockets) != 0 || f.post.Load() != 0 {
		t.Fatal("short original parent lost", err)
	}
}

type phaseReadyReader func(context.Context, value.APIContextOwnerCandidates) (kube.OwnerObservationDialCandidates, error)

func (f phaseReadyReader) ReadOwnerObservationDialCandidates(ctx context.Context, c value.APIContextOwnerCandidates) (kube.OwnerObservationDialCandidates, error) {
	return f(ctx, c)
}
func TestDirectHolderDiscoveryExpiresBeforeSelection(t *testing.T) {
	c, f, inputs, native, _ := directHolderFixture(t, "joined")
	until := time.Now().Add(50 * time.Millisecond)
	phaseCandidates(t, c, f, until)
	original := c.ready
	c.ready = phaseReadyReader(func(ctx context.Context, v value.APIContextOwnerCandidates) (kube.OwnerObservationDialCandidates, error) {
		<-ctx.Done()
		return original.ReadOwnerObservationDialCandidates(ctx, v)
	})
	if _, err := c.ObserveCluster(f.base.root, f.base.request()); err == nil || native.opens.Load() != 0 || inputs.tokens.Load() != 0 || f.get.Load() != 0 || len(c.sockets) != 0 {
		t.Fatal("expired discovery selected a peer", err)
	}
}
