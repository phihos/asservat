package bootstrap

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
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
		end, _ := ctx.Deadline()
		if r.reads.Load() > 1 && end.After(r.until) {
			return value.OwnerRegistrationObservation{}, value.ErrUnavailable
		}
		if v.FreshUntil.After(r.until) {
			v.FreshUntil = r.until
		}
	}
	return v, err
}
func directHolderFixture(t *testing.T, mode string) (*DirectHolderObservationClient, *localReceiverFixture, *localDirectInputs, *receiverNativeFixture, *localDirectRegistry) {
	t.Helper()
	receiverMode := "joined"
	if mode == "lost-get" || mode == "lost-post" {
		receiverMode = mode
	}
	f := newLocalReceiverFixture(t, receiverMode)
	f.base.owner.mode = mode
	inputs := &localDirectInputs{owner: f.base.owner, mode: mode}
	// H and A have independent original native instances. This fake models only
	// native/API authority; both real HTTPS legs and regional frames are actual.
	native := &receiverNativeFixture{pin: f.base.owner.pin, mode: mode, beginEntered: make(chan struct{}), beginCancelled: make(chan struct{}), beginRelease: make(chan struct{})}
	registry := &localDirectRegistry{OwnerCertificateRegistry: f.base.owner, f: f, mode: mode}
	c, err := newDirectHolderObservationClient(f.base.root, f.base.owner.pin, observationForwardID(701), f.base.base.roots, f.base.owner, registry, inputs, native, inputs, 2, time.Now)
	if err != nil {
		t.Fatal("newDirectHolderObservationClient", err)
	}
	c.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}
	t.Cleanup(c.Close)
	return c, f, inputs, native, registry
}
func TestDirectHolderActualHTTPAndRegionalFrames(t *testing.T) {
	for _, mode := range []string{"joined", "same-pod17", "candidate-error", "excluded-leaf", "ready-error", "empty-ready", "mutated-candidate-input", "wrong-address", "lost-get", "lost-post", "revoked-after-get", "revoked-after-post", "owner-final"} {
		t.Run(mode, func(t *testing.T) {
			c, f, inputs, native, registry := directHolderFixture(t, mode)
			r := f.base.request()
			result, err := c.ObserveCluster(f.base.root, r)
			if mode == "joined" || mode == "same-pod17" {
				if err != nil || result.RequestID != r.ID {
					t.Fatal("direct actual framed route", err)
				}
				if inputs.tokens.Load() != 1 || f.get.Load() != 1 || f.post.Load() != 1 || registry.reads.Load() != 6 || inputs.lists.Load() != 1 || native.opens.Load() != 1 {
					t.Fatal("changed structural read/transport count", inputs.tokens.Load(), f.get.Load(), f.post.Load(), registry.reads.Load(), inputs.lists.Load(), native.opens.Load())
				}
				native.mu.Lock()
				last := native.last
				native.mu.Unlock()
				if last == nil || last.final.Load() != 1 || last.closed.Load() != 1 {
					t.Fatal("H native not finalized and joined")
				}
			} else {
				if err == nil {
					t.Fatal("unavailable composition produced result")
				}
				if mode == "candidate-error" || mode == "excluded-leaf" || mode == "ready-error" || mode == "empty-ready" || mode == "mutated-candidate-input" || mode == "wrong-address" {
					if inputs.tokens.Load() != 0 || f.get.Load() != 0 || f.post.Load() != 0 {
						t.Fatal("token disclosed before exact peer proof")
					}
				}
				if mode == "lost-get" && (f.get.Load() != 1 || f.post.Load() != 0) {
					t.Fatal("unknown locator replayed")
				}
				if mode == "lost-post" && (f.get.Load() != 1 || f.post.Load() != 1) {
					t.Fatal("unknown claim replayed")
				}
			}
			if f.base.owner.legacy.Load() != 0 {
				t.Fatal("opted discovery fell back to legacy incomplete reader")
			}
			if len(c.sockets) != 0 {
				t.Fatal("transport slot released before joined Close or leaked")
			}
		})
	}
}
func TestDirectHolderOriginalShorterSQLDeadline(t *testing.T) {
	c, f, _, native, registry := directHolderFixture(t, "joined")
	registry.until = time.Now().Add(3 * time.Second)
	r := f.base.request()
	result, err := c.ObserveCluster(f.base.root, r)
	if err != nil || result.Interval.FreshUntil.After(registry.until) {
		t.Fatal("SQL cutoff propagation", err)
	}
	native.mu.Lock()
	last := native.last
	native.mu.Unlock()
	if last == nil || last.facts.FreshUntil.After(registry.until) {
		t.Fatal("native Begin exceeded original SQL cutoff")
	}
}
func TestDirectHolderCloseJoinsNativeBeginAndLosingTransport(t *testing.T) {
	c, f, inputs, native, _ := directHolderFixture(t, "cancel-native-begin")
	result := make(chan error, 1)
	go func() { _, err := c.ObserveCluster(f.base.root, f.base.request()); result <- err }()
	<-native.beginEntered
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	<-native.beginCancelled
	select {
	case <-closed:
		t.Fatal("Close returned before admitted native read joined")
	default:
	}
	close(native.beginRelease)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled Begin succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("request did not join")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join")
	}
	if inputs.tokens.Load() != 0 || f.get.Load() != 0 || len(c.sockets) != 0 {
		t.Fatal("cancelled proof disclosed token or retained socket")
	}
}
func TestDirectHolderSocketCeilingSharedAcrossOperations(t *testing.T) {
	c, f, _, _, _ := directHolderFixture(t, "joined")
	entered := make(chan struct{}, 3)
	var calls atomic.Int32
	c.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	call, cancel := context.WithCancel(f.base.root)
	var joined sync.WaitGroup
	for range 3 {
		joined.Add(1)
		go func() { defer joined.Done(); _, _ = c.open(call, "10.0.0.8", "fixed.invalid") }()
	}
	<-entered
	<-entered
	select {
	case <-entered:
		t.Fatal("third process socket admitted")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	joined.Wait()
	if calls.Load() != 2 || len(c.sockets) != 0 {
		t.Fatal("shared socket budget", calls.Load(), len(c.sockets))
	}
}

func TestDirectHolderUnavailableFirstCandidateKeepsIndependentPositive(t *testing.T) {
	c, f, inputs, _, _ := directHolderFixture(t, "joined")
	original := f.base.owner.servers[0]
	stale := original
	stale.PodUID = observationForwardID(9)
	stale.ProcessEpoch = observationForwardID(29)
	f.base.owner.servers = []value.OwnerBinding{stale, original}
	inputs.addresses = map[string][]string{stale.PodUID: {"10.0.0.7"}, original.PodUID: {"10.0.0.8"}}
	healthyEntered, failed, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var staleCalls, healthyCalls atomic.Int32
	c.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if host == "10.0.0.7" {
			staleCalls.Add(1)
			select {
			case <-healthyEntered:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			close(failed)
			return nil, value.ErrUnavailable
		}
		healthyCalls.Add(1)
		if healthyCalls.Load() == 1 {
			close(healthyEntered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}
	result := make(chan error, 1)
	go func() { _, err := c.ObserveCluster(f.base.root, f.base.request()); result <- err }()
	select {
	case <-failed:
	case <-time.After(time.Second):
		t.Fatal("both original candidates were not admitted")
	}
	select {
	case err := <-result:
		t.Fatal("unavailable first candidate cancelled independent pending positive", err)
	case <-time.After(50 * time.Millisecond):
	}
	if inputs.tokens.Load() != 0 {
		t.Fatal("token read before delayed selected TLS/native admission")
	}
	unblock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("independent positive denied", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("independent positive did not join")
	}
	if staleCalls.Load() != 1 || healthyCalls.Load() != 2 || f.get.Load() != 1 || f.post.Load() != 1 || inputs.tokens.Load() != 1 || len(c.sockets) != 0 {
		t.Fatal("candidate error became absence/retry or leaked transports", staleCalls.Load(), healthyCalls.Load(), f.get.Load(), f.post.Load())
	}
}

func TestDirectHolderAllUnavailableNeverAdvancesAsAbsence(t *testing.T) {
	c, f, inputs, _, _ := directHolderFixture(t, "joined")
	original := f.base.owner.servers[0]
	f.base.owner.servers = nil
	for i := 0; i < 3; i++ {
		b := original
		b.PodUID = observationForwardID(20 + i)
		b.ProcessEpoch = observationForwardID(40 + i)
		f.base.owner.servers = append(f.base.owner.servers, b)
	}
	var dials atomic.Int32
	c.dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, value.ErrUnavailable
	}
	if _, err := c.ObserveCluster(f.base.root, f.base.request()); err == nil || errors.Is(err, errHolderNoStandby) {
		t.Fatal("all unavailable became a successful empty result or an absence", err)
	}
	if dials.Load() != 2 || inputs.tokens.Load() != 0 || f.get.Load() != 0 || f.post.Load() != 0 || len(c.sockets) != 0 {
		t.Fatal("unknown candidate advanced or disclosed token", dials.Load(), inputs.tokens.Load())
	}
}

// Only an authenticated owner's explicit "no standby for this cluster" reply
// is classified as no free standby; it discloses nothing and claims nothing.
func TestDirectHolderAuthenticatedAbsenceIsNoStandby(t *testing.T) {
	c, f, _, _, _ := directHolderFixture(t, "joined")
	r := f.base.request()
	r.ClusterID = observationForwardID(990)
	_, err := c.ObserveCluster(f.base.root, r)
	if !errors.Is(err, errHolderNoStandby) {
		t.Fatal("authenticated absence not reported as no standby", err)
	}
	if f.get.Load() != 1 || f.post.Load() != 0 || len(c.sockets) != 0 {
		t.Fatal("absence claimed or leaked transports", f.get.Load(), f.post.Load())
	}
}
