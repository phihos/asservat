package bootstrap

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Real process-owned owner credentials/operation; native, SQL and installation
// facts remain synthetic. These tests exercise the retained handler lifetime,
// not actual TLS admission, regional framing or native route availability.
type pendingOwnerNative struct {
	facts                      value.OwnerObservationNativeFacts
	original, closed           atomic.Int32
	closeEntered, closeRelease chan struct{}
}

func (n *pendingOwnerNative) Original(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	n.original.Add(1)
	if ctx.Err() != nil || n.closed.Load() != 0 {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	return n.facts.Clone(), nil
}
func (n *pendingOwnerNative) Final(context.Context) (value.OwnerObservationNativeFacts, error) {
	return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
}
func (n *pendingOwnerNative) Close() {
	n.closed.Add(1)
	if n.closeEntered != nil {
		close(n.closeEntered)
		<-n.closeRelease
	}
}

type pendingFixture struct {
	store          *ownerObservationPending
	keys           *mtls.OwnerCredentials
	client         *mtls.OwnerCredentials
	state          tls.ConnectionState
	registry       *observationForwardFixture
	request        value.ClusterObservationRequest
	sender, server value.OwnerCertificate
	get            context.Context
	cancelGet      context.CancelFunc
}

func newPendingFixture(t *testing.T) *pendingFixture {
	t.Helper()
	base, _, unused := newRuntimeFixture(t)
	// Hold the pool's Port until the test ends: closing it here let the next
	// test server reuse that port as NativePort, which makes the pool invalid
	// (the flaky "invalid signed control work" fixture failures).
	t.Cleanup(func() { _ = unused.Close() })
	base.configuration.Pool.NativePort = 9444
	base.configuration.Pool.NativeBootstrap = value.OwnerBootstrapProfile
	base.configuration.Pool.NativeCandidateLimit = 1024
	pin := value.OwnerObservationPin{RootID: observationForwardID(800), SourceUID: runtimeID, Pool: base.configuration.Pool, TemplateDigest: artifact.Digest{3}, ImageDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{19}}
	registry := &observationForwardFixture{t: t, base: base, pin: pin, bound: time.Now().Add(5 * time.Second), identities: make(map[value.OwnerCertificate]value.OwnerEnrollment)}
	binding := value.OwnerBinding{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PodUID: observationForwardID(810), ProcessEpoch: observationForwardID(811)}
	keys, err := mtls.NewOwnerCredentialsForPool(binding, "server", pin.Pool, base.roots, registry, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	setup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = keys.Enroll(setup); err != nil {
		t.Fatal(err)
	}
	server, err := keys.ServingCertificate()
	if err != nil {
		t.Fatal(err)
	}
	clientBinding := binding
	clientBinding.PodUID, clientBinding.ProcessEpoch = observationForwardID(812), observationForwardID(813)
	client, err := mtls.NewOwnerCredentialsForPool(clientBinding, "client", pin.Pool, base.roots, registry, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err = client.Enroll(setup); err != nil {
		t.Fatal(err)
	}
	state := pendingTLS(t, keys, client, registry, false)
	verifier, err := mtls.NewOwnerPeerVerifierForPool(base.roots, pin.Pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := verifier.VerifyClient(&state)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newOwnerObservationPending(context.Background(), pin, binding, 1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	now := time.Now()
	request := value.ClusterObservationRequest{ID: observationForwardID(801), Challenge: observationForwardID(802), RootID: pin.RootID, ClusterID: observationForwardID(803), Purpose: value.ObserveCapacityNamespaces, RequestedAt: now, NotAfter: now.Add(2 * time.Second)}
	get, stopGet := context.WithDeadline(context.Background(), request.NotAfter)
	t.Cleanup(stopGet)
	return &pendingFixture{store: store, keys: keys, client: client, state: state, registry: registry, request: request, sender: sender, server: server, get: get, cancelGet: stopGet}
}
func (f *pendingFixture) reserve(t *testing.T) *ownerObservationPendingEntry {
	t.Helper()
	e, err := f.store.reserve(f.get, f.request.LocatorQuery(), f.sender, f.server)
	if err != nil {
		t.Fatal("reserve", err)
	}
	t.Cleanup(e.finishGET)
	return e
}
func (f *pendingFixture) retain(t *testing.T, e *ownerObservationPendingEntry) (*mtls.OwnerObservationOperation, *pendingOwnerNative, value.ClusterObservationLocator) {
	t.Helper()
	r := value.OwnerObservationRequest{RootID: f.request.RootID, ID: f.request.ID, Challenge: f.request.Challenge, RequestedAt: f.request.RequestedAt, NotAfter: f.request.NotAfter}
	routing, err := mtls.NewOwnerObservationRoutingAdmission(e.work, f.store.pin, r, f.keys, f.registry, &f.state, time.Now)
	if err != nil {
		t.Fatal("original routing admission", err)
	}
	call, peers, err := routing.NativeInput(e.work)
	if err != nil {
		routing.Close()
		t.Fatal(err)
	}
	until, _ := call.Deadline()
	facts := value.OwnerObservationNativeFacts{Request: r, Pin: f.store.pin, ObservedAt: time.Now(), FreshUntil: until}
	for _, b := range peers {
		facts.Peers = append(facts.Peers, value.OwnerObservationNativePeer{Binding: b, Pod: "owner-" + b.PodUID, ReplicaSetUID: runtimeID, Addresses: []string{"10.0.0.8"}, WorkloadDigest: artifact.Digest{45}})
	}
	native := &pendingOwnerNative{facts: facts}
	op, until, err := routing.Complete(e.work, native)
	if err != nil {
		routing.Close()
		t.Fatal("original operation", err)
	}
	locator := value.ClusterObservationLocator{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: f.request.ClusterID, Holder: f.server.Binding, ExchangeID: observationForwardID(814), Sequence: 1, Interval: value.ClusterObservationInterval{ObservedAt: time.Now(), FreshUntil: until}}
	// This private bookkeeping fixture isolates the pending map from holder
	// transport. Actual reservation/output is covered by the receiver/h2 tests.
	// It installs no runtime selector or public authority port.
	e.mu.Lock()
	e.routing, e.locator, e.phase = routing, locator, ownerObservationPrepared
	e.mu.Unlock()
	return op, native, locator
}
func pendingWait(t *testing.T, c <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(time.Second):
		t.Fatal("did not join", label)
	}
}

func TestOwnerPendingRetainsOriginalAfterGET(t *testing.T) {
	for _, delivery := range []string{"positive", "unknown"} {
		t.Run(delivery, func(t *testing.T) {
			f := newPendingFixture(t)
			e := f.reserve(t)
			op, native, locator := f.retain(t, e)
			got, err := e.possibleDelivery()
			if err != nil || !samePendingLocator(got, locator) {
				t.Fatal("possible delivery", err)
			}
			// Both a positive and an unknown flush have crossed the exact same
			// nonrefundable output boundary; neither recreates native work.
			e.finishGET()
			f.cancelGet()
			if e.work.Err() != nil || native.closed.Load() != 0 {
				t.Fatal("GET return cancelled retained original")
			}
			caller, stop := context.WithDeadline(context.Background(), f.request.NotAfter)
			defer stop()
			claim, err := f.store.claim(caller, value.ClusterObservationClaim{Request: f.request, Locator: locator}, f.sender, f.server)
			if err != nil {
				t.Fatal(err)
			}
			defer claim.Close()
			state := pendingTLS(t, f.keys, f.client, f.registry, true)
			borrowed, _, claimErr := claim.routing.Claim(claim.call, &state)
			if claimErr != nil || borrowed != op || native.original.Load() != 1 {
				t.Fatal("claim replaced or reopened original proof")
			}
			if end, _ := claim.call.Deadline(); !end.Equal(locator.Interval.FreshUntil) {
				t.Fatal("claim changed original end")
			}
			claim.Close()
			if native.closed.Load() != 1 {
				t.Fatal("exact proof was not closed once")
			}
			if _, err = f.store.claim(caller, value.ClusterObservationClaim{Request: f.request, Locator: locator}, f.sender, f.server); err == nil {
				t.Fatal("replayed POST")
			}
			other := f.request.LocatorQuery()
			other.RequestID = observationForwardID(890)
			if _, err = f.store.reserve(caller, other, f.sender, f.server); err == nil {
				t.Fatal("completed claim refunded original slot")
			}
		})
	}
}
func TestOwnerPendingCancellationBeforeDelivery(t *testing.T) {
	f := newPendingFixture(t)
	e := f.reserve(t)
	_, native, _ := f.retain(t, e)
	f.cancelGet()
	if _, err := e.possibleDelivery(); err == nil {
		t.Fatal("cancelled GET exposed locator")
	}
	e.finishGET()
	pendingWait(t, e.closed, "cancelled original")
	if native.closed.Load() != 1 {
		t.Fatal("cancelled proof not joined")
	}
	caller, stop := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer stop()
	if _, err := f.store.reserve(caller, f.request.LocatorQuery(), f.sender, f.server); err == nil {
		t.Fatal("cancelled original replay reopened")
	}
}
func TestOwnerPendingOneConcurrentClaim(t *testing.T) {
	f := newPendingFixture(t)
	e := f.reserve(t)
	_, _, locator := f.retain(t, e)
	if _, err := e.possibleDelivery(); err != nil {
		t.Fatal(err)
	}
	e.finishGET()
	caller, stop := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer stop()
	var wg sync.WaitGroup
	winners := make(chan *ownerObservationPendingClaim, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := f.store.claim(caller, value.ClusterObservationClaim{Request: f.request, Locator: locator}, f.sender, f.server)
			if err == nil {
				winners <- h
			}
		}()
	}
	wg.Wait()
	close(winners)
	count := 0
	for h := range winners {
		count++
		h.Close()
	}
	if count != 1 {
		t.Fatal("concurrent claims", count)
	}
}
func TestOwnerPendingExactOriginalBinding(t *testing.T) {
	for _, change := range []string{"challenge", "cluster", "query-end", "sequence", "locator-end", "holder-process", "sender-leaf", "server-leaf", "unbounded", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			f := newPendingFixture(t)
			e := f.reserve(t)
			_, _, locator := f.retain(t, e)
			if _, err := e.possibleDelivery(); err != nil {
				t.Fatal(err)
			}
			e.finishGET()
			input := value.ClusterObservationClaim{Request: f.request, Locator: locator}
			sender, server := f.sender, f.server
			caller, stop := context.WithDeadline(context.Background(), f.request.NotAfter)
			defer stop()
			switch change {
			case "challenge":
				input.Request.Challenge = observationForwardID(891)
				input.Locator.Challenge = input.Request.Challenge
			case "cluster":
				input.Request.ClusterID = observationForwardID(892)
				input.Locator.ClusterID = input.Request.ClusterID
			case "query-end":
				input.Request.NotAfter = input.Request.NotAfter.Add(-time.Millisecond)
				input.Locator.Interval.FreshUntil = input.Request.NotAfter
			case "sequence":
				input.Locator.Sequence++
			case "locator-end":
				input.Locator.Interval.FreshUntil = input.Locator.Interval.FreshUntil.Add(-time.Millisecond)
			case "holder-process":
				input.Locator.Holder.ProcessEpoch = observationForwardID(893)
			case "sender-leaf":
				sender.Digest[0]++
			case "server-leaf":
				server.Digest[0]++
			case "unbounded":
				caller = context.Background()
			case "cancelled":
				stop()
			}
			if h, err := f.store.claim(caller, input, sender, server); err == nil {
				h.Close()
				t.Fatal("changed claim accepted")
			}
		})
	}
}
func TestOwnerPendingCloseJoinsActualWork(t *testing.T) {
	f := newPendingFixture(t)
	e := f.reserve(t)
	_, native, locator := f.retain(t, e)
	native.closeEntered = make(chan struct{})
	native.closeRelease = make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(native.closeRelease) })
	if _, err := e.possibleDelivery(); err != nil {
		t.Fatal(err)
	}
	e.finishGET()
	caller, stop := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer stop()
	h, err := f.store.claim(caller, value.ClusterObservationClaim{Request: f.request, Locator: locator}, f.sender, f.server)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	defer func() { release.Do(func() { close(native.closeRelease) }); h.Close() }()
	go func() { f.store.Close(); close(closed) }()
	pendingWait(t, native.closeEntered, "native close entry")
	select {
	case <-h.call.Done():
	default:
		t.Fatal("process close did not cancel claim")
	}
	select {
	case <-closed:
		t.Fatal("released slot before native joined")
	default:
	}
	release.Do(func() { close(native.closeRelease) })
	select {
	case <-closed:
		t.Fatal("released slot before response work joined")
	default:
	}
	h.Close()
	pendingWait(t, closed, "process close")
	if native.closed.Load() != 1 {
		t.Fatal("native closed more than once")
	}
}

func TestOwnerPendingOriginalExpiryJoinsAndRetires(t *testing.T) {
	f := newPendingFixture(t)
	f.request.NotAfter = time.Now().Add(100 * time.Millisecond)
	e := f.reserve(t)
	_, native, _ := f.retain(t, e)
	if _, err := e.possibleDelivery(); err != nil {
		t.Fatal(err)
	}
	e.finishGET()
	f.cancelGet()
	pendingWait(t, e.retired, "original expiry")
	if native.closed.Load() != 1 {
		t.Fatal("idle expiry did not close original proof")
	}
	f.store.mu.Lock()
	remaining := len(f.store.entries)
	f.store.mu.Unlock()
	if remaining != 0 {
		t.Fatal("expired joined entry retained")
	}
	caller, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err := f.store.reserve(caller, f.request.LocatorQuery(), f.sender, f.server); err == nil {
		t.Fatal("original expired request gained a new interval")
	}
}
func TestOwnerPendingClaimCancellationAfterLockWait(t *testing.T) {
	f := newPendingFixture(t)
	e := f.reserve(t)
	_, _, locator := f.retain(t, e)
	if _, err := e.possibleDelivery(); err != nil {
		t.Fatal(err)
	}
	e.finishGET()
	caller, stop := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer stop()
	e.mu.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		h, err := f.store.claim(caller, value.ClusterObservationClaim{Request: f.request, Locator: locator}, f.sender, f.server)
		if h != nil {
			h.Close()
		}
		done <- err
	}()
	<-started
	blocked := false
	for until := time.Now().Add(time.Second); time.Now().Before(until); {
		if !f.store.mu.TryLock() {
			blocked = true
			break
		}
		f.store.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	stop()
	e.mu.Unlock()
	if !blocked {
		<-done
		t.Fatal("claim did not reach entry lock")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled caller crossed state lock")
		}
	case <-time.After(time.Second):
		t.Fatal("claim did not join")
	}
}
func TestOwnerPendingFailedPreparationKeepsSlot(t *testing.T) {
	f := newPendingFixture(t)
	e := f.reserve(t)
	// Failure before native construction still consumes the original admission.
	e.finishGET()
	if e.work.Err() == nil {
		t.Fatal("failed preparation remained live")
	}
	caller, stop := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer stop()
	for _, mutation := range []string{"same", "challenge", "new-request"} {
		q := f.request.LocatorQuery()
		if mutation == "challenge" {
			q.Challenge = observationForwardID(880)
		}
		if mutation == "new-request" {
			q.RequestID = observationForwardID(881)
		}
		if _, err := f.store.reserve(caller, q, f.sender, f.server); err == nil {
			t.Fatal("failed preparation refunded slot", mutation)
		}
	}
}

// Each state comes from a fresh mutually verified actual TLS1.3/h2 handshake.
func pendingTLS(t *testing.T, serverKeys, clientKeys *mtls.OwnerCredentials, f *observationForwardFixture, exact bool) tls.ConnectionState {
	t.Helper()
	serving, err := mtls.NewOwnerBootstrapServing(serverKeys, f.pin.Pool)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := mtls.OwnerBootstrapServerName(f.pin.Pool)
	if exact {
		leaf, e := serverKeys.ServingCertificate()
		if e != nil {
			t.Fatal(e)
		}
		name, _ = mtls.OwnerServerName(leaf.Binding)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	server := tls.Server(a, &tls.Config{GetCertificate: serving.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.base.roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true})
	client := tls.Client(b, &tls.Config{GetClientCertificate: clientKeys.GetClientCertificate, RootCAs: f.base.roots, ServerName: name, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	joined := make(chan error, 1)
	go func() { joined <- server.HandshakeContext(ctx) }()
	ce := client.HandshakeContext(ctx)
	if ce != nil {
		a.Close()
		b.Close()
	}
	se := <-joined
	if ce != nil || se != nil {
		t.Fatal("actual TLS", ce, se)
	}
	return server.ConnectionState()
}
