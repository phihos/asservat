package mtls

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Actual process-owned keys and fresh mutual TLS. SQL/native values here are
// explicit synthetic ports; this is not a native five-second route verdict.
type operationRoutingFixture struct {
	base      *routingPeerFixture
	root      context.Context
	request   value.OwnerObservationRequest
	admission *OwnerObservationRoutingAdmission
	native    *ownerOperationNativeFixture
	operation *OwnerObservationOperation
}

func newOperationRoutingFixture(t *testing.T) *operationRoutingFixture {
	t.Helper()
	x := newRoutingPeerFixture(t, false)
	root, cancel := context.WithDeadline(context.Background(), x.query.NotAfter)
	t.Cleanup(cancel)
	request := value.OwnerObservationRequest{RootID: x.query.RootID, ID: x.query.RequestID, Challenge: x.query.Challenge, RequestedAt: x.query.RequestedAt, NotAfter: x.query.NotAfter}
	r, err := NewOwnerObservationRoutingAdmission(root, x.pin, request, x.server, x.checker.owners.Registry, &x.state, time.Now)
	if err != nil {
		t.Fatal("current routing admission", err)
	}
	t.Cleanup(r.Close)
	return &operationRoutingFixture{base: x, root: root, request: request, admission: r}
}
func (f *operationRoutingFixture) complete(t *testing.T, ctx context.Context) {
	t.Helper()
	call, peers, err := f.admission.NativeInput(ctx)
	if err != nil {
		t.Fatal("native input", err)
	}
	end, _ := call.Deadline()
	facts := value.OwnerObservationNativeFacts{Pin: f.base.pin, Request: f.request, ObservedAt: time.Now(), FreshUntil: end}
	for _, b := range peers {
		facts.Peers = append(facts.Peers, value.OwnerObservationNativePeer{Binding: b, Pod: "owner-1", ReplicaSetUID: ownerTestID, Addresses: []string{"10.0.0.8"}, WorkloadDigest: artifact.Digest{11}})
	}
	f.native = &ownerOperationNativeFixture{facts: facts}
	f.operation, _, err = f.admission.Complete(ctx, f.native)
	if err != nil {
		t.Fatal("paired original native binding", err)
	}
}
func routingNewConnection(t *testing.T, x *routingPeerFixture, exact bool) tls.ConnectionState {
	t.Helper()
	serving, err := NewOwnerBootstrapServing(x.server, x.pin.Pool)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := OwnerBootstrapServerName(x.pin.Pool)
	if exact {
		name, _ = OwnerServerName(x.server.binding)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	server := tls.Server(a, &tls.Config{GetCertificate: serving.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x.clientFixture.ca.roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true})
	client := tls.Client(b, &tls.Config{GetClientCertificate: x.client.GetClientCertificate, RootCAs: x.serverFixture.ca.roots, ServerName: name, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true})
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
		t.Fatal("new actual TLS", ce, se)
	}
	return server.ConnectionState()
}
func TestOwnerOperationRoutingOriginalSurvivesGETAndClaimsOnce(t *testing.T) {
	f := newOperationRoutingFixture(t)
	get, cancelGET := context.WithCancel(f.root)
	f.complete(t, get)
	cancelGET()
	if f.operation.root.Err() != nil || f.admission.root.Err() != nil {
		t.Fatal("completed GET killed original operation")
	}
	state := routingNewConnection(t, f.base, true)
	got, until, err := f.admission.Claim(f.root, &state)
	if err != nil || got != f.operation || until.After(f.request.NotAfter) || f.native.original.Load() != 1 || f.native.final.Load() != 0 {
		t.Fatal("exact original claim", err)
	}
	if f.base.route != 0 || f.base.guard != 0 || f.base.work != 0 {
		t.Fatal("v2 silently invoked general full proof")
	}
	if _, _, err = f.admission.Claim(f.root, &state); err == nil {
		t.Fatal("second claim admitted")
	}
	f.admission.Close()
	if f.native.closed.Load() != 1 {
		t.Fatal("native ownership did not join once", f.native.closed.Load())
	}
}
func TestOwnerOperationRoutingRequiresBothCurrentOriginalPeers(t *testing.T) {
	for _, mode := range []string{"revoked", "changed-pool", "removed-root", "suspended", "source-replaced", "revision-changed", "wrong-sni", "resumed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperationRoutingFixture(t)
			f.complete(t, f.root)
			state := routingNewConnection(t, f.base, true)
			ctx := f.root
			f.base.mode = mode
			switch mode {
			case "wrong-sni":
				state.ServerName, _ = OwnerBootstrapServerName(f.base.pin.Pool)
			case "resumed":
				state.DidResume = true
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if _, _, err := f.admission.Claim(ctx, &state); err == nil {
				t.Fatal("changed current admission accepted")
			}
			if f.native.original.Load() != 1 || f.native.final.Load() != 0 {
				t.Fatal("failure reopened native proof")
			}
		})
	}
}
func TestOwnerOperationRoutingNativeMustBindSenderAndHolder(t *testing.T) {
	for _, mode := range []string{"missing-sender", "extra-peer", "sender-pod", "sender-rs", "wrong-request", "wrong-pin", "already-final"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperationRoutingFixture(t)
			call, peers, err := f.admission.NativeInput(f.root)
			if err != nil {
				t.Fatal(err)
			}
			end, _ := call.Deadline()
			facts := value.OwnerObservationNativeFacts{Request: f.request, Pin: f.base.pin, ObservedAt: time.Now(), FreshUntil: end}
			for _, b := range peers {
				facts.Peers = append(facts.Peers, value.OwnerObservationNativePeer{Binding: b, Pod: "owner-1", ReplicaSetUID: ownerTestID, Addresses: []string{"10.0.0.8"}, WorkloadDigest: artifact.Digest{3}})
			}
			switch mode {
			case "missing-sender":
				facts.Peers = facts.Peers[1:]
			case "extra-peer":
				facts.Peers = append(facts.Peers, facts.Peers[0])
			case "sender-pod":
				facts.Peers[0].Pod = "changed"
			case "sender-rs":
				facts.Peers[0].ReplicaSetUID = ownerOtherID
			case "wrong-request":
				facts.Request.Challenge = ownerTestID
			case "wrong-pin":
				facts.Pin.ImageDigest[0]++
			case "already-final":
				facts.Final = true
			}
			n := &ownerOperationNativeFixture{facts: facts}
			if _, _, err = f.admission.Complete(f.root, n); err == nil {
				t.Fatal("unbound native handle accepted")
			}
			f.admission.Close()
			if n.closed.Load() != 1 {
				t.Fatal("failed construction ownership", n.closed.Load())
			}
		})
	}
}
func TestOwnerOperationRoutingCloseJoinsAdmittedNativeBegin(t *testing.T) {
	f := newOperationRoutingFixture(t)
	call, _, err := f.admission.NativeInput(f.root)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { f.admission.Close(); close(done) }()
	<-call.Done()
	select {
	case <-done:
		t.Fatal("Close returned before admitted Begin joined")
	default:
	}
	if _, _, err = f.admission.Complete(f.root, nil); err == nil {
		t.Fatal("failed Begin completed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close failed to join Begin")
	}
}
func TestOwnerOperationRoutingShorterSQLDeadlineReachesNativeAndClaim(t *testing.T) {
	f := newOperationRoutingFixture(t)
	original := f.admission.registry
	short := time.Now().Add(250 * time.Millisecond)
	var calls atomic.Int32
	f.admission.registry = forwardRegistry(func(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
		n := calls.Add(1)
		if n > 1 {
			d, ok := ctx.Deadline()
			if !ok || d.After(short) {
				t.Error("earlier SQL cap not carried into next read")
			}
		}
		r, e := original.ReadOwnerRegistration(ctx, c)
		if e == nil && r.FreshUntil.After(short) {
			r.FreshUntil = short
		}
		return r, e
	})
	f.complete(t, f.root)
	if f.admission.until.After(short) || f.operation.until.After(short) {
		t.Fatal("original shorter cutoff lost")
	}
	// Waiting does not mint another interval. No native read is repeated on
	// an expired attempt, even though the caller has a longer original bound.
	<-time.After(time.Until(short) + time.Millisecond)
	state := f.base.state
	state.ServerName, _ = OwnerServerName(f.base.server.binding)
	if _, _, err := f.admission.Claim(f.root, &state); err == nil {
		t.Fatal("wait renewed original proof")
	}
	if f.native.original.Load() != 1 {
		t.Fatal("expiry reconstructed proof")
	}
}
func TestOwnerOperationRoutingClaimConcurrency(t *testing.T) {
	f := newOperationRoutingFixture(t)
	f.complete(t, f.root)
	state := routingNewConnection(t, f.base, true)
	var success atomic.Int32
	var calls sync.WaitGroup
	for i := 0; i < 8; i++ {
		calls.Add(1)
		go func() {
			defer calls.Done()
			if _, _, err := f.admission.Claim(f.root, &state); err == nil {
				success.Add(1)
			}
		}()
	}
	calls.Wait()
	if success.Load() != 1 {
		t.Fatal("one claim", success.Load())
	}
}
func TestOwnerOperationRoutingFinalRequiresActualFinalPhase(t *testing.T) {
	f := newOperationRoutingFixture(t)
	f.complete(t, f.root)
	state := routingNewConnection(t, f.base, true)
	if _, _, err := f.admission.Claim(f.root, &state); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admission.Final(f.root); err == nil {
		t.Fatal("initial facts represented completion")
	}
	if f.native.final.Load() != 0 {
		t.Fatal("result check performed implicit final native I/O")
	}
}

var _ app.OwnerNativeObservationOperation = (*ownerRoutingNative)(nil)
