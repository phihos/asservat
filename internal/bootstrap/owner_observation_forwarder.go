package bootstrap

import (
	"context"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerObservationForwarder performs only the closed regional observation
// purpose. It never forwards the local HWORK token or accepts a caller-selected
// locator, peer, URL, pool or candidate limit. The installed backend owns this
// object and its purpose-fixed concrete SQL/native dependencies.
type OwnerObservationForwarder struct {
	root       context.Context
	cancel     context.CancelFunc
	pin        value.OwnerObservationPin
	client     *mtls.OwnerCredentials
	roots      *x509.CertPool
	verifier   *mtls.OwnerPeerVerifier
	candidates *app.OwnerObservationCandidateSelection
	ready      app.OwnerObservationCandidateGroupsReader
	routes     app.OwnerRouteReader
	owners     *app.OwnerAuthenticator
	workloads  app.OwnerObservationWorkloadReader
	now        func() time.Time
	dial       func(context.Context, string, string) (net.Conn, error)
	mu         sync.Mutex
	closed     bool
	active     int
	joined     sync.WaitGroup
}

func (f *OwnerObservationForwarder) enter() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.root.Err() != nil || f.active >= 2 {
		return false
	}
	f.active++
	f.joined.Add(1)
	return true
}
func (f *OwnerObservationForwarder) leave() {
	f.mu.Lock()
	f.active--
	f.mu.Unlock()
	f.joined.Done()
}
func (f *OwnerObservationForwarder) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.closed = true
	f.cancel()
	f.mu.Unlock()
	f.joined.Wait()
}

func (f *OwnerObservationForwarder) peers(ctx context.Context, q value.ClusterObservationLocatorQuery, connection app.OwnerPeerConnection, expected value.OwnerCertificate) (value.ClusterObservationRoutingPeers, error) {
	var zero value.ClusterObservationRoutingPeers
	if ctx.Err() != nil || f.root.Err() != nil {
		return zero, value.ErrUnavailable
	}
	sender, err := f.owners.ObserveOwnerClient(ctx, f.client)
	if err != nil || sender.Certificate != expected || !sender.Valid(f.now()) || sender.Pool != f.pin.Pool || sender.ConfigurationRevision.UID != f.pin.SourceUID || sender.ProtectionDigest != f.pin.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(q.NotAfter, sender.ValidUntil)
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	sw, err := f.workloads.ObserveOwnerWorkload(call, sender.Certificate.Binding, sender.Pod)
	if err != nil || !sw.Valid(f.now()) || sw.Pin != f.pin || sw.Binding != expected.Binding || sw.Pod != sender.Pod || sw.ReplicaSetUID != sender.ReplicaSetUID {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, sw.FreshUntil)
	remoteCall, stopRemote := context.WithDeadline(call, until)
	defer stopRemote()
	holder, err := f.owners.AuthenticateOwner(remoteCall, connection)
	if err != nil || !holder.Valid(f.now()) || holder.Pool != f.pin.Pool || holder.ConfigurationRevision != sender.ConfigurationRevision || holder.ProtectionDigest != f.pin.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, holder.ValidUntil)
	workCall, stopWork := context.WithDeadline(remoteCall, until)
	defer stopWork()
	hw, err := f.workloads.ObserveOwnerWorkload(workCall, holder.Certificate.Binding, holder.Pod)
	if err != nil || !hw.Valid(f.now()) {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, hw.FreshUntil)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	client, ce := f.client.ClientCertificate()
	server, se := connection.OwnerCertificate()
	if ce != nil || se != nil || client != expected || server != holder.Certificate || workCall.Err() != nil || f.root.Err() != nil {
		return zero, value.ErrUnavailable
	}
	start := q.RequestedAt
	for _, d := range []time.Time{sender.VerifiedAt, sw.ObservedAt, holder.VerifiedAt, hw.ObservedAt} {
		if start.Before(d) {
			start = d
		}
	}
	out := value.ClusterObservationRoutingPeers{Query: q, Pin: f.pin, Sender: sender, Holder: holder, SenderWorkload: sw, HolderWorkload: hw, Interval: value.ClusterObservationInterval{ObservedAt: start, FreshUntil: until}}
	if !out.Valid(f.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
