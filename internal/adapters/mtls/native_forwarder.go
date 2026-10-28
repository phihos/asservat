package mtls

import (
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// NativeOwnerForwarder has no address override or worker-selected callback. It
// uses only the exact current SQL45 hub process and the accepted owner route.
// The client identity is a connector certificate, never a hub-owner substitute.
type NativeOwnerForwarderConfig struct {
	Pool           fleet.OwnerPool
	Connector      *NativeConnectorIdentity
	OwnerRoots     *x509.CertPool
	Routes         app.OwnerRouteReader
	Authentication *app.OwnerAuthenticator
	Origins        evidence.NativeOrigins
	Now            func() time.Time
	Concurrency    int
}
type NativeOwnerForwarder struct {
	config   NativeOwnerForwarderConfig
	verifier *OwnerPeerVerifier
	root     context.Context
	cancel   context.CancelFunc
	slots    chan struct{}
	mu       sync.Mutex
	closed   bool
	active   int
	done     chan struct{}
	streams  map[*routedNativeStream]struct{}
	dial     func(context.Context, string, string) (net.Conn, error)
}

func NewNativeOwnerForwarder(ctx context.Context, c NativeOwnerForwarderConfig) (*NativeOwnerForwarder, error) {
	if ctx == nil || ctx.Err() != nil || !c.Pool.Valid() || c.Pool.NativePort == 0 || c.Connector == nil || c.Connector.binding.InstallationID != c.Pool.InstallationID || c.Routes == nil || c.Authentication == nil || c.Origins.Operations == nil || c.Origins.Now == nil || c.Now == nil || c.Concurrency < 1 || c.Concurrency > 16 {
		return nil, artifact.ErrInvalid
	}
	verifier, e := NewOwnerPeerVerifierForPool(c.OwnerRoots, c.Pool, c.Now)
	if e != nil {
		return nil, e
	}
	c.OwnerRoots = c.OwnerRoots.Clone()
	root, cancel := context.WithCancel(ctx)
	f := &NativeOwnerForwarder{config: c, verifier: verifier, root: root, cancel: cancel, slots: make(chan struct{}, c.Concurrency), done: make(chan struct{}), streams: make(map[*routedNativeStream]struct{}), dial: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}).DialContext}
	context.AfterFunc(root, f.Close)
	return f, nil
}
func (f *NativeOwnerForwarder) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		f.cancel()
		if f.active == 0 {
			close(f.done)
		}
	}
	owned := make([]*routedNativeStream, 0, len(f.streams))
	for stream := range f.streams {
		owned = append(owned, stream)
	}
	f.mu.Unlock()
	for _, stream := range owned {
		stream.Close()
	}
	<-f.done
}
func (f *NativeOwnerForwarder) admit() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.root.Err() != nil {
		return false
	}
	select {
	case f.slots <- struct{}{}:
		f.active++
		return true
	default:
		return false
	}
}
func (f *NativeOwnerForwarder) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	<-f.slots
	f.active--
	if f.closed && f.active == 0 {
		close(f.done)
	}
}

func (f *NativeOwnerForwarder) OpenNativeOwner(ctx context.Context, origin evidence.NativeOrigin, h contracts.NativeHello) (contracts.NativeStream, *evidence.NativeFrameGate, error) {
	if f == nil || ctx == nil || ctx.Err() != nil || f.root.Err() != nil || !origin.Lease.Valid(f.config.Now()) || !origin.Lease.Operation.CurrentValid(f.config.Now()) || origin.Lease.Operation.Path.HubClusterID != f.config.Pool.ClusterID || origin.Lease.Operation.Path.ConnectorClusterID != f.config.Connector.binding.ClusterID || !origin.Proof.Valid(f.config.Now()) || h.Reference != nativeWireRef(origin.Lease.Operation.Reference) || len(h.WorkerLeaf) == 0 || origin.Proof.Binding.InstallationID != f.config.Pool.InstallationID || origin.Proof.Binding.ClusterID != f.config.Connector.binding.ClusterID {
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	if !f.admit() {
		return nil, nil, artifact.ErrDownloadCapacity
	}
	conversationUntil := origin.Lease.Until
	if origin.Lease.Operation.Kind == value.NativeResponse {
		conversationUntil = origin.Lease.Operation.Until
	}
	call, cancel := context.WithDeadline(ctx, conversationUntil)
	rootJoined := make(chan struct{})
	stopRoot := context.AfterFunc(f.root, func() { cancel(); close(rootJoined) })
	cleanup := sync.OnceFunc(func() {
		cancel()
		if !stopRoot() {
			<-rootJoined
		}
		f.release()
	})
	retained := false
	defer func() {
		if !retained {
			cleanup()
		}
	}()
	operation := origin.Lease.Operation
	binding := fleet.OwnerBinding{InstallationID: f.config.Pool.InstallationID, ClusterID: f.config.Pool.ClusterID, IssuerEpoch: f.config.Pool.IssuerEpoch, PodUID: operation.HubPodUID, ProcessEpoch: operation.HubProcessEpoch}
	route, e := f.config.Routes.CurrentOwnerRoute(call, binding)
	if e != nil || !route.Valid(f.config.Now()) || route.Endpoint.Binding != binding || route.Endpoint.Pool != f.config.Pool || route.Configuration.Configuration.Revision != operation.Path.HubConfiguration {
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	route.Configuration.Configuration = route.Configuration.Configuration.Clone()
	route.Endpoint.Addresses = slices.Clone(route.Endpoint.Addresses)
	certificate, local, localUntil, e := f.config.Connector.current(call)
	if e != nil {
		return nil, nil, e
	}
	until := identity.Earlier(origin.Lease.Until, identity.Earlier(route.FreshUntil, localUntil))
	if origin.Lease.Operation.Kind == value.NativeResponse {
		until = conversationUntil
	}
	bounded, stopBound := context.WithDeadline(call, until)
	oldCleanup := cleanup
	cleanup = sync.OnceFunc(func() { stopBound(); oldCleanup() })
	call = bounded
	name, e := OwnerServerName(binding)
	if e != nil {
		return nil, nil, e
	}
	var connection *OwnerConnection
	var original fleet.AuthenticatedOwner
	// Invoked synchronously during the actual TLS handshake before the POST can
	// forward its dedicated worker token. Later frames repeat the same checks.
	peers := func(c context.Context, state *tls.ConnectionState) (value.NativeLease, error) {
		_, current, localBound, e := f.config.Connector.current(c)
		if e != nil || current != local {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		conn, e := NewOwnerServerConnection(f.verifier, state, binding)
		if e != nil {
			return value.NativeLease{}, e
		}
		peer, e := f.config.Authentication.AuthenticateOwner(c, conn)
		if e != nil || !peer.Valid(f.config.Now()) || peer.Pool != f.config.Pool || peer.ConfigurationRevision != route.Configuration.Configuration.Revision || peer.Pod != route.Endpoint.Pod || peer.ReplicaSetUID != route.Endpoint.ReplicaSetUID {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		if original.Certificate.Digest != (artifact.Digest{}) && !sameForwardPeer(peer, original) {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		currentRoute, e := f.config.Routes.CurrentOwnerRoute(c, binding)
		if e != nil || !currentRoute.Valid(f.config.Now()) || !currentRoute.Configuration.Configuration.Equal(route.Configuration.Configuration) || currentRoute.Endpoint.Binding != route.Endpoint.Binding || currentRoute.Endpoint.Pod != route.Endpoint.Pod || currentRoute.Endpoint.ReplicaSetUID != route.Endpoint.ReplicaSetUID || !slices.Equal(currentRoute.Endpoint.Addresses, route.Endpoint.Addresses) {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		lease, e := f.config.Origins.Recheck(c, origin)
		if e != nil {
			return lease, e
		}
		lease.Until = identity.Earlier(lease.Until, identity.Earlier(until, identity.Earlier(localBound, identity.Earlier(peer.ValidUntil, currentRoute.FreshUntil))))
		if !lease.Valid(f.config.Now()) || c.Err() != nil || f.root.Err() != nil {
			return value.NativeLease{}, artifact.ErrDownloadExpired
		}
		connection = conn
		original = peer
		return lease, nil
	}
	tlsConfig := &tls.Config{RootCAs: f.config.OwnerRoots, Certificates: []tls.Certificate{*certificate}, Time: f.config.Now, SessionTicketsDisabled: true}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if state.DidResume {
			return artifact.ErrDownloadUnavailable
		}
		_, e := peers(call, &state)
		return e
	}
	client, e := NewNativeClient("https://"+net.JoinHostPort(name, strconv.Itoa(f.config.Pool.NativePort))+contracts.NativeOwnerPath, tlsConfig)
	if e != nil {
		return nil, nil, e
	}
	var supplied atomic.Bool
	client.dial = func(c context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(name, strconv.Itoa(f.config.Pool.NativePort)) || !supplied.CompareAndSwap(false, true) {
			return nil, artifact.ErrDownloadUnavailable
		}
		var last error
		for _, ip := range route.Endpoint.Addresses {
			if c.Err() != nil || call.Err() != nil {
				return nil, artifact.ErrDownloadExpired
			}
			raw, e := f.dial(c, "tcp", net.JoinHostPort(ip, strconv.Itoa(f.config.Pool.NativePort)))
			if e == nil && raw != nil {
				return raw, nil
			}
			if raw != nil {
				raw.Close()
			}
			last = e
		}
		if last == nil {
			last = artifact.ErrDownloadUnavailable
		}
		return nil, last
	}
	stream, e := client.Open(call, h)
	if e != nil {
		return nil, nil, e
	}
	if connection == nil {
		stream.Close()
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	// This callback may run concurrently for duplex reads/writes. The original
	// peer snapshot is immutable; serialize fresh checks and never replace it.
	firstPeer := original
	var mu sync.Mutex
	gate, e := evidence.NewNativeFrameGate(call, func(c context.Context) (value.NativeLease, error) {
		mu.Lock()
		defer mu.Unlock()
		state := stream.Peer()
		lease, e := peers(c, &state)
		if e != nil || !sameForwardPeer(original, firstPeer) {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		return lease, nil
	}, f.config.Now)
	if e != nil {
		stream.Close()
		return nil, nil, e
	}
	owned := &routedNativeStream{NativeStream: stream, gate: gate}
	baseCleanup := cleanup
	owned.cleanup = func() { f.mu.Lock(); delete(f.streams, owned); f.mu.Unlock(); baseCleanup() }
	f.mu.Lock()
	if f.closed || call.Err() != nil || f.root.Err() != nil {
		f.mu.Unlock()
		gate.Close()
		stream.Close()
		_ = gate.Wait(context.Background())
		return nil, nil, artifact.ErrDownloadExpired
	}
	f.streams[owned] = struct{}{}
	retained = true
	f.mu.Unlock()
	return owned, gate, nil
}

type routedNativeStream struct {
	contracts.NativeStream
	gate    *evidence.NativeFrameGate
	cleanup func()
	once    sync.Once
}

func (s *routedNativeStream) Close() error {
	var err error
	s.once.Do(func() {
		s.gate.Close()
		err = s.NativeStream.Close()
		_ = s.gate.Wait(context.Background())
		s.cleanup()
	})
	return err
}
