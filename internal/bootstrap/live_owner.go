package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	native "asservat.local/asservat/internal/transport/native"
)

type liveOwnerLocator interface {
	LookupLiveWatchOwner(context.Context, [32]byte, string, string) (fleet.OwnerBinding, bool, error)
}
type liveOwnerForwarder struct {
	runtime    *OwnerRuntime
	root       context.Context
	cancel     context.CancelFunc
	rootID     string
	lookup     liveOwnerLocator
	owners     *fleetapp.OwnerAuthenticator
	verifier   *mtls.OwnerPeerVerifier
	slots      chan struct{}
	mu         sync.Mutex
	closed     bool
	active     sync.WaitGroup
	deliveries map[*liveOwnerDelivery]struct{}
	// Tests may remap a protected Pod IP to their owned loopback listener.
	// Production always uses the fixed constructor and current route address.
	newClient func(string, string, *tls.Config) (*mtls.LiveOwnerClient, error)
}
type liveOwnerRoute struct {
	forward *liveOwnerForwarder
	binding fleet.OwnerBinding
}

func (r liveOwnerRoute) OwnerID() string { return r.binding.ProcessEpoch }
func (r liveOwnerRoute) Begin(ctx context.Context, current liveapp.CurrentIdentity, c liveapp.Command, keys liveapp.RouteKeys) (liveapp.CommandDelivery, error) {
	return r.forward.begin(ctx, current, c, keys, r.binding)
}

// newLiveOwner is installed before Run; no identity/network effect occurs at
// construction. Only the existing protected runtime supplies peer/route inputs.
func (d *OwnerDeployment) newLiveOwner(ctx context.Context, service *liveapp.Service, lookup liveOwnerLocator, rootID string) (*liveapp.RoutedService, error) {
	r := d.Runtime
	if ctx == nil || ctx.Err() != nil || r == nil || r.native == nil || r.native.handler == nil || lookup == nil || service == nil {
		return nil, fmt.Errorf("%w: live_owner:62", v.ErrUnavailable)
	}
	peers, ok := r.native.hub.(*mtls.OwnerRequestPeers)
	if !ok || peers.Authenticator == nil {
		return nil, fmt.Errorf("%w: live_owner:66", v.ErrUnavailable)
	}
	verifier, err := mtls.NewOwnerPeerVerifierForPool(r.roots, r.pool, time.Now)
	if err != nil {
		return nil, err
	}
	root, cancel := context.WithCancel(r.root)
	f := &liveOwnerForwarder{runtime: r, root: root, cancel: cancel, rootID: rootID, lookup: lookup, owners: peers.Authenticator, verifier: verifier, slots: make(chan struct{}, r.native.concurrency), deliveries: map[*liveOwnerDelivery]struct{}{}}
	// RootID comes from already accepted live composition, not public input.
	if f.rootID == "" {
		cancel()
		return nil, fmt.Errorf("%w: live_owner:77", v.ErrUnavailable)
	}
	name, err := mtls.OwnerServerName(r.binding)
	if err != nil {
		cancel()
		return nil, err
	}
	handler, err := native.NewLiveOwnerHandler(net.JoinHostPort(name, strconv.Itoa(r.pool.NativePort)), f.rootID, r.binding.ProcessEpoch, service, f, r.native.concurrency)
	if err != nil {
		cancel()
		return nil, err
	}
	r.compose.Lock()
	defer r.compose.Unlock()
	if r.started.Load() || r.native.live != nil {
		cancel()
		return nil, fmt.Errorf("%w: live_owner:93", v.ErrUnavailable)
	}
	roots := r.native.roots.Clone()
	for _, raw := range r.ownerRootDER {
		cert, e := x509.ParseCertificate(raw)
		if e != nil {
			cancel()
			return nil, e
		}
		roots.AddCert(cert)
	}
	r.native.live, r.native.liveRoots = handler, roots
	routed, err := liveapp.NewRoutedService(service, f)
	if err != nil {
		cancel()
		return nil, err
	}
	d.closers = append(d.closers, f.Close)
	return routed, nil
}

func (f *liveOwnerForwarder) LocateLiveOwner(ctx context.Context, k liveapp.RouteKeys) (liveapp.OwnerCommandRoute, bool, error) {
	if ctx == nil || ctx.Err() != nil || f.root.Err() != nil {
		return nil, false, fmt.Errorf("%w: live_owner:116", v.ErrUnavailable)
	}
	key := ""
	if k.WatchID == "" {
		key = hex.EncodeToString(k.OpenKey[:])
	}
	binding, found, err := f.lookup.LookupLiveWatchOwner(ctx, k.PrincipalKey, k.WatchID, key)
	if f.root.Err() != nil {
		return nil, false, fmt.Errorf("%w: live_owner:124", v.ErrUnavailable)
	}
	if err != nil || !found {
		return nil, found, err
	}
	r := f.runtime
	if !binding.Valid() || binding.InstallationID != r.binding.InstallationID || binding.ClusterID != r.binding.ClusterID || binding.IssuerEpoch != r.binding.IssuerEpoch {
		return nil, false, fmt.Errorf("%w: live_owner:131", v.ErrUnavailable)
	}
	return liveOwnerRoute{f, binding}, true, nil
}
func (f *liveOwnerForwarder) admit() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.root.Err() != nil {
		return false
	}
	select {
	case f.slots <- struct{}{}:
		f.active.Add(1)
		return true
	default:
		return false
	}
}
func (f *liveOwnerForwarder) release() { <-f.slots; f.active.Done() }
func (f *liveOwnerForwarder) Close() {
	f.mu.Lock()
	f.closed = true
	f.cancel()
	all := make([]*liveOwnerDelivery, 0, len(f.deliveries))
	for d := range f.deliveries {
		all = append(all, d)
	}
	f.mu.Unlock()
	for _, d := range all {
		_ = d.Close(context.Background())
	}
	f.active.Wait()
}

// CheckLiveOwner verifies an actual same-installation owner client and the
// current exact local server. It returns a shorter bound, never an assertion.
func (f *liveOwnerForwarder) CheckLiveOwner(ctx context.Context, state *tls.ConnectionState, h contracts.LiveOwnerHello) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || state == nil || state.DidResume || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" || h.RootID != f.rootID || h.OwnerID != f.runtime.binding.ProcessEpoch {
		return time.Time{}, fmt.Errorf("%w: live_owner:169", v.ErrDenied)
	}
	peer, err := mtls.NewOwnerClientConnection(f.verifier, state)
	if err != nil {
		return time.Time{}, err
	}
	owners := liveOwnerPhase(f.owners)
	caller, err := owners.AuthenticateOwner(ctx, peer)
	if err != nil || !caller.Valid(time.Now()) || caller.Pool != f.runtime.pool {
		return time.Time{}, fmt.Errorf("%w: live_owner:178", v.ErrDenied)
	}
	serving, err := owners.ObserveOwnerServing(ctx, f.runtime.server)
	if err != nil || !serving.Valid(time.Now()) || serving.Certificate.Binding != f.runtime.binding || serving.Pool != caller.Pool || serving.ConfigurationRevision != caller.ConfigurationRevision {
		return time.Time{}, fmt.Errorf("%w: live_owner:182", v.ErrDenied)
	}
	until := identity.Earlier(h.Until, identity.Earlier(caller.ValidUntil, serving.ValidUntil))
	if !time.Now().Before(until) || ctx.Err() != nil {
		return time.Time{}, fmt.Errorf("%w: live_owner:186", v.ErrUnavailable)
	}
	return until, nil
}
func (f *liveOwnerForwarder) begin(ctx context.Context, current liveapp.CurrentIdentity, c liveapp.Command, k liveapp.RouteKeys, binding fleet.OwnerBinding) (liveapp.CommandDelivery, error) {
	if current == nil || ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("%w: live_owner:192", v.ErrUnavailable)
	}
	if !f.admit() {
		return nil, fmt.Errorf("%w: live_owner:195", v.ErrCapacity)
	}
	retained := false
	defer func() {
		if !retained {
			f.release()
		}
	}()
	call, cancel := context.WithDeadline(ctx, k.Until)
	rootJoined := make(chan struct{})
	stopRoot := context.AfterFunc(f.root, func() { cancel(); close(rootJoined) })
	clean := sync.OnceFunc(func() {
		cancel()
		if !stopRoot() {
			<-rootJoined
		}
	})
	defer func() {
		if !retained {
			clean()
		}
	}()
	route, err := f.owners.Routes.CurrentOwnerRoute(call, binding)
	if err != nil || !route.Valid(time.Now()) || route.Endpoint.Binding != binding || route.Endpoint.Pool != f.runtime.pool || len(route.Endpoint.Addresses) == 0 {
		return nil, fmt.Errorf("%w: live_owner:219", v.ErrUnavailable)
	}
	until := identity.Earlier(k.Until, route.FreshUntil)
	call, stopBound := context.WithDeadline(call, until)
	previous := clean
	clean = sync.OnceFunc(func() { stopBound(); previous() })
	originalClient, err := f.runtime.client.ClientCertificate()
	if err != nil {
		return nil, fmt.Errorf("%w: live_owner:227", v.ErrUnavailable)
	}
	var originalPeer fleet.AuthenticatedOwner
	trust := &tls.Config{RootCAs: f.runtime.roots, GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		c, e := f.runtime.client.ClientCertificate()
		if e != nil || c != originalClient {
			return nil, fmt.Errorf("%w: live_owner:233", v.ErrUnavailable)
		}
		return f.runtime.client.GetClientCertificate(info)
	}}
	check := func(ctx context.Context, state *tls.ConnectionState) (time.Time, error) {
		owners := liveOwnerPhase(f.owners)
		local, e := owners.CheckOwnerClient(ctx, f.runtime.client)
		if e != nil {
			return time.Time{}, e
		}
		conn, e := mtls.NewOwnerServerConnection(f.verifier, state, binding)
		if e != nil {
			return time.Time{}, e
		}
		peer, e := owners.AuthenticateOwner(ctx, conn)
		if e != nil || !peer.Valid(time.Now()) || peer.Certificate.Binding != binding || peer.Pool != route.Endpoint.Pool || peer.Pod != route.Endpoint.Pod || peer.ReplicaSetUID != route.Endpoint.ReplicaSetUID || peer.ConfigurationRevision != route.Configuration.Configuration.Revision {
			return time.Time{}, fmt.Errorf("%w: live_owner:249", v.ErrUnavailable)
		}
		if originalPeer.Certificate.Binding.ProcessEpoch != "" && peer.Certificate != originalPeer.Certificate {
			return time.Time{}, fmt.Errorf("%w: live_owner:252", v.ErrUnavailable)
		}
		originalPeer = peer
		return identity.Earlier(until, identity.Earlier(local, peer.ValidUntil)), nil
	}
	trust.VerifyConnection = func(s tls.ConnectionState) error {
		end, e := check(call, &s)
		if e != nil {
			return e
		}
		until = identity.Earlier(until, end)
		return nil
	}
	name, err := mtls.OwnerServerName(binding)
	if err != nil {
		return nil, err
	}
	authority := net.JoinHostPort(name, strconv.Itoa(f.runtime.pool.NativePort))
	address := net.JoinHostPort(route.Endpoint.Addresses[0], strconv.Itoa(f.runtime.pool.NativePort))
	newClient := f.newClient
	if newClient == nil {
		newClient = mtls.NewLiveOwnerClient
	}
	client, err := newClient("https://"+authority+contracts.LiveOwnerPath, address, trust)
	if err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	command, err := json.Marshal(c)
	if err != nil || len(command) > contracts.LiveOwnerInputBytes {
		return nil, fmt.Errorf("%w: live_owner:285", v.ErrInvalid)
	}
	hello := contracts.LiveOwnerHello{Format: contracts.LiveOwnerFormat, RootID: f.rootID, OwnerID: binding.ProcessEpoch, CallID: ownerRandomID(), Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), Until: until, Actor: contracts.LiveOwnerActor{Issuer: k.Actor.Issuer, Subject: k.Actor.Subject, ClientID: k.Actor.ClientID, Kind: string(k.Actor.Kind)}, Policy: contracts.LiveOwnerPolicy{UID: k.Policy.UID, Generation: k.Policy.Generation, Digest: k.Policy.Digest}, Command: command}
	stream, err := client.Open(call, hello)
	clear(command)
	if err != nil {
		return nil, fmt.Errorf("%w: live_owner:291", v.ErrUnavailable)
	}
	owned := false
	defer func() {
		if !owned {
			_ = stream.Close()
		}
	}()
	sequence := uint64(0)
	for {
		raw, e := stream.Receive(call)
		if e != nil {
			return nil, fmt.Errorf("%w: live_owner:303", v.ErrUnavailable)
		}
		frame, e := contracts.DecodeLiveOwnerFrame(bytes.NewReader(raw.Payload))
		clear(raw.Payload)
		if e != nil || frame.Nonce != hello.Nonce || frame.Sequence != sequence+1 || frame.Until.After(hello.Until) || !time.Now().Before(frame.Until) {
			return nil, fmt.Errorf("%w: live_owner:308", v.ErrUnavailable)
		}
		sequence = frame.Sequence
		if frame.Kind == "current" {
			if raw.Kind != contracts.NativeMetadataFrame {
				return nil, fmt.Errorf("%w: live_owner:313", v.ErrUnavailable)
			}
			callback, stop := context.WithDeadline(call, frame.Until)
			who, e := current.ResolveIdentity(callback)
			stop()
			if e != nil || !who.Valid(time.Now()) || who.Principal != k.Actor || who.Policy != k.Policy {
				return nil, fmt.Errorf("%w: live_owner:319", v.ErrDenied)
			}
			until = identity.Earlier(until, identity.Earlier(frame.Until, who.ValidUntil))
			who.ValidUntil = until
			identityBytes, e := json.Marshal(who)
			if e != nil {
				return nil, e
			}
			reply := contracts.LiveOwnerFrame{Kind: "identity", Nonce: hello.Nonce, Sequence: sequence, Until: until, Identity: identityBytes}
			encoded, e := json.Marshal(reply)
			clear(identityBytes)
			if e != nil || len(encoded) > contracts.NativeCommandBytes {
				return nil, fmt.Errorf("%w: live_owner:331", v.ErrUnavailable)
			}
			e = stream.Send(call, contracts.NativeFrame{Kind: contracts.NativeCommandFrame, Payload: encoded})
			clear(encoded)
			if e != nil {
				return nil, fmt.Errorf("%w: live_owner:336", v.ErrUnavailable)
			}
			continue
		}
		if frame.Kind == "error" {
			return nil, liveOwnerFailure(frame.Failure)
		}
		if frame.Kind != "result" || raw.Kind != contracts.NativeMetadataFrame {
			return nil, fmt.Errorf("%w: live_owner:344", v.ErrUnavailable)
		}
		result, decodeErr := liveapp.DecodeOwnerResult(frame.Result, time.Now())
		if decodeErr != nil {
			return nil, fmt.Errorf("%w: live_owner:348", v.ErrUnavailable)
		}
		peer := stream.Peer()
		end, e := check(call, &peer)
		if e != nil {
			return nil, fmt.Errorf("%w: live_owner:353", v.ErrUnavailable)
		}
		until = identity.Earlier(until, identity.Earlier(frame.Until, end))
		// Exact route must still identify the same original process/Pod/configuration.
		currentRoute, e := f.owners.Routes.CurrentOwnerRoute(call, binding)
		if e != nil || !currentRoute.Valid(time.Now()) || currentRoute.Endpoint.Binding != binding || currentRoute.Endpoint.Pod != route.Endpoint.Pod || !currentRoute.Configuration.Configuration.Equal(route.Configuration.Configuration) || !time.Now().Before(until) {
			return nil, fmt.Errorf("%w: live_owner:359", v.ErrUnavailable)
		}
		until = identity.Earlier(until, currentRoute.FreshUntil)
		if result.Batch != nil {
			result.Batch.DisclosureUntil = until
		}
		ownedCtx, ownedCancel := context.WithDeadline(call, until)
		d := &liveOwnerDelivery{forward: f, stream: stream, ctx: ownedCtx, cancel: ownedCancel, until: until, result: result, hello: hello, sequence: sequence, client: originalClient, done: make(chan struct{}), clean: clean}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			ownedCancel()
			return nil, fmt.Errorf("%w: live_owner:371", v.ErrUnavailable)
		}
		f.deliveries[d] = struct{}{}
		f.mu.Unlock()
		retained, owned = true, true
		go d.watch()
		return d, nil
	}
}
func liveOwnerFailure(s string) error {
	switch s {
	case "denied":
		return fmt.Errorf("%w: live_owner:383", v.ErrDenied)
	case "conflict":
		return fmt.Errorf("%w: live_owner:385", v.ErrConflict)
	case "capacity":
		return fmt.Errorf("%w: live_owner:387", v.ErrCapacity)
	case "invalid":
		return fmt.Errorf("%w: live_owner:389", v.ErrInvalid)
	default:
		return fmt.Errorf("%w: live_owner:391", v.ErrUnavailable)
	}
}

type liveOwnerDelivery struct {
	forward   *liveOwnerForwarder
	stream    *mtls.NativeClientStream
	ctx       context.Context
	cancel    context.CancelFunc
	until     time.Time
	mu        sync.Mutex
	result    liveapp.CommandResult
	hello     contracts.LiveOwnerHello
	sequence  uint64
	client    fleet.OwnerCertificate
	closing   bool
	confirmed bool
	done      chan struct{}
	once      sync.Once
	clean     func()
}

func (d *liveOwnerDelivery) watch() {
	defer close(d.done)
	f, e := d.stream.Receive(d.ctx)
	if e == nil {
		ack, err := contracts.DecodeLiveOwnerFrame(bytes.NewReader(f.Payload))
		clear(f.Payload)
		d.mu.Lock()
		d.confirmed = err == nil && d.closing && f.Kind == contracts.NativeDoneFrame && ack.Kind == "done" && ack.Nonce == d.hello.Nonce && ack.Sequence == d.sequence+1 && !ack.Until.After(d.until)
		valid := d.confirmed
		d.mu.Unlock()
		if valid {
			return
		}
	}
	d.cancel()
	_ = d.stream.Close()
}
func (d *liveOwnerDelivery) Result() liveapp.CommandResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.result
	if out.Batch != nil {
		b := v.CloneBatch(*out.Batch)
		out.Batch = &b
	}
	if out.Watch != nil {
		b, _ := json.Marshal(out.Watch)
		var w v.Watch
		_ = json.Unmarshal(b, &w)
		clear(b)
		out.Watch = &w
	}
	return out
}
func (d *liveOwnerDelivery) Done() <-chan struct{} { return d.ctx.Done() }
func (d *liveOwnerDelivery) CheckDisclosure(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || d.ctx.Err() != nil || d.stream.Context().Err() != nil || !time.Now().Before(d.until) {
		return fmt.Errorf("%w: live_owner:450", v.ErrUnavailable)
	}
	current, e := d.forward.runtime.client.ClientCertificate()
	if e != nil || current != d.client {
		return fmt.Errorf("%w: live_owner:454", v.ErrUnavailable)
	}
	return nil
}
func (d *liveOwnerDelivery) Close(ctx context.Context) error {
	var result error
	d.once.Do(func() {
		d.mu.Lock()
		d.closing = true
		d.mu.Unlock()
		if d.CheckDisclosure(ctx) == nil {
			ack := contracts.LiveOwnerFrame{Kind: "done", Nonce: d.hello.Nonce, Sequence: d.sequence + 1, Until: d.until}
			b, _ := json.Marshal(ack)
			if d.stream.Send(d.ctx, contracts.NativeFrame{Kind: contracts.NativeDoneFrame, Payload: b}) == nil {
				<-d.done
			}
			clear(b)
		}
		d.cancel()
		_ = d.stream.Close()
		<-d.done
		d.clean()
		d.mu.Lock()
		if d.result.Batch != nil {
			clear(d.result.Batch.Rows)
		}
		d.result = liveapp.CommandResult{}
		confirmed := d.confirmed
		d.mu.Unlock()
		d.forward.mu.Lock()
		delete(d.forward.deliveries, d)
		d.forward.mu.Unlock()
		d.forward.release()
		if !confirmed {
			result = v.ErrUnavailable
		}
	})
	return result
}

var _ liveapp.OwnerCommandLookup = (*liveOwnerForwarder)(nil)
var _ native.LiveOwnerAdmission = (*liveOwnerForwarder)(nil)
