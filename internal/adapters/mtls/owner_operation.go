package mtls

import (
	"context"
	"crypto/tls"
	"slices"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
)

// OwnerObservationOperation owns one already-opened native handle. Its root is
// the original finite routing-operation lifetime, not a completed GET handler.
// Bootstrap transfers the native handle on successful construction. The routing
// record remains the sole Close owner; one regional coordinator may borrow it.
// Returned native facts/correlations cannot construct or replace this state.
// General OwnerAuthenticator semantics are unchanged.
type OwnerObservationOperation struct {
	root                          context.Context
	cancel                        context.CancelFunc
	pin                           value.OwnerObservationPin
	request                       value.OwnerObservationRequest
	server                        *OwnerCredentials
	registry                      app.OwnerCertificateRegistry
	native                        app.OwnerNativeObservationOperation
	leaf                          value.OwnerCertificate
	initial                       value.OwnerObservationNativeFacts
	facts                         value.OwnerObservationNativeFacts
	registration                  value.OwnerRegistrationObservation
	id                            string
	now                           func() time.Time
	mu                            sync.Mutex
	closed, busy, attached, final bool
	exchangeID                    string
	channel                       artifact.Digest
	peer                          value.PeerCertificate
	ordinal                       int
	until                         time.Time
	joined                        sync.WaitGroup
	once                          sync.Once
}

func NewOwnerObservationOperation(ctx context.Context, pin value.OwnerObservationPin, request value.OwnerObservationRequest, server *OwnerCredentials, registry app.OwnerCertificateRegistry, native app.OwnerNativeObservationOperation, now func() time.Time) (*OwnerObservationOperation, error) {
	if ctx == nil || ctx.Err() != nil || now == nil || !pin.Valid() || !request.Valid(now()) || request.RootID != pin.RootID || server == nil || server.usage != "server" || !server.verifier.matchesPool(pin.Pool) || registry == nil || native == nil {
		return nil, value.ErrInvalid
	}
	end, ok := ctx.Deadline()
	if !ok || !now().Before(end) {
		return nil, value.ErrInvalid
	}
	leaf, err := server.ServingCertificate()
	if err != nil {
		return nil, err
	}
	until := identity.Earlier(end, identity.Earlier(request.NotAfter, leaf.NotAfter))
	root, cancel := context.WithDeadline(ctx, until)
	o := &OwnerObservationOperation{root: root, cancel: cancel, pin: pin, request: request, server: server, registry: registry, native: native, leaf: leaf, id: uuid.NewString(), now: now, until: until}
	first, err := o.current(root)
	if err != nil {
		cancel()
		return nil, err
	}
	firstCall, stopFirst := context.WithDeadline(root, identity.Earlier(until, first.FreshUntil))
	defer stopFirst()
	facts, err := native.Original(firstCall)
	if err != nil || !facts.Valid(now()) || facts.Final || facts.Pin != pin || !value.SameOwnerObservationRequest(facts.Request, request) || !ownerOperationPeerMatches(facts, first) {
		cancel()
		return nil, value.ErrUnavailable
	}
	o.initial = facts.Clone()
	o.facts = facts.Clone()
	o.registration = first
	o.until = identity.Earlier(o.until, identity.Earlier(facts.FreshUntil, first.FreshUntil))
	finalCall, stopFinal := context.WithDeadline(root, o.until)
	defer stopFinal()
	last, err := o.current(finalCall)
	if err != nil || !sameOwnerOperationRegistration(first, last) || root.Err() != nil || !now().Before(o.until) {
		cancel()
		return nil, value.ErrUnavailable
	}
	o.until = identity.Earlier(o.until, last.FreshUntil)
	return o, nil
}
func ownerOperationPeerMatches(f value.OwnerObservationNativeFacts, r value.OwnerRegistrationObservation) bool {
	for _, p := range f.Peers {
		if p.Binding == r.Certificate.Binding {
			return p.Pod == r.Enrollment.Pod && p.ReplicaSetUID == r.Enrollment.ReplicaSetUID
		}
	}
	return false
}
func sameOwnerOperationRegistration(a, b value.OwnerRegistrationObservation) bool {
	return a.Certificate == b.Certificate && a.Enrollment == b.Enrollment && a.Configuration.Configuration.Equal(b.Configuration.Configuration)
}
func sameOwnerOperationFacts(a, b value.OwnerObservationNativeFacts) bool {
	if a.Pin != b.Pin || !value.SameOwnerObservationRequest(a.Request, b.Request) || !a.ObservedAt.Equal(b.ObservedAt) || b.FreshUntil.After(a.FreshUntil) || len(a.Peers) != len(b.Peers) {
		return false
	}
	for i, p := range a.Peers {
		q := b.Peers[i]
		if p.Binding != q.Binding || p.Pod != q.Pod || p.ReplicaSetUID != q.ReplicaSetUID || p.WorkloadDigest != q.WorkloadDigest || !slices.Equal(p.Addresses, q.Addresses) {
			return false
		}
	}
	return true
}
func (o *OwnerObservationOperation) current(ctx context.Context) (value.OwnerRegistrationObservation, error) {
	var z value.OwnerRegistrationObservation
	leaf, err := o.server.ServingCertificate()
	if err != nil || leaf != o.leaf || ctx.Err() != nil {
		return z, value.ErrUnavailable
	}
	r, err := o.registry.ReadOwnerRegistration(ctx, leaf)
	if err != nil || ctx.Err() != nil || !r.Valid(o.now()) || r.Certificate != leaf || r.Enrollment.Pool != o.pin.Pool || r.Enrollment.SourceUID != o.pin.SourceUID || r.Configuration.Configuration.Pool != o.pin.Pool || r.Configuration.Configuration.Revision.UID != o.pin.SourceUID {
		return z, value.ErrUnavailable
	}
	checked, err := o.server.VerifyServingCertificate(r.Configuration)
	if err != nil || checked != leaf || ctx.Err() != nil || !r.Valid(o.now()) {
		return z, value.ErrUnavailable
	}
	r.Configuration.Configuration = r.Configuration.Configuration.Clone()
	return r, nil
}
func (o *OwnerObservationOperation) fail() {
	if o != nil {
		o.mu.Lock()
		o.closed = true
		o.cancel()
		o.mu.Unlock()
	}
}
func (o *OwnerObservationOperation) Close() {
	if o == nil {
		return
	}
	o.once.Do(func() { o.fail(); o.native.Close(); o.joined.Wait() })
}

// attach is one-use and bound to the actual regional stream, request and serving
// leaf retained when that empty standby was created. It performs no native read.
func (o *OwnerObservationOperation) attach(ctx context.Context, state *tls.ConnectionState, exchange string, leaf value.OwnerCertificate, peer value.PeerCertificate, r value.OwnerObservationRequest) error {
	if o == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(exchange) {
		return value.ErrInvalid
	}
	channel, err := observationOperationConnection(state, r)
	o.mu.Lock()
	defer o.mu.Unlock()
	end, finite := ctx.Deadline()
	if err != nil || !finite || ctx.Err() != nil || o.closed || o.busy || o.attached || o.final || o.root.Err() != nil || leaf != o.leaf || !peer.Valid(o.now()) || peer.Binding.Role != value.ConnectorPeer || peer.Binding.InstallationID != o.pin.Pool.InstallationID || !value.SameOwnerObservationRequest(r, o.request) || !o.now().Before(o.until) {
		o.closed = true
		o.cancel()
		return value.ErrUnavailable
	}
	o.until = identity.Earlier(o.until, identity.Earlier(end, peer.NotAfter))
	if !o.now().Before(o.until) {
		o.closed = true
		o.cancel()
		return value.ErrUnavailable
	}
	o.attached = true
	o.exchangeID = exchange
	o.channel = channel
	o.peer = peer
	return nil
}

// read consumes each ordinal once. Final performs genuine independent native
// I/O once, before proof four. Later result checks consume the retained final
// facts; Original is never reopened after Final.
func (o *OwnerObservationOperation) read(ctx context.Context, ordinal int) (contracts.OwnerObservationOperationReply, error) {
	var z contracts.OwnerObservationOperationReply
	call, finish, err := o.enter(ctx, ordinal, false)
	if err != nil {
		return z, answerStep("enter", err, nil)
	}
	good := false
	defer func() { finish(good) }()
	r, err := o.current(call)
	if err != nil || !sameOwnerOperationRegistration(o.registration, r) {
		return z, answerStep("registration", value.ErrUnavailable, err)
	}
	o.mu.Lock()
	o.until = identity.Earlier(o.until, r.FreshUntil)
	registryEnd := o.until
	o.mu.Unlock()
	registryCall, stopRegistry := context.WithDeadline(call, registryEnd)
	defer stopRegistry()
	facts := o.facts.Clone()
	if ordinal == 4 {
		facts, err = o.native.Final(registryCall)
		if err != nil || !facts.Final || !facts.Valid(o.now()) || !sameOwnerOperationFacts(o.initial, facts) || !ownerOperationPeerMatches(facts, r) {
			return z, answerStep("final-native", value.ErrUnavailable, err)
		}
		nativeCall, stopNative := context.WithDeadline(registryCall, identity.Earlier(registryEnd, facts.FreshUntil))
		defer stopNative()
		r, err = o.current(nativeCall)
		if err != nil || !sameOwnerOperationRegistration(o.registration, r) {
			return z, answerStep("final-registration", value.ErrUnavailable, err)
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.root.Err() != nil || call.Err() != nil || ctx.Err() != nil || !facts.Valid(o.now()) || !r.Valid(o.now()) {
		step := "state"
		switch {
		case !facts.Valid(o.now()):
			step = "facts-expired"
		case !r.Valid(o.now()):
			step = "registration-expired"
		}
		return z, answerStep(step, value.ErrUnavailable, nil)
	}
	o.until = identity.Earlier(o.until, identity.Earlier(facts.FreshUntil, r.FreshUntil))
	facts.FreshUntil = identity.Earlier(facts.FreshUntil, o.until)
	if !facts.Valid(o.now()) {
		return z, answerStep("window", value.ErrUnavailable, nil)
	}
	if ordinal == 4 {
		o.final = true
		o.facts = facts.Clone()
	}
	w, err := ownerOperationReplyWire(o.pin, o.request, o.id, ordinal, o.channel, o.peer, o.leaf, facts, r, o.until, o.now())
	if err != nil {
		return z, err
	}
	good = true
	return w, nil
}
func (o *OwnerObservationOperation) enter(ctx context.Context, ordinal int, terminal bool) (context.Context, func(bool), error) {
	if o == nil {
		return nil, nil, value.ErrInvalid
	}
	o.mu.Lock()
	end, finite := time.Time{}, false
	if ctx != nil {
		end, finite = ctx.Deadline()
	}
	if ctx == nil || ctx.Err() != nil || !finite || o.closed || o.busy || !o.attached || o.root.Err() != nil || !o.now().Before(o.until) || (!terminal && (o.final || ordinal != o.ordinal+1 || ordinal > 4)) || (terminal && o.ordinal == 0) {
		o.closed = true
		o.cancel()
		o.mu.Unlock()
		return nil, nil, value.ErrUnavailable
	}
	o.busy = true
	if !terminal {
		o.ordinal = ordinal
	}
	o.until = identity.Earlier(o.until, end)
	until := o.until
	o.joined.Add(1)
	o.mu.Unlock()
	call, cancel := context.WithDeadline(o.root, until)
	join := linkObservationCancellation(ctx, cancel)
	return call, func(good bool) {
		cancel()
		join()
		o.mu.Lock()
		o.busy = false
		if !good {
			o.closed = true
			o.cancel()
		}
		o.mu.Unlock()
		o.joined.Done()
	}, nil
}

// CheckFinal is current SQL/key/time validation against the exact already final
// native facts. It is deliberately not another native observation or renewal.
// Routing calls it again after coordinator completion before final output.
func (o *OwnerObservationOperation) CheckFinal(ctx context.Context) (time.Time, error) {
	return o.checkRetained(ctx, true)
}
func (o *OwnerObservationOperation) checkRetained(ctx context.Context, requireFinal bool) (time.Time, error) {
	call, finish, err := o.enter(ctx, 0, true)
	if err != nil {
		return time.Time{}, err
	}
	good := false
	defer func() { finish(good) }()
	r, err := o.current(call)
	if err != nil || !sameOwnerOperationRegistration(o.registration, r) {
		return time.Time{}, value.ErrUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.root.Err() != nil || call.Err() != nil || ctx.Err() != nil || (requireFinal && (!o.facts.Final || o.ordinal != 4)) || !o.facts.Valid(o.now()) || !ownerOperationPeerMatches(o.facts, r) {
		return time.Time{}, value.ErrUnavailable
	}
	o.until = identity.Earlier(o.until, r.FreshUntil)
	if !o.now().Before(o.until) {
		return time.Time{}, value.ErrUnavailable
	}
	good = true
	return o.until, nil
}

// This ingress admits only the original installed regional TLS identity. It has
// no full-authenticator/source callback and grants no metadata authority. The
// borrowed operation plus separate SQL49 checks supply those later boundaries.
type OwnerObservationOperationIngress struct{ peers *OwnerObservationIngress }

func NewOwnerObservationOperationIngress(pin value.OwnerObservationPin, server *OwnerCredentials, peers []OwnerObservationPeer, now func() time.Time) (*OwnerObservationOperationIngress, error) {
	if !pin.Valid() || server == nil || server.usage != "server" || !server.verifier.matchesPool(pin.Pool) || now == nil || len(peers) < 1 || len(peers) > 16 {
		return nil, value.ErrInvalid
	}
	fixed := &OwnerObservationIngress{pin: pin, server: server, now: now, peers: make(map[value.PeerBinding]*PeerVerifier, len(peers))}
	for _, p := range peers {
		if !p.Binding.Valid() || p.Binding.Role != value.ConnectorPeer || p.Binding.InstallationID != pin.Pool.InstallationID || p.Binding.IssuerEpoch != pin.Pool.IssuerEpoch || fixed.peers[p.Binding] != nil {
			return nil, value.ErrInvalid
		}
		roots, _, err := OwnerTrustRoots(p.Roots, now())
		if err != nil {
			return nil, err
		}
		v, err := NewPeerVerifier(roots, p.Binding.InstallationID, value.ConnectorPeer, now)
		if err != nil {
			return nil, err
		}
		fixed.peers[p.Binding] = v
	}
	return &OwnerObservationOperationIngress{fixed}, nil
}
