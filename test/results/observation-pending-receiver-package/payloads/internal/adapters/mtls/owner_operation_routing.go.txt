package mtls

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerObservationRoutingAdmission belongs to one reserved v2 locator record.
// Its root is that record's original finite lifetime, not the GET context which
// net/http cancels on return. Bootstrap supplies the concrete native handle;
// correlations, leaf identities and returned facts cannot construct one.
// General OwnerAuthenticator and v1 receiving semantics remain unchanged.
//
// Complete takes ownership of its native handle even on error. The record owns
// Close; the framed coordinator only borrows the operation returned by Claim.
// The caller still owns response I/O and must join it before releasing its slot.
type OwnerObservationRoutingAdmission struct {
	root                                             context.Context
	cancel                                           context.CancelFunc
	pin                                              value.OwnerObservationPin
	request                                          value.OwnerObservationRequest
	server                                           *OwnerCredentials
	registry                                         app.OwnerCertificateRegistry
	peer                                             *OwnerConnection
	claimPeer                                        *OwnerConnection
	sender, holder                                   value.OwnerRegistrationObservation
	now                                              func() time.Time
	mu                                               sync.Mutex
	closed, busy, started, completed, claimed, final bool
	nativeRoot                                       context.Context
	nativeCancel                                     context.CancelFunc
	joinNativeInput                                  func()
	until                                            time.Time
	native                                           *ownerRoutingNative
	operation                                        *OwnerObservationOperation
	joined                                           sync.WaitGroup
	once                                             sync.Once
}

// This wrapper only joins duplicate Close ownership during constructor failure
// and concurrent process cancellation. It cannot refresh or repeat a read.
type ownerRoutingNative struct {
	app.OwnerNativeObservationOperation
	once sync.Once
}

func (n *ownerRoutingNative) Close() { n.once.Do(n.OwnerNativeObservationOperation.Close) }

func NewOwnerObservationRoutingAdmission(ctx context.Context, pin value.OwnerObservationPin, request value.OwnerObservationRequest, server *OwnerCredentials, registry app.OwnerCertificateRegistry, state *tls.ConnectionState, now func() time.Time) (*OwnerObservationRoutingAdmission, error) {
	if ctx == nil || ctx.Err() != nil || now == nil || !pin.Valid() || pin.Pool.NativeCandidateLimit == 0 || !request.Valid(now()) || request.RootID != pin.RootID || server == nil || server.usage != "server" || !server.verifier.matchesPool(pin.Pool) || registry == nil {
		return nil, value.ErrInvalid
	}
	end, finite := ctx.Deadline()
	if !finite || !now().Before(end) || end.After(now().Add(5*time.Second)) {
		return nil, value.ErrInvalid
	}
	common, err := OwnerBootstrapServerName(pin.Pool)
	if err != nil || !ownerRoutingTLS(state, common) {
		return nil, value.ErrDenied
	}
	peer, err := NewOwnerClientConnection(server.verifier, state)
	if err != nil {
		return nil, err
	}
	client, err := peer.OwnerCertificate()
	if err != nil {
		return nil, err
	}
	leaf, err := server.ServingCertificate()
	if err != nil {
		return nil, err
	}
	end = identity.Earlier(end, identity.Earlier(request.NotAfter, identity.Earlier(client.NotAfter, leaf.NotAfter)))
	root, cancel := context.WithDeadline(ctx, end)
	r := &OwnerObservationRoutingAdmission{root: root, cancel: cancel, pin: pin, request: request, server: server, registry: registry, peer: peer, now: now, until: end}
	// No native read can occur before both actual TLS identities and current
	// accepted SQL configuration have passed. Each earlier cap reaches the next
	// I/O immediately, including the native Begin performed by bootstrap.
	r.sender, err = r.current(root, client, peer)
	if err != nil {
		cancel()
		return nil, err
	}
	r.until = identity.Earlier(r.until, r.sender.FreshUntil)
	call, stop := context.WithDeadline(root, r.until)
	defer stop()
	r.holder, err = r.current(call, leaf, nil)
	if err != nil || !r.sender.Configuration.Configuration.Equal(r.holder.Configuration.Configuration) || call.Err() != nil {
		cancel()
		return nil, value.ErrUnavailable
	}
	r.until = identity.Earlier(r.until, r.holder.FreshUntil)
	if !now().Before(r.until) {
		cancel()
		return nil, value.ErrUnavailable
	}
	return r, nil
}
func ownerRoutingTLS(state *tls.ConnectionState, name string) bool {
	return state != nil && state.HandshakeComplete && !state.DidResume && state.Version == tls.VersionTLS13 && state.NegotiatedProtocol == "h2" && state.ServerName == name
}

// NativeInput supplies bootstrap's one concrete Begin with the exact peers and
// retained context. Complete must be called exactly once after Begin returns,
// including Complete(ctx, nil) on a failed Begin. Close cancels and joins that
// admitted construction before returning. The context remains owned here; a
// successful Begin must not be destroyed when its GET handler returns.
func (r *OwnerObservationRoutingAdmission) NativeInput(ctx context.Context) (context.Context, []value.OwnerBinding, error) {
	if r == nil {
		return nil, nil, value.ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	end, valid := r.callEnd(ctx)
	if !valid || r.busy || r.started {
		return nil, nil, value.ErrUnavailable
	}
	peers := []value.OwnerBinding{r.sender.Certificate.Binding}
	if r.holder.Certificate.Binding != peers[0] {
		peers = append(peers, r.holder.Certificate.Binding)
	}
	r.until = end
	call, stop := context.WithDeadline(r.root, end)
	r.nativeRoot, r.nativeCancel = call, stop
	r.joinNativeInput = sync.OnceFunc(linkObservationCancellation(ctx, r.cancel))
	r.started, r.busy = true, true
	r.joined.Add(1)
	return call, peers, nil
}

// Complete takes the native handle on the first call, even if that call fails.
// A duplicate/no-Begin call takes no ownership. It cannot replace the original
// handle. A nil handle reports failed Begin and still joins the admitted work.
func (r *OwnerObservationRoutingAdmission) Complete(ctx context.Context, native app.OwnerNativeObservationOperation) (*OwnerObservationOperation, time.Time, error) {
	if r == nil {
		return nil, time.Time{}, value.ErrInvalid
	}
	r.mu.Lock()
	if !r.started || r.completed {
		r.mu.Unlock()
		return nil, time.Time{}, value.ErrUnavailable
	}
	end, valid := r.callEnd(ctx)
	r.completed = true
	if native != nil {
		r.native = &ownerRoutingNative{OwnerNativeObservationOperation: native}
	}
	owned, inputJoin := r.native, r.joinNativeInput
	r.mu.Unlock()
	good := false
	defer func() {
		inputJoin()
		if !good && owned != nil {
			owned.Close()
		}
		r.finish(good)
	}()
	if !valid || owned == nil {
		return nil, time.Time{}, value.ErrUnavailable
	}
	// This constructor parent survives successful completion. Cancelling an
	// ordinary I/O child on return would also kill the retained native proof.
	call, cancel := context.WithDeadline(r.nativeRoot, end)
	join := sync.OnceFunc(linkObservationCancellation(ctx, r.cancel))
	defer func() {
		join()
		if !good {
			cancel()
		}
	}()
	op, err := NewOwnerObservationOperation(call, r.pin, r.request, r.server, r.registry, owned, r.now)
	if err != nil {
		return nil, time.Time{}, err
	}
	r.mu.Lock()
	r.operation = op
	r.mu.Unlock()
	if !sameOwnerOperationRegistration(op.registration, r.holder) || !r.matchesPeers(op.initial) {
		return nil, time.Time{}, value.ErrUnavailable
	}
	end = identity.Earlier(end, op.until)
	current, stopCurrent := context.WithDeadline(call, end)
	defer stopCurrent()
	sender, err := r.current(current, r.sender.Certificate, r.peer)
	if err != nil || !sameOwnerOperationRegistration(sender, r.sender) {
		return nil, time.Time{}, value.ErrUnavailable
	}
	end = identity.Earlier(end, sender.FreshUntil)
	join()
	inputJoin()
	if !r.restrict(op, end) || ctx.Err() != nil || current.Err() != nil {
		return nil, time.Time{}, value.ErrUnavailable
	}
	good = true
	return op, end, nil
}

// Claim spends the exact admitted record before current blocking reads. New
// TLS is mandatory and must use the exact owner SNI and the original client
// leaf. A failed/unknown claim cannot be retried through this object.
func (r *OwnerObservationRoutingAdmission) Claim(ctx context.Context, state *tls.ConnectionState) (*OwnerObservationOperation, time.Time, error) {
	if r == nil {
		return nil, time.Time{}, value.ErrInvalid
	}
	r.mu.Lock()
	end, valid := r.callEnd(ctx)
	if !valid || r.busy || !r.completed || r.operation == nil || r.claimed {
		r.mu.Unlock()
		return nil, time.Time{}, value.ErrUnavailable
	}
	r.claimed, r.busy = true, true
	op := r.operation
	r.joined.Add(1)
	r.mu.Unlock()
	call, cancel := context.WithDeadline(r.root, end)
	join := linkObservationCancellation(ctx, cancel)
	good := false
	defer func() { cancel(); join(); r.finish(good) }()
	name, err := OwnerServerName(r.holder.Certificate.Binding)
	if err != nil || !ownerRoutingTLS(state, name) {
		return nil, time.Time{}, value.ErrDenied
	}
	peer, err := NewOwnerClientConnection(r.server.verifier, state)
	if err != nil {
		return nil, time.Time{}, err
	}
	client, err := peer.OwnerCertificate()
	if err != nil || client != r.sender.Certificate {
		return nil, time.Time{}, value.ErrDenied
	}
	sender, err := r.current(call, client, peer)
	if err != nil || !sameOwnerOperationRegistration(sender, r.sender) {
		return nil, time.Time{}, value.ErrUnavailable
	}
	end = identity.Earlier(end, sender.FreshUntil)
	next, stop := context.WithDeadline(call, end)
	defer stop()
	holder, err := r.current(next, r.holder.Certificate, nil)
	if err != nil || !sameOwnerOperationRegistration(holder, r.holder) {
		return nil, time.Time{}, value.ErrUnavailable
	}
	end = identity.Earlier(end, holder.FreshUntil)
	if !r.restrict(op, end) || next.Err() != nil || ctx.Err() != nil {
		return nil, time.Time{}, value.ErrUnavailable
	}
	r.mu.Lock()
	r.claimPeer = peer
	r.mu.Unlock()
	good = true
	return op, end, nil
}

// Final is after the framed coordinator's acknowledged terminal EOF/join. It
// consumes the same operation's already final native facts; it cannot perform
// Original again, create another bracket, or certify response delivery.
func (r *OwnerObservationRoutingAdmission) Final(ctx context.Context) (time.Time, error) {
	if r == nil {
		return time.Time{}, value.ErrInvalid
	}
	r.mu.Lock()
	end, valid := r.callEnd(ctx)
	if !valid || r.busy || !r.claimed || r.final || r.operation == nil {
		r.mu.Unlock()
		return time.Time{}, value.ErrUnavailable
	}
	r.final, r.busy = true, true
	op := r.operation
	r.joined.Add(1)
	r.mu.Unlock()
	call, cancel := context.WithDeadline(r.root, end)
	join := linkObservationCancellation(ctx, cancel)
	good := false
	defer func() { cancel(); join(); r.finish(good) }()
	ownerEnd, err := op.CheckFinal(call)
	if err != nil {
		return time.Time{}, err
	}
	end = identity.Earlier(end, ownerEnd)
	current, stop := context.WithDeadline(call, end)
	defer stop()
	sender, err := r.current(current, r.sender.Certificate, r.claimPeer)
	if err != nil || !sameOwnerOperationRegistration(sender, r.sender) {
		return time.Time{}, value.ErrUnavailable
	}
	end = identity.Earlier(end, sender.FreshUntil)
	op.mu.Lock()
	facts := op.facts.Clone()
	op.mu.Unlock()
	if !facts.Final || !facts.Valid(r.now()) || !r.matchesPeers(facts) || !r.restrict(op, end) || ctx.Err() != nil || current.Err() != nil {
		return time.Time{}, value.ErrUnavailable
	}
	good = true
	return end, nil
}

func (r *OwnerObservationRoutingAdmission) current(ctx context.Context, leaf value.OwnerCertificate, peer *OwnerConnection) (value.OwnerRegistrationObservation, error) {
	var zero value.OwnerRegistrationObservation
	if ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	serving, err := r.server.ServingCertificate()
	if err != nil || serving.Binding != r.server.binding || (!r.holder.Certificate.NotAfter.IsZero() && serving != r.holder.Certificate) || peer == nil && serving != leaf {
		return zero, value.ErrUnavailable
	}
	registration, err := r.registry.ReadOwnerRegistration(ctx, leaf)
	if err != nil || ctx.Err() != nil || !registration.Valid(r.now()) || registration.Certificate != leaf || registration.Enrollment.Pool != r.pin.Pool || registration.Enrollment.SourceUID != r.pin.SourceUID || registration.Configuration.Configuration.Revision.UID != r.pin.SourceUID {
		return zero, value.ErrUnavailable
	}
	var checked value.OwnerCertificate
	if peer != nil {
		checked, err = peer.VerifyCurrentOwner(registration.Configuration)
	} else {
		checked, err = r.server.VerifyServingCertificate(registration.Configuration)
	}
	currentServing, servingErr := r.server.ServingCertificate()
	if err != nil || checked != leaf || servingErr != nil || currentServing != serving || ctx.Err() != nil || !registration.Valid(r.now()) {
		return zero, value.ErrUnavailable
	}
	registration.Configuration.Configuration = registration.Configuration.Configuration.Clone()
	return registration, nil
}
func (r *OwnerObservationRoutingAdmission) matchesPeers(facts value.OwnerObservationNativeFacts) bool {
	count := 2
	if r.sender.Certificate.Binding == r.holder.Certificate.Binding {
		count = 1
	}
	return len(facts.Peers) == count && ownerOperationPeerMatches(facts, r.sender) && ownerOperationPeerMatches(facts, r.holder)
}

// callEnd requires r.mu. The supplied context may narrow, never replace the
// retained process/caller root or a previously observed source/registry bound.
func (r *OwnerObservationRoutingAdmission) callEnd(ctx context.Context) (time.Time, bool) {
	if ctx == nil || ctx.Err() != nil || r.closed || r.root.Err() != nil {
		return time.Time{}, false
	}
	leaf, err := r.server.ServingCertificate()
	client, clientErr := r.peer.OwnerCertificate()
	if err != nil || clientErr != nil || leaf != r.holder.Certificate || client != r.sender.Certificate || ctx.Err() != nil {
		r.closed = true
		r.cancel()
		return time.Time{}, false
	}
	end, finite := ctx.Deadline()
	end = identity.Earlier(end, r.until)
	return end, finite && r.now().Before(end)
}
func (r *OwnerObservationRoutingAdmission) restrict(op *OwnerObservationOperation, end time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.root.Err() != nil || !r.now().Before(end) {
		return false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.closed || op.busy || op.root.Err() != nil || !r.now().Before(op.until) {
		return false
	}
	r.until = identity.Earlier(r.until, identity.Earlier(end, op.until))
	op.until = r.until
	return true
}
func (r *OwnerObservationRoutingAdmission) finish(good bool) {
	r.mu.Lock()
	r.busy = false
	if !good {
		r.closed = true
		r.cancel()
	}
	r.mu.Unlock()
	r.joined.Done()
}
func (r *OwnerObservationRoutingAdmission) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.cancel()
		native, stop := r.native, r.nativeCancel
		r.mu.Unlock()
		if stop != nil {
			stop()
		}
		if native != nil {
			native.Close()
		}
		r.joined.Wait()
		r.mu.Lock()
		op := r.operation
		r.mu.Unlock()
		if op != nil {
			op.Close()
		}
	})
}
