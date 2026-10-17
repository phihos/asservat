package clusterobservation

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// HubObservationConversation is implemented by the concrete same-channel
// coordinator. The installed bootstrap factory binds the exact original
// profile, native owner proof and separately scoped SQL49 registry. A routing
// hello and this transport interface cannot establish those authorities.
type HubObservationConversation interface {
	ObserveCluster(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error)
	Close()
}

// HubObservationFactory belongs to bootstrap, never to a received request. The
// stream and TLS state are the actual accepted connection; there is no address,
// credential, principal, source callback or alternate protocol in the wire.
type HubObservationFactory func(context.Context, context.Context, *tls.ConnectionState, contracts.ClusterObservationHello, *HubObservationStream) (HubObservationConversation, error)

// HubObservationLocator is a bounded local routing observation only. It cannot
// attest activation, namespace protection or another owner's delegation. A
// caller must independently authenticate a remote holder before using its wire
// equivalent. Reading or copying it does not reserve a standby.
type HubObservationLocator struct {
	RootID, ClusterID, ExchangeID string
	Sequence                      uint64
	ObservedAt, FreshUntil        time.Time
}

func (l HubObservationLocator) valid(now time.Time) bool {
	return l.Sequence > 0 && authorization.UUID(l.RootID) && authorization.UUID(l.ClusterID) && authorization.UUID(l.ExchangeID) && identity.Fresh(l.ObservedAt, l.FreshUntil, now, 5*time.Second)
}

// HubObservationHolder counts setup, idle, claimed and closing streams against
// the same finite process limit. One exact claim spends an entry irreversibly.
// Removing routing eligibility never releases its slot before handler cleanup.
type HubObservationHolder struct {
	root    context.Context
	cancel  context.CancelFunc
	now     func() time.Time
	mu      sync.Mutex
	closed  bool
	maximum int
	next    uint64
	entries map[*hubObservationEntry]struct{}
	joined  sync.WaitGroup
}

type hubObservationEntry struct {
	holder                            *HubObservationHolder
	ctx                               context.Context
	cancel                            context.CancelFunc
	rootStop                          func() bool
	rootDone                          chan struct{}
	hello                             contracts.ClusterObservationHello
	sequence                          uint64
	stream                            *HubObservationStream
	conversation                      HubObservationConversation
	ready, claimed, detached, closing bool // protected by holder.mu
	operationDone                     chan struct{}
	resultDone                        chan struct{}
	joined                            chan struct{}
	closeOnce                         sync.Once
}

func NewHubObservationHolder(ctx context.Context, maximum int, now func() time.Time) (*HubObservationHolder, error) {
	if ctx == nil || ctx.Err() != nil || maximum < 1 || maximum > 16 || now == nil {
		return nil, fleet.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	return &HubObservationHolder{root: root, cancel: cancel, maximum: maximum, now: now, entries: make(map[*hubObservationEntry]struct{})}, nil
}

// reserve precedes reading Hello and invoking the bootstrap factory. Failed or
// unknown setup cannot temporarily exceed the admitted process/socket budget.
func (h *HubObservationHolder) reserve(ctx context.Context) (*hubObservationEntry, error) {
	if h == nil || ctx == nil || ctx.Err() != nil {
		return nil, fleet.ErrUnavailable
	}
	end, finite := ctx.Deadline()
	if !finite || !h.now().Before(end) || end.After(h.now().Add(30*time.Second)) {
		return nil, fleet.ErrInvalid
	}
	if d, ok := h.root.Deadline(); ok {
		end = identity.Earlier(end, d)
	}
	if !h.now().Before(end) {
		return nil, fleet.ErrUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.root.Err() != nil || len(h.entries) >= h.maximum || h.next == ^uint64(0) {
		return nil, fleet.ErrUnavailable
	}
	h.next++
	call, cancel := context.WithDeadline(ctx, end)
	e := &hubObservationEntry{holder: h, sequence: h.next, ctx: call, cancel: cancel, operationDone: make(chan struct{}), resultDone: make(chan struct{}), joined: make(chan struct{})}
	e.rootDone = make(chan struct{})
	e.rootStop = context.AfterFunc(h.root, func() { cancel(); close(e.rootDone) })
	h.entries[e] = struct{}{}
	h.joined.Add(1)
	return e, nil
}

func (e *hubObservationEntry) bind(hello contracts.ClusterObservationHello, stream *HubObservationStream, conversation HubObservationConversation) error {
	if e == nil || stream == nil || conversation == nil || hello.Format != contracts.ClusterObservationExchangeFormat || !authorization.UUID(hello.RootID) || !authorization.UUID(hello.ClusterID) || !authorization.UUID(hello.ExchangeID) {
		return fleet.ErrInvalid
	}
	h := e.holder
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || e.closing || e.ctx.Err() != nil || e.conversation != nil {
		return fleet.ErrUnavailable
	}
	for other := range h.entries {
		if other != e && other.hello.ExchangeID == hello.ExchangeID {
			return fleet.ErrUnavailable
		}
	}
	e.hello, e.stream, e.conversation = hello, stream, conversation
	stream.entry = e
	return nil
}

// publish is called only after successful streaming response-header flush.
// Claims cannot race header setup on the ResponseWriter.
func (e *hubObservationEntry) publish() error {
	h := e.holder
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || e.closing || e.ctx.Err() != nil || e.conversation == nil || e.ready {
		return fleet.ErrUnavailable
	}
	e.ready = true
	return nil
}

func (h *HubObservationHolder) Lookup(ctx context.Context, rootID, clusterID string) (HubObservationLocator, error) {
	var zero HubObservationLocator
	if h == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(rootID) || !authorization.UUID(clusterID) {
		return zero, fleet.ErrUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.root.Err() != nil {
		return zero, fleet.ErrUnavailable
	}
	var selected *hubObservationEntry
	for e := range h.entries {
		if !e.ready || e.claimed || e.detached || e.closing || e.ctx.Err() != nil || e.hello.RootID != rootID || e.hello.ClusterID != clusterID {
			continue
		}
		// Deterministic selection is not takeover: a later failed exact claim
		// must not call Lookup again for this original request.
		if selected == nil || e.hello.ExchangeID < selected.hello.ExchangeID {
			selected = e
		}
	}
	if selected == nil {
		return zero, fleet.ErrUnavailable
	}
	start := h.now()
	end, _ := selected.ctx.Deadline()
	end = identity.Earlier(end, start.Add(5*time.Second))
	if d, ok := ctx.Deadline(); ok {
		end = identity.Earlier(end, d)
	}
	l := HubObservationLocator{RootID: rootID, ClusterID: clusterID, ExchangeID: selected.hello.ExchangeID, Sequence: selected.sequence, ObservedAt: start, FreshUntil: end}
	if ctx.Err() != nil || !l.valid(h.now()) {
		return zero, fleet.ErrUnavailable
	}
	return l, nil
}

// Observe consumes only the exact already selected local entry. Upstream
// caller/owner authentication remains mandatory; the conversation independently
// checks its native source and SQL registry before and after metadata.
func (h *HubObservationHolder) Observe(ctx context.Context, locator HubObservationLocator, request fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	var zero fleet.ClusterObservationResult
	if h == nil || ctx == nil || ctx.Err() != nil || !locator.valid(h.now()) || !request.Valid(h.now()) || request.RootID != locator.RootID || request.ClusterID != locator.ClusterID {
		return zero, fleet.ErrUnavailable
	}
	h.mu.Lock()
	var selected *hubObservationEntry
	if !h.closed && h.root.Err() == nil {
		for e := range h.entries {
			if e.sequence == locator.Sequence && e.hello.ExchangeID == locator.ExchangeID && e.hello.RootID == locator.RootID && e.hello.ClusterID == locator.ClusterID && e.ready && !e.claimed && !e.detached && !e.closing && e.ctx.Err() == nil {
				selected = e
				break
			}
		}
	}
	if selected == nil {
		h.mu.Unlock()
		return zero, fleet.ErrUnavailable
	}
	selected.claimed = true
	conversation := selected.conversation
	end, _ := selected.ctx.Deadline()
	end = identity.Earlier(end, identity.Earlier(locator.FreshUntil, request.NotAfter))
	h.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, end)
	joined := make(chan struct{})
	stop := context.AfterFunc(selected.ctx, func() { cancel(); close(joined) })
	var result fleet.ClusterObservationResult
	err := fleet.ErrUnavailable
	if call.Err() == nil {
		result, err = conversation.ObserveCluster(call, request.Clone())
	}
	if call.Err() != nil || selected.stream == nil || !selected.stream.completed() {
		err = fleet.ErrUnavailable
	}
	if !stop() {
		<-joined
	}
	cancel()
	// The handler can now join coordinator/stream cleanup. Wait for its actual
	// completion even when the caller has already cancelled; cancellation is
	// not evidence that an admitted operation has returned.
	close(selected.operationDone)
	close(selected.resultDone)
	<-selected.joined
	digest, digestErr := RequestDigest(request)
	result = result.Restrict(request.RequestedAt, end)
	if err != nil || digestErr != nil || ctx.Err() != nil || h.root.Err() != nil || !result.Matches(request, digest, h.now()) {
		return zero, fleet.ErrUnavailable
	}
	return result, nil
}

// detach is positive exact local routing removal, not a remote acknowledgement.
// It must happen before Receipt is written and cannot release capacity.
func (e *hubObservationEntry) detach() error {
	h := e.holder
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.entries[e]; !ok || e.closing || !e.claimed || e.detached || e.ctx.Err() != nil {
		return fleet.ErrUnavailable
	}
	e.detached = true
	e.ready = false
	return nil
}

// close is owned by the receiving handler, including setup failures. A stale
// entry releases only its own pointer, never a later exchange or replacement.
func (e *hubObservationEntry) close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		h := e.holder
		h.mu.Lock()
		e.closing = true
		e.ready = false
		e.detached = true
		e.cancel()
		stream, conversation, claimed := e.stream, e.conversation, e.claimed
		h.mu.Unlock()
		if stream != nil {
			_ = stream.Close()
		}
		if conversation != nil {
			conversation.Close()
		}
		if claimed {
			<-e.operationDone
		}
		if !e.rootStop() {
			<-e.rootDone
		}
		h.mu.Lock()
		delete(h.entries, e)
		h.mu.Unlock()
		close(e.joined)
		h.joined.Done()
	})
}

func (h *HubObservationHolder) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.cancel()
	entries := make([]*hubObservationEntry, 0, len(h.entries))
	for e := range h.entries {
		entries = append(entries, e)
	}
	h.mu.Unlock()
	// Each receiving handler retains ownership and joins closure. Cancellation
	// wakes it without starting new transport/source work from this method.
	for _, e := range entries {
		e.cancel()
	}
	h.joined.Wait()
}
