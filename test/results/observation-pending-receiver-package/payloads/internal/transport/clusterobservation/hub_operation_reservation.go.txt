package clusterobservation

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// HubObservationOperationReservation spends one exact standby before locator
// output. The original query contains no metadata selection or authority. Only
// one later matching full request may select this retained conversation; a lost
// GET/POST cannot return it to the routing set or bind another query.
// The receiving pending record owns Close, including unknown output/expiry.
type HubObservationOperationReservation struct {
	claim            *HubObservationOperationClaim
	query            fleet.ClusterObservationLocatorQuery
	mu               sync.Mutex
	closed, selected bool
	cancelParent     context.CancelFunc
	joinCaller       func()
	once             sync.Once
}

func (h *HubObservationOperationHolder) ReserveLocator(ctx context.Context, locator HubObservationLocator, q fleet.ClusterObservationLocatorQuery) (*HubObservationOperationReservation, error) {
	if h == nil || ctx == nil || ctx.Err() != nil || !locator.valid(h.now()) || !q.Valid(h.now()) || locator.RootID != q.RootID || locator.ClusterID != q.ClusterID {
		return nil, fleet.ErrUnavailable
	}
	callerEnd, finite := ctx.Deadline()
	if !finite {
		return nil, fleet.ErrUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var selected *hubObservationOperationEntry
	if !h.closed && h.root.Err() == nil && ctx.Err() == nil {
		for e := range h.entries {
			if e.sequence == locator.Sequence && e.hello.ExchangeID == locator.ExchangeID && e.hello.RootID == locator.RootID && e.hello.ClusterID == locator.ClusterID && e.ready && !e.claimed && !e.detached && !e.closing && e.ctx.Err() == nil {
				selected = e
				break
			}
		}
	}
	if selected == nil {
		return nil, fleet.ErrUnavailable
	}
	end, _ := selected.ctx.Deadline()
	end = identity.Earlier(end, identity.Earlier(callerEnd, identity.Earlier(locator.FreshUntil, q.NotAfter)))
	if !h.now().Before(end) {
		return nil, fleet.ErrUnavailable
	}
	selected.claimed = true
	call, cancel := context.WithDeadline(ctx, end)
	// An unselected claim is private to this reservation and cannot Observe.
	// Existing claim shutdown retains the socket slot until handler join.
	c := &HubObservationOperationClaim{entry: selected, parent: ctx, ctx: call, cancel: cancel, until: end, conversation: selected.conversation, closedDone: make(chan struct{}), entryDone: make(chan struct{}), callbackDone: make(chan struct{})}
	c.stopEntry = context.AfterFunc(selected.ctx, func() { cancel(); close(c.entryDone) })
	c.stop = context.AfterFunc(call, func() { c.shutdown(); close(c.callbackDone) })
	return &HubObservationOperationReservation{claim: c, query: q}, nil
}
func (r *HubObservationOperationReservation) Until() time.Time {
	if r == nil {
		return time.Time{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.claim.until
}
func sameOperationLocatorQuery(a, b fleet.ClusterObservationLocatorQuery) bool {
	return a.RootID == b.RootID && a.ClusterID == b.ClusterID && a.RequestID == b.RequestID && a.Challenge == b.Challenge && a.RequestedAt.Equal(b.RequestedAt) && a.NotAfter.Equal(b.NotAfter)
}

// Select is not a new holder lookup/admission and cannot renew the retained
// root. The caller has already checked current exact claim TLS/SQL/native facts.
// It receives the original bootstrap-owned conversation, never proof authority.
func (r *HubObservationOperationReservation) Select(ctx context.Context, request fleet.ClusterObservationRequest) (*HubObservationOperationClaim, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, fleet.ErrUnavailable
	}
	end, finite := ctx.Deadline()
	if !finite {
		return nil, fleet.ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.claim
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.entry.holder.now()
	if r.closed || r.selected || c.closed || c.started || c.ctx.Err() != nil || ctx.Err() != nil || !request.Valid(now) || !sameOperationLocatorQuery(r.query, request.LocatorQuery()) {
		return nil, fleet.ErrUnavailable
	}
	end = identity.Earlier(end, c.until)
	if !now.Before(end) {
		return nil, fleet.ErrUnavailable
	}
	r.selected = true
	// The result-check parent is independent of normal claim.Close: successful
	// stream cleanup must not look like caller cancellation. Actual POST loss
	// cancels both this parent and the original claimed stream immediately.
	parent, cancelParent := context.WithDeadline(c.parent, end)
	call, cancelCall := context.WithDeadline(parent, end)
	originalCancel := c.cancel
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { cancelParent(); originalCancel(); close(done) })
	r.cancelParent = cancelParent
	r.joinCaller = func() {
		if !stop() {
			<-done
		}
	}
	c.parent, c.ctx, c.until, c.request = parent, call, end, request.Clone()
	c.cancel = func() { cancelCall(); originalCancel() }
	return c, nil
}
func (r *HubObservationOperationReservation) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		c, join, cancel := r.claim, r.joinCaller, r.cancelParent
		r.mu.Unlock()
		c.Close()
		if join != nil {
			join()
		}
		if cancel != nil {
			cancel()
		}
	})
}
