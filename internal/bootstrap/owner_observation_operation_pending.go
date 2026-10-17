package bootstrap

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
)

// ownerObservationPending is private receiving orchestration state, not an
// authority port. The concrete receiver authenticates both TLS connections and
// checks current SQL/key state; this map can only retain/spend the original
// native operation. No returned ID or locator can construct a replacement.
// A slot includes preparation, possible delivery, claim, joined closure and the
// spent marker through the original end. Failed output never refunds it.
type ownerObservationPending struct {
	root    context.Context
	cancel  context.CancelFunc
	pin     value.OwnerObservationPin
	binding value.OwnerBinding
	maximum int
	now     func() time.Time
	mu      sync.Mutex
	closed  bool
	entries map[ownerObservationPendingKey]*ownerObservationPendingEntry
	joined  sync.WaitGroup
}
type ownerObservationPendingKey struct{ root, request string }
type ownerObservationPendingPhase uint8

const (
	ownerObservationPreparing ownerObservationPendingPhase = iota
	ownerObservationPrepared
	ownerObservationPossiblyDelivered
	ownerObservationClaimed
	ownerObservationSpent
)

type ownerObservationPendingEntry struct {
	store          *ownerObservationPending
	key            ownerObservationPendingKey
	query          value.ClusterObservationLocatorQuery
	sender, server value.OwnerCertificate
	// retention owns the one original slot interval. Cancelling work early
	// cannot delete the spent marker or let another request refill that slot.
	retention    context.Context
	retireCancel context.CancelFunc
	work         context.Context
	cancel       context.CancelFunc
	end          time.Time
	get          context.Context
	stopGet      func() bool
	getDone      chan struct{}
	getJoin      sync.Once
	mu           sync.Mutex
	phase        ownerObservationPendingPhase
	locator      value.ClusterObservationLocator
	routing      *mtls.OwnerObservationRoutingAdmission
	reservation  *wire.HubObservationOperationReservation
	calls        sync.WaitGroup
	prepareDone  sync.Once
	closeOnce    sync.Once
	retireOnce   sync.Once
	closed       chan struct{}
	retired      chan struct{}
}

type ownerObservationPendingClaim struct {
	entry       *ownerObservationPendingEntry
	call        context.Context
	cancel      context.CancelFunc
	stopCaller  func() bool
	callerDone  chan struct{}
	routing     *mtls.OwnerObservationRoutingAdmission
	reservation *wire.HubObservationOperationReservation
	closeOnce   sync.Once
}

func newOwnerObservationPending(root context.Context, pin value.OwnerObservationPin, binding value.OwnerBinding, maximum int, now func() time.Time) (*ownerObservationPending, error) {
	if root == nil || root.Err() != nil || !pin.Valid() || !binding.Valid() || binding.InstallationID != pin.Pool.InstallationID || binding.ClusterID != pin.Pool.ClusterID || binding.IssuerEpoch != pin.Pool.IssuerEpoch || maximum < 1 || maximum > 16 || now == nil {
		return nil, value.ErrInvalid
	}
	ctx, cancel := context.WithCancel(root)
	return &ownerObservationPending{root: ctx, cancel: cancel, pin: pin, binding: binding, maximum: maximum, now: now, entries: make(map[ownerObservationPendingKey]*ownerObservationPendingEntry)}, nil
}

// reserve must precede native Begin. get is the actual accepted GET context,
// including its original socket deadline. Its cancellation owns preparation,
// but it is deliberately not the parent of the retained operation context.
// sender/server are exact already authenticated leaves, never decoded wire pins.
func (s *ownerObservationPending) reserve(get context.Context, q value.ClusterObservationLocatorQuery, sender, server value.OwnerCertificate) (*ownerObservationPendingEntry, error) {
	if s == nil || get == nil || get.Err() != nil || !q.Valid(s.now()) || q.RootID != s.pin.RootID || !sender.Valid(s.now()) || sender.Usage != "client" || !server.Valid(s.now()) || server.Usage != "server" || server.Binding != s.binding || sender.Binding.InstallationID != s.pin.Pool.InstallationID || sender.Binding.ClusterID != s.pin.Pool.ClusterID || sender.Binding.IssuerEpoch != s.pin.Pool.IssuerEpoch {
		return nil, value.ErrUnavailable
	}
	end, finite := get.Deadline()
	if !finite || !s.now().Before(end) || end.After(s.now().Add(5*time.Second)) {
		return nil, value.ErrUnavailable
	}
	end = identity.Earlier(end, identity.Earlier(q.NotAfter, identity.Earlier(sender.NotAfter, server.NotAfter)))
	if d, ok := s.root.Deadline(); ok {
		end = identity.Earlier(end, d)
	}
	key := ownerObservationPendingKey{q.RootID, q.RequestID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.root.Err() != nil || get.Err() != nil || !s.now().Before(end) || len(s.entries) >= s.maximum || s.entries[key] != nil {
		return nil, value.ErrUnavailable
	}
	retention, retireCancel := context.WithDeadline(s.root, end)
	work, cancel := context.WithCancel(retention)
	e := &ownerObservationPendingEntry{store: s, key: key, query: q, sender: sender, server: server, retention: retention, retireCancel: retireCancel, work: work, cancel: cancel, end: end, get: get, getDone: make(chan struct{}), closed: make(chan struct{}), retired: make(chan struct{})}
	e.calls.Add(1) // actual GET preparation/output, joined by finishGET
	e.stopGet = context.AfterFunc(get, func() { cancel(); close(e.getDone) })
	s.entries[key] = e
	s.joined.Add(1)
	// Restrictive cleanup only: no source reads, renewal, replacement or retry.
	context.AfterFunc(retention, e.retire)
	return e, nil
}

func samePendingQuery(a, b value.ClusterObservationLocatorQuery) bool {
	return a.RootID == b.RootID && a.RequestID == b.RequestID && a.Challenge == b.Challenge && a.ClusterID == b.ClusterID && a.RequestedAt.Equal(b.RequestedAt) && a.NotAfter.Equal(b.NotAfter)
}
func samePendingLocator(a, b value.ClusterObservationLocator) bool {
	return a.RootID == b.RootID && a.RequestID == b.RequestID && a.Challenge == b.Challenge && a.ClusterID == b.ClusterID && a.Holder == b.Holder && a.ExchangeID == b.ExchangeID && a.Sequence == b.Sequence && a.Interval.ObservedAt.Equal(b.Interval.ObservedAt) && a.Interval.FreshUntil.Equal(b.Interval.FreshUntil)
}

// retain is called only by the concrete receiver which constructs routing
// from e.work and the exact original query/peers. Ownership transfers only on
// success; a failed transfer leaves Close with that constructing caller. The
// public locator is copied, and cannot be edited to name another holder/period.
func (e *ownerObservationPendingEntry) retain(locator value.ClusterObservationLocator, routing *mtls.OwnerObservationRoutingAdmission, reservation *wire.HubObservationOperationReservation) error {
	if e == nil || routing == nil || reservation == nil {
		return value.ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.phase != ownerObservationPreparing || e.work.Err() != nil || e.get.Err() != nil || !locator.Matches(e.query, e.server.Binding, e.store.now()) || locator.Interval.FreshUntil.After(e.end) {
		return value.ErrUnavailable
	}
	e.routing, e.reservation, e.locator, e.phase = routing, reservation, locator, ownerObservationPrepared
	return nil
}
func (e *ownerObservationPendingEntry) joinGET() {
	e.getJoin.Do(func() {
		if !e.stopGet() {
			<-e.getDone
		}
	})
}

// possibleDelivery is invoked before the first response byte/header can expose
// the locator. Detach and join only GET cancellation: the original process,
// query, socket and leaf bounds still own the retained native operation. A
// race that already cancelled preparation cannot resurrect it.
func (e *ownerObservationPendingEntry) possibleDelivery() (value.ClusterObservationLocator, error) {
	var zero value.ClusterObservationLocator
	if e == nil {
		return zero, value.ErrUnavailable
	}
	e.mu.Lock()
	if e.phase != ownerObservationPrepared || e.routing == nil || e.work.Err() != nil || e.get.Err() != nil || !e.locator.Matches(e.query, e.server.Binding, e.store.now()) {
		e.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	e.phase = ownerObservationPossiblyDelivered
	locator := e.locator
	e.mu.Unlock()
	e.joinGET()
	if e.get.Err() != nil || e.work.Err() != nil {
		e.cancel()
		return zero, value.ErrUnavailable
	}
	return locator, nil
}

// finishGET runs after actual output/cancellation work has joined, including
// failed or unknown writes. A possible write retains the original slot/proof;
// a pre-output failure closes work but retains the same spent slot to expiry.
func (e *ownerObservationPendingEntry) finishGET() {
	if e == nil {
		return
	}
	e.prepareDone.Do(func() {
		e.joinGET()
		e.mu.Lock()
		aborted := e.phase == ownerObservationPreparing || e.phase == ownerObservationPrepared || e.work.Err() != nil
		e.mu.Unlock()
		e.calls.Done()
		if aborted {
			e.closeWork()
		}
	})
}

// claim irreversibly selects the original entry before any further blocking
// SQL/native/stream work. The receiving adapter still authenticates the actual
// new exact-SNI TLS connection, checks current SQL/key/guard facts and holds the
// handle until its final response I/O has joined. This map is not that proof.
func (s *ownerObservationPending) claim(ctx context.Context, input value.ClusterObservationClaim, sender, server value.OwnerCertificate) (*ownerObservationPendingClaim, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !input.Matches(s.binding, s.now()) {
		return nil, value.ErrUnavailable
	}
	end, finite := ctx.Deadline()
	if !finite {
		return nil, value.ErrUnavailable
	}
	s.mu.Lock()
	e := s.entries[ownerObservationPendingKey{input.Request.RootID, input.Request.ID}]
	if s.closed || s.root.Err() != nil || e == nil {
		s.mu.Unlock()
		return nil, value.ErrUnavailable
	}
	e.mu.Lock()
	s.mu.Unlock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || e.phase != ownerObservationPossiblyDelivered || e.work.Err() != nil || !samePendingQuery(e.query, input.Request.LocatorQuery()) || !samePendingLocator(e.locator, input.Locator) || e.routing == nil || sender != e.sender || server != e.server || !sender.Valid(s.now()) || !server.Valid(s.now()) || !s.now().Before(e.end) {
		return nil, value.ErrUnavailable
	}
	end = identity.Earlier(end, identity.Earlier(e.end, e.locator.Interval.FreshUntil))
	if !s.now().Before(end) {
		return nil, value.ErrUnavailable
	}
	e.phase = ownerObservationClaimed
	e.calls.Add(1)
	call, cancel := context.WithDeadline(e.work, end)
	h := &ownerObservationPendingClaim{entry: e, call: call, cancel: cancel, routing: e.routing, reservation: e.reservation, callerDone: make(chan struct{})}
	h.stopCaller = context.AfterFunc(ctx, func() { cancel(); close(h.callerDone) })
	return h, nil
}
func (h *ownerObservationPendingClaim) Close() {
	if h == nil {
		return
	}
	h.closeOnce.Do(func() {
		h.cancel()
		if !h.stopCaller() {
			<-h.callerDone
		}
		h.entry.calls.Done()
		h.entry.closeWork()
	})
}

// closeWork closes the exact retained routing, then joins both handler work
// owners. It never removes the marker. Callers must finish their own work lease
// before joining this method; expiry/process callbacks have no such lease.
func (e *ownerObservationPendingEntry) closeWork() {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.phase = ownerObservationSpent
		e.cancel()
		op, reservation := e.routing, e.reservation
		e.mu.Unlock()
		if op != nil {
			op.Close()
		}
		if reservation != nil {
			reservation.Close()
		}
		e.calls.Wait()
		e.joinGET()
		e.mu.Lock()
		e.routing = nil
		e.reservation = nil
		e.mu.Unlock()
		close(e.closed)
	})
}
func (e *ownerObservationPendingEntry) retire() {
	e.retireOnce.Do(func() {
		e.retireCancel()
		e.closeWork()
		s := e.store
		s.mu.Lock()
		// Exact pointer identity prevents delayed cleanup removing a replacement.
		if s.entries[e.key] == e {
			delete(s.entries, e.key)
		}
		s.mu.Unlock()
		close(e.retired)
		s.joined.Done()
	})
}
func (s *ownerObservationPending) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.joined.Wait()
}
