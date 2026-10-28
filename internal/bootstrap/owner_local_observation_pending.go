package bootstrap

import (
	"bytes"
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
)

// ownerLocalObservationPending is private receiving orchestration state, not an
// authority port. The concrete receiver checks each actual receiving TLS connection and
// checks current SQL/key and local token state; this map can only retain/spend the original
// native operation. No returned ID or locator can construct a replacement.
// Active capacity includes preparation, possible delivery, claim and joined
// closure. The same-ID spent marker remains through its original end under a
// separate total-retained ceiling; uncertain work never releases active capacity.
type ownerLocalObservationPending struct {
	root    context.Context
	cancel  context.CancelFunc
	pin     value.OwnerObservationPin
	binding value.OwnerBinding
	maximum int
	active  int
	now     func() time.Time
	mu      sync.Mutex
	closed  bool
	entries map[ownerLocalObservationPendingKey]*ownerLocalObservationPendingEntry
	joined  sync.WaitGroup
}
type ownerLocalObservationPendingKey struct{ root, request string }
type ownerLocalObservationPendingPhase uint8

const (
	ownerLocalObservationPreparing ownerLocalObservationPendingPhase = iota
	ownerLocalObservationPrepared
	ownerLocalObservationPossiblyDelivered
	ownerLocalObservationClaimed
	ownerLocalObservationSpent
)

type ownerLocalObservationPendingEntry struct {
	store  *ownerLocalObservationPending
	key    ownerLocalObservationPendingKey
	query  value.ClusterObservationLocatorQuery
	server value.OwnerCertificate
	podUID string
	token  []byte
	// retention owns the one original slot interval. Cancelling work early
	// cannot delete the spent marker or let the same request run again.
	retention         context.Context
	retireCancel      context.CancelFunc
	work              context.Context
	cancel            context.CancelFunc
	end               time.Time
	get               context.Context
	stopGet           func() bool
	getDone           chan struct{}
	getJoin           sync.Once
	mu                sync.Mutex
	phase             ownerLocalObservationPendingPhase
	locator           value.ClusterObservationLocator
	operation         *mtls.OwnerObservationOperation
	native            ownerLocalNativeOperation
	registry          *ownerLocalObservationRegistry
	reservation       *wire.HubObservationOperationReservation
	reservationCancel context.CancelFunc
	calls             sync.WaitGroup
	prepareDone       sync.Once
	closeOnce         sync.Once
	retireOnce        sync.Once
	closed            chan struct{}
	retired           chan struct{}
}

type ownerLocalObservationPendingClaim struct {
	entry       *ownerLocalObservationPendingEntry
	call        context.Context
	cancel      context.CancelFunc
	stopCaller  func() bool
	callerDone  chan struct{}
	operation   *mtls.OwnerObservationOperation
	native      ownerLocalNativeOperation
	registry    *ownerLocalObservationRegistry
	reservation *wire.HubObservationOperationReservation
	closeOnce   sync.Once
}

func newOwnerLocalObservationPending(root context.Context, pin value.OwnerObservationPin, binding value.OwnerBinding, maximum int, now func() time.Time) (*ownerLocalObservationPending, error) {
	if root == nil || root.Err() != nil || !pin.Valid() || !binding.Valid() || binding.InstallationID != pin.Pool.InstallationID || binding.ClusterID != pin.Pool.ClusterID || binding.IssuerEpoch != pin.Pool.IssuerEpoch || maximum < 1 || maximum > 16 || now == nil {
		return nil, value.ErrInvalid
	}
	ctx, cancel := context.WithCancel(root)
	return &ownerLocalObservationPending{root: ctx, cancel: cancel, pin: pin, binding: binding, maximum: maximum, now: now, entries: make(map[ownerLocalObservationPendingKey]*ownerLocalObservationPendingEntry)}, nil
}

// reserve must precede native Begin. get is the actual accepted GET context,
// including its original socket deadline. Its cancellation owns preparation,
// but it is deliberately not the parent of the retained operation context.
// Server is the actual process-owned serving leaf. Token is private, bounded,
// and retained solely for exact matching by the purpose-fixed native reader.
func (s *ownerLocalObservationPending) reserve(get context.Context, q value.ClusterObservationLocatorQuery, podUID string, token []byte, server value.OwnerCertificate) (*ownerLocalObservationPendingEntry, error) {
	if s == nil || get == nil || get.Err() != nil || !q.Valid(s.now()) || q.RootID != s.pin.RootID || !authorization.UUID(podUID) || len(token) == 0 || len(token) > 16<<10 || !server.Valid(s.now()) || server.Usage != "server" || server.Binding != s.binding {
		return nil, value.ErrUnavailable
	}

	end, finite := get.Deadline()
	if !finite || !s.now().Before(end) || end.After(s.now().Add(5*time.Second)) {
		return nil, value.ErrUnavailable
	}
	end = identity.Earlier(end, identity.Earlier(q.NotAfter, server.NotAfter))
	if d, ok := s.root.Deadline(); ok {
		end = identity.Earlier(end, d)
	}
	key := ownerLocalObservationPendingKey{q.RootID, q.RequestID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.root.Err() != nil || get.Err() != nil || !s.now().Before(end) || s.active >= s.maximum || len(s.entries) >= 2*s.maximum || s.entries[key] != nil {
		return nil, value.ErrUnavailable
	}
	retention, retireCancel := context.WithDeadline(s.root, end)
	work, cancel := context.WithCancel(retention)
	e := &ownerLocalObservationPendingEntry{store: s, key: key, query: q, server: server, podUID: podUID, token: bytes.Clone(token), retention: retention, retireCancel: retireCancel, work: work, cancel: cancel, end: end, get: get, getDone: make(chan struct{}), closed: make(chan struct{}), retired: make(chan struct{})}
	e.calls.Add(1) // actual GET preparation/output, joined by finishGET
	e.stopGet = context.AfterFunc(get, func() { cancel(); close(e.getDone) })
	s.entries[key] = e
	s.active++
	s.joined.Add(1)
	// Restrictive cleanup only: no source reads, renewal, replacement or retry.
	context.AfterFunc(retention, e.retire)
	return e, nil
}

// retain is called only by the concrete receiver which constructs the operation
// from e.work and the exact original query/caller/server. Ownership transfers only on
// success; a failed transfer leaves Close with that constructing caller. The
// public locator is copied, and cannot be edited to name another holder/period.
func (e *ownerLocalObservationPendingEntry) retain(locator value.ClusterObservationLocator, operation *mtls.OwnerObservationOperation, native ownerLocalNativeOperation, registry *ownerLocalObservationRegistry, reservation *wire.HubObservationOperationReservation, reservationCancel context.CancelFunc) error {
	if e == nil || operation == nil || native == nil || registry == nil || reservation == nil || reservationCancel == nil {
		return value.ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.phase != ownerLocalObservationPreparing || e.work.Err() != nil || e.get.Err() != nil || !locator.Matches(e.query, e.server.Binding, e.store.now()) || locator.Interval.FreshUntil.After(e.end) {
		return value.ErrUnavailable
	}
	e.operation, e.native, e.registry, e.reservation, e.locator, e.phase = operation, native, registry, reservation, locator, ownerLocalObservationPrepared
	e.reservationCancel = reservationCancel
	return nil
}

func (e *ownerLocalObservationPendingEntry) joinGET() {
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
func (e *ownerLocalObservationPendingEntry) possibleDelivery() (value.ClusterObservationLocator, error) {
	var zero value.ClusterObservationLocator
	if e == nil {
		return zero, value.ErrUnavailable
	}
	e.mu.Lock()
	if e.phase != ownerLocalObservationPrepared || e.operation == nil || e.work.Err() != nil || e.get.Err() != nil || !e.locator.Matches(e.query, e.server.Binding, e.store.now()) {
		e.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	e.phase = ownerLocalObservationPossiblyDelivered
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
// a pre-output failure joins work but retains its same-ID marker to expiry.
func (e *ownerLocalObservationPendingEntry) finishGET() {
	if e == nil {
		return
	}
	e.prepareDone.Do(func() {
		e.joinGET()
		e.mu.Lock()
		aborted := e.phase == ownerLocalObservationPreparing || e.phase == ownerLocalObservationPrepared || e.work.Err() != nil
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
func (s *ownerLocalObservationPending) claim(ctx context.Context, input value.ClusterObservationClaim, podUID string, token []byte, server value.OwnerCertificate) (*ownerLocalObservationPendingClaim, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !input.Matches(s.binding, s.now()) {
		return nil, value.ErrUnavailable
	}
	end, finite := ctx.Deadline()
	if !finite {
		return nil, value.ErrUnavailable
	}
	s.mu.Lock()
	e := s.entries[ownerLocalObservationPendingKey{input.Request.RootID, input.Request.ID}]
	if s.closed || s.root.Err() != nil || e == nil {
		s.mu.Unlock()
		return nil, value.ErrUnavailable
	}
	e.mu.Lock()
	s.mu.Unlock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || e.phase != ownerLocalObservationPossiblyDelivered || e.work.Err() != nil || !samePendingQuery(e.query, input.Request.LocatorQuery()) || !samePendingLocator(e.locator, input.Locator) || e.operation == nil || podUID != e.podUID || !bytes.Equal(token, e.token) || server != e.server || !server.Valid(s.now()) || !s.now().Before(e.end) {
		return nil, value.ErrUnavailable
	}
	end = identity.Earlier(end, identity.Earlier(e.end, e.locator.Interval.FreshUntil))
	if !s.now().Before(end) {
		return nil, value.ErrUnavailable
	}
	e.phase = ownerLocalObservationClaimed
	e.calls.Add(1)
	call, cancel := context.WithDeadline(e.work, end)
	h := &ownerLocalObservationPendingClaim{entry: e, call: call, cancel: cancel, operation: e.operation, native: e.native, registry: e.registry, reservation: e.reservation, callerDone: make(chan struct{})}
	h.stopCaller = context.AfterFunc(ctx, func() { cancel(); close(h.callerDone) })
	return h, nil
}
func (h *ownerLocalObservationPendingClaim) Close() {
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

// closeWork closes the exact retained operation, then joins both handler work
// owners. It never removes the marker. Callers must finish their own work lease
// before joining this method; expiry/process callbacks have no such lease.
func (e *ownerLocalObservationPendingEntry) closeWork() {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.phase = ownerLocalObservationSpent
		e.cancel()
		op, reservation, cancelReservation := e.operation, e.reservation, e.reservationCancel
		e.mu.Unlock()
		if op != nil {
			op.Close()
		}
		if cancelReservation != nil {
			cancelReservation()
		}
		if reservation != nil {
			reservation.Close()
		}
		e.calls.Wait()
		e.joinGET()
		e.mu.Lock()
		e.operation = nil
		e.native = nil
		e.registry = nil
		clear(e.token)
		e.token = nil
		e.reservation = nil
		e.mu.Unlock()
		// Do not acquire the store mutex while holding the entry mutex:
		// claim/reserve own the store first. A Spent phase alone is not joined.
		e.store.mu.Lock()
		e.store.active--
		e.store.mu.Unlock()
		close(e.closed)
	})
}
func (e *ownerLocalObservationPendingEntry) retire() {
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
func (s *ownerLocalObservationPending) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.joined.Wait()
}
