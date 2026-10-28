package bootstrap

import (
	"context"
	"sync"
	"testing"
	"time"
	"unsafe"

	value "asservat.local/asservat/internal/domain/fleet"
)

// Real pending/claim/mtls-operation lifetime machinery; native/SQL facts are
// synthetic, as in the existing local pending fixtures. No collector or API.
func TestLocalPendingCompletedCallsDoNotConsumeActiveConcurrency(t *testing.T) {
	maximum := capacityRegionalCalls(1)
	if maximum != 2 {
		t.Fatal("production single-region concurrency changed", maximum)
	}
	var store *ownerLocalObservationPending
	var anchor *pendingFixture
	for i := 0; i < maximum; i++ {
		f, s, e, native, locator := localPendingFixtureIn(t, store, anchor, maximum, 5*time.Second)
		store = s
		anchor = f
		until := e.end
		if _, err := e.possibleDelivery(); err != nil {
			t.Fatal(err)
		}
		e.finishGET()
		call, cancel := context.WithDeadline(context.Background(), until)
		h, err := s.claim(call, value.ClusterObservationClaim{Request: f.request, Locator: locator}, observationForwardID(701), []byte(localObservationFixtureToken), f.server)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		h.Close()
		cancel()
		if native.closed.Load() != 1 || len(e.token) != 0 {
			t.Fatal("completed operation not joined/cleared")
		}
		select {
		case <-e.closed:
		default:
			t.Fatal("completion did not join")
		}
		if !time.Now().Before(until) || !e.end.Equal(until) {
			t.Fatal("original five-second interval was spent/changed")
		}
		// The same immutable request is still spent until its original end.
		replay, stop := context.WithDeadline(context.Background(), until)
		if duplicate, err := s.reserve(replay, e.query, observationForwardID(701), []byte(localObservationFixtureToken), f.server); err == nil {
			duplicate.finishGET()
			stop()
			t.Fatal("completed request replayed")
		}
		stop()
		t.Logf("joined discovery=%d nativeClose=1 tokenCleared=true originalEndLive=true replayDenied=true", i+1)
	}
	// A distinct demand must not compete with fully joined discovery resources.
	q := anchor.request.LocatorQuery()
	q.RequestID, q.Challenge = ownerRandomID(), ownerRandomID()
	q.RequestedAt = time.Now()
	q.NotAfter = q.RequestedAt.Add(5 * time.Second)
	call, cancel := context.WithDeadline(context.Background(), q.NotAfter)
	defer cancel()
	next, err := store.reserve(call, q, observationForwardID(701), []byte(localObservationFixtureToken), anchor.server)
	if err != nil {
		t.Fatal("fresh third demand refused after two joined discovery operations, with original replay markers live", err)
	}
	next.finishGET()
}

func TestLocalPendingUnjoinedAndPossiblyDeliveredHoldActiveConcurrency(t *testing.T) {
	f, s, e, native, locator := localPendingFixtureIn(t, nil, nil, 2, 5*time.Second)
	native.closeEntered, native.closeRelease = make(chan struct{}), make(chan struct{})
	if _, err := e.possibleDelivery(); err != nil {
		t.Fatal(err)
	}
	e.finishGET()
	call, cancel := context.WithDeadline(context.Background(), e.end)
	defer cancel()
	h, err := s.claim(call, value.ClusterObservationClaim{Request: f.request, Locator: locator}, observationForwardID(701), []byte(localObservationFixtureToken), f.server)
	if err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	go func() { h.Close(); close(joined) }()
	<-native.closeEntered
	defer func() { close(native.closeRelease); <-joined }()
	_, _, pending, _, _ := localPendingFixtureIn(t, s, f, 2, 5*time.Second)
	if _, err := pending.possibleDelivery(); err != nil {
		t.Fatal(err)
	}
	pending.finishGET()
	q := e.query
	q.RequestID = ownerRandomID()
	q.Challenge = ownerRandomID()
	if extra, err := s.reserve(call, q, observationForwardID(701), []byte(localObservationFixtureToken), f.server); err == nil {
		extra.finishGET()
		t.Fatal("unjoined/possibly-delivered operations released active capacity")
	}
}

func TestLocalPendingAccountingValueSizes(t *testing.T) {
	t.Logf("entry_value_bytes=%d key_value_bytes=%d claim_value_bytes=%d max_region_calls=%d token_cap_bytes=%d; excludes maps/contexts/timers/native retained graphs", unsafe.Sizeof(ownerLocalObservationPendingEntry{}), unsafe.Sizeof(ownerLocalObservationPendingKey{}), unsafe.Sizeof(ownerLocalObservationPendingClaim{}), capacityRegionalCalls(16), 16<<10)
}

// The retained ceiling stays finite even for fast, known pre-output failures.
// Short synthetic original intervals exercise real expiry without changing any
// production five-second limit or moving an already issued deadline.
func TestLocalPendingRetainedSaturationAndNaturalExpiry(t *testing.T) {
	f := newPendingFixture(t)
	s, err := newOwnerLocalObservationPending(context.Background(), f.store.pin, f.server.Binding, 2, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	end := time.Now().Add(250 * time.Millisecond)
	var entries []*ownerLocalObservationPendingEntry
	for range 4 {
		q := f.request.LocatorQuery()
		q.RequestID, q.Challenge = ownerRandomID(), ownerRandomID()
		q.RequestedAt = time.Now()
		q.NotAfter = end
		call, cancel := context.WithDeadline(context.Background(), end)
		t.Cleanup(cancel)
		e, err := s.reserve(call, q, observationForwardID(701), []byte(localObservationFixtureToken), f.server)
		if err != nil {
			t.Fatal("bounded retained headroom", err)
		}
		e.finishGET()
		pendingWait(t, e.closed, "pre-output owner join")
		entries = append(entries, e)
		if replay, err := s.reserve(call, q, observationForwardID(701), []byte(localObservationFixtureToken), f.server); err == nil {
			replay.finishGET()
			t.Fatal("spent marker replay")
		}
	}
	s.mu.Lock()
	active, total := s.active, len(s.entries)
	s.mu.Unlock()
	if active != 0 || total != 4 {
		t.Fatal("retained accounting", active, total)
	}
	q := f.request.LocatorQuery()
	q.RequestID, q.Challenge = ownerRandomID(), ownerRandomID()
	call, cancel := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer cancel()
	if extra, err := s.reserve(call, q, observationForwardID(701), []byte(localObservationFixtureToken), f.server); err == nil {
		extra.finishGET()
		t.Fatal("total retained ceiling exceeded")
	}
	for _, e := range entries {
		pendingWait(t, e.retired, "natural original expiry")
	}
	s.mu.Lock()
	active, total = s.active, len(s.entries)
	s.mu.Unlock()
	if active != 0 || total != 0 {
		t.Fatal("expiry did not retire exact entries", active, total)
	}
	next, err := s.reserve(call, q, observationForwardID(701), []byte(localObservationFixtureToken), f.server)
	if err != nil {
		t.Fatal("expired markers retained capacity", err)
	}
	next.finishGET()
}

func TestLocalPendingConcurrentAccountingAndClose(t *testing.T) {
	f := newPendingFixture(t)
	s, err := newOwnerLocalObservationPending(context.Background(), f.store.pin, f.server.Binding, 2, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	var owners sync.WaitGroup
	start := make(chan struct{})
	admitted := make(chan *ownerLocalObservationPendingEntry, 16)
	for range 16 {
		owners.Add(1)
		go func() {
			defer owners.Done()
			<-start
			q := f.request.LocatorQuery()
			q.RequestID, q.Challenge = ownerRandomID(), ownerRandomID()
			if e, err := s.reserve(f.get, q, observationForwardID(701), []byte(localObservationFixtureToken), f.server); err == nil {
				admitted <- e
			}
		}()
	}
	close(start)
	owners.Wait()
	close(admitted)
	var entries []*ownerLocalObservationPendingEntry
	for e := range admitted {
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatal("concurrent active ceiling", len(entries))
	}
	for _, e := range entries {
		owners.Add(1)
		go func(e *ownerLocalObservationPendingEntry) { defer owners.Done(); e.finishGET(); e.closeWork() }(e)
	}
	owners.Wait()
	s.Close()
	s.mu.Lock()
	active, total := s.active, len(s.entries)
	s.mu.Unlock()
	if active != 0 || total != 0 {
		t.Fatal("joined shutdown accounting", active, total)
	}
	q := f.request.LocatorQuery()
	q.RequestID = ownerRandomID()
	if e, err := s.reserve(f.get, q, observationForwardID(701), []byte(localObservationFixtureToken), f.server); err == nil {
		e.finishGET()
		t.Fatal("closed store admitted")
	}
}
