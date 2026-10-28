package bootstrap

import (
	"context"
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
