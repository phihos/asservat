package clusterobservation

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
)

// The fixture installs a synthetic conversation. These tests establish holder
// ownership only; the bootstrap receiver tests exercise actual h2/frame/EOF.
func reservationFixture(t *testing.T) (*HubObservationOperationHolder, *hubObservationOperationEntry, HubObservationLocator, *hubOperationHolderConversation) {
	t.Helper()
	h, err := NewHubObservationOperationHolder(context.Background(), 1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	c := &hubOperationHolderConversation{read: func(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
		return fleet.ClusterObservationResult{}, fleet.ErrUnavailable
	}}
	e, l := hubOperationHolderEntry(t, h, c)
	t.Cleanup(func() { e.close(); h.Close() })
	return h, e, l, c
}

func cleanReservation(t *testing.T, e *hubObservationOperationEntry, r *HubObservationOperationReservation) {
	t.Helper()
	t.Cleanup(func() {
		closed := make(chan struct{})
		go func() { r.Close(); close(closed) }()
		e.close()
		<-closed
	})
}

func joinReservedHandler(e *hubObservationOperationEntry) <-chan struct{} {
	joined := make(chan struct{})
	go func() { <-e.resultDone; e.close(); close(joined) }()
	return joined
}

func TestHubObservationOperationReservationSpendsBeforeLocatorOutput(t *testing.T) {
	h, e, l, c := reservationFixture(t)
	r := localRequest()
	ctx, cancel := context.WithDeadline(context.Background(), r.NotAfter)
	defer cancel()
	reserved, err := h.ReserveLocator(ctx, l, r.LocatorQuery())
	if err != nil {
		t.Fatal(err)
	}
	cleanReservation(t, e, reserved)
	// No locator write, request selection or metadata read has happened. A
	// lost GET must nevertheless leave the exact socket irreversibly spent.
	if _, err = h.Lookup(ctx, l.RootID, l.ClusterID); err == nil {
		t.Fatal("reserved socket remains routeable")
	}
	if _, err = h.ReserveLocator(ctx, l, r.LocatorQuery()); err == nil {
		t.Fatal("unknown locator output reopened original socket")
	}
	if _, err = h.Claim(ctx, l, r); err == nil {
		t.Fatal("legacy claim bypassed v2 reservation")
	}
	closing := make(chan struct{})
	go func() { reserved.Close(); close(closing) }()
	select {
	case <-reserved.claim.closedDone:
	case <-time.After(time.Second):
		t.Fatal("abandoned reservation did not close conversation")
	}
	if c.closes.Load() != 1 {
		t.Fatal("conversation not closed exactly once", c.closes.Load())
	}
	select {
	case <-closing:
		t.Fatal("reservation returned before receiving handler joined")
	default:
	}
	if _, err = h.reserve(ctx); err == nil {
		t.Fatal("unjoined reservation refunded process slot")
	}
	e.close()
	<-closing
	replacement, next := hubOperationHolderEntry(t, h, c)
	if next.Sequence == l.Sequence || next.ExchangeID != l.ExchangeID {
		t.Fatal("fixture does not cover repeated wire UUID")
	}
	reserved.Close()
	if _, err = h.ReserveLocator(ctx, l, r.LocatorQuery()); err == nil {
		t.Fatal("old reservation selected replacement")
	}
	current, err := h.Lookup(ctx, next.RootID, next.ClusterID)
	if err != nil || current.Sequence != next.Sequence {
		t.Fatal("delayed old cleanup removed replacement", err)
	}
	replacement.close()
}

func TestHubObservationOperationReservationSelectsExactQueryOnce(t *testing.T) {
	for _, mode := range []string{"root", "cluster", "request", "challenge", "start", "end", "cancelled", "unbounded"} {
		t.Run(mode, func(t *testing.T) {
			h, e, l, _ := reservationFixture(t)
			r := localRequest()
			ctx, cancel := context.WithDeadline(context.Background(), r.NotAfter)
			defer cancel()
			reserved, err := h.ReserveLocator(ctx, l, r.LocatorQuery())
			if err != nil {
				t.Fatal(err)
			}
			cleanReservation(t, e, reserved)
			joined := joinReservedHandler(e)
			defer func() { reserved.Close(); <-joined }()
			changed := r.Clone()
			bad, stop := context.WithCancel(ctx)
			defer stop()
			switch mode {
			case "root":
				changed.RootID = localID(91)
			case "cluster":
				changed.ClusterID = localID(91)
			case "request":
				changed.ID = localID(91)
			case "challenge":
				changed.Challenge = localID(91)
			case "start":
				changed.RequestedAt = changed.RequestedAt.Add(-time.Millisecond)
			case "end":
				changed.NotAfter = changed.NotAfter.Add(-time.Millisecond)
			case "cancelled":
				stop()
			case "unbounded":
				bad = context.Background()
			}
			if _, err = reserved.Select(bad, changed); err == nil {
				t.Fatal("changed or unbounded selection admitted")
			}
			selected, err := reserved.Select(ctx, r)
			if err != nil || selected != reserved.claim {
				t.Fatal("exact original first selection lost", err)
			}
			if _, err = reserved.Select(ctx, r); err == nil {
				t.Fatal("second selection admitted")
			}
		})
	}
}

func TestHubObservationOperationReservationConcurrentSelectionOneWinner(t *testing.T) {
	h, e, l, _ := reservationFixture(t)
	r := localRequest()
	ctx, cancel := context.WithDeadline(context.Background(), r.NotAfter)
	defer cancel()
	reserved, err := h.ReserveLocator(ctx, l, r.LocatorQuery())
	if err != nil {
		t.Fatal(err)
	}
	cleanReservation(t, e, reserved)
	joined := joinReservedHandler(e)
	defer func() { reserved.Close(); <-joined }()
	var admitted atomic.Int32
	var callers sync.WaitGroup
	for range 8 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if c, err := reserved.Select(ctx, r); err == nil && c == reserved.claim {
				admitted.Add(1)
			}
		}()
	}
	callers.Wait()
	if admitted.Load() != 1 {
		t.Fatal("concurrent selection count", admitted.Load())
	}
}

func TestHubObservationOperationReservationRetainsOriginalExpiryBeforeSelection(t *testing.T) {
	h, e, l, c := reservationFixture(t)
	r := localRequest()
	original, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	reserved, err := h.ReserveLocator(original, l, r.LocatorQuery())
	if err != nil {
		t.Fatal(err)
	}
	cleanReservation(t, e, reserved)
	end, _ := original.Deadline()
	if !reserved.Until().Equal(end) {
		t.Fatal("reservation did not retain earlier original interval")
	}
	select {
	case <-reserved.claim.closedDone:
	case <-time.After(time.Second):
		t.Fatal("original expiry did not close unselected reservation")
	}
	later, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err = reserved.Select(later, r); err == nil {
		t.Fatal("later caller renewed expired reservation")
	}
	if c.closes.Load() != 1 {
		t.Fatal("expiry missed original conversation")
	}
	if _, err = h.reserve(later); err == nil {
		t.Fatal("expiry refunded unjoined original slot")
	}
	e.close()
	reserved.Close()
}

func TestHubObservationOperationReservationCallerCancellationJoinsActualRead(t *testing.T) {
	h, e, l, c := reservationFixture(t)
	r := localRequest()
	original, cancelOriginal := context.WithDeadline(context.Background(), r.NotAfter)
	defer cancelOriginal()
	reserved, err := h.ReserveLocator(original, l, r.LocatorQuery())
	if err != nil {
		t.Fatal(err)
	}
	cleanReservation(t, e, reserved)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	c.read = func(ctx context.Context, _ fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return fleet.ClusterObservationResult{}, fleet.ErrUnavailable
	}
	joined := joinReservedHandler(e)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); reserved.Close(); <-joined })
	post, cancelPost := context.WithTimeout(original, time.Second)
	defer cancelPost()
	selected, err := reserved.Select(post, r)
	if err != nil {
		t.Fatal(err)
	}
	postEnd, _ := post.Deadline()
	actualEnd, _ := selected.ctx.Deadline()
	if !actualEnd.Equal(postEnd) || selected.until.After(reserved.query.NotAfter) {
		t.Fatal("actual conversation did not inherit earlier POST bound")
	}
	result := make(chan error, 1)
	go func() { _, err := selected.Observe(); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("metadata read not admitted")
	}
	cancelPost()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("POST cancellation did not reach actual read")
	}
	closing := make(chan struct{})
	go func() { reserved.Close(); close(closing) }()
	select {
	case <-closing:
		t.Fatal("Close returned before admitted read joined")
	case <-time.After(10 * time.Millisecond):
	}
	if _, err = h.reserve(original); err == nil {
		t.Fatal("cancelled but unjoined read refunded slot")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err = <-result:
		if err == nil {
			t.Fatal("cancelled read returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("Observe failed to join")
	}
	select {
	case <-closing:
	case <-time.After(time.Second):
		t.Fatal("reservation Close failed to join")
	}
	if c.closes.Load() != 1 {
		t.Fatal("multiple conversation closes", c.closes.Load())
	}
}
