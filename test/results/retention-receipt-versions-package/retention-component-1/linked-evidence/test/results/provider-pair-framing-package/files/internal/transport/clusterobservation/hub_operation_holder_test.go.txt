package clusterobservation

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

type hubOperationHolderConversation struct {
	read   func(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error)
	closes atomic.Int32
}

func (c *hubOperationHolderConversation) ObserveCluster(ctx context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	return c.read(ctx, r)
}
func (c *hubOperationHolderConversation) Close() { c.closes.Add(1) }

func hubOperationHolderEntry(t *testing.T, h *HubObservationOperationHolder, c *hubOperationHolderConversation) (*hubObservationOperationEntry, HubObservationLocator) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	e, err := h.reserve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := contracts.ClusterObservationHello{Format: contracts.ClusterObservationOperationExchangeFormat, RootID: localID(1), ClusterID: localID(12), ExchangeID: localID(99)}
	b, _ := contracts.EncodeClusterObservationHello(hello)
	s, err := newHubObservationOperationStream(e.ctx, &hubHolderResponse{header: make(http.Header)}, io.NopCloser(bytes.NewReader(nil)), hello, len(b), time.Now)
	if err != nil {
		e.close()
		t.Fatal(err)
	}
	if e.bind(hello, s, c) != nil || e.publish() != nil {
		e.close()
		t.Fatal("bind fixture")
	}
	l, err := h.Lookup(ctx, hello.RootID, hello.ClusterID)
	if err != nil {
		e.close()
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	return e, l
}

func TestHubObservationOperationHolderClaimRetainsClosingSlotAndExactEntry(t *testing.T) {
	h, err := NewHubObservationOperationHolder(context.Background(), 1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	c := &hubOperationHolderConversation{read: func(ctx context.Context, _ fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return fleet.ClusterObservationResult{}, fleet.ErrUnavailable
	}}
	e, l := hubOperationHolderEntry(t, h, c)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); e.close(); h.Close() })
	result := make(chan error, 1)
	go func() { _, err := h.Observe(context.Background(), l, localRequest()); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("claim not admitted")
	}
	if _, err = h.Observe(context.Background(), l, localRequest()); err == nil {
		t.Fatal("second claim admitted")
	}
	if _, err = h.Lookup(context.Background(), l.RootID, l.ClusterID); err == nil {
		t.Fatal("claimed entry still located")
	}
	closed := make(chan struct{})
	go func() { e.close(); close(closed) }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("original call not cancelled")
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err = h.reserve(ctx); err == nil {
		t.Fatal("closing stream refunded slot")
	}
	select {
	case <-closed:
		t.Fatal("cleanup returned before actual work joined")
	case <-time.After(10 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err = <-result:
		if err == nil {
			t.Fatal("cancelled claim succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("claim failed to join")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("handler cleanup failed to join")
	}
	if c.closes.Load() != 1 {
		t.Fatal("conversation close count", c.closes.Load())
	}
	replacement, err := h.reserve(ctx)
	if err != nil {
		t.Fatal("joined slot not released", err)
	}
	e.close()
	h.mu.Lock()
	_, exists := h.entries[replacement]
	count := len(h.entries)
	h.mu.Unlock()
	if !exists || count != 1 {
		t.Fatal("stale cleanup removed replacement")
	}
	replacement.close()
	h.Close()
}

func TestHubObservationOperationHolderRejectsLocatorMutationAndKeepsOriginalSocketEnd(t *testing.T) {
	for _, mode := range []string{"root", "cluster", "exchange", "expired", "cancelled", "normal"} {
		t.Run(mode, func(t *testing.T) {
			h, _ := NewHubObservationOperationHolder(context.Background(), 1, time.Now)
			var calls atomic.Int32
			c := &hubOperationHolderConversation{read: func(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
				calls.Add(1)
				return fleet.ClusterObservationResult{}, fleet.ErrUnavailable
			}}
			e, l := hubOperationHolderEntry(t, h, c)
			end, _ := e.ctx.Deadline()
			if l.FreshUntil.After(end) {
				t.Fatal("locator renewed socket")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "root":
				l.RootID = localID(23)
			case "cluster":
				l.ClusterID = localID(24)
			case "exchange":
				l.ExchangeID = localID(25)
			case "expired":
				l.FreshUntil = time.Now().Add(-time.Millisecond)
			case "cancelled":
				cancel()
			}
			joined := make(chan struct{})
			go func() {
				select {
				case <-e.resultDone:
				case <-e.ctx.Done():
				}
				e.close()
				close(joined)
			}()
			_, err := h.Observe(ctx, l, localRequest())
			if err == nil {
				t.Fatal("unavailable fixture returned result")
			}
			want := int32(0)
			if mode == "normal" {
				want = 1
			}
			if calls.Load() != want {
				t.Fatal("invalid locator reached conversation", calls.Load())
			}
			e.cancel()
			<-joined
			h.Close()
		})
	}
}

func TestHubObservationOperationHolderNoReceiptCannotProduceSuccess(t *testing.T) {
	h, _ := NewHubObservationOperationHolder(context.Background(), 1, time.Now)
	c := &hubOperationHolderConversation{read: func(_ context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
		return localResult(r), nil
	}}
	e, l := hubOperationHolderEntry(t, h, c)
	joined := make(chan struct{})
	go func() { <-e.resultDone; e.close(); close(joined) }()
	if _, err := h.Observe(context.Background(), l, localRequest()); err == nil {
		t.Fatal("unclosed transport inferred from successful local result")
	}
	<-joined
	h.Close()
}

func TestHubObservationOperationHolderRepeatedHelloCannotAliasOldLocator(t *testing.T) {
	h, _ := NewHubObservationOperationHolder(context.Background(), 1, time.Now)
	var calls atomic.Int32
	makeConversation := func() *hubOperationHolderConversation {
		return &hubOperationHolderConversation{read: func(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
			calls.Add(1)
			return fleet.ClusterObservationResult{}, fleet.ErrUnavailable
		}}
	}
	original, oldLocator := hubOperationHolderEntry(t, h, makeConversation())
	original.close()
	replacement, newLocator := hubOperationHolderEntry(t, h, makeConversation())
	if oldLocator.ExchangeID != newLocator.ExchangeID || oldLocator.Sequence == newLocator.Sequence {
		t.Fatal("fixture did not repeat wire UUID with distinct registration")
	}
	if _, err := h.Observe(context.Background(), oldLocator, localRequest()); err == nil || calls.Load() != 0 {
		t.Fatal("old locator claimed replacement socket")
	}
	oldCleanup := make(chan struct{})
	go func() { original.close(); close(oldCleanup) }()
	<-oldCleanup
	current, err := h.Lookup(context.Background(), newLocator.RootID, newLocator.ClusterID)
	if err != nil || current.Sequence != newLocator.Sequence {
		t.Fatal("delayed old cleanup removed replacement", err)
	}
	joined := make(chan struct{})
	go func() { <-replacement.resultDone; replacement.close(); close(joined) }()
	if _, err = h.Observe(context.Background(), newLocator, localRequest()); err == nil || calls.Load() != 1 {
		t.Fatal("exact new locator did not reach one original conversation", err, calls.Load())
	}
	<-joined
	h.Close()
}

func TestHubObservationOperationHolderSequenceOverflowCannotWrap(t *testing.T) {
	h, _ := NewHubObservationOperationHolder(context.Background(), 1, time.Now)
	h.next = ^uint64(0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := h.reserve(ctx); err == nil || h.next != ^uint64(0) || len(h.entries) != 0 {
		t.Fatal("registration sequence overflow wrapped or allocated")
	}
	h.Close()
}

// The old convenience test shape receives an explicit finite fixture caller;
// production uses Claim and the bootstrap-owned typed operation binding.
func (h *HubObservationOperationHolder) Observe(ctx context.Context, l HubObservationLocator, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	call, cancel := context.WithDeadline(ctx, r.NotAfter)
	defer cancel()
	claim, err := h.Claim(call, l, r)
	if err != nil {
		return fleet.ClusterObservationResult{}, err
	}
	defer claim.Close()
	return claim.Observe()
}

func TestHubObservationOperationHolderAbandonedClaimStaysSpentUntilJoin(t *testing.T) {
	h, _ := NewHubObservationOperationHolder(context.Background(), 1, time.Now)
	var reads atomic.Int32
	conversation := &hubOperationHolderConversation{read: func(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
		reads.Add(1)
		return fleet.ClusterObservationResult{}, fleet.ErrUnavailable
	}}
	e, l := hubOperationHolderEntry(t, h, conversation)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	claim, err := h.Claim(ctx, l, localRequest())
	if err != nil {
		t.Fatal(err)
	}
	if claim.Conversation() != conversation {
		t.Fatal("claim substituted installed conversation")
	}
	if _, err = h.Claim(ctx, l, localRequest()); err == nil {
		t.Fatal("unknown original claim replayed")
	}
	if _, err = h.Lookup(ctx, l.RootID, l.ClusterID); err == nil {
		t.Fatal("spent claim still routeable")
	}
	// Original expiry shuts down an unstarted claim. Slot remains until the
	// actual receiving handler runs its joined cleanup; there is no refund.
	select {
	case <-claim.closedDone:
	case <-time.After(time.Second):
		t.Fatal("abandoned claim not closed")
	}
	if reads.Load() != 0 || conversation.closes.Load() != 1 {
		t.Fatal("expiry ran metadata or missed close")
	}
	bounded, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err = h.reserve(bounded); err == nil {
		t.Fatal("claim close released handler slot early")
	}
	e.close()
	claim.Close()
	replacement, err := h.reserve(bounded)
	if err != nil {
		t.Fatal(err)
	}
	e.close()
	h.mu.Lock()
	_, present := h.entries[replacement]
	h.mu.Unlock()
	if !present {
		t.Fatal("old claim removed replacement")
	}
	replacement.close()
	h.Close()
}

func TestHubObservationOperationHolderRejectsUnboundedClaimWithoutSpending(t *testing.T) {
	h, _ := NewHubObservationOperationHolder(context.Background(), 1, time.Now)
	c := &hubOperationHolderConversation{read: func(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
		t.Fatal("unbounded metadata")
		return fleet.ClusterObservationResult{}, nil
	}}
	e, l := hubOperationHolderEntry(t, h, c)
	if _, err := h.Claim(context.Background(), l, localRequest()); err == nil {
		t.Fatal("unbounded caller admitted")
	}
	current, err := h.Lookup(context.Background(), l.RootID, l.ClusterID)
	if err != nil || current.Sequence != l.Sequence {
		t.Fatal("rejected claim spent valid original")
	}
	e.close()
	h.Close()
}
