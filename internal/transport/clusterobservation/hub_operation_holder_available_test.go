package clusterobservation

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestOperationHolderAbsenceIsNotUnavailable(t *testing.T) {
	const root = "11111111-1111-4111-8111-111111111111"
	const cluster = "22222222-2222-4222-8222-222222222222"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	h, err := NewHubObservationOperationHolder(ctx, 1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := h.LookupAvailable(ctx, root, cluster); err != nil || found {
		t.Fatal("current empty holder", found, err)
	}
	if _, err := h.Lookup(ctx, root, cluster); err == nil {
		t.Fatal("legacy lookup changed absence semantics")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, found, err := h.LookupAvailable(cancelled, root, cluster); err == nil || found {
		t.Fatal("cancellation became absence")
	}
	if _, found, err := h.LookupAvailable(ctx, "invalid", cluster); err == nil || found {
		t.Fatal("invalid scope became absence")
	}
	h.Close()
	if _, found, err := h.LookupAvailable(ctx, root, cluster); err == nil || found {
		t.Fatal("closed holder became absence")
	}
}
func TestOperationHolderLookupChecksDeadlineAfterLock(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	h, err := NewHubObservationOperationHolder(ctx, 1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	call, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	h.mu.Lock()
	done := make(chan error, 1)
	go func() { _, _, e := h.LookupAvailable(call, id, id); done <- e }()
	<-call.Done()
	h.mu.Unlock()
	if err := <-done; err == nil {
		t.Fatal("expired blocked lookup became absence")
	}
}

// Standbys from two regions share one holder. Lookup and Claim select only the
// requested cluster's entry, even when the other region's standby would win
// the deterministic ExchangeID tiebreak, and a locator never claims for
// another cluster's request.
func TestOperationHolderSeparatesRegionsSharingOneHolder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h, err := NewHubObservationOperationHolder(ctx, 2, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close) // after every entry's own cleanup
	a, b := localID(12), localID(13)
	conversations := map[string]*hubOperationHolderConversation{}
	entries := map[string]*hubObservationOperationEntry{}
	for cluster, exchange := range map[string]string{a: localID(99), b: localID(98)} {
		e, err := h.reserve(ctx)
		if err != nil {
			t.Fatal(err)
		}
		hello := contracts.ClusterObservationHello{Format: contracts.ClusterObservationOperationExchangeFormat, RootID: localID(1), ClusterID: cluster, ExchangeID: exchange}
		raw, _ := contracts.EncodeClusterObservationHello(hello)
		s, err := newHubObservationOperationStream(e.ctx, &hubHolderResponse{header: make(http.Header)}, io.NopCloser(bytes.NewReader(nil)), hello, len(raw), time.Now)
		if err != nil {
			e.close()
			t.Fatal(err)
		}
		c := &hubOperationHolderConversation{}
		if e.bind(hello, s, c) != nil || e.publish() != nil {
			e.close()
			t.Fatal("bind fixture")
		}
		conversations[cluster], entries[cluster] = c, e
		t.Cleanup(e.close)
	}
	l, err := h.Lookup(ctx, localID(1), a)
	if err != nil || l.ClusterID != a || l.ExchangeID != localID(99) {
		t.Fatal("lookup crossed regions", l, err)
	}
	other := localRequest()
	other.ClusterID = b
	if _, err := h.Claim(ctx, l, other); err == nil {
		t.Fatal("cluster A locator claimed for cluster B's request")
	}
	own := localRequest()
	own.ClusterID = a
	claim, err := h.Claim(ctx, l, own)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Conversation() != HubObservationOperationConversation(conversations[a]) {
		t.Fatal("claim returned another region's standby")
	}
	// The receiving handler owns entry cleanup; the claim joins it.
	closed := make(chan struct{})
	go func() { claim.Close(); close(closed) }()
	entries[a].close()
	<-closed
	if l, err = h.Lookup(ctx, localID(1), b); err != nil || l.ExchangeID != localID(98) {
		t.Fatal("cluster B standby lost", err)
	}
}
