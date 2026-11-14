package clusterobservation

import (
	"context"
	"testing"
	"time"
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
