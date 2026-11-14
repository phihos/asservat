package clusterobservation

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

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
