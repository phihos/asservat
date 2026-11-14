package clusterobservation

import (
	"bytes"
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
)

type hubHolderResponse struct {
	bytes.Buffer
	header http.Header
}

func (w *hubHolderResponse) Header() http.Header            { return w.header }
func (*hubHolderResponse) WriteHeader(int)                  {}
func (*hubHolderResponse) Flush()                           {}
func (*hubHolderResponse) SetReadDeadline(time.Time) error  { return nil }
func (*hubHolderResponse) SetWriteDeadline(time.Time) error { return nil }

type hubHolderConversation struct {
	read   func(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error)
	closes atomic.Int32
}

func (c *hubHolderConversation) ObserveCluster(ctx context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	return c.read(ctx, r)
}
func (c *hubHolderConversation) Close() { c.closes.Add(1) }

func TestHubObservationHolderSequenceOverflowCannotWrap(t *testing.T) {
	h, _ := NewHubObservationHolder(context.Background(), 1, time.Now)
	h.next = ^uint64(0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := h.reserve(ctx); err == nil || h.next != ^uint64(0) || len(h.entries) != 0 {
		t.Fatal("registration sequence overflow wrapped or allocated")
	}
	h.Close()
}
