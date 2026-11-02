package bootstrap

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/domain/collector"
)

// ADR-282: until the node projection exists, an HTTP header work item is
// refused fail-closed before any engine, budget or observation use; it never
// runs as a raw or header recording.
func TestNodeRefusesHTTPProjectionWork(t *testing.T) {
	now := time.Now()
	w, id := nodePermitWork(now)
	w.Packet.Raw = &collector.RawPrefix{Snaplen: 1500}
	w.Packet.HTTP = &collector.HTTPProjection{MaxFlows: 16, MaxHeaderBytes: 8 << 10, MaxFlowBytes: 64 << 10, MaxTotalBytes: 1 << 20, IdleTimeout: 10 * time.Second}
	if !w.Packet.Valid() {
		t.Fatal("fixture invalid")
	}
	var mu sync.Mutex
	budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20}, now)
	var calls atomic.Int32
	engine := func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
		calls.Add(1)
		return gadget.CaptureStats{}, nil
	}
	n := &nodePackets{engine: engine, observedEngine: func(context.Context, string, int, func(gadget.Frame), func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		calls.Add(1)
		return gadget.CaptureStats{}, nil
	}, identity: func() collector.Identity { return id }, available: true, now: func() time.Time { return now }, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}}
	receipt := n.start(context.Background(), id.Epoch, w)
	if receipt.Outcome == collector.OutcomeAccepted || receipt.Reason != collector.ReasonEngineUnavailable || calls.Load() != 0 || budget.Usage(now).FrozenReserved != 0 || len(n.observations) != 0 {
		t.Fatal("HTTP projection work was not refused before the engine", receipt, calls.Load())
	}
	n.wg.Wait()
}
