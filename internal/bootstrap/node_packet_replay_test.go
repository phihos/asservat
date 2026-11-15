package bootstrap

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/collector"
)

// A reconnect resends work that has no receipt yet, so the same original
// work can arrive twice.
func TestNodeObservationResentWorkCannotCreateSecondMeter(t *testing.T) {
	w, _ := nodePermitWork(time.Now())
	var mu sync.Mutex
	budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
	var calls atomic.Int32
	release := make(chan struct{})
	n := &nodePackets{engine: func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
		t.Error("legacy fallback")
		return gadget.CaptureStats{}, nil
	}, observedEngine: func(context.Context, string, int, func(gadget.Frame), func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		calls.Add(1)
		<-release
		return gadget.CaptureStats{}, nil
	}, available: true, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}, upload: func(context.Context, collector.PacketResult, []byte) error { return nil }}
	defer func() { close(release); n.wg.Wait() }()
	p := &nodeProcess{root: context.Background(), packets: n, now: time.Now, sleep: nodeSleep}
	first, second := p.handle(t.Context(), delivery.NodeWorkDelivery{Work: w}), p.handle(t.Context(), delivery.NodeWorkDelivery{Work: w})
	if first.Outcome != collector.OutcomeAccepted || second.Reason != collector.ReasonCaptureBusy {
		t.Fatal("original permit replay created another accepted attempt", first, second)
	}
	if r := n.start(t.Context(), w); r.Reason != collector.ReasonCaptureBusy {
		t.Fatal("direct duplicate was rearmed", r)
	}
	changed := *w.Packet.Observation
	changed.Binding.Fence = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	w.Packet.Observation = &changed
	if r := n.start(t.Context(), w); r.Reason != collector.ReasonCaptureBusy {
		t.Fatal("conflicting fence took over the capture", r)
	}
}

func TestNodeObservationReplayCacheUsesExistingBoundAndPrunesOnlyOriginalCutoff(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	w, _ := nodePermitWork(now())
	var mu sync.Mutex
	budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, now())
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	n := &nodePackets{engine: func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
		return gadget.CaptureStats{}, nil
	}, observedEngine: func(context.Context, string, int, func(gadget.Frame), func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		entered <- struct{}{}
		<-release
		return gadget.CaptureStats{}, nil
	}, available: true, now: now, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}, upload: func(context.Context, collector.PacketResult, []byte) error { return nil }, observations: map[string]time.Time{}}
	defer func() { close(release); n.wg.Wait() }()
	for i := range collector.MaxQueuedWork {
		n.observations[fmt.Sprintf("prior-capture-%d", i)] = now().Add(time.Second)
	}
	if r := n.start(t.Context(), w); r.Reason != collector.ReasonCaptureBusy || budget.Usage(now()).FrozenReserved != 0 || len(n.observations) != collector.MaxQueuedWork {
		t.Fatal("full bounded cache started another attempt", r)
	}
	clock.Add(int64(2 * time.Second))
	if r := n.start(t.Context(), w); r.Outcome != collector.OutcomeAccepted {
		t.Fatal("expired claims blocked a valid original permit", r)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("valid engine did not start")
	}
	mu.Lock()
	count := len(n.observations)
	until := n.observations[w.Packet.CaptureID]
	mu.Unlock()
	if count != 1 || !until.Equal(w.Packet.Observation.StartBy) {
		t.Fatal("cache renewed cutoff or failed to prune", count, until)
	}
	clock.Store(w.Packet.Observation.StartBy.UnixNano())
	if r := n.start(t.Context(), w); r.Outcome == collector.OutcomeAccepted {
		t.Fatal("expired original start was revived after cache cutoff", r)
	}
}
