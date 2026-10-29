package bootstrap

import (
	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/transport/node"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Same epoch/key re-enrollment starts a new pollLoop at After=0. A lost
// status receipt can therefore expose the same original work again.
type replayNodeChannel struct {
	fakeNodeChannel
	work   collector.Work
	resets int
}

func (c *replayNodeChannel) Poll(_ context.Context, _ string, after uint64) ([]collector.Work, error) {
	if after == 0 {
		c.resets++
		return []collector.Work{c.work}, nil
	}
	return nil, node.ErrUnauthenticated
}
func TestNodeObservationSameEpochPollResetCannotCreateSecondMeter(t *testing.T) {
	w, id := nodePermitWork(time.Now())
	ch := &replayNodeChannel{work: w}
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
	}, identity: func() collector.Identity { return id }, available: true, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}, upload: func(context.Context, string, collector.PacketResult, []byte) error { return nil }}
	defer func() { close(release); n.wg.Wait() }()
	p := &nodeProcess{client: ch, epoch: id.Epoch, root: context.Background(), packets: n, now: time.Now, sleep: nodeSleep}
	for range 2 {
		if err := p.pollLoop(t.Context(), make(chan struct{}, 1)); !errors.Is(err, errNodeReenroll) {
			t.Fatal("fixture did not exercise re-enrollment cursor reset", err)
		}
	}
	if ch.resets != 2 || len(p.receipts) != 2 || p.receipts[0].Outcome != collector.OutcomeAccepted || p.receipts[1].Reason != collector.ReasonCaptureBusy {
		t.Fatal("original permit replay created another accepted attempt", ch.resets, p.receipts)
	}
	if r := n.start(t.Context(), id.Epoch, w); r.Reason != collector.ReasonCaptureBusy {
		t.Fatal("direct duplicate was rearmed", r)
	}
	changed := *w.Packet.Observation
	changed.Binding.Fence = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	w.Packet.Observation = &changed
	if r := n.start(t.Context(), id.Epoch, w); r.Reason != collector.ReasonCaptureBusy {
		t.Fatal("conflicting fence took over the capture", r)
	}
}

func TestNodeObservationReplayCacheUsesExistingBoundAndPrunesOnlyOriginalCutoff(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	w, id := nodePermitWork(now())
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
	}, identity: func() collector.Identity { return id }, available: true, now: now, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}, upload: func(context.Context, string, collector.PacketResult, []byte) error { return nil }, observations: map[string]time.Time{}}
	defer func() { close(release); n.wg.Wait() }()
	for i := range collector.MaxQueuedWork {
		n.observations[fmt.Sprintf("prior-capture-%d", i)] = now().Add(time.Second)
	}
	if r := n.start(t.Context(), id.Epoch, w); r.Reason != collector.ReasonCaptureBusy || budget.Usage(now()).FrozenReserved != 0 || len(n.observations) != collector.MaxQueuedWork {
		t.Fatal("full bounded cache started another attempt", r)
	}
	clock.Add(int64(2 * time.Second))
	if r := n.start(t.Context(), id.Epoch, w); r.Outcome != collector.OutcomeAccepted {
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
	if r := n.start(t.Context(), id.Epoch, w); r.Outcome == collector.OutcomeAccepted {
		t.Fatal("expired original start was revived after cache cutoff", r)
	}
}
