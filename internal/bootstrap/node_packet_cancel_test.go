package bootstrap

import (
	"context"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/domain/collector"
)

// ADR-283: a cancelPacketCapture item stops exactly the named running capture
// early; the capture still uploads its failure and releases its budget.
func TestNodePacketCaptureCancelStopsRunningCapture(t *testing.T) {
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	budget, _ := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, clock)
	var mu sync.Mutex
	up := &uploads{done: make(chan struct{})}
	entered := make(chan struct{})
	engine := func(ctx context.Context, _ string, _ int, _ func(gadget.Frame)) (gadget.CaptureStats, error) {
		close(entered)
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	n := &nodePackets{engine: engine, upload: up.upload, available: true, now: func() time.Time { return clock }, log: func(string) {}, budget: func() *collector.Budget { return budget }, budgetMu: &mu}
	const captureID, workID = "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	p := collector.PacketCapture{CaptureID: captureID, PodUID: "11111111-1111-4111-8111-111111111111", Duration: collector.MaxPacketCaptureDuration, MaxBytes: 1 << 20}
	if r := n.start(context.Background(), "epoch", collector.Work{ID: workID, Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: clock.Add(time.Second), Packet: &p}); r.Outcome != collector.OutcomeAccepted {
		t.Fatalf("%+v", r)
	}
	<-entered
	cancelWork := func(seq uint64, c collector.PacketCancel) collector.Work {
		return collector.Work{ID: "44444444-4444-4444-8444-44444444444" + string(rune('0'+seq)), Sequence: seq, Kind: collector.WorkCancelPacketCapture, NotAfter: clock.Add(5 * time.Second), CancelPacket: &c}
	}

	// An unknown capture: nothing runs, so the cancel is accepted and harmless.
	if r := n.cancel(cancelWork(2, collector.PacketCancel{CaptureID: "55555555-5555-4555-8555-555555555555", WorkID: workID})); r.Outcome != collector.OutcomeAccepted {
		t.Fatalf("unknown capture: %+v", r)
	}
	// The running capture under another work item's ID is refused.
	if r := n.cancel(cancelWork(3, collector.PacketCancel{CaptureID: captureID, WorkID: "66666666-6666-4666-8666-666666666666"})); r.Outcome != collector.OutcomeRefused || r.Reason != collector.ReasonWorkUnknown {
		t.Fatalf("wrong work ID: %+v", r)
	}
	// Expired and malformed cancels are refused by Decide.
	expired := cancelWork(4, collector.PacketCancel{CaptureID: captureID, WorkID: workID})
	expired.NotAfter = clock
	if r := n.cancel(expired); r.Reason != collector.ReasonWorkExpired {
		t.Fatalf("expired: %+v", r)
	}
	if r := n.cancel(cancelWork(5, collector.PacketCancel{CaptureID: captureID})); r.Reason != collector.ReasonWorkUnknown {
		t.Fatalf("malformed: %+v", r)
	}
	select {
	case <-up.done:
		t.Fatal("a refused cancel stopped the capture")
	default:
	}

	if r := n.cancel(cancelWork(6, collector.PacketCancel{CaptureID: captureID, WorkID: workID})); r.Outcome != collector.OutcomeAccepted {
		t.Fatalf("cancel: %+v", r)
	}
	select {
	case <-up.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the cancelled capture did not report")
	}
	n.wg.Wait()
	if len(up.r) != 1 || up.r[0].Failure != collector.ReasonCaptureFailed || up.r[0].WorkID != workID || up.r[0].CaptureID != captureID {
		t.Fatalf("a cancelled capture must report a failure: %+v", up.r)
	}
	mu.Lock()
	reserved, registered := budget.Usage(clock).FrozenReserved, len(n.running)
	mu.Unlock()
	if reserved != 0 || registered != 0 {
		t.Fatalf("budget %d still reserved, %d captures registered", reserved, registered)
	}
	// A repeated cancel after completion is accepted and changes nothing.
	if r := n.cancel(cancelWork(7, collector.PacketCancel{CaptureID: captureID, WorkID: workID})); r.Outcome != collector.OutcomeAccepted || len(up.r) != 1 {
		t.Fatalf("repeat: %+v", r)
	}
}

// A capture that ends on its own deadline leaves no registration behind.
func TestNodePacketCaptureRegistryEmptiesOnCompletion(t *testing.T) {
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	budget, _ := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, clock)
	var mu sync.Mutex
	up := &uploads{done: make(chan struct{})}
	engine := func(ctx context.Context, _ string, _ int, _ func(gadget.Frame)) (gadget.CaptureStats, error) {
		<-ctx.Done()
		return gadget.CaptureStats{}, nil
	}
	n := &nodePackets{engine: engine, upload: up.upload, available: true, now: func() time.Time { return clock }, log: func(string) {}, budget: func() *collector.Budget { return budget }, budgetMu: &mu}
	p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: "11111111-1111-4111-8111-111111111111", Duration: time.Second, MaxBytes: 1 << 20}
	if r := n.start(context.Background(), "epoch", collector.Work{ID: "33333333-3333-4333-8333-333333333333", Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: clock.Add(time.Second), Packet: &p}); r.Outcome != collector.OutcomeAccepted {
		t.Fatalf("%+v", r)
	}
	<-up.done
	n.wg.Wait()
	mu.Lock()
	registered := len(n.running)
	mu.Unlock()
	if registered != 0 || up.r[0].Failure != "" {
		t.Fatalf("%d registered, result %+v", registered, up.r[0])
	}
}
