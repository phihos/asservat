package delivery

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

// ADR-283: a packet capture cancel names only work this channel queued for
// the node's process and never creates or extends a result slot.
func TestPacketCancelTargetsOnlyQueuedCapture(t *testing.T) {
	ch, _, clk, _ := newChannel(t)
	enroll(t, ch, epochA)
	p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: "33333333-3333-4333-8333-333333333333", Duration: 10 * time.Second, MaxBytes: 1 << 20}
	started, err := ch.EnqueuePacket("node-uid", p, clk.now().Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ch.mu.Lock()
	before := ch.nodes["node-uid"].captures[started.ID]
	slots := len(ch.nodes["node-uid"].captures)
	ch.mu.Unlock()
	// The fake clock lies before real time; only the deadline's presence and
	// its order relative to until matter here.
	ctx, stop := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer stop()
	until := clk.now().Add(5 * time.Second)

	if _, err := ch.EnqueuePacketCancel(ctx, "node-uid", p.CaptureID, "44444444-4444-4444-8444-444444444444", until); err == nil {
		t.Fatal("cancel of unknown work queued")
	}
	if _, err := ch.EnqueuePacketCancel(ctx, "node-uid", "55555555-5555-4555-8555-555555555555", started.ID, until); err == nil {
		t.Fatal("cancel with another capture ID queued")
	}
	if _, err := ch.EnqueuePacketCancel(ctx, "node-uid", p.CaptureID, started.ID, clk.now().Add(5*time.Second+time.Millisecond)); err == nil {
		t.Fatal("cancel beyond five seconds queued")
	}
	if _, err := ch.EnqueuePacketCancel(context.Background(), "node-uid", p.CaptureID, started.ID, until); err == nil {
		t.Fatal("cancel without a caller deadline queued")
	}
	short, stopShort := context.WithDeadline(context.Background(), clk.now().Add(time.Second))
	defer stopShort()
	if _, err := ch.EnqueuePacketCancel(short, "node-uid", p.CaptureID, started.ID, until); err == nil {
		t.Fatal("cancel under an ended caller deadline queued")
	}
	if _, err := ch.EnqueuePacketCancel(ctx, "other-node", p.CaptureID, started.ID, until); err == nil {
		t.Fatal("cancel for another node queued")
	}
	if _, err := ch.Enqueue("node-uid", collector.WorkCancelPacketCapture, until); !errors.Is(err, ErrNodeInvalid) {
		t.Fatal("generic enqueue accepted a payload kind", err)
	}

	w, err := ch.EnqueuePacketCancel(ctx, "node-uid", p.CaptureID, started.ID, until)
	if err != nil || w.Kind != collector.WorkCancelPacketCapture || w.CancelPacket == nil || *w.CancelPacket != (collector.PacketCancel{CaptureID: p.CaptureID, WorkID: started.ID}) ||
		w.Sequence != started.Sequence+1 || !w.NotAfter.Equal(until) || w.ID == started.ID {
		t.Fatal(w, err)
	}
	if r := collector.Decide(w, clk.now()); r.Reason == collector.ReasonWorkUnknown || r.Reason == collector.ReasonWorkExpired {
		t.Fatalf("queued cancel is not a valid work item: %+v", r)
	}
	ch.mu.Lock()
	after, ok := ch.nodes["node-uid"].captures[started.ID]
	count := len(ch.nodes["node-uid"].captures)
	ch.mu.Unlock()
	if !ok || after != before || count != slots {
		t.Fatalf("the upload slot changed: %+v -> %+v (%d -> %d slots)", before, after, slots, count)
	}

	// After the capture's slot expires nothing remains to cancel.
	clk.add(10*time.Second + p.Duration + PacketUploadMargin)
	if _, err := ch.EnqueuePacketCancel(ctx, "node-uid", p.CaptureID, started.ID, clk.now().Add(time.Second)); err == nil {
		t.Fatal("cancel of an expired capture queued")
	}
}
