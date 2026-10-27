package delivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

type recordingSink struct {
	got  []collector.PacketResult
	body [][]byte
	err  error
}

func (s *recordingSink) DeliverPacket(_ context.Context, _ collector.Identity, r collector.PacketResult, body io.Reader) error {
	b, _ := io.ReadAll(body)
	s.got, s.body = append(s.got, r), append(s.body, b)
	return s.err
}

// ADR-248: only the process a capture was queued for may deliver its result,
// once, before the capture's deadline; the item is a typed packetCapture.
func TestPacketCaptureDeliveredOnceByItsProcess(t *testing.T) {
	ch, _, clk, _ := newChannel(t)
	sink := &recordingSink{}
	ch.SetPacketSink(sink)
	peer, _ := enroll(t, ch, epochA)
	p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: "33333333-3333-4333-8333-333333333333", Duration: 10 * time.Second, MaxBytes: 1 << 20}
	if _, err := ch.Enqueue("node-uid", collector.WorkPacketCapture, clk.now().Add(time.Minute)); !errors.Is(err, ErrNodeInvalid) {
		t.Fatal("a packet capture needs its payload")
	}
	w, err := ch.EnqueuePacket("node-uid", p, clk.now().Add(10*time.Second))
	if err != nil || w.Packet == nil || w.Kind != collector.WorkPacketCapture {
		t.Fatal(w, err)
	}
	polled, err := ch.Poll(context.Background(), peer, epochA, 0, 0)
	if err != nil || len(polled) != 1 || polled[0].Packet.CaptureID != p.CaptureID {
		t.Fatal(polled, err)
	}
	result := collector.PacketResult{WorkID: w.ID, CaptureID: p.CaptureID, StartedAt: clk.now(), EndedAt: clk.now().Add(10 * time.Second), Seen: 1, Retained: 1, CapturedBytes: 3, Snaplen: 134}
	wrong := result
	wrong.CaptureID = "44444444-4444-4444-8444-444444444444"
	if err := ch.DeliverPacket(context.Background(), peer, epochA, wrong, bytes.NewReader([]byte("abc"))); !errors.Is(err, ErrNodeConflict) {
		t.Fatal("another capture's result accepted", err)
	}
	clk.add(5 * time.Second)
	if err := ch.DeliverPacket(context.Background(), peer, epochA, result, bytes.NewReader([]byte("abcdef"))); err != nil {
		t.Fatal(err)
	}
	if len(sink.got) != 1 || string(sink.body[0]) != "abc" {
		t.Fatalf("sink got %+v %q (body bounded by CapturedBytes)", sink.got, sink.body)
	}
	if err := ch.DeliverPacket(context.Background(), peer, epochA, result, bytes.NewReader([]byte("abc"))); !errors.Is(err, ErrNodeConflict) {
		t.Fatal("a second delivery accepted", err)
	}

	// After the deadline a result is refused; a replaced process loses it.
	w2, _ := ch.EnqueuePacket("node-uid", p, clk.now().Add(10*time.Second))
	clk.add(10*time.Second + p.Duration + PacketUploadMargin)
	r2 := result
	r2.WorkID = w2.ID
	if err := ch.DeliverPacket(context.Background(), peer, epochA, r2, bytes.NewReader([]byte("abc"))); !errors.Is(err, ErrNodeConflict) {
		t.Fatal("a late result accepted", err)
	}
	w3, _ := ch.EnqueuePacket("node-uid", p, clk.now().Add(10*time.Second))
	peerB, _ := enroll(t, ch, epochB)
	r3 := result
	r3.WorkID = w3.ID
	if err := ch.DeliverPacket(context.Background(), peerB, epochB, r3, bytes.NewReader([]byte("abc"))); !errors.Is(err, ErrNodeConflict) {
		t.Fatal("a replacement process delivered the earlier process's capture", err)
	}
	if err := ch.DeliverPacket(context.Background(), peer, epochA, r3, bytes.NewReader([]byte("abc"))); !errors.Is(err, ErrNodeUnauthenticated) {
		t.Fatal("a replaced process delivered", err)
	}
}

func TestPacketRecorderAvailableNeedsCurrentReport(t *testing.T) {
	v := NodeView{}
	if v.PacketRecorderAvailable() {
		t.Fatal("no report")
	}
	r := &collector.Report{Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable}}}
	v.Report = r
	if v.PacketRecorderAvailable() {
		t.Fatal("stale report")
	}
	v.Current = true
	if !v.PacketRecorderAvailable() {
		t.Fatal("available")
	}
}
