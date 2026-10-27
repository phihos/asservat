package bootstrap

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/collector"
)

// Gitar #95: a capture that finished on its own deadline is delivered even
// when the node stops right after; a capture the node stopped early, or one
// larger than the upload burst, is reported as a failure instead of being
// dropped silently.
func TestNodePacketCaptureDeliversOrReportsEveryOutcome(t *testing.T) {
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	frames := func(deliver func(gadget.Frame)) {
		for i := range 20 {
			f := syntheticTCP(80, "payload")
			wire := uint32(len(f))
			deliver(gadget.Frame{Data: f[:min(len(f), packets.Snaplen)], Wire: wire, At: clock.Add(time.Duration(i) * time.Millisecond)})
		}
	}
	for name, c := range map[string]struct {
		burst   int64
		engine  func(capture context.Context, stopNode context.CancelFunc, deliver func(gadget.Frame)) (gadget.CaptureStats, error)
		failure collector.Reason
		frames  bool
	}{
		"completed, then the node stops": {burst: 64 << 20, engine: func(capture context.Context, stopNode context.CancelFunc, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
			frames(deliver)
			<-capture.Done()
			stopNode() // the node stops after the deadline ended the capture
			return gadget.CaptureStats{}, nil
		}, frames: true},
		"node stopped during the capture": {burst: 64 << 20, engine: func(capture context.Context, stopNode context.CancelFunc, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
			frames(deliver)
			stopNode()
			<-capture.Done()
			return gadget.CaptureStats{}, nil
		}, failure: collector.ReasonCaptureFailed},
		"larger than the upload burst": {burst: 1024, engine: func(capture context.Context, _ context.CancelFunc, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
			frames(deliver)
			<-capture.Done()
			return gadget.CaptureStats{}, nil
		}, failure: collector.ReasonCaptureFailed},
	} {
		t.Run(name, func(t *testing.T) {
			budget, err := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 16 << 20, UploadBytesPerSecond: 1 << 20, UploadBurstBytes: c.burst}, clock)
			if err != nil {
				t.Fatal(err)
			}
			node, stopNode := context.WithCancel(context.Background())
			defer stopNode()
			var mu, bmu sync.Mutex
			var got []collector.PacketResult
			var pcaps [][]byte
			upload := func(ctx context.Context, _ string, r collector.PacketResult, pcapng []byte) error {
				if ctx.Err() != nil {
					t.Error("delivery context already ended")
				}
				mu.Lock()
				got, pcaps = append(got, r), append(pcaps, append([]byte(nil), pcapng...))
				mu.Unlock()
				return nil
			}
			engine := func(capture context.Context, _ string, _ int, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
				return c.engine(capture, stopNode, deliver)
			}
			n := &nodePackets{engine: engine, upload: upload, available: true, now: func() time.Time { return clock }, log: func(string) {}, budget: func() *collector.Budget { return budget }, budgetMu: &bmu}
			p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: "11111111-1111-4111-8111-111111111111", Duration: time.Second, MaxBytes: 1 << 20}
			if r := n.start(node, "epoch", collector.Work{ID: "33333333-3333-4333-8333-333333333333", Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: clock.Add(time.Second), Packet: &p}); r.Outcome != collector.OutcomeAccepted {
				t.Fatalf("%+v", r)
			}
			n.wg.Wait()
			if len(got) != 1 || got[0].Failure != c.failure || !got[0].Valid() {
				t.Fatalf("%+v", got)
			}
			count, err := packets.CheckHeadersOnly(bytes.NewReader(pcaps[0]))
			if err != nil || (count == 20) != c.frames || (count == 0) == c.frames {
				t.Fatal(count, err)
			}
		})
	}
}
