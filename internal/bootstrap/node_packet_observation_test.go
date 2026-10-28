package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/planning"
)

func packetObservation(t testing.TB, ctx context.Context, credit, rate int64, lease time.Duration) *LocalObservationGate {
	t.Helper()
	now := time.Now()
	b := ObservationBinding{Scope: [32]byte{1}, AccountingRule: ObservationAccountingRule(), SessionID: "00000000-0000-4000-8000-000000000001", Fence: "00000000-0000-4000-8000-000000000002", CaptureID: "capture", ActionID: "packet", PodUID: "pod", NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch"}
	p := ObservationPermit{Binding: b, StartedAt: now, SessionUntil: now.Add(time.Minute), LeaseUntil: now.Add(lease), Sequence: 1, Credit: credit, BytesPerSecond: rate}
	m, err := NewLocalObservationGate(ctx, b, p, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func TestPacketObservationChargesBeforeActualFilterDecoderAndOutputLimit(t *testing.T) {
	for _, mode := range []string{"retained", "zero-match", "malformed", "output-full"} {
		t.Run(mode, func(t *testing.T) {
			frame := syntheticTCP(80, "")
			var program []planning.BPFInstruction
			n := 1
			switch mode {
			case "zero-match":
				program = []planning.BPFInstruction{{Code: 0x06, K: 0}}
			case "malformed":
				frame = []byte{1, 2}
			case "output-full":
				n = 200
			}
			rec, err := packets.NewRecorder(program, 4096, time.Now(), "")
			if err != nil {
				t.Fatal(err)
			}
			m := packetObservation(t, context.Background(), int64(n*1600), 1<<20, time.Second)
			joined := false
			engine := func(ctx context.Context, _ string, _ int, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
				for i := 0; i < n+1; i++ {
					deliver(gadget.Frame{Data: frame, Wire: 1600, At: time.Now()})
				}
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("refusal did not cancel engine")
				}
				// A callback already in the engine queue must also be refused.
				deliver(gadget.Frame{Data: frame, Wire: 1600, At: time.Now()})
				joined = true
				return gadget.CaptureStats{}, nil
			}
			_, err = runPacketEngine(context.Background(), engine, "pod", rec, m)
			if !errors.Is(err, ErrObservationCredit) || !joined {
				t.Fatal("engine not canceled and joined", err, joined)
			}
			_, c, err := rec.Close(time.Now(), 0)
			if err != nil {
				t.Fatal(err)
			}
			s := m.Snapshot()
			if c.Seen != uint64(n) || s.Bytes != uint64(n*1600) || s.Frames != uint64(n) {
				t.Fatal("predicate ran without full original wire debit", c, s)
			}
			switch mode {
			case "retained":
				if c.Retained != 1 || c.WireBytes != 1600 {
					t.Fatal(c)
				}
			case "zero-match":
				if c.Filtered != 1 || c.WireBytes != 0 {
					t.Fatal(c)
				}
			case "malformed":
				if c.Malformed != 1 || c.WireBytes != 0 {
					t.Fatal(c)
				}
			case "output-full":
				if c.OutputFull == 0 || c.Retained == 0 || c.WireBytes >= s.Bytes {
					t.Fatal(c, s)
				}
			}
		})
	}
}

func TestPacketObservationStopsBeforePredicateForMissingLengthRateCancelAndIdleExpiry(t *testing.T) {
	for _, mode := range []string{"missing-wire", "short-wire", "tiny-rate", "canceled", "idle-lease"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			lease := time.Second
			rate := int64(1 << 20)
			if mode == "tiny-rate" {
				rate = 1
			}
			if mode == "idle-lease" {
				lease = 15 * time.Millisecond
			}
			m := packetObservation(t, parent, 10000, rate, lease)
			rec, err := packets.NewRecorder(nil, 4096, time.Now(), "")
			if err != nil {
				t.Fatal(err)
			}
			frame := syntheticTCP(80, "")
			wire := uint32(1600)
			if mode == "missing-wire" {
				wire = 0
			}
			if mode == "short-wire" {
				wire = 1
			}
			if mode == "canceled" {
				cancel()
			}
			joined := false
			engine := func(ctx context.Context, _ string, _ int, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
				if mode != "idle-lease" {
					deliver(gadget.Frame{Data: frame, Wire: wire, At: time.Now()})
				}
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("engine remained live")
				}
				deliver(gadget.Frame{Data: frame, Wire: wire, At: time.Now()})
				joined = true
				return gadget.CaptureStats{}, nil
			}
			_, err = runPacketEngine(parent, engine, "pod", rec, m)
			if err == nil || !joined {
				t.Fatal("refusal not joined", err)
			}
			_, c, e := rec.Close(time.Now(), 0)
			if e != nil {
				t.Fatal(e)
			}
			if c.Seen != 0 || m.Snapshot().Frames != 0 {
				t.Fatal("predicate ran after refusal", c, m.Snapshot())
			}
			if mode == "tiny-rate" && !errors.Is(err, ErrObservationRate) {
				t.Fatal("tiny rate silently relaxed", err)
			}
		})
	}
}

func TestPacketObservationLossStaysUnknownAndSpent(t *testing.T) {
	m := packetObservation(t, context.Background(), 1000, 1000, time.Second)
	rec, err := packets.NewRecorder(nil, 4096, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	engine := func(_ context.Context, _ string, _ int, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
		deliver(gadget.Frame{Data: syntheticTCP(80, ""), Wire: 100, At: time.Now()})
		return gadget.CaptureStats{LostSamples: 3}, nil
	}
	stats, err := runPacketEngine(context.Background(), engine, "pod", rec, m)
	if err == nil || stats.LostSamples != 3 {
		t.Fatal(err, stats)
	}
	s := m.Snapshot()
	if !s.UnknownInput || s.Bytes != 100 || s.Frames != 1 {
		t.Fatal("loss fabricated bytes/refund", s)
	}
}

// Actual packetInput -> maintained BPF -> Recorder path, synthetic engine data.
// Fixed iterations keep both output/credit bounded; compare baseline and meter
// on identical zero-match/malformed/output-full workloads, never native overhead.
func BenchmarkPacketObservationCallback(b *testing.B) {
	for _, mode := range []string{"zero-match", "malformed", "output-full"} {
		for _, metered := range []bool{false, true} {
			label := "baseline"
			if metered {
				label = "meter"
			}
			b.Run(mode+"/"+label, func(b *testing.B) {
				frame := syntheticTCP(80, "")
				var program []planning.BPFInstruction
				if mode == "zero-match" {
					program = []planning.BPFInstruction{{Code: 0x06, K: 0}}
				}
				if mode == "malformed" {
					frame = []byte{1, 2}
				}
				rec, err := packets.NewRecorder(program, 4096, time.Now(), "")
				if err != nil {
					b.Fatal(err)
				}
				var m *LocalObservationGate
				if metered {
					m = packetObservation(b, context.Background(), 1<<40, 1<<30, 30*time.Second)
				}
				input := packetInput{ctx: context.Background(), recorder: rec, meter: m}
				f := gadget.Frame{Data: frame, Wire: 64, At: time.Now()}
				b.ReportAllocs()
				b.SetBytes(64)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					input.add(f)
				}
				b.StopTimer()
				if m != nil && m.Snapshot().Frames != uint64(b.N) {
					b.Fatal("benchmark hit a refusal", m.Snapshot())
				}
			})
		}
	}
}

func TestPacketObservationCanceledIdleParentCannotReturnSuccess(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	m := packetObservation(t, parent, 1000, 1000, time.Second)
	rec, err := packets.NewRecorder(nil, 4096, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	engine := func(ctx context.Context, _ string, _ int, _ func(gadget.Frame)) (gadget.CaptureStats, error) {
		cancel()
		<-ctx.Done()
		return gadget.CaptureStats{}, nil
	}
	if _, err = runPacketEngine(parent, engine, "pod", rec, m); !errors.Is(err, context.Canceled) {
		t.Fatal("idle cancellation became success", err)
	}
	if m.Snapshot().Frames != 0 {
		t.Fatal(m.Snapshot())
	}
}
