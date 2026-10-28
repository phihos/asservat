package bootstrap

import (
	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func nodePermitWork(now time.Time) (collector.Work, collector.Identity) {
	id := collector.Identity{NodeUID: "11111111-1111-4111-8111-111111111111", PodUID: "22222222-2222-4222-8222-222222222222", BootID: "33333333-3333-4333-8333-333333333333", Epoch: "44444444-4444-4444-8444-444444444444"}
	program := []planning.BPFInstruction{{Code: 0x28, K: 12}, {Code: 0x15, Jf: 8, K: 0x800}, {Code: 0x30, K: 23}, {Code: 0x15, Jf: 6, K: 6}, {Code: 0x28, K: 20}, {Code: 0x45, Jt: 4, K: 0x1fff}, {Code: 0xb1, K: 14}, {Code: 0x50, K: 27}, {Code: 0x45, Jf: 1, K: 2}, {Code: 6, K: 65535}, {Code: 6}}
	p := collector.PacketCapture{CaptureID: "55555555-5555-4555-8555-555555555555", PodUID: "66666666-6666-4666-8666-666666666666", Program: program, ProgramDigest: [32]byte(compiler.FilterProgramDigest(program)), Duration: time.Second, MaxBytes: 1 << 20}
	p.Observation = &collector.ObservationPermit{Binding: collector.ObservationBinding{Scope: [32]byte{1}, ProgramDigest: p.ProgramDigest, ExpectationDigest: [32]byte{2}, AccountingRule: collector.ObservationAccountingRule(), SessionID: "77777777-7777-4777-8777-777777777777", Fence: "88888888-8888-4888-8888-888888888888", CaptureID: p.CaptureID, ActionID: "packet", PodUID: p.PodUID, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch}, StartedAt: now, SessionUntil: now.Add(10 * time.Second), LeaseUntil: now.Add(10 * time.Second), StartBy: now.Add(5 * time.Second), Duration: p.Duration, Sequence: 1, Credit: 1 << 20, BytesPerSecond: 1 << 20}
	return collector.Work{ID: "99999999-9999-4999-8999-999999999999", Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: p.Observation.StartBy, Packet: &p}, id
}
func TestNodeObservedPacketRejectsBeforeBudgetOrEngine(t *testing.T) {
	for _, mode := range []string{"node", "boot", "collector", "epoch", "capture", "pod", "program", "expectation", "rule", "late-start", "duration", "prefix", "missing-engine", "missing-identity", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			w, id := nodePermitWork(now)
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
			o := w.Packet.Observation
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "node":
				id.NodeUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "boot":
				id.BootID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "collector":
				id.PodUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "epoch":
				id.Epoch = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "capture":
				o.Binding.CaptureID = "other"
			case "pod":
				o.Binding.PodUID = "other"
			case "program":
				w.Packet.Program[0].K++
			case "expectation":
				o.Binding.ExpectationDigest = [32]byte{}
			case "rule":
				o.Binding.AccountingRule[0]++
			case "late-start":
				now = o.StartBy
			case "duration":
				o.Duration += time.Second
			case "prefix":
				w.Packet.Program = []planning.BPFInstruction{{Code: 0x30, K: 134}, {Code: 6, K: 65535}}
				w.Packet.ProgramDigest = [32]byte(compiler.FilterProgramDigest(w.Packet.Program))
				o.Binding.ProgramDigest = w.Packet.ProgramDigest
			case "missing-engine":
				n.observedEngine = nil
			case "missing-identity":
				n.identity = nil
			case "cancelled":
				cancel()
			}
			receipt := n.start(ctx, "44444444-4444-4444-8444-444444444444", w)
			if receipt.Outcome == collector.OutcomeAccepted || calls.Load() != 0 || budget.Usage(now).FrozenReserved != 0 {
				t.Fatal("refusal reached engine/budget", mode, receipt, calls.Load())
			}
		})
	}
}
func TestNodeObservedPacketNoticesStopBeforeNextPredicateAndJoin(t *testing.T) {
	for _, mode := range []string{"credit", "loss", "unknown", "complete", "parent-deadline", "changed-before-engine"} {
		t.Run(mode, func(t *testing.T) {
			w, id := nodePermitWork(time.Now())
			if mode == "credit" {
				w.Packet.Observation.Credit = 1
			}
			var mu sync.Mutex
			budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
			up := &uploads{done: make(chan struct{})}
			stopped, release := make(chan struct{}), make(chan struct{})
			var joined atomic.Bool
			var called atomic.Int32
			var views atomic.Int32
			n := &nodePackets{engine: func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
				t.Error("observed capture downgraded to ordinary engine")
				return gadget.CaptureStats{}, nil
			}, available: true, identity: func() collector.Identity {
				v := id
				if mode == "changed-before-engine" && views.Add(1) > 1 {
					v.Epoch = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				}
				return v
			}, now: time.Now, version: "fixture", log: func(string) {}, budget: func() *collector.Budget { return budget }, budgetMu: &mu}
			n.upload = func(ctx context.Context, epoch string, r collector.PacketResult, data []byte) error {
				if called.Load() > 0 && !joined.Load() {
					t.Error("upload preceded engine join")
				}
				return up.upload(ctx, epoch, r, data)
			}
			n.observedEngine = func(ctx context.Context, _ string, snap int, deliver func(gadget.Frame), notice func(gadget.InputNotice)) (gadget.CaptureStats, error) {
				called.Add(1)
				f := syntheticTCP(80, "synthetic marker")
				f[47] = 2
				deliver(gadget.Frame{Data: f, Wire: uint32(len(f)), At: time.Now()})
				stats := gadget.CaptureStats{}
				switch mode {
				case "loss":
					notice(gadget.InputNotice{LostSamples: 3})
					stats.LostSamples = 3
				case "unknown":
					notice(gadget.InputNotice{})
				}
				if mode != "complete" && mode != "parent-deadline" {
					<-ctx.Done()
					deliver(gadget.Frame{Data: f, Wire: uint32(len(f)), At: time.Now()})
					close(stopped)
					<-release
				} else {
					<-ctx.Done()
				}
				joined.Store(true)
				return stats, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "parent-deadline" {
				var end context.CancelFunc
				ctx, end = context.WithTimeout(ctx, 50*time.Millisecond)
				defer end()
			}
			if r := n.start(ctx, id.Epoch, w); r.Outcome != collector.OutcomeAccepted {
				t.Fatal(r)
			}
			if mode == "credit" || mode == "loss" || mode == "unknown" {
				select {
				case <-stopped:
				case <-time.After(time.Second):
					t.Fatal("notice did not cancel engine")
				}
				mu.Lock()
				reserved := budget.Usage(time.Now()).FrozenReserved
				mu.Unlock()
				if reserved != w.Packet.MaxBytes {
					t.Error("budget released before engine joined", reserved)
				}
				close(release)
			}
			select {
			case <-up.done:
			case <-time.After(2 * time.Second):
				t.Fatal("capture did not finish")
			}
			n.wg.Wait()
			r := up.r[0]
			if mode == "complete" {
				if r.Failure != "" || r.Seen != 1 || r.Retained != 1 {
					t.Fatal("finite completion failed", r)
				}
			} else if r.Failure == "" {
				t.Fatal("failed/unknown source reported successful output", mode, r)
			}
			if mode == "credit" && r.Seen != 0 {
				t.Fatal("credit refusal reached predicate", r)
			}
			if (mode == "loss" || mode == "unknown") && r.Seen != 1 {
				t.Fatal("post-notice callback reached predicate", r)
			}
			if mode == "changed-before-engine" && called.Load() != 0 {
				t.Fatal("changed local source reached engine")
			}
			mu.Lock()
			reserved := budget.Usage(time.Now()).FrozenReserved
			mu.Unlock()
			if reserved != 0 {
				t.Fatal("joined engine kept budget", reserved)
			}
		})
	}
}
func TestObservedPacketEngineUnknownNoticeMarksUnknownWithoutLostCount(t *testing.T) {
	m, _, _ := localObservationFixture(t, 1000, 1000)
	rec, _ := packets.NewRecorder(nil, 64<<10, time.Now(), "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stats, err := runObservedPacketEngine(ctx, func(ctx context.Context, _ string, _ int, _ func(gadget.Frame), notice func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		notice(gadget.InputNotice{})
		<-ctx.Done()
		return gadget.CaptureStats{}, nil
	}, "pod", rec, m)
	if err == nil || !errors.Is(err, ErrObservationClosed) || !m.Snapshot().UnknownInput || stats.LostSamples != 0 {
		t.Fatal("unknown gap fabricated measured loss or failed to stop", err, stats)
	}
}
