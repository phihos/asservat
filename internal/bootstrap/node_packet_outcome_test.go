package bootstrap

import (
	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/collector"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNodeObservationCompletionCannotMaskEarlierUnknownOrBudget(t *testing.T) {
	for _, mode := range []string{"normal-deadline", "final-loss", "early-loss", "early-unknown", "early-credit"} {
		t.Run(mode, func(t *testing.T) {
			w, id := nodePermitWork(time.Now())
			if mode == "early-credit" {
				w.Packet.Observation.Credit = 1
			}
			var mu sync.Mutex
			budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
			result := make(chan collector.PacketResult, 1)
			n := &nodePackets{engine: func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
				t.Error("ordinary fallback")
				return gadget.CaptureStats{}, nil
			}, identity: func() collector.Identity { return id }, available: true, now: time.Now, version: "fixture", budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}, upload: func(_ context.Context, _ string, r collector.PacketResult, _ []byte) error { result <- r; return nil }}
			n.observedEngine = func(ctx context.Context, _ string, _ int, deliver func(gadget.Frame), notice func(gadget.InputNotice)) (gadget.CaptureStats, error) {
				until, _ := ctx.Deadline()
				f := syntheticTCP(80, "synthetic marker")
				f[47] = 2
				deliver(gadget.Frame{Data: f, Wire: uint32(len(f)), At: time.Now()})
				switch mode {
				case "early-loss":
					notice(gadget.InputNotice{LostSamples: 2})
				case "early-unknown":
					notice(gadget.InputNotice{})
				}
				// Model a provider that observes cancellation but joins at the original
				// action timeout, returning its own DeadlineExceeded rather than Canceled.
				timer := time.NewTimer(time.Until(until))
				defer timer.Stop()
				<-timer.C
				if mode == "normal-deadline" {
					<-ctx.Done()
				}
				stats := gadget.CaptureStats{}
				if mode == "final-loss" || mode == "early-loss" {
					stats.LostSamples = 2
				}
				return stats, context.DeadlineExceeded
			}
			if r := n.start(t.Context(), id.Epoch, w); r.Outcome != collector.OutcomeAccepted {
				t.Fatal(r)
			}
			var got collector.PacketResult
			select {
			case got = <-result:
			case <-time.After(2 * time.Second):
				t.Fatal("finite engine did not join")
			}
			n.wg.Wait()
			if (mode == "normal-deadline") != (got.Failure == "") {
				t.Fatal("provider deadline masked input outcome", mode, got.Failure)
			}
		})
	}
}

func TestPacketEngineWithoutObservationPreservesProviderOutcome(t *testing.T) {
	for _, provider := range []error{nil, context.DeadlineExceeded, context.Canceled, errors.New("synthetic engine failure")} {
		rec, err := packets.NewRecorder(nil, 64<<10, time.Now(), "")
		if err != nil {
			t.Fatal(err)
		}
		stats, got := runPacketEngine(t.Context(), func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
			return gadget.CaptureStats{LostSamples: 2}, provider
		}, "pod", rec, nil)
		if got != provider || stats.LostSamples != 2 {
			t.Fatal("ordinary provider outcome changed", got, stats)
		}
	}
}
func TestObservedPacketOutcomePreservesUnknownAfterNormalStopAndRealEngineError(t *testing.T) {
	for _, mode := range []string{"unknown-after-deadline", "real-engine-error"} {
		t.Run(mode, func(t *testing.T) {
			meter, _, _ := localObservationFixture(t, 1000, 1000)
			rec, _ := packets.NewRecorder(nil, 64<<10, time.Now(), "")
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
			defer cancel()
			provider := errors.New("synthetic engine failure")
			_, err := runObservedPacketEngine(ctx, func(engineCtx context.Context, _ string, _ int, _ func(gadget.Frame), notice func(gadget.InputNotice)) (gadget.CaptureStats, error) {
				<-engineCtx.Done()
				if mode == "real-engine-error" {
					return gadget.CaptureStats{}, provider
				}
				meter.Stop(context.DeadlineExceeded)
				notice(gadget.InputNotice{})
				return gadget.CaptureStats{}, context.DeadlineExceeded
			}, "pod", rec, meter)
			snapshot := meter.Snapshot()
			if mode == "unknown-after-deadline" {
				if !snapshot.UnknownInput || !errors.Is(snapshot.Stopped, context.DeadlineExceeded) || err == nil || errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("unknown input became normal completion", snapshot, err)
				}
			} else if !errors.Is(err, provider) || !errors.Is(snapshot.Stopped, context.DeadlineExceeded) {
				t.Fatal("later normal deadline replaced real engine failure", snapshot, err)
			}
		})
	}
}
