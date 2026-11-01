package bootstrap

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

func distinctCancellationSnapshot(x collector.SourceSnapshot) collector.SourceSnapshot {
	x.CaptureID = "44444444-4444-4444-8444-444444444444"
	x.AttemptID = "55555555-5555-4555-8555-555555555555"
	x.Request.SnapshotID = "66666666-6666-4666-8666-666666666666"
	return x
}
func snapshotCancelWork(x collector.SourceSnapshot, now time.Time) collector.Work {
	return collector.Work{ID: "22222222-2222-4222-8222-222222222222", Sequence: 2, Kind: collector.WorkCancelSourceSnapshot, NotAfter: now.Add(time.Second), CancelSnapshot: &x}
}
func assertSourceBudget(t *testing.T, n *nodeSources, frozen int64, sources int) {
	t.Helper()
	n.budgetMu.Lock()
	defer n.budgetMu.Unlock()
	if usage := n.budget.Usage(n.now()); usage.FrozenReserved != frozen {
		t.Fatal("incorrect frozen ownership", usage.FrozenReserved, frozen)
	}
	if actual, _, _ := n.budget.SourceUsage(); actual != int64(sources) {
		t.Fatal("cancellation changed source ownership", actual, sources)
	}
}
func TestNodeSnapshotCancelBeforeDelayedStartFencesExactAttempt(t *testing.T) {
	n, source, clock, x := sourceSnapshotPipelineFixture(t, func(context.Context, string, collector.PacketResult, []byte) error {
		t.Error("cancelled snapshot uploaded")
		return nil
	})
	x = distinctCancellationSnapshot(x)
	cancel := snapshotCancelWork(x, clock.now())
	if r := n.decide(t.Context(), x.Binding.CollectorEpoch, cancel); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	start := collector.Work{ID: x.CaptureID, Sequence: 3, Kind: collector.WorkPacketSourceSnapshot, NotAfter: x.Request.StartBy, Snapshot: &x}
	if r := n.decide(t.Context(), x.Binding.CollectorEpoch, start); r.Outcome == collector.OutcomeAccepted {
		t.Fatal("delayed start ignored exact cancellation fence", r)
	}
	bad := x
	bad.AttemptID = "33333333-3333-4333-8333-333333333333"
	cancel.CancelSnapshot = &bad
	if r := n.decide(t.Context(), x.Binding.CollectorEpoch, cancel); r.Outcome == collector.OutcomeAccepted {
		t.Fatal("another attempt borrowed cancellation", r)
	}
	assertSourceBudget(t, n, 0, 1)
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed || source.engineExited {
		t.Fatal("snapshot cancellation stopped live source")
	}
}
func TestNodeSnapshotCancelWaitsForUploaderAndIndependentCopyJoin(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "liveSource", true: "expiredSource"}[expired], func(t *testing.T) {
			uploaded := make(chan struct{})
			observedCancel := make(chan struct{})
			release := make(chan struct{})
			n, source, clock, x := sourceSnapshotPipelineFixture(t, func(ctx context.Context, _ string, _ collector.PacketResult, _ []byte) error {
				close(uploaded)
				<-ctx.Done()
				close(observedCancel)
				<-release
				return ctx.Err()
			})
			x = distinctCancellationSnapshot(x)
			// Always release before cleanup if an assertion fails, so the test owns its blocked uploader.
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			start := collector.Work{ID: x.CaptureID, Sequence: 1, Kind: collector.WorkPacketSourceSnapshot, NotAfter: x.Request.StartBy, Snapshot: &x}
			if r := n.decide(t.Context(), x.Binding.CollectorEpoch, start); r.Outcome != collector.OutcomeAccepted {
				t.Fatal(r)
			}
			select {
			case <-uploaded:
			case <-time.After(time.Second):
				t.Fatal("snapshot never entered uploader")
			}
			sources := 1
			if expired {
				clock.set(source.meter.Permit().LeafUntil)
				source.onTimer()
				<-source.done
				sources = 0
			}
			wrong := x
			wrong.AttemptID = "33333333-3333-4333-8333-333333333333"
			if r := n.decide(t.Context(), x.Binding.CollectorEpoch, snapshotCancelWork(wrong, clock.now())); r.Outcome == collector.OutcomeAccepted {
				t.Fatal("wrong attempt cancelled original uploader")
			}
			result := make(chan collector.Receipt, 1)
			go func() { result <- n.decide(t.Context(), x.Binding.CollectorEpoch, snapshotCancelWork(x, clock.now())) }()
			select {
			case <-observedCancel:
			case <-time.After(time.Second):
				t.Fatal("cancellation never reached uploader")
			}
			select {
			case r := <-result:
				t.Fatal("acknowledged before uploader joined", r)
			default:
			}
			assertSourceBudget(t, n, 2*65536, sources)
			close(release)
			select {
			case r := <-result:
				if r.Outcome != collector.OutcomeAccepted {
					t.Fatal(r)
				}
			case <-time.After(time.Second):
				t.Fatal("joined cancellation missing")
			}
			assertSourceBudget(t, n, 0, sources)
			if !expired {
				source.mu.Lock()
				closed := source.closed
				source.mu.Unlock()
				if closed {
					t.Fatal("snapshot cancellation stopped live source")
				}
			}
		})
	}
}
