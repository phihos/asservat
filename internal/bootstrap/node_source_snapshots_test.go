package bootstrap

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

func TestNodeSourceSnapshotCopiesOnceWithoutRearmingAndHoldsBothArenas(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "stopped"}[stopped], func(t *testing.T) {
			testNodeSourceSnapshot(t, stopped)
		})
	}
}
func testNodeSourceSnapshot(t *testing.T, stopped bool) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	clock := &packetRingClock{at: now}
	p := sourceOwnerPermit(now)
	p.Binding.AudienceDigest = [32]byte{7}
	b, err := collector.NewBudget(collector.Ceilings{SourceLimits: collector.SourceLimits{MaxActiveSources: 2, InputBytesPerSecond: 2 << 20, InputBurstBytes: 2 << 20}, RingBytes: 4096, FrozenBytes: 2 * 65536}, now)
	if err != nil {
		t.Fatal(err)
	}
	mu := &sync.Mutex{}
	ready := make(chan struct{})
	uploaded := make(chan collector.PacketResult, 1)
	release := make(chan struct{})
	naturalStop := make(chan struct{})
	engine := func(ctx context.Context, _ string, _ int, emit func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		frame := syntheticTCP(80, "secret-payload")
		emit(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: now})
		close(ready)
		select {
		case <-ctx.Done():
			return gadget.CaptureStats{}, ctx.Err()
		case <-naturalStop:
			return gadget.CaptureStats{}, nil
		}
	}
	limits := sourceOwnerLimits()
	limits.MaxFrozenBytes = 65536
	source, err := newPacketSource(t.Context(), p, collector.PolicyLimits{}, limits, nil, engine, clock.now, b, mu)
	if err != nil {
		t.Fatal(err)
	}
	<-ready
	n := &nodeSources{now: clock.now, budget: b, budgetMu: mu, sources: map[string]*packetSource{p.Binding.SourceID: source}, identity: func() collector.Identity {
		return collector.Identity{NodeUID: p.Binding.NodeUID, PodUID: p.Binding.CollectorPodUID, BootID: p.Binding.BootID, Epoch: p.Binding.CollectorEpoch}
	}, takeUpload: func(context.Context, int64) bool { return true }, upload: func(ctx context.Context, _ string, r collector.PacketResult, native []byte) error {
		if count, err := packets.CheckHeadersOnly(bytes.NewReader(native)); err != nil || count != 1 || bytes.Contains(native, []byte("secret-payload")) {
			t.Errorf("unsafe snapshot %d %v", count, err)
		}
		uploaded <- r
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	}}
	defer n.Close()
	if stopped {
		clock.set(now.Add(100*time.Millisecond + 37*time.Nanosecond))
		close(naturalStop)
		for {
			source.mu.Lock()
			exited := source.engineExited
			source.mu.Unlock()
			if exited {
				break
			}
			time.Sleep(time.Millisecond)
		}
		clock.set(now.Add(200 * time.Millisecond))
	}
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(deliveryapp.SourceBindingDigest(p.Binding)), SourceID: p.Binding.SourceID, Fence: p.Binding.Fence, SnapshotID: p.Binding.SourceID, SourceStartedAt: p.StartedAt, SourceHardUntil: p.HardUntil, T0: clock.now(), IssuedAt: clock.now(), StartBy: now.Add(time.Second), ProcessingUntil: now.Add(time.Minute), Before: time.Second, MaxBytes: 65536}
	snapshot := collector.SourceSnapshot{AttemptID: p.Binding.SourceID, WriterPodUID: p.Binding.SourceID, WriterEpoch: p.Binding.SourceID, Binding: p.Binding, CaptureID: p.Binding.SourceID, ExpectationDigest: [32]byte{5}, Request: request}
	work := collector.Work{ID: p.Binding.SourceID, Sequence: 1, Kind: collector.WorkPacketSourceSnapshot, NotAfter: request.StartBy, Snapshot: &snapshot}
	if r := n.decide(t.Context(), p.Binding.CollectorEpoch, work); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	var result collector.PacketResult
	select {
	case result = <-uploaded:
	case <-time.After(time.Second):
		t.Fatal("snapshot did not reach actual uploader")
	}
	expectedEnd := now
	if stopped {
		expectedEnd = now.Add(100*time.Millisecond + 37*time.Nanosecond)
	}
	if result.Snapshot == nil || result.Snapshot.WindowComplete || result.Snapshot.HistoryComplete || result.StartedAt != now || !result.EndedAt.Equal(expectedEnd) || stopped && !result.EndedAt.Equal(result.Snapshot.SourceStoppedAt) {
		t.Fatal("fabricated quiet coverage or changed cutoff", result)
	}
	if r := n.decide(t.Context(), p.Binding.CollectorEpoch, work); r.Outcome != collector.OutcomeAccepted {
		t.Fatal("lost exact replay", r)
	}
	mu.Lock()
	usage := b.Usage(now)
	count, _, _ := b.SourceUsage()
	mu.Unlock()
	if usage.FrozenReserved != 2*65536 || count != 1 {
		t.Fatal("unaccounted native arena or rearmed source", usage, count)
	}
	if source.ring.State().Snapshots != 1 {
		t.Fatal("duplicate snapshot")
	}
	close(release)
	n.snapshotWG.Wait()
	mu.Lock()
	usage = b.Usage(now)
	count, _, _ = b.SourceUsage()
	mu.Unlock()
	if usage.FrozenReserved != 0 || count != 1 {
		t.Fatal("snapshot release stopped source or leaked bytes", usage, count)
	}
	bad := snapshot
	bad.Binding.Fence = "22222222-2222-4222-8222-222222222222"
	work.Snapshot = &bad
	if r := n.decide(t.Context(), p.Binding.CollectorEpoch, work); r.Outcome == collector.OutcomeAccepted {
		t.Fatal("accepted substituted fence")
	}
}
