package bootstrap

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/domain/collector"
)

func TestNodeSourcesStopBeforeDelayedArmDoesNotStartAnEngine(t *testing.T) {
	now := time.Now().UTC()
	clock := &packetRingClock{at: now}
	permit := sourceOwnerPermit(now)
	resource := collector.SourceResources{PolicyUID: "resource-policy"}
	permit.Binding.ResourceDigest = deliveryapp.SourceResourcesDigest(resource)
	b, bmu := sourceOwnerBudget(t, now)
	var starts atomic.Int64
	n := &nodeSources{now: clock.now, budget: b, budgetMu: bmu, available: true, identity: func() collector.Identity {
		return collector.Identity{NodeUID: permit.Binding.NodeUID, PodUID: permit.Binding.CollectorPodUID, BootID: permit.Binding.BootID, Epoch: permit.Binding.CollectorEpoch}
	}, engine: func(ctx context.Context, _ string, _ int, _ func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		starts.Add(1)
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}}
	defer n.Close()
	// The issuer can commit an initial source, pause before dispatch, then
	// deliver its terminal control first. The node sequence orders enqueue,
	// not those independently committed upstream effects: arm has later seq.
	stop := collector.Work{ID: permit.Binding.SourceID, Sequence: 1, Kind: collector.WorkStopPacketSource, NotAfter: permit.DispatchUntil, StopSource: &permit.Binding}
	if r := n.decide(t.Context(), permit.Binding.CollectorEpoch, stop); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	l := sourceOwnerLimits()
	source := collector.PacketSource{Permit: permit, Resources: resource, Ring: collector.SourceRingLimits{MaxAge: l.MaxAge, MaxBytes: l.MaxBytes, SegmentBytes: l.SegmentBytes, MaxSegments: l.MaxSegments, MaxFrozenBytes: l.MaxFrozenBytes, MaxConcurrentSnapshots: l.MaxConcurrentSnapshots}}
	arm := collector.Work{ID: permit.Binding.SourceID, Sequence: 2, Kind: collector.WorkPacketSource, NotAfter: permit.DispatchUntil, Source: &source}
	if r := n.decide(t.Context(), permit.Binding.CollectorEpoch, arm); r.Outcome == collector.OutcomeAccepted {
		t.Fatal("stop-before-delayed-arm resurrected source", r)
	}
	if starts.Load() != 0 {
		t.Fatal("attached revoked source")
	}
}

func TestNodeSourceReportPreservesSnapshotTimeAcrossBlockingMetadata(t *testing.T) {
	now := time.Now().UTC()
	clock := &packetRingClock{at: now}
	permit := sourceOwnerPermit(now)
	meter, err := collector.NewSourceMeter(permit, now)
	if err != nil {
		t.Fatal(err)
	}
	captured := make(chan struct{})
	var once sync.Once
	n := &nodeSources{sources: map[string]*packetSource{permit.Binding.SourceID: {meter: meter}}, now: func() time.Time { at := clock.now(); once.Do(func() { close(captured) }); return at }}
	budget, _ := collector.NewBudget(collector.Ceilings{}, now)
	p := &nodeProcess{sources: n, budget: budget, now: clock.now}
	p.mu.Lock()
	done := make(chan collector.Report, 1)
	go func() { done <- p.report() }()
	<-captured
	clock.set(now.Add(6 * time.Second))
	p.mu.Unlock()
	report := <-done
	if !report.ObservedAt.Equal(now) {
		t.Fatal("blocking metadata freshened original source-set snapshot", report.ObservedAt, now)
	}
}

func TestNodeSourceReportKeepsNaturalStopAfterSourceSetAsOf(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Microsecond)
	clock := &packetRingClock{at: start}
	permit := sourceOwnerPermit(start)
	meter, err := collector.NewSourceMeter(permit, start)
	if err != nil {
		t.Fatal(err)
	}
	source := &packetSource{meter: meter}
	source.mu.Lock()
	sampled := make(chan struct{})
	var once sync.Once
	n := &nodeSources{sources: map[string]*packetSource{permit.Binding.SourceID: source}, now: func() time.Time { at := clock.now(); once.Do(func() { close(sampled) }); return at }}
	type report struct {
		sources []collector.SourceStatus
		asOf    time.Time
	}
	done := make(chan report, 1)
	go func() { s, at := n.Status(); done <- report{s, at} }()
	<-sampled
	// Natural engine stop owns s.mu independently of n.mu. It can occur after
	// the conservative source-set timestamp but before this source is copied.
	stop := start.Add(time.Second)
	clock.set(stop)
	source.stoppedUntil = stop.Add(packetSourceStopGrace)
	source.mu.Unlock()
	got := <-done
	if len(got.sources) != 1 || !got.asOf.Equal(start) || !got.sources[0].SourceStoppedAt.Equal(stop) || !got.sources[0].Valid(got.asOf) {
		t.Fatal("actual stop was rejected or restamped to set timestamp", got)
	}
}
