package bootstrap

import (
	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLiveExistingSourceTapDoesNotCollectPinOrBorrowRaw(t *testing.T) {
	now := time.Now()
	p := sourceOwnerPermit(now)
	budget, bmu := sourceOwnerBudget(t, now)
	started := make(chan struct{})
	deliver := make(chan func(gadget.Frame), 1)
	engine := func(ctx context.Context, _ string, snap int, f func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		if snap != 134 {
			t.Error("viewer changed snaplen", snap)
		}
		deliver <- f
		close(started)
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	s, e := newPacketSource(t.Context(), p, collector.PolicyLimits{}, sourceOwnerLimits(), nil, nil, engine, time.Now, budget, bmu, nil, "")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	<-started
	f := <-deliver
	source := v.Source{Binding: p.Binding, Target: authorization.Target{ClusterID: p.Binding.RootID, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: p.Binding.PodUID}, OwnerKind: "policy", OwnerID: "policy", State: "Ready", SaveVia: "recordingSave", Projections: []string{v.Packet}, LeaseUntil: p.LeafUntil, HardUntil: p.HardUntil, PrivacyUntil: p.HardUntil}
	// Genuine current source exists but a missing operator live budget cannot
	// start a cohort or change the engine/ring.
	sample, e := sampleLiveClock("monotonic")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.activateLive(source, v.Packet, time.Now().Add(time.Second), nil, sample); e == nil {
		t.Fatal("unqualified viewer budget accepted")
	}
	b := &nodeLiveBudget{limits: v.ProcessingLimits{Subscriptions: 1, MemoryBytes: 1 << 20, EventsPerSecond: 100000, BytesPerSecond: 1 << 20, TimePerSecond: 100 * time.Millisecond}}
	sample, _ = sampleLiveClock("monotonic")
	c, e := s.activateLive(source, v.Packet, time.Now().Add(5*time.Second), b, sample)
	if e != nil {
		t.Fatal(e)
	}
	// Existing acquisition callback, Ethernet/IPv4/TCP plus synthetic payload.
	raw := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0, 0x45, 0, 0, 60, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0x04, 0xd2, 0x1f, 0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 2, 4, 0, 0, 0, 0, 0}
	raw = append(raw, []byte("SYNTHETIC-LIVE-PAYLOAD")...)
	stamp, _ := sampleLiveClock("monotonic")
	f(gadget.Frame{Data: raw, Wire: uint32(len(raw)), At: time.Now(), RawTimestamp: uint64(stamp.Nanos), Clock: "monotonic", DirectionKnown: true})
	if status := b.status(); status.PendingRows != 1 {
		t.Fatal("accepted live row is not pending", status)
	}
	call, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	rows, pos, e := c.Read(call, v.Position{}, 100, time.Now)
	if e != nil || len(rows) != 1 || pos.Sequence != 1 || rows[0].Row.Packet.RemotePort != 8080 {
		t.Fatal(rows, pos, e)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), "SYNTHETIC-LIVE-PAYLOAD") {
		t.Fatal("payload crossed tap")
	}
	if s.meter.ObservedBytes() != int64(len(raw)) || s.ring.State().FrozenBytes != 0 {
		t.Fatal("viewer changed source accounting or pinned ring")
	}
	read := func(after v.Position) ([]v.StampedRow, v.Position, error) {
		fresh, err := sampleLiveClock("monotonic")
		if err != nil {
			return nil, v.Position{}, err
		}
		if err := c.activate(source, time.Now().Add(5*time.Second), fresh, time.Now()); err != nil {
			return nil, v.Position{}, err
		}
		bounded, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		return c.Read(bounded, after, 100, time.Now)
	}
	priorSequence, priorLoss := uint64(1), uint64(0)
	for batch := 0; batch < 20; batch++ {
		stamp, _ = sampleLiveClock("monotonic")
		for range 100 {
			f(gadget.Frame{Data: raw, Wire: uint32(len(raw)), At: time.Now(), RawTimestamp: uint64(stamp.Nanos), Clock: "monotonic", DirectionKnown: true})
		}
		rows, pos, e = read(pos)
		if e != nil || pos.Sequence < priorSequence || pos.Lost < priorLoss {
			t.Fatal("sustained live batch regressed cursor or loss", batch, len(rows), pos, e)
		}
		priorSequence, priorLoss = pos.Sequence, pos.Lost
	}
	if got := s.meter.ObservedBytes(); got != int64(2001*len(raw)) {
		t.Fatal("sustained live reads changed recorder accounting", got)
	}
	stamp, _ = sampleLiveClock("monotonic")
	for range 1000 {
		f(gadget.Frame{Data: raw, Wire: uint32(len(raw)), At: time.Now(), RawTimestamp: uint64(stamp.Nanos), Clock: "monotonic", DirectionKnown: true})
	}
	if got := s.meter.ObservedBytes(); got != int64(3001*len(raw)) {
		t.Fatal("reader lag backpressured the recorder", got)
	}
	rows, pos, e = read(pos)
	if e != nil || pos.Sequence < priorSequence || pos.Lost == 0 {
		t.Fatal("reader lag did not retain bounded rows and explicit loss", len(rows), pos, e)
	}
	before := p
	b.attach(c)
	if got := b.status().LostEvents; got != int64(pos.Lost) {
		t.Fatal("repeated manual-style attach reset cohort loss", got, pos.Lost)
	}
	c.Close()
	retained := b.status()
	if b.held != 0 || s.closed || s.meter.Permit() != before || retained.PendingRows != 0 || retained.LostEvents != int64(pos.Lost) {
		t.Fatal("close viewer changed collection or lost its counters", retained, pos)
	}
	sample, _ = sampleLiveClock("monotonic")
	next, e := s.activateLive(source, v.Packet, time.Now().Add(5*time.Second), b, sample)
	if e != nil {
		t.Fatal(e)
	}
	next.Close()
	if got := b.status().LostEvents; got != retained.LostEvents {
		t.Fatal("new cohort counted retained source loss again", got, retained.LostEvents)
	}
	// Changing a source epoch or projection cannot reuse its cohort.
	changed := source
	changed.Binding.Fence = "22222222-2222-4222-8222-222222222222"
	if _, e = s.activateLive(changed, v.Packet, time.Now().Add(time.Second), b, sample); e == nil {
		t.Fatal("replacement source accepted")
	}
	if _, e = s.activateLive(source, v.HTTP, time.Now().Add(time.Second), b, sample); e == nil {
		t.Fatal("134-byte source claimed HTTP")
	}
}
func TestLiveNodeProcessingCreditCountsFilteredEventsAndNeverWaits(t *testing.T) {
	now := time.Now()
	b := &nodeLiveBudget{limits: v.ProcessingLimits{Subscriptions: 1, MemoryBytes: 1 << 20, EventsPerSecond: 1, BytesPerSecond: 100, TimePerSecond: time.Millisecond}}
	if !b.reserve() || b.reserve() {
		t.Fatal("aggregate slots")
	}
	if !b.take(now, 100) || b.take(now, 1) {
		t.Fatal("independent scan credit")
	}
	b.finish(time.Millisecond)
	b.deliver(now, 2, 120, 3)
	status := b.status()
	if status.Cohorts != 1 || status.ScanEvents != 1 || status.ScanBytes != 100 || status.ScanCPUNanos != int64(time.Millisecond) || status.DeliveredRows != 2 || status.DeliveredBytes != 120 || status.RefusedAdmissions != 1 || status.DroppedRows != 3 {
		t.Fatal("live status lost scan, delivery, drop or refused-admission counters", status)
	}
	if b.take(now, 0) {
		t.Fatal("CPU upper bound")
	}
	b.mu.Lock()
	if b.take(now, 0) {
		t.Fatal("collector blocked by viewer lock")
	}
	b.mu.Unlock()
	if !b.take(now.Add(time.Second), 1) {
		t.Fatal("finite refill")
	}
	if next := b.status(); next.ScanEvents != 2 || next.ScanBytes != 101 || next.DeliveredRows != 2 || next.DeliveredBytes != 120 || next.RefusedAdmissions != 1 {
		t.Fatal("rate-limit refill reset cumulative live counters", next)
	}
	b.release()
	if status := b.status(); status.Cohorts != 0 {
		t.Fatal("live cohort did not release", status)
	}
}
