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
	b := &nodeLiveBudget{limits: v.ProcessingLimits{Subscriptions: 1, MemoryBytes: 1 << 20, EventsPerSecond: 100, BytesPerSecond: 1 << 20, TimePerSecond: 100 * time.Millisecond}}
	sample, _ = sampleLiveClock("monotonic")
	c, e := s.activateLive(source, v.Packet, time.Now().Add(time.Second), b, sample)
	if e != nil {
		t.Fatal(e)
	}
	// Existing acquisition callback, Ethernet/IPv4/TCP plus synthetic payload.
	raw := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0, 0x45, 0, 0, 60, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0x04, 0xd2, 0x1f, 0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 2, 4, 0, 0, 0, 0, 0}
	raw = append(raw, []byte("SYNTHETIC-LIVE-PAYLOAD")...)
	stamp, _ := sampleLiveClock("monotonic")
	at := time.Now()
	f(gadget.Frame{Data: raw, Wire: uint32(len(raw)), At: at, RawTimestamp: uint64(stamp.Nanos), Clock: "monotonic", DirectionKnown: true})
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
	before := p
	c.Close()
	if b.held != 0 || s.closed || s.meter.Permit() != before {
		t.Fatal("close viewer stopped or renewed collector")
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
	b.release()
}
