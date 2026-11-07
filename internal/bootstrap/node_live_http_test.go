package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	live "asservat.local/asservat/internal/domain/live"
)

func TestLiveHTTPUsesExistingReviewedProducerOriginalClockAndSanitizer(t *testing.T) {
	now := time.Now()
	permit := sourceOwnerPermit(now)
	permit.Binding.ObservationGrantID = permit.Binding.SourceID
	work, _ := httpWork(now)
	permit.Binding.ProgramDigest = work.Packet.ProgramDigest
	budget, e := collector.NewBudget(collector.Ceilings{SourceLimits: collector.SourceLimits{MaxActiveSources: 2, InputBytesPerSecond: 2 << 20, InputBurstBytes: 2 << 20}, RingBytes: 2 << 20, FrozenBytes: 2 << 20}, now)
	if e != nil {
		t.Fatal(e)
	}
	bmu := &sync.Mutex{}
	deliver := make(chan func(gadget.Frame), 1)
	engine := func(ctx context.Context, _ string, snap int, emit func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		if snap != 1500 {
			t.Error("viewer changed reviewed source prefix", snap)
		}
		deliver <- emit
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	limits := packets.RingLimits{MaxAge: time.Minute, MaxBytes: 4 * 65536, SegmentBytes: 65536, MaxSegments: 4, MaxFrozenBytes: 1 << 20, MaxConcurrentSnapshots: 2}
	source, e := newPacketSource(t.Context(), permit, collector.PolicyLimits{}, limits, work.Packet.Program, nil, engine, time.Now, budget, bmu, nil, "", &testHTTPProjection)
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	emit := <-deliver
	liveBudget := &nodeLiveBudget{limits: live.ProcessingLimits{Subscriptions: 1, MemoryBytes: 1 << 20, EventsPerSecond: 1000, BytesPerSecond: 1 << 20, TimePerSecond: 100 * time.Millisecond}}
	selected := live.Source{Binding: permit.Binding, Target: authorization.Target{ClusterID: permit.Binding.RootID, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: permit.Binding.PodUID}, OwnerKind: "policy", OwnerID: permit.Binding.PolicyUID, State: "Ready", SaveVia: "recordingSave", Projections: []string{live.HTTP}, LeaseUntil: permit.LeafUntil, HardUntil: permit.HardUntil, PrivacyUntil: permit.HardUntil}
	sample, e := sampleLiveClock("monotonic")
	if e != nil {
		t.Fatal(e)
	}
	cohort, e := source.activateLive(selected, live.HTTP, time.Now().Add(time.Second), liveBudget, sample)
	if e != nil {
		t.Fatal(e)
	}
	var wire int64
	for _, frame := range httpExchange() {
		stamp, e := sampleLiveClock("monotonic")
		if e != nil {
			t.Fatal(e)
		}
		wire += int64(len(frame))
		emit(gadget.Frame{Data: frame, Wire: uint32(len(frame)), At: time.Now(), RawTimestamp: uint64(stamp.Nanos), Clock: "monotonic"})
	}
	rows, position, e := cohort.Read(t.Context(), live.Position{}, 100, time.Now, false)
	if e != nil || len(rows) != 1 || rows[0].Nanos <= 0 || rows[0].Clock != "monotonic" || rows[0].Row.HTTP == nil || rows[0].Row.HTTP.Method != "GET" || rows[0].Row.HTTP.Status == nil || *rows[0].Row.HTTP.Status != 200 || rows[0].Row.HTTP.Duration != nil || len(rows[0].Row.HTTP.Headers) != 2 {
		t.Fatal(rows, position, e)
	}
	encoded, _ := json.Marshal(rows)
	for _, secret := range []string{httpSecret, "shop.example", "authorization", "set-cookie", "boundary="} {
		if bytes.Contains(bytes.ToLower(encoded), []byte(secret)) {
			t.Fatal("source secrets crossed approved live projection", secret)
		}
	}
	// Missing native time and unsupported protocols produce explicit bounded
	// coverage; no synthetic wall-clock placement or plaintext row is invented.
	cohort.appendHTTP(httpheaders.ObservedRecord{Record: httpheaders.Record{Method: "GET", Headers: []httpheaders.Header{}}}, time.Now())
	cohort.httpLoss(httpheaders.Counters{StoppedTLS: 1, StoppedHTTP2: 1}, time.Now())
	cohort.sensorLoss(3)
	after, next, e := cohort.Read(t.Context(), position, 100, time.Now, false)
	if e != nil || len(after) != 0 || next.ClockLost != 1 || next.Unsupported != 2 || next.SensorLost != 3 || next.Lost != 6 {
		t.Fatal(after, next, e)
	}
	cohort.Close()
	source.mu.Lock()
	observed := source.meter.ObservedBytes()
	closed := source.closed
	source.mu.Unlock()
	if observed != wire || closed || liveBudget.held != 0 || source.ring.State().FrozenBytes != 0 {
		t.Fatal("viewer mutated source credit/lifecycle or pinned history", observed, wire, closed, liveBudget.held)
	}
}
