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
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

func TestOngoingHTTPSourceOriginalPrefixPrivateRingSaveAndJoinedBudget(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	clock := &packetRingClock{at: now}
	permit := sourceOwnerPermit(now)
	permit.Binding.ObservationGrantID = permit.Binding.SourceID
	permit.Binding.AudienceDigest = [32]byte{7}
	work, _ := httpWork(now)
	program := work.Packet.Program
	// Classic BPF return128 remains a predicate; it cannot truncate the
	// independently approved source prefix before HTTP reassembly.
	for i := range program {
		if program[i].Code == 6 && program[i].K > 0 {
			program[i].K = 128
		}
	}
	permit.Binding.ProgramDigest = [32]byte(compiler.FilterProgramDigest(program))
	budget, err := collector.NewBudget(collector.Ceilings{SourceLimits: collector.SourceLimits{MaxActiveSources: 2, InputBytesPerSecond: 2 << 20, InputBurstBytes: 2 << 20}, RingBytes: 2 << 20, FrozenBytes: 2 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	bmu := &sync.Mutex{}
	limits := packets.RingLimits{MaxAge: time.Minute, MaxBytes: 4 * 65536, SegmentBytes: 65536, MaxSegments: 4, MaxFrozenBytes: 1 << 20, MaxConcurrentSnapshots: 2}
	start, ready, joined, cancelled := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	frames := httpExchange()
	engine := func(ctx context.Context, _ string, snap int, emit func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		if snap != 1500 {
			t.Error("HTTP source prefix changed", snap)
		}
		<-start
		for i, f := range frames {
			at := now.Add(time.Duration(i+1) * time.Millisecond)
			clock.set(at)
			emit(gadget.Frame{Data: f, Wire: uint32(len(f)), At: at, RawTimestamp: uint64(i + 100), Clock: "monotonic"})
		}
		close(ready)
		<-ctx.Done()
		close(cancelled)
		<-joined
		return gadget.CaptureStats{}, ctx.Err()
	}
	source, err := newPacketSource(t.Context(), permit, collector.PolicyLimits{}, limits, program, nil, engine, clock.now, budget, bmu, nil, "", &testHTTPProjection)
	if err != nil {
		t.Fatal(err)
	}
	var releaseJoin sync.Once
	defer func() { releaseJoin.Do(func() { close(joined) }); _ = source.Close() }()
	var observed []httpheaders.ObservedRecord
	source.mu.Lock()
	source.httpObserved = func(r httpheaders.ObservedRecord) { observed = append(observed, r) }
	source.mu.Unlock()
	close(start)
	<-ready
	// A separately bounded ordinary metadata source coexists; neither viewer
	// nor the HTTP projector borrows its source slot/ring/rate allowance.
	peerPermit := sourceOwnerPermit(now)
	peerPermit.Binding.SourceID = "22222222-2222-4222-8222-222222222222"
	peerStarted := make(chan struct{})
	peerEngine := func(ctx context.Context, _ string, snap int, _ func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		if snap != packets.Snaplen {
			t.Error("HTTP source widened metadata peer")
		}
		close(peerStarted)
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	peer, err := newPacketSource(t.Context(), peerPermit, collector.PolicyLimits{}, sourceOwnerLimits(), nil, nil, peerEngine, clock.now, budget, bmu, nil, "")
	if err != nil {
		t.Fatal("separately funded metadata peer unavailable", err)
	}
	<-peerStarted
	if source.sameHTTPConfig(nil) || peer.sameHTTPConfig(&testHTTPProjection) {
		t.Fatal("source mode silently replaced")
	}
	_ = peer.Close()
	if len(observed) != 1 || observed[0].Record.Status != 200 || len(observed[0].Record.Headers) != 2 || observed[0].Stamp.RawTimestamp != 105 {
		t.Fatal("lost full approved prefix or original request stamp", observed)
	}
	processing, cancelProcessing := context.WithTimeout(t.Context(), time.Minute)
	defer cancelProcessing()
	copy, err := source.BeginWindow(processing, packets.RingWindow{From: now, Until: clock.now()}, clock.now(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if err = copy.Complete(clock.now()); err != nil {
		t.Fatal(err)
	}
	h := testHTTPProjection
	native, account, complete, err := httpheaders.EncodeSourceWindow(t.Context(), copy, httpheaders.Limits{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleTimeout: h.IdleTimeout}, 1<<20, now, clock.now(), true)
	if err != nil || !complete || account.Seen != uint64(len(frames)) || account.Filtered != 1 || account.Retained != uint64(len(frames)-1) {
		t.Fatal("not actual saved event-window counters", account, complete, err)
	}
	if bytes.Contains(native, []byte(httpSecret)) || bytes.Contains(native, []byte("shop.example")) || !bytes.Contains(native, []byte(`"open_at_close_flows":null`)) {
		t.Fatal("raw source bytes or fabricated open-flow gauge", string(native))
	}
	var pr httpheaders.Projection
	if json.Unmarshal(native, &pr) != nil || len(pr.Records) != 1 || pr.SourceWindow == nil {
		t.Fatal("invalid saved native")
	}
	// Exercise the actual source snapshot dispatcher and upload boundary too.
	if err = copy.Close(); err != nil {
		t.Fatal(err)
	}
	uploaded := make(chan collector.PacketResult, 1)
	n := &nodeSources{now: clock.now, budget: budget, budgetMu: bmu, sources: map[string]*packetSource{permit.Binding.SourceID: source}, version: "synthetic", identity: func() collector.Identity {
		return collector.Identity{NodeUID: permit.Binding.NodeUID, PodUID: permit.Binding.CollectorPodUID, BootID: permit.Binding.BootID, Epoch: permit.Binding.CollectorEpoch}
	}, takeUpload: func(context.Context, int64) bool { return true }, upload: func(_ context.Context, _ string, r collector.PacketResult, b []byte) error {
		e := artifact.ContextExpectation{NativeType: artifact.HTTPHeadersArtifact, Snapshot: &r.Snapshot.Request}
		check := httpheaders.NewExpectationCheck(e)
		if err := check.Write(b); err != nil {
			t.Error(err)
		}
		if err := check.Close(); err != nil {
			t.Error(err)
		}
		if !r.Valid() || r.NativeType != artifact.HTTPHeadersArtifact || r.Snaplen != 1500 || check.PacketCount() != r.Retained || r.Filtered != 1 {
			t.Error("actual snapshot delivery mismatch", r)
		}
		uploaded <- r
		return nil
	}}
	q := artifact.SourceSnapshotRequest{HTTP: artifact.RecordingHTTP{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleMillis: h.IdleTimeout.Milliseconds()}, SourceBindingDigest: artifact.Digest(deliveryapp.SourceBindingDigest(permit.Binding)), SourceID: permit.Binding.SourceID, Fence: permit.Binding.Fence, SnapshotID: permit.Binding.SourceID, SourceStartedAt: permit.StartedAt, SourceHardUntil: permit.HardUntil, T0: clock.now(), IssuedAt: clock.now(), StartBy: now.Add(time.Second), ProcessingUntil: now.Add(time.Minute), Before: time.Second, MaxBytes: 65536}
	x := collector.SourceSnapshot{Binding: permit.Binding, CaptureID: permit.Binding.SourceID, AttemptID: permit.Binding.SourceID, ExpectationDigest: [32]byte{4}, Request: q}
	w := collector.Work{ID: permit.Binding.SourceID, Sequence: 1, Kind: collector.WorkPacketSourceSnapshot, NotAfter: q.StartBy, Snapshot: &x}
	if receipt := n.decide(t.Context(), permit.Binding.CollectorEpoch, w); receipt.Outcome != collector.OutcomeAccepted {
		t.Fatal("HTTP source snapshot refused", receipt)
	}
	select {
	case <-uploaded:
	case <-time.After(time.Second):
		t.Fatal("HTTP snapshot never reached actual upload")
	}
	n.snapshotWG.Wait()
	source.mu.Lock()
	observedBytes := source.meter.ObservedBytes()
	source.mu.Unlock()
	var wire int64
	for _, f := range frames {
		wire += int64(len(f))
	}
	if observedBytes != wire {
		t.Fatal("filtered bytes not prepaid", observedBytes, wire)
	}
	source.mu.Lock()
	source.stopLocked(context.Canceled)
	source.mu.Unlock()
	<-cancelled
	bmu.Lock()
	count, _, _ := budget.SourceUsage()
	reserved := budget.Usage(clock.now()).RingReserved
	bmu.Unlock()
	if count != 1 || reserved != limits.MaxBytes+int64(h.MaxTotalBytes) {
		t.Fatal("released before original engine join", count, reserved)
	}
	releaseJoin.Do(func() { close(joined) })
	<-source.done
	bmu.Lock()
	count, _, _ = budget.SourceUsage()
	reserved = budget.Usage(clock.now()).RingReserved
	bmu.Unlock()
	if count != 0 || reserved != 0 {
		t.Fatal("joined source leaked allocation", count, reserved)
	}
}

func TestOngoingHTTPSourceRefusesWorkingMemoryBeforeEngine(t *testing.T) {
	now := time.Now().UTC()
	permit := sourceOwnerPermit(now)
	permit.Binding.ObservationGrantID = permit.Binding.SourceID
	work, _ := httpWork(now)
	permit.Binding.ProgramDigest = work.Packet.ProgramDigest
	budget, bmu := sourceOwnerBudget(t, now)
	called := false
	engine := func(context.Context, string, int, func(gadget.Frame), func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		called = true
		return gadget.CaptureStats{}, nil
	}
	source, err := newPacketSource(t.Context(), permit, collector.PolicyLimits{}, sourceOwnerLimits(), work.Packet.Program, nil, engine, time.Now, budget, bmu, nil, "", &testHTTPProjection)
	if err == nil || source != nil || called {
		t.Fatal("started without aggregate reassembly reservation", err)
	}
}
