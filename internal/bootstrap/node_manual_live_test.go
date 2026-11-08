package bootstrap

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/transport/node"
)

func manualLiveID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func manualLiveBinding(id collector.Identity, w collector.Work) collector.ManualLiveSource {
	return collector.ManualLiveSource{RootID: manualLiveID(1), CaptureID: w.Packet.CaptureID, AttemptID: manualLiveID(2), ActionID: "packets", WorkID: w.ID, ExecutorPodUID: manualLiveID(3), ExecutorEpoch: manualLiveID(4), PodUID: w.Packet.PodUID, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}}
}
func manualLiveRequest(m collector.ManualLiveSource) collector.Work {
	return collector.Work{ID: manualLiveID(60), Sequence: 2, Kind: collector.WorkLiveRead, NotAfter: time.Now().Add(time.Second), Live: &collector.LiveRead{Manual: &m, Inspect: true, Head: true, ClusterID: manualLiveID(1), NamespaceUID: "ns", WorkloadUID: "work", Projection: v.Packet, PrivacyUntil: time.Now().Add(10 * time.Second), Limit: 20}}
}
func TestManualLiveActualFinitePacketHolderIsPassiveAndDoesNotRenew(t *testing.T) {
	now := time.Now()
	id := collector.Identity{NodeName: "node", NodeUID: manualLiveID(10), PodUID: manualLiveID(11), BootID: manualLiveID(12), Epoch: manualLiveID(13)}
	budget, e := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, now)
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var starts atomic.Int32
	deliver := make(chan func(gadget.Frame), 1)
	source, stop := context.WithCancel(t.Context())
	defer stop()
	n := &nodePackets{available: true, identity: func() collector.Identity { return id }, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}, upload: func(context.Context, string, collector.PacketResult, []byte) error { return nil }, engine: func(ctx context.Context, pod string, snap int, add func(gadget.Frame)) (gadget.CaptureStats, error) {
		starts.Add(1)
		if pod != manualLiveID(20) || snap != packets.Snaplen {
			t.Error("viewer changed actual acquisition", pod, snap)
		}
		deliver <- add
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}}
	defer func() { stop(); n.wg.Wait() }()
	original := collector.Work{ID: manualLiveID(30), Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: now.Add(2 * time.Second), Packet: &collector.PacketCapture{CaptureID: manualLiveID(21), PodUID: manualLiveID(20), Duration: 2 * time.Second, MaxBytes: 1 << 20}}
	if r := n.start(source, id.Epoch, original); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	add := <-deliver
	processing := &nodeLiveBudget{limits: v.ProcessingLimits{Subscriptions: 2, MemoryBytes: 1 << 20, EventsPerSecond: 100, BytesPerSecond: 1 << 20, TimePerSecond: 100 * time.Millisecond}}
	inspect := manualLiveRequest(manualLiveBinding(id, original))
	got, e := n.readManualLive(t.Context(), inspect, processing)
	if e != nil || got.Manual == nil || len(got.Rows) != 0 || processing.held != 0 || got.Fence != original.ID || starts.Load() != 1 {
		t.Fatal("passive exact finite holder", got, e, processing.held)
	}
	m := *got.Manual
	if !m.Valid() || m.HardUntil.Sub(m.StartedAt) != original.Packet.Duration || m.ObservationKind != "" {
		t.Fatal("invented original observation/times", m)
	}
	for _, wrong := range []string{"capture", "work", "node", "boot", "collector", "observation", "projection"} {
		q := inspect
		r := *inspect.Live
		q.Live = &r
		binding := *r.Manual
		r.Manual = &binding
		switch wrong {
		case "capture":
			binding.CaptureID = manualLiveID(99)
		case "work":
			binding.WorkID = manualLiveID(99)
		case "node":
			binding.NodeUID = manualLiveID(99)
		case "boot":
			binding.BootID = manualLiveID(99)
		case "collector":
			binding.CollectorEpoch = manualLiveID(99)
		case "observation":
			binding.ObservationKind = "packet"
			binding.ObservationSessionID = manualLiveID(98)
			binding.ObservationFence = manualLiveID(99)
		case "projection":
			r.Projection = v.HTTP
		}
		if _, e = n.readManualLive(t.Context(), q, processing); e == nil {
			t.Fatal("foreign finite holder accepted", wrong)
		}
	}
	read := inspect
	request := *inspect.Live
	read.Live = &request
	request.Manual = &m
	request.Inspect = false
	request.Head = false
	first, e := n.readManualLive(t.Context(), read, processing)
	if e != nil || len(first.Rows) != 0 || processing.held != 1 {
		t.Fatal("finite cohort activation", first, e)
	}
	// Actual original engine callback; live output is fixed transport metadata.
	stamp, e := sampleLiveClock("monotonic")
	if e != nil {
		t.Fatal(e)
	}
	raw := syntheticTCP(8080, "SYNTHETIC-ARGUMENT-BODY-CANARY")
	add(gadget.Frame{Data: raw, Wire: uint32(len(raw)), At: time.Now(), RawTimestamp: uint64(stamp.Nanos), Clock: "monotonic", DirectionKnown: true})
	got, e = n.readManualLive(t.Context(), read, processing)
	if e != nil || len(got.Rows) != 1 || got.Rows[0].Row.Packet == nil || got.Rows[0].Row.Packet.RemotePort != 8080 {
		t.Fatal("original finite callback", got, e)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "CANARY") {
		t.Fatal("raw user data entered approved live cohort")
	}
	if got.Manual == nil || *got.Manual != m || starts.Load() != 1 {
		t.Fatal("view replaced or extended original capture")
	}
	n.budgetMu.Lock()
	holder := n.running[m.CaptureID].live
	n.budgetMu.Unlock()
	holder.mu.Lock()
	cohort := holder.cohort
	holder.mu.Unlock()
	cohort.Close()
	if processing.held != 0 || source.Err() != nil {
		t.Fatal("viewer closure changed collection")
	}
	stop()
	n.wg.Wait()
	if _, e = n.readManualLive(t.Context(), inspect, processing); e == nil {
		t.Fatal("joined finite source remained discoverable")
	}
	if processing.held != 0 || starts.Load() != 1 {
		t.Fatal("finite source leak/restart")
	}
}

func TestManualLiveArgumentTapUsesOriginalPermitAndNeverProjectsValues(t *testing.T) {
	n, w, results, bodies := nodeArgumentFixture(t)
	entered, emit, emitted, leave := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var leaveOnce sync.Once
	defer leaveOnce.Do(func() { close(leave) })
	var engineCalls atomic.Int32
	n.argumentTrace = func(ctx context.Context, r gadget.ArgumentRequest, deliver func([]byte), _ func(gadget.InputNotice)) (gadget.ArgumentStats, error) {
		engineCalls.Add(1)
		if r.Events != uint64(w.Packet.Arguments.EventCredit) || r.Bytes != uint64(w.Packet.Arguments.ByteCredit) || !r.StartBy.Equal(w.NotAfter) {
			t.Error("viewer changed original argument authority")
		}
		close(entered)
		select {
		case <-emit:
		case <-ctx.Done():
			return gadget.ArgumentStats{}, ctx.Err()
		}
		wall, _ := bootWallClock()
		boot := uint64(time.Now().Sub(wall))
		for phase := uint32(0); phase < 2; phase++ {
			raw := make([]byte, 160)
			le := binary.LittleEndian
			le.PutUint32(raw, phase)
			le.PutUint64(raw[56:], 10)
			le.PutUint64(raw[64:], boot+uint64(phase))
			le.PutUint32(raw[72:], 20)
			le.PutUint16(raw[78:], 3)
			le.PutUint32(raw[104:], 21)
			le.PutUint32(raw[108:], 1)
			le.PutUint64(raw[112:], 1)
			le.PutUint64(raw[120:], 1)
			deliver(raw)
		}
		close(emitted)
		<-ctx.Done()
		<-leave
		return gadget.ArgumentStats{CoverageUnknown: true}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); leaveOnce.Do(func() { close(leave) }); n.wg.Wait() }()
	if got := n.startSyscall(ctx, n.identity().Epoch, w); got.Outcome != collector.OutcomeAccepted {
		t.Fatal(got)
	}
	<-entered
	m := manualLiveBinding(n.identity(), w)
	m.ActionID = w.Packet.Arguments.Binding.ActionID
	m.Scope = [32]byte{9} // capture scope is distinct from permit scope
	m.ObservationKind = "arguments"
	m.ObservationSessionID = w.Packet.Arguments.Binding.SessionID
	m.ObservationFence = w.Packet.Arguments.Binding.Fence
	request := manualLiveRequest(m)
	request.Live.Projection = v.Syscall
	budget := &nodeLiveBudget{limits: v.ProcessingLimits{Subscriptions: 1, MemoryBytes: 1 << 20, EventsPerSecond: 100, BytesPerSecond: 1 << 20, TimePerSecond: 100 * time.Millisecond}}
	head, e := n.readManualLive(t.Context(), request, budget)
	if e != nil || head.Manual == nil || budget.held != 0 {
		t.Fatal("original argument holder", head, e)
	}
	original := *head.Manual
	if !original.StartedAt.Equal(original.StartedAt.Truncate(time.Microsecond)) {
		t.Fatal("argument live start finer than the decoded result", original.StartedAt)
	}
	request.Live.Manual = &original
	request.Live.Inspect = false
	request.Live.Head = false
	if _, e = n.readManualLive(t.Context(), request, budget); e != nil {
		t.Fatal(e)
	}
	close(emit)
	<-emitted
	got, e := n.readManualLive(t.Context(), request, budget)
	if e != nil || len(got.Rows) != 1 || got.Rows[0].Row.Syscall == nil || got.Rows[0].Row.Syscall.Name != "close" || !got.Rows[0].Row.Syscall.Paired || got.Rows[0].Row.Syscall.PID != 20 {
		t.Fatal("qualified fixed argument metadata", got, e)
	}
	// Even a retained paired call with synthetic user memory cannot put values
	// into the typed metadata tap. The native decoder/permit remains separate.
	n.budgetMu.Lock()
	holder := n.running[m.CaptureID].live
	n.budgetMu.Unlock()
	wall, _ := bootWallClock()
	boot := uint64(time.Now().Sub(wall))
	holder.argument(syscalls.ArgumentCall{Entry: &syscalls.ArgumentProbe{Event: syscalls.ArgumentRecord{Number: 3, PID: 20, Boot: boot}, Memory: &syscalls.ArgumentRecord{Data: []byte("SYNTHETIC-PRIVATE-ARGUMENT-CANARY")}}, Exit: &syscalls.ArgumentProbe{Event: syscalls.ArgumentRecord{Number: 3, PID: 20, Boot: boot + 1}}}, time.Now())
	got, e = n.readManualLive(t.Context(), request, budget)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "CANARY") || strings.Contains(string(raw), `"arguments":`) {
		t.Fatal("argument values entered approved fields")
	}
	stop := collector.Work{ID: manualLiveID(70), Sequence: 3, Kind: collector.WorkCancelPacketCapture, NotAfter: time.Now().Add(time.Second), CancelPacket: &collector.PacketCancel{CaptureID: w.Packet.CaptureID, WorkID: w.ID}}
	if r := n.cancel(stop); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	if _, e = n.readManualLive(t.Context(), request, budget); e == nil || budget.held != 0 {
		t.Fatal("stop kept disclosable metadata", e, budget.held)
	}
	n.budgetMu.Lock()
	count, _, _ := n.budget().SourceUsage()
	running := len(n.running)
	n.budgetMu.Unlock()
	if count != 1 || running != 1 {
		t.Fatal("source capacity released before actual engine join", count, running)
	}
	leaveOnce.Do(func() { close(leave) })
	n.wg.Wait()
	<-results
	<-bodies
	n.budgetMu.Lock()
	count, _, _ = n.budget().SourceUsage()
	running = len(n.running)
	n.budgetMu.Unlock()
	if count != 0 || running != 0 || engineCalls.Load() != 1 {
		t.Fatal("joined original argument capture leaked/restarted", count, running, engineCalls.Load())
	}
}

func TestManualLiveHTTPUsesSameFiniteSanitizerAndOriginalClock(t *testing.T) {
	w, id := httpWork(time.Now())
	var mu sync.Mutex
	budget, e := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	callback := make(chan func(gadget.Frame), 1)
	var engines atomic.Int32
	uploaded := make(chan collector.PacketResult, 1)
	n := &nodePackets{available: true, identity: func() collector.Identity { return id }, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}, upload: func(_ context.Context, _ string, r collector.PacketResult, _ []byte) error { uploaded <- r; return nil }, engine: func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
		t.Error("unobserved HTTP fallback")
		return gadget.CaptureStats{}, nil
	}, observedEngine: func(ctx context.Context, pod string, snap int, deliver func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		engines.Add(1)
		if snap != httpheaders.Snaplen || pod != w.Packet.PodUID {
			t.Error("changed original HTTP acquisition")
		}
		callback <- deliver
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); n.wg.Wait() }()
	if r := n.start(ctx, id.Epoch, w); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	add := <-callback
	m := manualLiveBinding(id, w)
	m.ActionID = w.Packet.Observation.Binding.ActionID
	m.ObservationKind = "packet"
	m.ObservationSessionID = w.Packet.Observation.Binding.SessionID
	m.ObservationFence = w.Packet.Observation.Binding.Fence
	request := manualLiveRequest(m)
	request.Live.Projection = v.HTTP
	processing := &nodeLiveBudget{limits: v.ProcessingLimits{Subscriptions: 1, MemoryBytes: 1 << 20, EventsPerSecond: 1000, BytesPerSecond: 1 << 20, TimePerSecond: 100 * time.Millisecond}}
	head, e := n.readManualLive(t.Context(), request, processing)
	if e != nil || head.Manual == nil || processing.held != 0 {
		t.Fatal(head, e)
	}
	original := *head.Manual
	request.Live.Manual = &original
	request.Live.Inspect = false
	request.Live.Head = false
	if _, e = n.readManualLive(t.Context(), request, processing); e != nil {
		t.Fatal(e)
	}
	for _, raw := range httpExchange() {
		stamp, e := sampleLiveClock("monotonic")
		if e != nil {
			t.Fatal(e)
		}
		add(gadget.Frame{Data: raw, Wire: uint32(len(raw)), At: time.Now(), RawTimestamp: uint64(stamp.Nanos), Clock: "monotonic"})
	}
	got, e := n.readManualLive(t.Context(), request, processing)
	if e != nil || len(got.Rows) != 1 || got.Rows[0].Row.HTTP == nil || got.Rows[0].Row.HTTP.Method != "GET" || got.Rows[0].Clock != "monotonic" {
		t.Fatal("same finite HTTP sanitizer tap", got, e)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), httpSecret) || strings.Contains(string(raw), "shop.example") || strings.Contains(string(raw), "orders") {
		t.Fatal("HTTP private fields entered live output")
	}
	if engines.Load() != 1 || *got.Manual != original {
		t.Fatal("viewer restarted or extended HTTP source")
	}
	request.Live.AfterSequence = got.Position.Sequence
	conn := &httpTestFlow{cseq: 1000, sseq: 5000, port: 50}
	frames := [][]byte{conn.frame(true, true, false, false, nil), conn.frame(false, true, true, false, nil), conn.frame(true, false, true, false, nil), conn.frame(true, false, true, false, []byte{0x16, 0x03, 0x01, 0, 0x2f, 1, 0, 0, 0x2b, 3, 3})}
	for _, raw := range frames {
		stamp, _ := sampleLiveClock("monotonic")
		add(gadget.Frame{Data: raw, Wire: uint32(len(raw)), At: time.Now(), RawTimestamp: uint64(stamp.Nanos), Clock: "monotonic"})
	}
	limited, e := n.readManualLive(t.Context(), request, processing)
	if e != nil || len(limited.Rows) != 0 || limited.Position.Unsupported == 0 || limited.Position.Lost < limited.Position.Unsupported {
		t.Fatal("unsupported TLS silently looked complete", limited, e)
	}
	cancel()
	n.wg.Wait()
	if processing.held != 0 {
		t.Fatal("HTTP source join left projection resources")
	}
	// The hub decodes PacketResult times at microsecond precision; the live
	// binding must name that same instant (native run 42472479320).
	select {
	case r := <-uploaded:
		if !original.StartedAt.Equal(original.StartedAt.Truncate(time.Microsecond)) || !r.StartedAt.Equal(original.StartedAt) {
			t.Fatal("live original start differs from the uploaded result", original.StartedAt, r.StartedAt)
		}
	default:
		t.Fatal("joined HTTP capture uploaded no result")
	}
}

func TestManualLiveSixteenSourcesCanRetainOneWholeRowWithinPrivateBudget(t *testing.T) {
	now := time.Now()
	id := collector.Identity{NodeUID: manualLiveID(10), PodUID: manualLiveID(11), BootID: manualLiveID(12), Epoch: manualLiveID(13)}
	w := collector.Work{ID: manualLiveID(30), Packet: &collector.PacketCapture{CaptureID: manualLiveID(21), PodUID: manualLiveID(20)}}
	m := manualLiveBinding(id, w)
	m.ActionID = "a111111111111111111111111"
	m.StartedAt = now
	m.HardUntil = now.Add(time.Minute)
	m.ObservationKind = "packet"
	m.ObservationSessionID = manualLiveID(31)
	m.ObservationFence = manualLiveID(32)
	row := v.Row{ID: m.CaptureID + "-1", SourceID: m.CaptureID, Sequence: 1, ObservedAt: now, ReceivedAt: now, ExpiresAt: now.Add(time.Second), Projection: v.Packet, PodUID: m.PodUID, Packet: &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", RemotePort: 8080, Direction: "egress", WireBytes: 1500}}
	out := v.NodeReply{Manual: &m, WorkID: manualLiveID(60), SourceID: m.CaptureID, Fence: m.WorkID, BootID: m.BootID, Clock: "monotonic", Sample: 1, Rows: []v.StampedRow{{Row: row, Nanos: 1, Clock: "monotonic"}}, Position: v.Position{Sequence: 1}}
	request := collector.LiveRead{Manual: &m, Limit: 2, ReplyBytes: (28 << 10) / 16}
	wire, _ := node.WireLiveReply(id.Epoch, out)
	raw, _ := json.Marshal(wire)
	got, e := boundManualLiveReply(id.Epoch, request, out)
	if e != nil || len(got.Rows) != 1 {
		t.Fatal("sixteen-source private header consumed every whole row", len(raw), request.ReplyBytes, e, len(got.Rows))
	}
	t.Logf("compact manual packet reply=%dB sourceBudget=%dB retainedWholeRows=%d (prior full echo1975B)", len(raw), request.ReplyBytes, len(got.Rows))
}

func TestManualLiveMetadataSyscallTapAndStopKeepOriginalSource(t *testing.T) {
	now := time.Now()
	id := collector.Identity{NodeName: "node", NodeUID: manualLiveID(10), PodUID: manualLiveID(11), BootID: manualLiveID(12), Epoch: manualLiveID(13)}
	budget, e := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, now)
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	callback := make(chan func(), 1)
	leave := make(chan struct{})
	var release sync.Once
	var engines atomic.Int32
	n := &nodePackets{identity: func() collector.Identity { return id }, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}, upload: func(context.Context, string, collector.PacketResult, []byte) error { return nil }, syscallTrace: func(ctx context.Context, pod string, numbers []uint16, deliver func([]byte), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		engines.Add(1)
		if pod != manualLiveID(20) || len(numbers) != 1 || numbers[0] != 0 {
			t.Error("viewer changed original metadata source")
		}
		callback <- func() {
			stamp, _ := sampleLiveClock("boottime")
			boot := uint64(stamp.Nanos)
			deliver(rawSyscall(syscalls.EventEnter, 0, 7, 10, boot, 0))
			deliver(rawSyscall(syscalls.EventExit, 0, 7, 10, boot+1, 5))
		}
		<-ctx.Done()
		<-leave
		return gadget.CaptureStats{}, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); release.Do(func() { close(leave) }); n.wg.Wait() }()
	w := collector.Work{ID: manualLiveID(30), Sequence: 1, Kind: collector.WorkSyscallCapture, NotAfter: now.Add(time.Second), Packet: &collector.PacketCapture{CaptureID: manualLiveID(21), PodUID: manualLiveID(20), Duration: time.Second, MaxBytes: 1 << 20, Syscalls: &collector.SyscallFilter{Names: []string{"read"}, MaxEvents: 100, MaxTrackedThreads: 16}, MaxEventsPerSecond: 100}}
	if r := n.startSyscall(ctx, id.Epoch, w); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	emit := <-callback
	m := manualLiveBinding(id, w)
	q := manualLiveRequest(m)
	q.Live.Projection = v.Syscall
	processing := &nodeLiveBudget{limits: v.ProcessingLimits{Subscriptions: 1, MemoryBytes: 1 << 20, EventsPerSecond: 100, BytesPerSecond: 1 << 20, TimePerSecond: 100 * time.Millisecond}}
	head, e := n.readManualLive(t.Context(), q, processing)
	if e != nil || head.Manual == nil || head.Manual.ObservationKind != "" || processing.held != 0 {
		t.Fatal("metadata invented a sensitive observation", head, e)
	}
	original := *head.Manual
	if !original.StartedAt.Equal(original.StartedAt.Truncate(time.Microsecond)) {
		t.Fatal("syscall live start finer than the decoded result", original.StartedAt) // native run 42480440424
	}
	q.Live.Manual = &original
	q.Live.Inspect = false
	q.Live.Head = false
	if _, e = n.readManualLive(t.Context(), q, processing); e != nil {
		t.Fatal(e)
	}
	emit()
	got, e := n.readManualLive(t.Context(), q, processing)
	if e != nil || len(got.Rows) != 1 || got.Rows[0].Row.Syscall == nil || got.Rows[0].Row.Syscall.Name != "read" || got.Rows[0].Row.Syscall.PID != 7 || !got.Rows[0].Row.Syscall.Paired {
		t.Fatal("existing fixed syscall metadata", got, e)
	}
	stop := collector.Work{ID: manualLiveID(70), Sequence: 3, Kind: collector.WorkCancelPacketCapture, NotAfter: time.Now().Add(time.Second), CancelPacket: &collector.PacketCancel{CaptureID: w.Packet.CaptureID, WorkID: manualLiveID(71)}}
	if r := n.cancel(stop); r.Outcome == collector.OutcomeAccepted {
		t.Fatal("foreign work stopped metadata source")
	}
	stop.CancelPacket.WorkID = w.ID
	if r := n.cancel(stop); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	if _, e = n.readManualLive(t.Context(), q, processing); e == nil || processing.held != 0 {
		t.Fatal("stopped source remained readable", e)
	}
	n.budgetMu.Lock()
	usage := n.budget().Usage(n.now())
	pending := len(n.running)
	n.budgetMu.Unlock()
	if pending != 1 || usage.FrozenReserved != w.Packet.MaxBytes {
		t.Fatal("unjoined metadata source refunded", pending, usage)
	}
	release.Do(func() { close(leave) })
	n.wg.Wait()
	if engines.Load() != 1 {
		t.Fatal("viewer restarted metadata engine")
	}
}

func TestManualLiveInactiveArgumentTapDoesNotSerializeOrAllocate(t *testing.T) {
	h := &manualLiveHolder{}
	call := syscalls.ArgumentCall{Entry: &syscalls.ArgumentProbe{Event: syscalls.ArgumentRecord{Number: 3, PID: 7, Boot: 1}}, Exit: &syscalls.ArgumentProbe{Event: syscalls.ArgumentRecord{Number: 3, PID: 7, Boot: 2}}}
	now := time.Now()
	if allocations := testing.AllocsPerRun(1000, func() { h.argument(call, now) }); allocations != 0 {
		t.Fatal("inactive finite capture allocated viewer metadata", allocations)
	}
}
