package bootstrap

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

func nodeArgumentFixture(t *testing.T) (*nodePackets, collector.Work, chan collector.PacketResult, chan []byte) {
	t.Helper()
	now := time.Now().UTC()
	id := collector.Identity{NodeUID: "11111111-1111-4111-8111-111111111111", PodUID: "22222222-2222-4222-8222-222222222222", BootID: "33333333-3333-4333-8333-333333333333", Epoch: "44444444-4444-4444-8444-444444444444"}
	defs, _ := syscalls.ArgumentDefinitions([]string{"close"}, false, 1)
	raw, _ := hex.DecodeString(gadget.ArgumentObjectSHA256)
	var program [32]byte
	copy(program[:], raw)
	a := collector.ArgumentObservationPermit{Binding: collector.ArgumentObservationBinding{Scope: [32]byte{1}, ProgramDigest: program, DefinitionDigest: syscalls.ArgumentDefinitionDigest(defs), ExpectationDigest: [32]byte{2}, AccountingRule: collector.ArgumentObservationAccountingRule(), SessionID: "55555555-5555-4555-8555-555555555555", Fence: "66666666-6666-4666-8666-666666666666", CaptureID: "77777777-7777-4777-8777-777777777777", ActionID: "action", PodUID: "88888888-8888-4888-8888-888888888888", NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch}, StartedAt: now, StartBy: now.Add(5 * time.Second), SessionUntil: now.Add(6 * time.Second), LeaseUntil: now.Add(6 * time.Second), Duration: time.Second, Sequence: 1, EventCredit: 1000, ByteCredit: 1 << 20, EventsPerSecond: 1000, BytesPerSecond: 1 << 20, MaxProbeBytes: 256, MaxBytesPerEvent: 1, MaxTrackedThreads: 16}
	p := collector.PacketCapture{CaptureID: a.Binding.CaptureID, PodUID: a.Binding.PodUID, Duration: time.Second, MaxBytes: 64 << 10, Arguments: &a, Syscalls: &collector.SyscallFilter{Names: []string{"close"}, MaxEvents: 100, MaxTrackedThreads: 16}, MaxEventsPerSecond: 1000}
	w := collector.Work{ID: "99999999-9999-4999-8999-999999999999", Sequence: 1, Kind: collector.WorkSyscallCapture, NotAfter: a.StartBy, Packet: &p}
	budget, err := collector.NewBudget(collector.Ceilings{SourceLimits: collector.SourceLimits{MaxActiveSources: 16, InputBytesPerSecond: 16 << 20, InputBurstBytes: 16 << 20}, RingBytes: 256 << 20, FrozenBytes: 256 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan collector.PacketResult, 4)
	bodies := make(chan []byte, 4)
	n := &nodePackets{identity: func() collector.Identity { return id }, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &sync.Mutex{}, argumentResources: func(int) (int64, error) { return gadget.ArgumentWorkingSet(2, 4096, 16) }, log: func(string) {}, upload: func(_ context.Context, _ string, r collector.PacketResult, b []byte) error {
		bodies <- append([]byte(nil), b...)
		results <- r
		return nil
	}}
	return n, w, results, bodies
}
func TestNodeArgumentStopJoinsBeforeResourceReleaseAndPreservesUnknown(t *testing.T) {
	n, w, results, bodies := nodeArgumentFixture(t)
	entered := make(chan struct{})
	leave := make(chan struct{})
	joined := make(chan struct{})
	n.argumentTrace = func(ctx context.Context, r gadget.ArgumentRequest, deliver func([]byte), _ func(gadget.InputNotice)) (gadget.ArgumentStats, error) {
		if r.AccountingRule != collector.ArgumentObservationAccountingRule() || r.Events != 1000 || !r.StartBy.Equal(w.NotAfter) {
			t.Error("original engine input changed")
		}
		if _, err := gadget.NewArgumentRecorder(r); err != nil {
			t.Error("node request rejected by actual argument recorder", err)
		}
		wall, _ := bootWallClock()
		boot := uint64(time.Now().Sub(wall))
		le := binary.LittleEndian
		for phase := uint32(0); phase < 2; phase++ {
			raw := make([]byte, 160)
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
		close(entered)
		<-ctx.Done()
		<-leave
		close(joined)
		return gadget.ArgumentStats{CoverageUnknown: true}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if got := n.startSyscall(ctx, n.identity().Epoch, w); got.Outcome != collector.OutcomeAccepted {
		t.Fatal(got)
	}
	<-entered
	if got := n.startSyscall(ctx, n.identity().Epoch, w); got.Outcome == collector.OutcomeAccepted {
		t.Fatal("replay accepted")
	}
	stop := collector.Work{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Sequence: 2, Kind: collector.WorkCancelPacketCapture, NotAfter: time.Now().Add(time.Second), CancelPacket: &collector.PacketCancel{CaptureID: w.Packet.CaptureID, WorkID: w.ID}}
	if got := n.cancel(stop); got.Outcome != collector.OutcomeAccepted {
		t.Fatal(got)
	}
	n.budgetMu.Lock()
	count, _, _ := n.budget().SourceUsage()
	n.budgetMu.Unlock()
	if count != 1 {
		t.Fatal("released before join")
	}
	close(leave)
	n.wg.Wait()
	<-joined
	r := <-results
	if r.NativeType != artifact.SyscallArgumentsArtifact || r.Failure != collector.ReasonCaptureFailed || r.Retained != 1 || !r.Valid() {
		t.Fatal(r)
	}
	native := <-bodies
	lines := strings.Split(strings.TrimSpace(string(native)), "\n")
	if len(lines) != 3 {
		t.Fatal(string(native))
	}
	var footer syscalls.ArgumentFooter
	if json.Unmarshal([]byte(lines[2]), &footer) != nil || !footer.CoverageUnknown || footer.ObservedEvents != nil || footer.Outcome != "cancelled" {
		t.Fatal(footer)
	}
	n.budgetMu.Lock()
	count, _, _ = n.budget().SourceUsage()
	n.budgetMu.Unlock()
	if count != 0 {
		t.Fatal("source retained after joined delivery")
	}
}
func TestNodeArgumentRejectsReplacementAndInsufficientWorkingCapacity(t *testing.T) {
	for _, change := range []func(*nodePackets, *collector.Work){func(_ *nodePackets, w *collector.Work) {
		w.Packet.Arguments.Binding.CollectorEpoch = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	}, func(_ *nodePackets, w *collector.Work) { w.Packet.Arguments.Binding.DefinitionDigest[0]++ }, func(n *nodePackets, _ *collector.Work) {
		n.argumentResources = func(int) (int64, error) { return 257 << 20, nil }
	}} {
		n, w, _, _ := nodeArgumentFixture(t)
		n.argumentTrace = func(context.Context, gadget.ArgumentRequest, func([]byte), func(gadget.InputNotice)) (gadget.ArgumentStats, error) {
			t.Error("refused input reached engine")
			return gadget.ArgumentStats{}, nil
		}
		change(n, &w)
		if got := n.startSyscall(t.Context(), n.identity().Epoch, w); got.Outcome == collector.OutcomeAccepted {
			t.Fatal(got)
		}
	}
}

func TestNodeArgumentObservationEndsBeforeDelayedJoin(t *testing.T) {
	n, w, results, bodies := nodeArgumentFixture(t)
	a := w.Packet.Arguments
	now := time.Now().UTC()
	a.StartedAt = now.Add(-4 * time.Second)
	a.StartBy = now.Add(100 * time.Millisecond)
	a.SessionUntil = a.StartBy.Add(a.Duration)
	a.LeaseUntil = a.SessionUntil
	w.NotAfter = a.StartBy
	deadlineReached, leave := make(chan time.Time, 1), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(leave) })
	n.argumentTrace = func(ctx context.Context, r gadget.ArgumentRequest, deliver func([]byte), _ func(gadget.InputNotice)) (gadget.ArgumentStats, error) {
		if !r.StartBy.Equal(a.StartBy) || r.Deadline.After(a.SessionUntil) {
			t.Error("original authority changed")
		}
		wall, _ := bootWallClock()
		send := func(phase uint32, tid uint32, at time.Time) {
			raw := make([]byte, 160)
			le := binary.LittleEndian
			le.PutUint32(raw, phase)
			le.PutUint64(raw[56:], 10)
			le.PutUint64(raw[64:], uint64(at.Sub(wall)))
			le.PutUint32(raw[72:], 20)
			le.PutUint16(raw[78:], 3)
			le.PutUint32(raw[104:], tid)
			le.PutUint32(raw[108:], 1)
			le.PutUint64(raw[112:], 1)
			le.PutUint64(raw[120:], 1)
			deliver(raw)
		}
		// One complete call and one valid entry whose exit falls beyond the
		// authorized observation window. Buffered delivery itself can be later.
		send(0, 21, r.Deadline.Add(-100*time.Millisecond))
		send(1, 21, r.Deadline.Add(-90*time.Millisecond))
		send(0, 22, r.Deadline.Add(-10*time.Millisecond))
		<-ctx.Done()
		deadlineReached <- r.Deadline
		<-leave
		send(1, 22, r.Deadline.Add(100*time.Millisecond))
		return gadget.ArgumentStats{AccountingKnown: true, ConsumedEvents: 4, ConsumedBytes: 1024, CoverageUnknown: true}, ctx.Err()
	}
	if got := n.startSyscall(t.Context(), n.identity().Epoch, w); got.Outcome != collector.OutcomeAccepted {
		t.Fatal(got)
	}
	deadline := <-deadlineReached
	// Deliberately retain the engine past the whole original session window.
	timer := time.NewTimer(time.Until(a.SessionUntil.Add(30 * time.Millisecond)))
	defer timer.Stop()
	<-timer.C
	select {
	case r := <-results:
		t.Fatalf("uploaded before detach/join: %+v", r)
	default:
	}
	n.budgetMu.Lock()
	count, _, _ := n.budget().SourceUsage()
	n.budgetMu.Unlock()
	if count != 1 {
		t.Fatal("released source before detach/join")
	}
	release.Do(func() { close(leave) })
	n.wg.Wait()
	result, native := <-results, <-bodies
	lines := strings.Split(strings.TrimSpace(string(native)), "\n")
	var footer syscalls.ArgumentFooter
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &footer); err != nil {
		t.Fatal(err)
	}
	if !result.EndedAt.Equal(deadline) || !footer.EndedAt.Equal(deadline) || footer.EndedAt.After(a.SessionUntil) {
		t.Fatalf("observation endpoint includes delayed cleanup: result=%v footer=%v deadline=%v session=%v", result.EndedAt, footer.EndedAt, deadline, a.SessionUntil)
	}
	if footer.Outcome != "completed" || footer.Retained != 2 || footer.PairGaps != 1 || footer.Malformed != 1 || !footer.CoverageUnknown || footer.ObservedEvents == nil || *footer.ObservedEvents != 4 || footer.ObservedBytes == nil || *footer.ObservedBytes != 1024 {
		t.Fatalf("window/gap/accounting semantics lost: %+v", footer)
	}
	var last syscalls.ArgumentEventLine
	if err := json.Unmarshal([]byte(lines[len(lines)-2]), &last); err != nil || last.Event.Outcome != "unfinished" {
		t.Fatalf("missing exit fabricated: %+v %v", last, err)
	}
	b := a.Binding
	e := artifact.ContextExpectation{PodUID: b.PodUID, Recording: &artifact.Recording{MaxBytes: w.Packet.MaxBytes, Syscalls: &artifact.RecordingSyscalls{Names: w.Packet.Syscalls.Names, MaxEvents: w.Packet.Syscalls.MaxEvents}, Arguments: &artifact.RecordingArguments{ProgramDigest: artifact.Digest(b.ProgramDigest), DefinitionDigest: artifact.Digest(b.DefinitionDigest), AccountingRule: artifact.Digest(b.AccountingRule), MaxProbeBytes: a.MaxProbeBytes, MaxBytesPerEvent: a.MaxBytesPerEvent}}}
	source := artifact.ArgumentSourceProvenance{PodUID: b.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, SessionID: b.SessionID, Fence: b.Fence, StartedAt: a.StartedAt, StartBy: a.StartBy, Until: a.SessionUntil}
	check, err := syscalls.NewArgumentCheck(e, source)
	if err != nil {
		t.Fatal(err)
	}
	if err = check.Write(native); err != nil {
		t.Fatalf("bounded artifact rejected by independent publisher: %v\n%s", err, native)
	}
	if err = check.Close(); err != nil {
		t.Fatal(err)
	}
}
