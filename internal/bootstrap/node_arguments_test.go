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
