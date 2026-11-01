package bootstrap

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"golang.org/x/sys/unix"
)

// B3: a finite syscall recording runs the source engine on one Pod for its
// duration, retains paired calls as JSON Lines up to the per-second limit,
// and uploads them with the syscall native type; a selection the node cannot
// resolve is refused, and a quiet interval reports failure.
func TestNodeSyscallCaptureRecordsPairedCalls(t *testing.T) {
	clock := time.Now().UTC()
	budget, _ := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, clock)
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	boot := uint64(ts.Nano())
	const pod = "11111111-1111-4111-8111-111111111111"
	calls := 3
	trace := func(ctx context.Context, p string, numbers []uint16, deliver func([]byte), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		if p != pod || len(numbers) != 1 {
			t.Error("changed pod or selection", p, numbers)
		}
		for i := 0; i < calls; i++ {
			at := boot + uint64(i)*1000
			deliver(rawSyscall(syscalls.EventEnter, numbers[0], 7, 100, at, 0))
			deliver(rawSyscall(syscalls.EventExit, numbers[0], 7, 100, at+500, 5))
		}
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	var mu sync.Mutex
	run := func(names []string, perSecond int64) (collector.Receipt, *uploads) {
		up := &uploads{done: make(chan struct{})}
		n := &nodePackets{syscallTrace: trace, upload: up.upload, version: "v0.57.0", now: func() time.Time { return time.Now().UTC() }, log: func(string) {}, budget: func() *collector.Budget { return budget }, budgetMu: &mu}
		p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: pod, Duration: time.Second, MaxBytes: 1 << 20,
			Syscalls: &collector.SyscallFilter{Names: names, MaxEvents: 100, MaxTrackedThreads: 16}, MaxEventsPerSecond: perSecond}
		w := collector.Work{ID: "33333333-3333-4333-8333-333333333333", Sequence: 1, Kind: collector.WorkSyscallCapture, NotAfter: time.Now().Add(10 * time.Second), Packet: &p}
		r := n.startSyscall(context.Background(), "44444444-4444-4444-8444-444444444444", w)
		if r.Outcome == collector.OutcomeAccepted {
			select {
			case <-up.done:
			case <-time.After(10 * time.Second):
				t.Fatal("no upload")
			}
			n.wg.Wait()
		}
		return r, up
	}
	r, up := run([]string{"read"}, 2)
	if r.Outcome != collector.OutcomeAccepted {
		t.Fatalf("%+v", r)
	}
	res := up.r[0]
	if res.NativeType != artifact.SyscallRecordsArtifact || res.Failure != "" || res.Seen != 3 || res.Retained != 2 || res.OutputFull != 1 || !res.Valid() || bytes.Count(up.pcap[0], []byte("\n")) != 2 {
		t.Fatalf("%+v %q", res, up.pcap[0])
	}
	if r, _ := run([]string{"no-such-call"}, 2); r.Outcome == collector.OutcomeAccepted || r.Reason != collector.ReasonFilterUnsupported {
		t.Fatal("unknown syscall name accepted", r)
	}
	calls = 0
	if _, up = run([]string{"read"}, 2); up.r[0].Failure != collector.ReasonCaptureFailed || up.r[0].NativeType != artifact.SyscallRecordsArtifact {
		t.Fatal("a quiet interval did not report failure", up.r[0])
	}
}
