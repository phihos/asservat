package bootstrap

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/syscalls"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/collector"
	"golang.org/x/sys/unix"
)

func rawSyscall(typ uint32, nr uint16, pid uint32, mono, boot uint64, ret int64) []byte {
	b := make([]byte, syscalls.EventSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], typ)
	le.PutUint64(b[8:], uint64(ret))
	le.PutUint64(b[56:], mono)
	le.PutUint64(b[64:], boot)
	le.PutUint32(b[72:], pid)
	le.PutUint16(b[78:], nr)
	return b
}

// One paired read is retained as a record; a second call beyond the rate is a
// visible gap that leaves the source running (ADR-273).
func TestSyscallSourceRetainsPairedCallsAndDropsOverRateAsGap(t *testing.T) {
	now := time.Now().UTC()
	clock := &packetRingClock{at: now.Add(time.Second)}
	p := sourceOwnerPermit(now)
	p.BytesPerSecond = syscallEventCredit // one event per second
	filter := &collector.SyscallFilter{MaxEvents: 100, MaxTrackedThreads: 16}
	p.Binding.ProgramDigest = deliveryapp.SyscallFilterDigest(*filter)
	b, bmu := sourceOwnerBudget(t, now)
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	boot := uint64(ts.Nano())
	delivered := make(chan struct{})
	trace := func(ctx context.Context, pod string, numbers []uint16, deliver func([]byte), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		if pod != p.Binding.PodUID || numbers != nil {
			t.Error("changed pod/filter")
		}
		deliver(rawSyscall(syscalls.EventEnter, 0, 7, 100, boot, 0))
		deliver(rawSyscall(syscalls.EventExit, 0, 7, 100, boot+1000, 5))
		deliver(rawSyscall(syscalls.EventEnter, 1, 7, 200, boot+2000, 0))
		deliver(rawSyscall(syscalls.EventExit, 1, 7, 200, boot+3000, -2))
		close(delivered)
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	s, err := newPacketSource(t.Context(), p, collector.PolicyLimits{}, sourceOwnerLimits(), nil, filter, syscallEngine(trace, nil, false, 16), clock.now, b, bmu, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	<-delivered
	s.mu.Lock()
	state, closed, unknown := s.ring.State(), s.closed, s.inputUnknown
	s.mu.Unlock()
	// The drop is a ring gap only: source-level InputUnknown would make the
	// hub end and replace the source.
	if state.Packets.Retained != 1 || closed || unknown {
		t.Fatalf("retained=%d closed=%t inputUnknown=%t", state.Packets.Retained, closed, unknown)
	}
	_ = s.Close()

	// A packet permit cannot start a syscall source.
	packetPermit := sourceOwnerPermit(now)
	if _, err := newPacketSource(t.Context(), packetPermit, collector.PolicyLimits{}, sourceOwnerLimits(), nil, filter, syscallEngine(trace, nil, false, 16), clock.now, b, bmu, nil, ""); err == nil {
		t.Fatal("syscall source started on a packet program digest")
	}
}

// A selection beyond the kernel filter's 16 entries is filtered in userspace.
func TestSyscallEngineFiltersLargeSelectionsInUserspace(t *testing.T) {
	numbers := make([]uint16, 17)
	for i := range numbers {
		numbers[i] = uint16(i + 1) // excludes read (0)
	}
	var kernel []uint16
	trace := func(_ context.Context, _ string, k []uint16, deliver func([]byte), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		kernel = k
		deliver(rawSyscall(syscalls.EventEnter, 0, 7, 100, 1, 0))
		deliver(rawSyscall(syscalls.EventExit, 0, 7, 100, 2, 5))
		deliver(rawSyscall(syscalls.EventEnter, 1, 7, 200, 3, 0))
		deliver(rawSyscall(syscalls.EventExit, 1, 7, 200, 4, 5))
		return gadget.CaptureStats{}, nil
	}
	var got []uint16
	_, err := syscallEngine(trace, numbers, false, 16)(t.Context(), "pod", 0, func(f gadget.Frame) {
		c, err := syscalls.UnmarshalRecord(f.Data)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, c.Number)
	}, nil)
	if err != nil || kernel != nil || len(got) != 1 || got[0] != 1 {
		t.Fatalf("kernel=%v got=%v err=%v", kernel, got, err)
	}
}

// result: errors charges every call but retains only failures.
func TestSyscallEngineErrorsOnlyChargesSuccesses(t *testing.T) {
	trace := func(_ context.Context, _ string, _ []uint16, deliver func([]byte), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		deliver(rawSyscall(syscalls.EventEnter, 0, 7, 100, 1, 0))
		deliver(rawSyscall(syscalls.EventExit, 0, 7, 100, 2, 5)) // success
		deliver(rawSyscall(syscalls.EventEnter, 257, 7, 200, 3, 0))
		deliver(rawSyscall(syscalls.EventExit, 257, 7, 200, 4, -2)) // ENOENT
		return gadget.CaptureStats{}, nil
	}
	var charged, retained int
	_, err := syscallEngine(trace, nil, true, 16)(t.Context(), "pod", 0, func(f gadget.Frame) {
		charged++
		if len(f.Data) > 0 {
			retained++
		}
	}, nil)
	if err != nil || charged != 2 || retained != 1 {
		t.Fatalf("charged=%d retained=%d err=%v", charged, retained, err)
	}
}
