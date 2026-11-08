package bootstrap

import (
	"context"
	"errors"
	"io"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/collector"
	"golang.org/x/sys/unix"
)

const syscallEventCredit = collector.SyscallEventCredit

// syscallTraceEngine is gadget.TraceSyscalls (tests substitute it).
type syscallTraceEngine func(context.Context, string, []uint16, func([]byte), func(gadget.InputNotice)) (gadget.CaptureStats, error)

// kernelSyscallFilter is the traceloop program's syscall_filters capacity.
const kernelSyscallFilter = 16

// syscallEngine adapts the traceloop engine to the packet-source engine
// shape: paired calls become fixed 32-byte records stamped with wall time,
// and pairing gaps become input notices. Pending halves are flushed when the
// engine stops. A selection beyond the kernel filter's capacity is filtered
// here, before any event is charged.
func syscallEngine(trace syscallTraceEngine, numbers []uint16, errorsOnly bool, maxTrackedThreads int) observedPacketEngine {
	kernel := numbers
	var allowed map[uint16]bool
	if len(numbers) > kernelSyscallFilter {
		kernel, allowed = nil, make(map[uint16]bool, len(numbers))
		for _, n := range numbers {
			allowed[n] = true
		}
	}
	return func(ctx context.Context, pod string, _ int, deliver func(gadget.Frame), notice func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		bootWall, err := bootWallClock()
		if err != nil {
			return gadget.CaptureStats{}, gadget.ErrEngineUnavailable
		}
		pairer := syscalls.NewPairer(maxTrackedThreads)
		emit := func(c syscalls.Call) {
			f := gadget.Frame{Wire: syscallEventCredit, At: bootWall.Add(time.Duration(c.Time())), RawTimestamp: c.Time(), Clock: "boottime"}
			// result: errors still charges every observed call (spec), but
			// retains only failures.
			if _, failed := syscalls.Errno(c.Ret); !errorsOnly || (c.Status == syscalls.Returned || c.Status == syscalls.Unmatched) && failed {
				f.Data = syscalls.MarshalRecord(c)
			}
			deliver(f)
		}
		gaps := func() {
			if n := pairer.TakeGaps(); n > 0 && notice != nil {
				notice(gadget.InputNotice{LostSamples: n})
			}
		}
		stats, err := trace(ctx, pod, kernel, func(raw []byte) {
			e, err := syscalls.DecodeEvent(raw)
			if err != nil {
				if notice != nil {
					notice(gadget.InputNotice{LostSamples: 1})
				}
				return
			}
			if allowed != nil && !allowed[e.Number] {
				return
			}
			if c, ok := pairer.Add(e); ok {
				emit(c)
			}
			gaps()
		}, notice)
		for _, c := range pairer.Flush() {
			emit(c)
		}
		gaps()
		return stats, err
	}
}

// bootWallClock is the wall-clock instant of CLOCK_BOOTTIME zero.
func bootWallClock() (time.Time, error) {
	var ts unix.Timespec
	wall := time.Now()
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Time{}, err
	}
	return wall.Round(0).Add(-time.Duration(ts.Nano())), nil
}

// encodeSyscallWindow writes a frozen window of syscall records as JSON Lines
// into exactly maxBytes of output (the snapshot's reserved native storage),
// at most maxEvents lines (the policy's per-snapshot event cap).
// Each line is stamped with its ring time, which the window already bounds;
// lines that no longer fit count as OutputFull. Records keep ring order
// (pairing completion), not sorted by call time.
func encodeSyscallWindow(ctx context.Context, records packets.PacketIterator, maxBytes int, maxEvents int64, podUID, sourceEpoch string, started, ended time.Time) (out []byte, counters packets.Counters, err error) {
	if ctx == nil || ctx.Err() != nil || records == nil || maxBytes < 4096 || maxBytes > 8<<20 || started.IsZero() || ended.Before(started) {
		return nil, counters, packets.ErrInvalid
	}
	buf := make([]byte, 0, maxBytes)
	defer func() {
		if err != nil {
			clear(buf[:cap(buf)])
		}
	}()
	var p packets.RingPacket
	var line []byte
	for {
		if err = ctx.Err(); err != nil {
			return nil, counters, err
		}
		err = records.Next(&p)
		if errors.Is(err, io.EOF) {
			return buf, counters, nil
		}
		if err != nil {
			return nil, counters, err
		}
		c, err := syscalls.UnmarshalRecord(p.Header[:p.Length])
		if err != nil || p.At.Before(started) || p.At.After(ended) {
			return nil, counters, packets.ErrInvalid
		}
		counters.Seen++
		if line, err = syscalls.AppendEvent(line[:0], c, p.At, podUID, sourceEpoch); err != nil {
			return nil, counters, err
		}
		if len(buf)+len(line) > maxBytes || int64(counters.Retained) >= maxEvents {
			counters.OutputFull++
			continue
		}
		buf = append(buf, line...)
		counters.Retained++
		counters.WireBytes += syscallEventCredit
	}
}
