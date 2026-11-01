package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

// startSyscall answers one syscallCapture item (B3): a finite run of the
// source syscall engine on one Pod for the recording's duration, written as
// JSON Lines and uploaded like a packet capture. Without a source permit, a
// local events-per-second limit bounds retention.
func (n *nodePackets) startSyscall(ctx context.Context, epoch string, w collector.Work) collector.Receipt {
	r := collector.Decide(w, n.now())
	if r.Reason == collector.ReasonWorkUnknown || r.Reason == collector.ReasonWorkExpired {
		return r
	}
	p := *w.Packet
	if n.syscallTrace == nil || p.Syscalls == nil {
		r.Reason = collector.ReasonEngineUnavailable
		return r
	}
	numbers, ok := syscalls.Numbers(p.Syscalls.Names)
	if !ok {
		r.Reason = collector.ReasonFilterUnsupported
		return r
	}
	n.budgetMu.Lock()
	err := n.budget().ReserveFrozen(p.MaxBytes)
	n.budgetMu.Unlock()
	if err != nil {
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	engine := syscallEngine(n.syscallTrace, numbers, p.Syscalls.ErrorsOnly, int(p.Syscalls.MaxTrackedThreads))
	started := n.now().UTC()
	r.Outcome, r.Reason = collector.OutcomeAccepted, ""
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() {
			n.budgetMu.Lock()
			_ = n.budget().ReleaseFrozen(p.MaxBytes)
			n.budgetMu.Unlock()
		}()
		n.runSyscall(ctx, epoch, w.ID, p, engine, started)
	}()
	return r
}

func (n *nodePackets) runSyscall(ctx context.Context, epoch, workID string, p collector.PacketCapture, engine observedPacketEngine, started time.Time) {
	capture, cancel := context.WithTimeout(ctx, p.Duration)
	var mu sync.Mutex
	out := make([]byte, 0, p.MaxBytes)
	defer func() { clear(out[:cap(out)]) }()
	var seen, retained, outputFull, malformed, unretained, wire, lost uint64
	var line []byte
	var second time.Time
	var inSecond int64
	stats, err := engine(capture, p.PodUID, 0, func(f gadget.Frame) {
		mu.Lock()
		defer mu.Unlock()
		seen++
		wire += uint64(f.Wire)
		if f.Data == nil { // charged but not retained (errors only)
			unretained++
			return
		}
		if s := f.At.Truncate(time.Second); !s.Equal(second) {
			second, inSecond = s, 0
		}
		c, e := syscalls.UnmarshalRecord(f.Data)
		if e != nil {
			malformed++
			return
		}
		if line, e = syscalls.AppendEvent(line[:0], c, f.At, p.PodUID, epoch); e != nil {
			malformed++
			return
		}
		if inSecond >= p.MaxEventsPerSecond || int64(retained) >= p.Syscalls.MaxEvents || len(out)+len(line) > int(p.MaxBytes) {
			outputFull++
			return
		}
		inSecond++
		out = append(out, line...)
		retained++
	}, func(notice gadget.InputNotice) {
		mu.Lock()
		lost += notice.LostSamples
		mu.Unlock()
	})
	// Like a packet capture, the recording completed when its own deadline
	// ended it; an engine stop reported as that deadline is not a failure.
	completed := errors.Is(capture.Err(), context.DeadlineExceeded)
	if completed && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		err = nil
	}
	cancel()
	ended := n.now().UTC()
	mu.Lock()
	result := collector.PacketResult{WorkID: workID, CaptureID: p.CaptureID, StartedAt: started, EndedAt: ended, Seen: seen, Retained: retained, Filtered: unretained, Malformed: malformed,
		OutputFull: outputFull, LostSamples: stats.LostSamples + lost, WireBytes: wire, CapturedBytes: int64(len(out)), Snaplen: syscalls.RecordSize, EngineVersion: n.version, NativeType: artifact.SyscallRecordsArtifact}
	native := out
	mu.Unlock()
	switch {
	case errors.Is(err, gadget.ErrTargetNotFound):
		result.Failure = collector.ReasonTargetNotFound
	case err != nil || !completed:
		result.Failure = collector.ReasonCaptureFailed
	}
	if err != nil {
		n.log(fmt.Sprintf("node collector: syscall capture %s stopped: %v", p.CaptureID, err))
	}
	deliver, stop := context.WithTimeout(context.WithoutCancel(ctx), packetDeliveryGrace)
	defer stop()
	// ponytail: a quiet interval (no retained call) reports failure, as an
	// empty source window does; add a zero-byte result if quiet Pods matter.
	if result.Failure != "" || retained == 0 || !result.Valid() || !n.takeUpload(deliver, result.CapturedBytes) {
		if result.Failure == "" {
			n.log("node collector: syscall capture " + p.CaptureID + " produced no deliverable result")
			result.Failure = collector.ReasonCaptureFailed
		}
		// The connector checks the native type, then discards this placeholder.
		native = emptyCapture(started, ended)
		result.CapturedBytes, result.Seen, result.Retained, result.Filtered, result.Malformed, result.OutputFull = int64(len(native)), 0, 0, 0, 0, 0
		if native == nil || !result.Valid() || !n.takeUpload(deliver, result.CapturedBytes) {
			n.log("node collector: syscall capture " + p.CaptureID + " failure could not be reported")
			return
		}
	}
	if err := n.upload(deliver, epoch, result, native); err != nil {
		n.log(fmt.Sprintf("node collector: syscall capture %s upload failed: %v", p.CaptureID, err))
		return
	}
	n.log(fmt.Sprintf("node collector: syscall capture %s uploaded: %d of %d calls retained, %d bytes, %d lost samples, failure %q", p.CaptureID, result.Retained, result.Seen, result.CapturedBytes, result.LostSamples, result.Failure))
}
