package bootstrap

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
)

type argumentTraceEngine func(context.Context, gadget.ArgumentRequest, func([]byte), func(gadget.InputNotice)) (gadget.ArgumentStats, error)

func argumentTraceIfAvailable(mechanisms []collector.Availability) argumentTraceEngine {
	if !mechanismAvailable(mechanisms, collector.MechanismSyscall) {
		return nil
	}
	return traceArgumentCapture
}
func traceArgumentCapture(ctx context.Context, r gadget.ArgumentRequest, deliver func([]byte), notice func(gadget.InputNotice)) (gadget.ArgumentStats, error) {
	rec, err := gadget.NewArgumentRecorder(r)
	if err != nil {
		return gadget.ArgumentStats{}, err
	}
	return rec.Capture(ctx, deliver, notice)
}
func (n *nodePackets) startArguments(ctx context.Context, epoch string, w collector.Work) collector.Receipt {
	r := collector.Decide(w, n.now())
	if r.Reason == collector.ReasonWorkUnknown || r.Reason == collector.ReasonWorkExpired {
		return r
	}
	if w.Packet == nil || !w.Packet.Valid() || w.Packet.Arguments == nil || n.argumentTrace == nil || n.argumentResources == nil || n.identity == nil || ctx == nil || ctx.Err() != nil {
		r.Reason = collector.ReasonEngineUnavailable
		return r
	}
	p := *w.Packet
	a := *p.Arguments
	p.Arguments = &a
	filter := *p.Syscalls
	filter.Names = append([]string(nil), filter.Names...)
	p.Syscalls = &filter
	id, b := n.identity(), a.Binding
	defs, err := syscalls.ArgumentDefinitions(filter.Names, a.CaptureBuffers, int(a.MaxBytesPerEvent))
	pin, _ := hex.DecodeString(gadget.ArgumentObjectSHA256)
	var program [32]byte
	copy(program[:], pin)
	if err != nil || !a.ValidFinite(n.now()) || !a.StartBy.Equal(w.NotAfter) || !authorization.UUID(id.NodeUID) || !authorization.UUID(id.PodUID) || !authorization.UUID(id.BootID) || !authorization.UUID(id.Epoch) || b.NodeUID != id.NodeUID || b.BootID != id.BootID || b.CollectorPodUID != id.PodUID || b.CollectorEpoch != id.Epoch || b.CollectorEpoch != epoch || b.ProgramDigest != program || b.DefinitionDigest != syscalls.ArgumentDefinitionDigest(defs) || a.MaxProbeBytes != int64(syscalls.ArgumentMaxProbeBytes(defs)) {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	working, err := n.argumentResources(int(a.MaxTrackedThreads))
	if err != nil {
		r.Reason = collector.ReasonEngineUnavailable
		return r
	}
	rate := a.EffectiveEventsPerSecond() * a.MaxProbeBytes
	source := collector.SourceReservation{RingBytes: working, InputBytesPerSecond: rate, InputBurstBytes: rate}
	capture, stop := context.WithCancel(ctx)
	var started time.Time
	var holder *manualLiveHolder
	n.budgetMu.Lock()
	now := n.now()
	for key, until := range n.observations {
		if !now.Before(until) {
			delete(n.observations, key)
		}
	}
	_, replay := n.observations[p.CaptureID]
	_, busy := n.running[p.CaptureID]
	if replay || busy || len(n.observations) >= collector.MaxQueuedWork || len(n.running) >= collector.MaxQueuedWork || !a.ValidFinite(now) || ctx.Err() != nil {
		n.budgetMu.Unlock()
		stop()
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	err = n.budget().ReserveSource(source)
	if err == nil {
		err = n.budget().ReserveFrozen(p.MaxBytes)
		if err != nil {
			_ = n.budget().ReleaseSource(source)
		}
	}
	if err == nil {
		if n.observations == nil {
			n.observations = make(map[string]time.Time)
		}
		n.observations[p.CaptureID] = a.StartBy
		if n.running == nil {
			n.running = make(map[string]runningPacket)
		}
		started = n.now().UTC()
		holder = n.newManualLive(w, p, started, id)
		if holder != nil {
			holder.ctx = capture
		}
		n.running[p.CaptureID] = runningPacket{workID: w.ID, cancel: stop, live: holder}
	}
	n.budgetMu.Unlock()
	if err != nil {
		stop()
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	r.Outcome, r.Reason = collector.OutcomeAccepted, ""
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer stop()
		defer func() {
			n.budgetMu.Lock()
			_ = n.budget().ReleaseSource(source)
			_ = n.budget().ReleaseFrozen(p.MaxBytes)
			if current, ok := n.running[p.CaptureID]; ok && current.workID == w.ID {
				delete(n.running, p.CaptureID)
			}
			n.budgetMu.Unlock()
		}()
		n.runArguments(capture, epoch, w.ID, p, started, defs, holder)
	}()
	return r
}
func (n *nodePackets) runArguments(parent context.Context, epoch, workID string, p collector.PacketCapture, started time.Time, defs []syscalls.ArgumentDefinition, holders ...*manualLiveHolder) {
	var holder *manualLiveHolder
	if len(holders) > 0 {
		holder = holders[0]
	}
	a, b := p.Arguments, p.Arguments.Binding
	until := started.Add(p.Duration)
	if a.LeaseUntil.Before(until) {
		until = a.LeaseUntil
	}
	ctx, cancel := context.WithDeadline(parent, until)
	defer cancel()
	header := syscalls.ArgumentHeader{Record: "header", Format: syscalls.ArgumentNativeFormat, PodUID: p.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, SourceEpoch: epoch, SessionID: b.SessionID, Fence: b.Fence, EngineDigest: hex.EncodeToString(b.ProgramDigest[:]), DefinitionDigest: hex.EncodeToString(b.DefinitionDigest[:]), AccountingRule: hex.EncodeToString(b.AccountingRule[:]), Decoder: syscalls.ArgumentDecoderVersion, ABI: syscalls.ABI, StartedAt: started}
	footer := syscalls.ArgumentFooter{Record: "footer", CoverageUnknown: true, Outcome: "failed"}
	out := make([]byte, 0, p.MaxBytes)
	defer func() { clear(out[:cap(out)]) }()
	out, _ = syscalls.AppendArgumentLine(out, header)
	wall, clockErr := bootWallClock()
	decoder, _ := syscalls.NewArgumentDecoder(p.Syscalls.Names, a.CaptureBuffers, int(a.MaxBytesPerEvent), int(a.MaxTrackedThreads))
	pairer, _ := syscalls.NewArgumentPairer(int(a.MaxTrackedThreads))
	var mu sync.Mutex
	var outputFull uint64
	emit := func(call syscalls.ArgumentCall) {
		defer call.Clear()
		if call.Entry == nil || call.Exit == nil {
			footer.PairGaps++
		}
		for _, probe := range []*syscalls.ArgumentProbe{call.Entry, call.Exit} {
			if probe != nil && probe.Memory != nil {
				if probe.Memory.Failed {
					footer.Faults++
				}
				if probe.Memory.Truncated {
					footer.Truncated++
				}
			}
		}
		if p.Syscalls.ErrorsOnly {
			if call.Entry == nil || call.Exit == nil {
				footer.Filtered++
				return
			}
			if _, failed := syscalls.Errno(call.Exit.Event.Ret); !failed {
				footer.Filtered++
				return
			}
		}
		holder.argument(call, n.now())
		event, err := syscalls.ArgumentEvent(call, header, wall, defs)
		if err != nil {
			footer.Malformed++
			return
		}
		line, err := syscalls.AppendArgumentLine(nil, syscalls.ArgumentEventLine{Record: "event", Event: event})
		if err != nil {
			footer.Malformed++
			return
		}
		defer clear(line)
		if footer.Retained >= uint64(p.Syscalls.MaxEvents) || len(out)+len(line)+2048 > cap(out) {
			outputFull++
			cancel()
			return
		}
		out = append(out, line...)
		footer.Retained++
	}
	request := gadget.ArgumentRequest{PodUID: p.PodUID, AccountingRule: b.AccountingRule, Names: append([]string(nil), p.Syscalls.Names...), CaptureBuffers: a.CaptureBuffers, MaxBytesPerEvent: int(a.MaxBytesPerEvent), MaxTrackedThreads: int(a.MaxTrackedThreads), Events: uint64(a.EventCredit), Bytes: uint64(a.ByteCredit), EventsPerSecond: uint64(a.EventsPerSecond), BytesPerSecond: uint64(a.BytesPerSecond), Deadline: until, StartBy: a.StartBy}
	var stats gadget.ArgumentStats
	err := clockErr
	if err == nil {
		stats, err = n.argumentTrace(ctx, request, func(raw []byte) {
			mu.Lock()
			defer mu.Unlock()
			probe, e := decoder.Add(raw)
			if e != nil {
				footer.Malformed++
				return
			}
			if probe != nil {
				observed := wall.Add(time.Duration(probe.Event.Boot))
				if observed.Before(started) || observed.After(until) {
					// Buffered delivery may finish after the kernel deadline;
					// an out-of-window probe cannot extend the observation or
					// complete a valid entry. Flush retains its missing-pair gap.
					syscalls.ArgumentCall{Entry: probe}.Clear()
					footer.Malformed++
					return
				}
				for _, call := range pairer.Add(*probe) {
					emit(call)
				}
			}
		}, func(notice gadget.InputNotice) {
			mu.Lock()
			defer mu.Unlock()
			footer.LostSamples += notice.LostSamples
			holder.notice(notice.LostSamples)
			footer.PairGaps += decoder.Flush()
			pairer.Flush(emit)
		})
	}
	holder.Close()
	mu.Lock()
	footer.PairGaps += decoder.Flush()
	pairer.Flush(emit)
	joinedAt := n.now().UTC()
	// EndedAt is the observation endpoint, bounded by the exact deadline
	// enforced before kernel user-memory reads. Detach/perf flush may join
	// later; delivery and resource release still wait for that actual join.
	footer.EndedAt = joinedAt
	if until.Before(footer.EndedAt) {
		footer.EndedAt = until
	}
	footer.LostSamples = max(footer.LostSamples, stats.LostSamples)
	footer.OutputFull = outputFull
	if stats.AccountingKnown {
		events, credit := stats.ConsumedEvents, stats.ConsumedBytes
		footer.ObservedEvents = &events
		footer.ObservedBytes = &credit
	}
	// A setup timeout can occur before attachment. Only the final budget
	// read after detach establishes an observed window, including an empty one.
	completed := stats.AccountingKnown && !joinedAt.Before(until) && parent.Err() == nil && (err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled))
	switch {
	case outputFull > 0:
		footer.Outcome = "outputLimit"
	case parent.Err() != nil:
		footer.Outcome = "cancelled"
	case stats.Stopped:
		footer.Outcome = "observationStopped"
	case completed:
		footer.Outcome = "completed"
	}
	if footer.Outcome == "failed" && n.log != nil {
		n.log("node collector: argument acquisition failed at " + gadget.ArgumentFailureStage(err))
	}
	out, encodeErr := syscalls.AppendArgumentLine(out, footer)
	result := collector.PacketResult{WorkID: workID, CaptureID: p.CaptureID, StartedAt: started, EndedAt: footer.EndedAt, Retained: footer.Retained, Filtered: footer.Filtered, Malformed: footer.Malformed, OutputFull: outputFull, LostSamples: footer.LostSamples, CapturedBytes: int64(len(out)), Snaplen: 0, EngineVersion: syscalls.ArgumentDecoderVersion, NativeType: artifact.SyscallArgumentsArtifact}
	result.Seen = result.Retained + result.Filtered + result.Malformed + result.OutputFull
	if footer.Outcome == "failed" || footer.Outcome == "cancelled" || encodeErr != nil {
		result.Failure = collector.ReasonCaptureFailed
	}
	if errors.Is(err, gadget.ErrTargetNotFound) {
		result.Failure = collector.ReasonTargetNotFound
	}
	mu.Unlock()
	deliver, stop := context.WithTimeout(context.WithoutCancel(parent), packetDeliveryGrace)
	defer stop()
	if encodeErr != nil || !result.Valid() || !n.takeUpload(deliver, result.CapturedBytes) {
		return
	}
	if err := n.upload(deliver, epoch, result, out); err != nil && n.log != nil {
		n.log("node collector: argument result delivery failed")
	}
}
