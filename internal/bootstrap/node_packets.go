package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/adapters/packets"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
)

// ADR-248: the node side of a manual networkHeaders capture. The pinned
// Inspektor Gadget tcpdump gadget delivers each frame of the target Pod
// (at most packets.Snaplen bytes); the hub-compiled filter selects frames,
// each retained frame is cut at the end of its transport header, and the
// PCAPNG (at most the capture's output cap, reserved from the node's frozen
// budget) is uploaded once to the connector. The node holds no evidence key:
// encryption happens at the connector.

type packetEngine func(ctx context.Context, podUID string, snaplen int, deliver func(gadget.Frame)) (gadget.CaptureStats, error)
type observedPacketEngine func(context.Context, string, int, func(gadget.Frame), func(gadget.InputNotice)) (gadget.CaptureStats, error)

type packetUploader func(ctx context.Context, epoch string, r collector.PacketResult, pcapng []byte) error

// nodePackets runs the node's packet captures.
type nodePackets struct {
	engine         packetEngine
	observedEngine observedPacketEngine
	// syscallTrace runs finite syscall recordings (B3); nil when the
	// syscall mechanism is not available.
	syscallTrace      syscallTraceEngine
	argumentTrace     argumentTraceEngine
	argumentResources func(int) (int64, error)
	identity          func() collector.Identity
	upload            packetUploader
	available         bool // the packet mechanism assessed Available
	version           string
	now               func() time.Time
	log               func(string)
	budget            func() *collector.Budget
	budgetMu          *sync.Mutex
	// Protected by budgetMu; same-epoch poll resets cannot refill one permit.
	// At most MaxQueuedWork capture IDs, each retained only until StartBy.
	observations map[string]time.Time
	// running holds the packetCapture items started by start that have not
	// yet returned from runObserved, by capture ID (ADR-283), so a
	// cancelPacketCapture item can stop exactly one of them early. Protected
	// by budgetMu; at most MaxQueuedWork entries.
	running map[string]runningPacket

	wg sync.WaitGroup
}

// runningPacket is one registered running packet capture: the ID of the
// work item that started it and the cancellation of its capture context.
type runningPacket struct {
	live   *manualLiveHolder
	workID string
	cancel context.CancelFunc
}

// start answers one packetCapture item. An accepted item runs in its own
// goroutine until its duration ends (or ctx ends) and then uploads.
func (n *nodePackets) start(ctx context.Context, epoch string, w collector.Work) collector.Receipt {
	r := collector.Decide(w, n.now())
	if r.Reason == collector.ReasonWorkUnknown || r.Reason == collector.ReasonWorkExpired {
		return r
	}
	p := *w.Packet
	if !n.available || n.engine == nil {
		r.Reason = collector.ReasonEngineUnavailable
		return r
	}
	// ADR-282: an HTTP header projection reads payload, so it runs only as
	// a metered finite observation at the fixed engine snaplen; it never
	// falls back to a raw or header recording.
	if p.HTTP != nil && (p.Observation == nil || p.Raw == nil || p.Raw.Snaplen != httpheaders.Snaplen) {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	var actual [32]byte
	if len(p.Program) > 0 {
		actual = [32]byte(compiler.FilterProgramDigest(p.Program))
		if actual != p.ProgramDigest {
			r.Reason = collector.ReasonFilterUnsupported
			return r
		}
	}
	var meter *LocalObservationGate
	if o := p.Observation; o != nil {
		permit := *o
		p.Observation = &permit
		if n.observedEngine == nil || n.identity == nil {
			r.Reason = collector.ReasonEngineUnavailable
			return r
		}
		id, b := n.identity(), permit.Binding
		if !permit.ValidFinite(n.now()) || !permit.StartBy.Equal(w.NotAfter) || permit.Duration != p.Duration ||
			!authorization.UUID(id.NodeUID) || !authorization.UUID(id.PodUID) || !authorization.UUID(id.BootID) || !authorization.UUID(id.Epoch) ||
			b.CaptureID != p.CaptureID || b.PodUID != p.PodUID || b.ProgramDigest != actual ||
			b.NodeUID != id.NodeUID || b.BootID != id.BootID || b.CollectorPodUID != id.PodUID || b.CollectorEpoch != id.Epoch || b.CollectorEpoch != epoch {
			r.Reason = collector.ReasonWorkUnknown
			return r
		}
		if packets.CheckPrefixProgram(p.Program) != nil {
			r.Reason = collector.ReasonFilterUnsupported
			return r
		}
		// Scope/expectation remain authenticated producer provenance. Only the
		// program, finite fit and current local source facts are independent here;
		// C09 verifies the full expectation against its original signed work.
		if ctx == nil || ctx.Err() != nil {
			r.Reason = collector.ReasonWorkUnknown
			return r
		}
	}
	started := n.now().UTC()
	liveID := collector.Identity{}
	if n.identity != nil {
		liveID = n.identity()
	}
	holder := n.newManualLive(w, p, started, liveID)
	var rec frameRecorder
	var err error
	if h := p.HTTP; h != nil {
		if holder != nil {
			rec, err = newHTTPRecorder(p.Program, p.MaxBytes, started, *h, func(r httpheaders.ObservedRecord) { holder.http(r, n.now()) })
		} else {
			rec, err = newHTTPRecorder(p.Program, p.MaxBytes, started, *h)
		}
	} else if raw := p.Raw; raw != nil {
		rec, err = packets.NewRawRecorder(p.Program, int(p.MaxBytes), started, "asservat rawPackets capture of one pod; frames cut at the approved prefix caps", packets.RawLimits{Snaplen: raw.Snaplen, TCP: raw.TCP, UDP: raw.UDP, ICMP: raw.ICMP})
	} else {
		rec, err = packets.NewRecorder(p.Program, int(p.MaxBytes), started, "asservat networkHeaders capture of one pod; frames cut at the transport header")
	}
	if err != nil {
		if meter != nil {
			meter.Close()
		}
		r.Reason = collector.ReasonFilterUnsupported
		if errors.Is(err, httpheaders.ErrInvalid) {
			r.Reason = collector.ReasonWorkUnknown // limits below the parser's floors
		}
		return r
	}
	if observed, ok := rec.(*httpRecorder); ok && holder != nil {
		observed.observedActive = func() bool { return holder.observing(n.now()) }
		observed.observedLoss = holder.httpLoss
	}

	capture, stopCapture := context.WithCancel(ctx)
	if holder != nil {
		holder.ctx = capture
	}
	n.budgetMu.Lock()
	if _, busy := n.running[p.CaptureID]; busy || len(n.running) >= collector.MaxQueuedWork {
		n.budgetMu.Unlock()
		stopCapture()
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	if p.Observation != nil {
		now := n.now()
		for capture, until := range n.observations {
			if !now.Before(until) {
				delete(n.observations, capture)
			}
		}
		_, replay := n.observations[p.CaptureID]
		if replay || len(n.observations) >= collector.MaxQueuedWork {
			n.budgetMu.Unlock()
			stopCapture()
			r.Reason = collector.ReasonCaptureBusy
			return r
		}
	}
	failureReason := collector.ReasonCaptureBusy
	err = n.budget().ReserveFrozen(p.MaxBytes)
	if err == nil && p.Observation != nil {
		if n.observations == nil {
			n.observations = make(map[string]time.Time)
		}
		n.observations[p.CaptureID] = p.Observation.StartBy
		meter, err = NewLocalObservationGate(ctx, p.Observation.Binding, *p.Observation, n.now)
		if err != nil {
			_ = n.budget().ReleaseFrozen(p.MaxBytes)
			failureReason = collector.ReasonWorkUnknown
		}
	}
	if err == nil {
		// Registered before the goroutine runs, so a cancel decided after
		// this receipt always finds the running capture.
		if n.running == nil {
			n.running = make(map[string]runningPacket)
		}
		n.running[p.CaptureID] = runningPacket{workID: w.ID, cancel: stopCapture, live: holder}
	}
	n.budgetMu.Unlock()
	if err != nil {
		stopCapture()
		if meter != nil {
			meter.Close()
		}
		r.Reason = failureReason
		return r
	}
	r.Outcome, r.Reason = collector.OutcomeAccepted, ""
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() {
			n.budgetMu.Lock()
			_ = n.budget().ReleaseFrozen(p.MaxBytes)
			n.budgetMu.Unlock()
		}()
		// A cancel ends capture like a node stop: runObserved reports the
		// early stop as a failure, never as a shorter recording.
		n.runObserved(capture, epoch, w.ID, p, rec, started, meter, holder)
		n.budgetMu.Lock()
		if running, ok := n.running[p.CaptureID]; ok && running.workID == w.ID {
			delete(n.running, p.CaptureID)
		}
		n.budgetMu.Unlock()
		stopCapture()
	}()
	return r
}

// packetDeliveryGrace bounds the delivery of a finished capture after the
// node stops: the result still reaches the connector (or the attempt ends)
// within this time; the connector accepts it until startBy + duration + 30 s.
const packetDeliveryGrace = 10 * time.Second

func (n *nodePackets) run(ctx context.Context, epoch, workID string, p collector.PacketCapture, rec frameRecorder, started time.Time) {
	n.runObserved(ctx, epoch, workID, p, rec, started, nil)
}

func (n *nodePackets) runObserved(ctx context.Context, epoch, workID string, p collector.PacketCapture, rec frameRecorder, started time.Time, meter *LocalObservationGate, holders ...*manualLiveHolder) {
	capture, cancel := context.WithTimeout(ctx, p.Duration)
	var stats gadget.CaptureStats
	var err error
	var holder *manualLiveHolder
	if len(holders) > 0 {
		holder = holders[0]
	}
	engine := n.engine
	observed := n.observedEngine
	if holder != nil {
		engine = func(call context.Context, pod string, snaplen int, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
			return n.engine(call, pod, snaplen, func(f gadget.Frame) {
				deliver(f)
				if holder.projection != "httpHeaders" && (meter == nil || meter.Context().Err() == nil) {
					holder.append(f, n.now())
				}
			})
		}
		observed = func(call context.Context, pod string, snaplen int, deliver func(gadget.Frame), notice func(gadget.InputNotice)) (gadget.CaptureStats, error) {
			return n.observedEngine(call, pod, snaplen, func(f gadget.Frame) {
				deliver(f)
				if holder.projection != "httpHeaders" && meter.Context().Err() == nil {
					holder.append(f, n.now())
				}
			}, func(input gadget.InputNotice) { notice(input); holder.notice(input.LostSamples) })
		}
	}
	if meter == nil {
		stats, err = runPacketEngine(capture, engine, p.PodUID, rec, nil)
	} else {
		// A queued goroutine cannot inherit a fresh start window. Recheck
		// original finite fit and current enrollment immediately before engine.
		b, id := p.Observation.Binding, n.identity()
		if ctx.Err() != nil || meter.Context().Err() != nil || !p.Observation.ValidFinite(n.now()) || b.NodeUID != id.NodeUID || b.BootID != id.BootID || b.CollectorPodUID != id.PodUID || b.CollectorEpoch != id.Epoch {
			meter.Stop(ErrObservationExpired)
			meter.Close()
			err = ErrObservationExpired
		} else {
			stats, err = runObservedPacketEngine(capture, observed, p.PodUID, rec, meter)
		}
	}
	holder.Close()
	// The capture completed when its own deadline ended it; a later node
	// stop does not discard that result. A capture the node stopped early is
	// reported as failed, never as a shorter recording.
	completed := errors.Is(capture.Err(), context.DeadlineExceeded)
	if meter != nil {
		completed = completed && ctx.Err() == nil
		if completed && errors.Is(err, context.DeadlineExceeded) {
			err = nil
		}
	}
	cancel()
	ended := n.now().UTC()
	out, counters, closeErr := rec.Close(ended, stats.LostSamples)
	result := collector.PacketResult{WorkID: workID, CaptureID: p.CaptureID, StartedAt: started, EndedAt: ended, Seen: counters.Seen, Retained: counters.Retained,
		Filtered: counters.Filtered, Unsupported: counters.Unsupported, Fragment: counters.Fragment, Extension: counters.Extension, Malformed: counters.Malformed,
		OutputFull: counters.OutputFull, LostSamples: stats.LostSamples, WireBytes: counters.WireBytes, CapturedBytes: int64(len(out)), Snaplen: rec.Snaplen(),
		EngineVersion: n.version, ProgramDigest: p.ProgramDigest}
	switch {
	case p.HTTP != nil:
		result.NativeType = artifact.HTTPHeadersArtifact
	case p.Raw != nil:
		result.NativeType = artifact.RawPCAPNGArtifact
	}
	switch {
	case errors.Is(err, gadget.ErrTargetNotFound):
		result.Failure = collector.ReasonTargetNotFound
	case errors.Is(err, gadget.ErrTargetHostNetwork):
		result.Failure = collector.ReasonTargetHostNet
	case err != nil || closeErr != nil || !completed:
		result.Failure = collector.ReasonCaptureFailed
	}
	if err != nil {
		n.log(fmt.Sprintf("node collector: capture %s stopped: %v", p.CaptureID, err))
	}
	// Delivery has its own bounded context, so a node stop cannot silently
	// drop a finished capture or its failure.
	deliver, stop := context.WithTimeout(context.WithoutCancel(ctx), packetDeliveryGrace)
	defer stop()
	if result.Failure != "" || !result.Valid() || !n.takeUpload(deliver, result.CapturedBytes) {
		// A failed, invalid or oversized result is reported as a failure with
		// an empty PCAPNG, so the connector records a terminal state.
		if result.Failure == "" {
			n.log("node collector: capture " + p.CaptureID + " produced no deliverable result")
			result.Failure = collector.ReasonCaptureFailed
		}
		out = emptyCapture(started, ended)
		result.CapturedBytes = int64(len(out))
		if out == nil || !result.Valid() || !n.takeUpload(deliver, result.CapturedBytes) {
			n.log("node collector: capture " + p.CaptureID + " failure could not be reported")
			return
		}
	}
	if err := n.upload(deliver, epoch, result, out); err != nil {
		n.log(fmt.Sprintf("node collector: capture %s upload failed: %v", p.CaptureID, err))
		return
	}
	n.log(fmt.Sprintf("node collector: capture %s uploaded: %d of %d frames retained, %d bytes, %d lost samples, failure %q", p.CaptureID, result.Retained, result.Seen, result.CapturedBytes, result.LostSamples, result.Failure))
}

// takeUpload waits for the node's upload token bucket (it never consumes on
// a wait) within ctx; false when the bytes exceed the burst or ctx ends.
func (n *nodePackets) takeUpload(ctx context.Context, bytes int64) bool {
	for {
		n.budgetMu.Lock()
		wait, err := n.budget().TakeUpload(n.now(), bytes)
		n.budgetMu.Unlock()
		if err != nil {
			return false
		}
		if wait == 0 {
			return true
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
}

// emptyCapture is the PCAPNG of a failure report: section and interface
// headers only.
func emptyCapture(started, ended time.Time) []byte {
	r, err := packets.NewRecorder(nil, 64<<10, started, "")
	if err != nil {
		return nil
	}
	out, _, err := r.Close(ended, 0)
	if err != nil {
		return nil
	}
	return out
}
