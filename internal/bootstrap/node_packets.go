package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	compiler "asservat.local/asservat/internal/application/planning"
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

type packetUploader func(ctx context.Context, epoch string, r collector.PacketResult, pcapng []byte) error

// nodePackets runs the node's packet captures.
type nodePackets struct {
	engine    packetEngine
	upload    packetUploader
	available bool // the packet mechanism assessed Available
	version   string
	now       func() time.Time
	log       func(string)
	budget    func() *collector.Budget
	budgetMu  *sync.Mutex

	wg sync.WaitGroup
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
	if len(p.Program) > 0 && [32]byte(compiler.FilterProgramDigest(p.Program)) != p.ProgramDigest {
		r.Reason = collector.ReasonFilterUnsupported
		return r
	}
	started := n.now().UTC()
	rec, err := packets.NewRecorder(p.Program, int(p.MaxBytes), started, "asservat networkHeaders capture of one pod; frames cut at the transport header")
	if err != nil {
		r.Reason = collector.ReasonFilterUnsupported
		return r
	}
	n.budgetMu.Lock()
	err = n.budget().ReserveFrozen(p.MaxBytes)
	n.budgetMu.Unlock()
	if err != nil {
		r.Reason = collector.ReasonCaptureBusy
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
		n.run(ctx, epoch, w.ID, p, rec, started)
	}()
	return r
}

// packetDeliveryGrace bounds the delivery of a finished capture after the
// node stops: the result still reaches the connector (or the attempt ends)
// within this time; the connector accepts it until startBy + duration + 30 s.
const packetDeliveryGrace = 10 * time.Second

func (n *nodePackets) run(ctx context.Context, epoch, workID string, p collector.PacketCapture, rec *packets.Recorder, started time.Time) {
	capture, cancel := context.WithTimeout(ctx, p.Duration)
	stats, err := runPacketEngine(capture, n.engine, p.PodUID, rec, nil)
	// The capture completed when its own deadline ended it; a later node
	// stop does not discard that result. A capture the node stopped early is
	// reported as failed, never as a shorter recording.
	completed := errors.Is(capture.Err(), context.DeadlineExceeded)
	cancel()
	ended := n.now().UTC()
	out, counters, closeErr := rec.Close(ended, stats.LostSamples)
	result := collector.PacketResult{WorkID: workID, CaptureID: p.CaptureID, StartedAt: started, EndedAt: ended, Seen: counters.Seen, Retained: counters.Retained,
		Filtered: counters.Filtered, Unsupported: counters.Unsupported, Fragment: counters.Fragment, Extension: counters.Extension, Malformed: counters.Malformed,
		OutputFull: counters.OutputFull, LostSamples: stats.LostSamples, WireBytes: counters.WireBytes, CapturedBytes: int64(len(out)), Snaplen: packets.Snaplen,
		EngineVersion: n.version, ProgramDigest: p.ProgramDigest}
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
