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

func (n *nodePackets) run(ctx context.Context, epoch, workID string, p collector.PacketCapture, rec *packets.Recorder, started time.Time) {
	var mu sync.Mutex
	capture, cancel := context.WithTimeout(ctx, p.Duration)
	stats, err := n.engine(capture, p.PodUID, packets.Snaplen, func(f gadget.Frame) {
		mu.Lock()
		rec.Add(f.Data, f.Wire, f.At)
		mu.Unlock()
	})
	cancel()
	ended := n.now().UTC()
	if ctx.Err() != nil {
		return
	}
	mu.Lock()
	out, counters, closeErr := rec.Close(ended, stats.LostSamples)
	mu.Unlock()
	result := collector.PacketResult{WorkID: workID, CaptureID: p.CaptureID, StartedAt: started, EndedAt: ended, Seen: counters.Seen, Retained: counters.Retained,
		Filtered: counters.Filtered, Unsupported: counters.Unsupported, Fragment: counters.Fragment, Extension: counters.Extension, Malformed: counters.Malformed,
		OutputFull: counters.OutputFull, LostSamples: stats.LostSamples, WireBytes: counters.WireBytes, CapturedBytes: int64(len(out)), Snaplen: packets.Snaplen,
		EngineVersion: n.version, ProgramDigest: p.ProgramDigest}
	switch {
	case errors.Is(err, gadget.ErrTargetNotFound):
		result.Failure = collector.ReasonTargetNotFound
	case errors.Is(err, gadget.ErrTargetHostNetwork):
		result.Failure = collector.ReasonTargetHostNet
	case err != nil || closeErr != nil:
		result.Failure = collector.ReasonCaptureFailed
	}
	if err != nil {
		n.log(fmt.Sprintf("node collector: capture %s stopped: %v", p.CaptureID, err))
	}
	if closeErr != nil || !result.Valid() {
		n.log("node collector: capture " + p.CaptureID + " produced no valid result")
		return
	}
	// The upload token bucket never consumes on a wait: wait, then take.
	for {
		n.budgetMu.Lock()
		wait, err := n.budget().TakeUpload(n.now(), result.CapturedBytes)
		n.budgetMu.Unlock()
		if err != nil {
			n.log("node collector: capture " + p.CaptureID + " exceeds the node upload burst")
			return
		}
		if wait == 0 {
			break
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	if err := n.upload(ctx, epoch, result, out); err != nil {
		n.log(fmt.Sprintf("node collector: capture %s upload failed: %v", p.CaptureID, err))
		return
	}
	n.log(fmt.Sprintf("node collector: capture %s uploaded: %d of %d frames retained, %d bytes, %d lost samples, failure %q", p.CaptureID, result.Retained, result.Seen, result.CapturedBytes, result.LostSamples, result.Failure))
}
