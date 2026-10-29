package bootstrap

import (
	"context"
	"errors"
	"sync"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
)

// packetInput is the actual node callback boundary, not a second predicate.
// Its mutex also protects Recorder, whose BPF VM/counters are owner serialized.
type packetInput struct {
	ctx      context.Context
	mu       sync.Mutex
	recorder *packets.Recorder
	meter    *LocalObservationGate
}

// Notices run on the engine's existing callback owner. Only mark/cancel here;
// runPacketEngine owns the synchronous join before budget release.
func runObservedPacketEngine(ctx context.Context, engine observedPacketEngine, pod string, rec *packets.Recorder, meter *LocalObservationGate) (gadget.CaptureStats, error) {
	return runPacketEngine(ctx, func(call context.Context, pod string, snaplen int, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
		return engine(call, pod, snaplen, deliver, func(n gadget.InputNotice) {
			if n.LostSamples > 0 {
				meter.LostSamples(n.LostSamples)
			} else {
				meter.UnknownInput()
			}
		})
	}, pod, rec, meter)
}

func (p *packetInput) add(f gadget.Frame) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		if p.meter != nil {
			p.meter.Stop(p.ctx.Err())
		}
		return
	}
	if p.meter != nil && p.meter.Consume(f.Wire, len(f.Data)) != nil {
		return
	}
	p.recorder.Add(f.Data, f.Wire, f.At)
}

// runPacketEngine joins the existing synchronous engine before returning. A
// debit refusal cancels its context, rather than relying on a datasource callback
// error (Gadget logs those and continues). Raw runtime producers remain refused
// until the complete SQL/channel/recording path is qualified.
func runPacketEngine(ctx context.Context, engine packetEngine, pod string, rec *packets.Recorder, meter *LocalObservationGate) (gadget.CaptureStats, error) {
	input := packetInput{ctx: ctx, recorder: rec, meter: meter}
	if meter == nil {
		return engine(ctx, pod, packets.Snaplen, input.add)
	}
	capture, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(meter.Context(), cancel)
	defer stop()
	defer cancel()
	defer meter.Close()
	if meter.Context().Err() != nil {
		cancel()
	}
	stats, err := engine(capture, pod, packets.Snaplen, input.add)
	meter.LostSamples(stats.LostSamples)
	if ctx.Err() != nil {
		meter.Stop(ctx.Err())
	}
	if meter.Context().Err() != nil {
		meter.Stop(meter.Context().Err())
	}
	outcome := meter.Snapshot()
	// Unknown input is never natural completion, even when the deadline was
	// recorded first. A provider's cancellation/deadline cannot mask a prior
	// debit refusal; a real provider failure remains useful when only the normal
	// action deadline stopped the meter.
	if outcome.UnknownInput {
		err = ErrObservationClosed
	} else if err == nil || errors.Is(err, context.DeadlineExceeded) ||
		(errors.Is(err, context.Canceled) && !errors.Is(outcome.Stopped, context.DeadlineExceeded)) {
		if outcome.Stopped != nil {
			err = outcome.Stopped
		}
	}
	return stats, err
}
