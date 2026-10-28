package bootstrap

import (
	"context"
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
// error (Gadget logs those and continues). No product caller supplies a meter yet:
// raw-predicate acceptance stays refused until the SQL/channel permit path exists.
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
	if err == nil {
		err = meter.Snapshot().Stopped
	}
	return stats, err
}
