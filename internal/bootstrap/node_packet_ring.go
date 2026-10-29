package bootstrap

import (
	"context"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
)

// packetRingInput serializes callback time samples and preserves unknown input
// even when the ring has already expired and cannot accept another Gap.
type packetRingInput struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	ring    *packets.Ring
	now     func() time.Time
	err     error
	unknown bool
}

func (p *packetRingInput) add(f gadget.Frame) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		return
	}
	if err := p.ring.Add(f.Data, f.Wire, f.At, p.now()); err != nil {
		if p.err == nil {
			p.err = err
		}
		p.unknown = p.unknown || !errors.Is(err, packets.ErrRingClosed)
		p.cancel()
	}
}

func (p *packetRingInput) notice(gadget.InputNotice) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unknown = true
	if err := p.ring.Gap(p.now()); err != nil && p.err == nil {
		p.err = err
	}
	// InputNotice requires cancellation; joining here would deadlock the engine.
	p.cancel()
}

// runPacketRingEngine is an unused finite integration boundary, not source
// admission. Its caller owns the ring under the same original source context,
// its reservations and independent snapshot processing. It asserts no health
// or quiet coverage and never calls ObservedThrough. Shutdown joins before
// returning; stopped valid history remains caller-owned until explicit Close.
func runPacketRingEngine(ctx context.Context, engine observedPacketEngine, podUID string, ring *packets.Ring, now func() time.Time) (gadget.CaptureStats, error) {
	var stats gadget.CaptureStats
	if ctx == nil || ctx.Err() != nil || engine == nil || podUID == "" || ring == nil || now == nil {
		return stats, packets.ErrInvalid
	}
	until, ok := ctx.Deadline()
	if !ok || !now().Before(until) {
		return stats, packets.ErrInvalid
	}
	if err := ring.Advance(now()); err != nil {
		return stats, err
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	input := packetRingInput{ctx: call, cancel: cancel, ring: ring, now: now}
	stats, engineErr := engine(call, podUID, packets.Snaplen, input.add, input.notice)
	if stats.LostSamples > 0 {
		input.notice(gadget.InputNotice{LostSamples: stats.LostSamples})
	}
	input.mu.Lock()
	defer input.mu.Unlock()
	if ctx.Err() != nil {
		_ = ring.Close()
	} else if err := ring.Stop(now()); err != nil && input.err == nil {
		input.err = err
	}
	var unknown error
	if input.unknown {
		unknown = ErrObservationClosed
	}
	return stats, errors.Join(engineErr, ctx.Err(), input.err, unknown)
}
