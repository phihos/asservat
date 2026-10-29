package bootstrap

import (
	"context"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
)

// packetSource owns one admitted ordinary ring/engine incarnation. The private
// constructor is not authority: its caller must verify source-purpose delivery
// and current committed policy/resource credit before calling it. No public or
// node work kind is enabled by this local lifecycle composition.
type packetSource struct {
	mu                             sync.Mutex
	ctx                            context.Context
	cancel                         context.CancelFunc
	ring                           *packets.Ring
	meter                          *collector.SourceMeter
	now                            func() time.Time
	timer                          *time.Timer
	timerAt                        time.Time
	stoppedUntil                   time.Time
	closed, engineExited, released bool
	inputUnknown                   bool
	err                            error
	done                           chan struct{}
	release                        func()
	budget                         *collector.Budget
	budgetMu                       *sync.Mutex
	lowering                       collector.PolicyLimits
}

func newPacketSource(parent context.Context, permit collector.SourcePermit, lowering collector.PolicyLimits, limits packets.RingLimits, program []planning.BPFInstruction, engine observedPacketEngine, now func() time.Time, budget *collector.Budget, budgetMu *sync.Mutex) (*packetSource, error) {
	if parent == nil || parent.Err() != nil || engine == nil || now == nil || budget == nil || budgetMu == nil || !permit.Startable(now()) {
		return nil, collector.ErrInvalid
	}
	var actual [32]byte
	if len(program) > 0 {
		actual = [32]byte(compiler.FilterProgramDigest(program))
	}
	if actual != permit.Binding.ProgramDigest {
		return nil, collector.ErrInvalid
	}
	// One-second burst is the existing wire-token rule. Ring physical bytes
	// include all fixed segment framing and are reserved before allocation.
	r := collector.SourceReservation{RingBytes: int64(limits.MaxSegments) * limits.SegmentBytes, InputBytesPerSecond: permit.BytesPerSecond, InputBurstBytes: permit.BytesPerSecond}
	if limits.MaxSegments < 2 || limits.MaxSegments > 64 || limits.SegmentBytes <= 0 || limits.SegmentBytes > 64<<20 {
		return nil, collector.ErrInvalid
	}
	budgetMu.Lock()
	err := budget.ReserveSourceWithin(r, lowering)
	budgetMu.Unlock()
	if err != nil {
		return nil, err
	}
	release := func() { budgetMu.Lock(); defer budgetMu.Unlock(); _ = budget.ReleaseSource(r) }
	ctx, cancel := context.WithDeadline(parent, permit.HardUntil)
	ring, err := packets.NewRing(ctx, packets.RingBounds{StartedAt: permit.StartedAt, Until: permit.HardUntil}, limits, program)
	if err != nil {
		cancel()
		release()
		return nil, err
	}
	meter, err := collector.NewSourceMeter(permit, now())
	if err != nil {
		cancel()
		_ = ring.Close()
		release()
		return nil, err
	}
	s := &packetSource{ctx: ctx, cancel: cancel, ring: ring, meter: meter, now: now, done: make(chan struct{}), release: release, budget: budget, budgetMu: budgetMu, lowering: lowering}
	s.mu.Lock()
	s.scheduleLocked()
	s.mu.Unlock()
	go s.run(engine, permit.Binding.PodUID)
	return s, nil
}

func (s *packetSource) scheduleLocked() {
	if s.closed {
		return
	}
	next := s.meter.Permit().LeafUntil
	if end, ok := s.ctx.Deadline(); ok && end.Before(next) {
		next = end
	}
	if !s.stoppedUntil.IsZero() && s.stoppedUntil.Before(next) {
		next = s.stoppedUntil
	}
	if expiry := s.ring.NextExpiry(); !expiry.IsZero() && expiry.Before(next) {
		next = expiry
	}
	if s.timer != nil && s.timerAt.Equal(next) {
		return
	}
	s.timerAt = next
	if s.timer != nil {
		s.timer.Reset(max(time.Duration(0), next.Sub(s.now())))
		return
	}
	// A stopped timer may have an already queued callback. Every callback
	// checks the current permit and current next deadline under this lock.
	s.timer = time.AfterFunc(max(time.Duration(0), next.Sub(s.now())), s.onTimer)
}

func (s *packetSource) onTimer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	now := s.now()
	if s.ctx.Err() != nil || !now.Before(s.meter.Permit().LeafUntil) || (!s.stoppedUntil.IsZero() && !now.Before(s.stoppedUntil)) {
		s.stopLocked(collector.ErrObservationLeaseExpired)
		return
	}
	if err := s.ring.Advance(now); err != nil {
		s.stopLocked(err)
		return
	}
	// Force reschedule even if this was an obsolete queued callback. No old
	// callback may erase a newer current leaf or release its reservation.
	s.timerAt = time.Time{}
	s.scheduleLocked()
}

func (s *packetSource) finishLocked() {
	if s.closed && s.engineExited && !s.released {
		s.released = true
		s.release()
		close(s.done)
	}
}
func (s *packetSource) stopLocked(err error) {
	if !s.closed {
		s.closed = true
		if s.err == nil {
			s.err = err
		}
		s.cancel()
		if s.timer != nil {
			s.timer.Stop()
		}
		_ = s.ring.Close()
	}
	s.finishLocked()
}

func (s *packetSource) add(f gadget.Frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return
	}
	now := s.now()
	// Debit original wire length before filter/sanitizer, including frames
	// which the ring discards. There is no per-packet API or SQL call.
	if err := s.meter.Charge(int64(f.Wire), now); err != nil {
		s.stopLocked(err)
		return
	}
	if err := s.ring.Add(f.Data, f.Wire, f.At, now); err != nil {
		s.inputUnknown = true
		s.stopLocked(err)
		return
	}
	s.scheduleLocked()
}
func (s *packetSource) notice(gadget.InputNotice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inputUnknown = true
	s.stopLocked(ErrObservationClosed)
}

func (s *packetSource) run(engine observedPacketEngine, pod string) {
	s.mu.Lock()
	if s.ctx.Err() != nil || !s.meter.Permit().Startable(s.now()) {
		s.stopLocked(collector.ErrObservationLeaseExpired)
	}
	closed := s.closed
	s.mu.Unlock()
	var stats gadget.CaptureStats
	var err error
	if !closed {
		stats, err = engine(s.ctx, pod, packets.Snaplen, s.add, s.notice)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.engineExited = true
	if stats.LostSamples > 0 {
		s.inputUnknown = true
		err = errors.Join(err, ErrObservationClosed)
	}
	if s.closed {
		s.finishLocked()
		return
	}
	if s.ctx.Err() != nil || err != nil {
		s.stopLocked(errors.Join(err, s.ctx.Err()))
		return
	}
	// A genuine natural engine return has an observed stop instant. Retain
	// its existing history for at most the existing default stop grace, also
	// capped by the current leaf/hard end. Cancellation fabricates no stop.
	now := s.now()
	if err = s.ring.Stop(now); err != nil {
		s.stopLocked(err)
		return
	}
	s.stoppedUntil = now.Add(30 * time.Second)
	s.scheduleLocked()
}

func (s *packetSource) Renew(next collector.SourcePermit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.engineExited || s.ctx.Err() != nil {
		return collector.ErrObservationLeaseExpired
	}
	if err := s.meter.Renew(next, s.now()); err != nil {
		return err
	}
	s.scheduleLocked()
	return nil
}

// Close is called by the lifecycle/control owner, never in an engine callback.
// It joins acquisition before returning capacity; unknown input stays charged.
func (s *packetSource) Close() error {
	s.mu.Lock()
	s.stopLocked(context.Canceled)
	s.mu.Unlock()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// BeginWindow is local copying after the caller's separate current save or
// incident admission. It cannot allocate output/custody or authorize disclosure.
// A copied snapshot owns frozen capacity independently of the live source and
// retains its supplied original processing deadline after source shutdown.
func (s *packetSource) BeginWindow(processing context.Context, window packets.RingWindow, t0 time.Time, maxCopyBytes int64) (*packetSourceSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || !s.now().Before(s.meter.Permit().LeafUntil) {
		return nil, packets.ErrRingClosed
	}
	s.budgetMu.Lock()
	err := s.budget.ReserveFrozenWithin(maxCopyBytes, s.lowering)
	s.budgetMu.Unlock()
	if err != nil {
		return nil, err
	}
	release := func() { s.budgetMu.Lock(); defer s.budgetMu.Unlock(); _ = s.budget.ReleaseFrozen(maxCopyBytes) }
	copy, err := s.ring.BeginWindowSnapshot(processing, window, t0, s.now(), maxCopyBytes)
	if err != nil {
		release()
		return nil, err
	}
	return &packetSourceSnapshot{copy: copy, release: release}, nil
}

type packetSourceSnapshot struct {
	copy    *packets.WindowSnapshot
	once    sync.Once
	release func()
}

// Close follows joined processing/upload and erases the copy before releasing
// global frozen RAM. Source expiry alone does not release these bytes.
func (s *packetSourceSnapshot) Close() error {
	var err error
	s.once.Do(func() { err = s.copy.Close(); s.release() })
	return err
}
func (s *packetSourceSnapshot) Complete(now time.Time) error     { return s.copy.Complete(now) }
func (s *packetSourceSnapshot) Next(p *packets.RingPacket) error { return s.copy.Next(p) }
func (s *packetSourceSnapshot) Coverage() packets.RingCoverage   { return s.copy.Coverage() }
