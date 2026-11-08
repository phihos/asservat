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
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	liveapp "asservat.local/asservat/internal/application/live"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
)

// packetSource owns one admitted ordinary ring/engine incarnation. The private
// constructor is not authority: its caller must verify source-purpose delivery
// and current committed policy/resource credit before calling it. No public or
// node work kind is enabled by this local lifecycle composition.
const packetSourceStopGrace = 30 * time.Second

type packetSource struct {
	httpConfig                         *collector.HTTPProjection
	httpProjector                      *httpheaders.Projector
	httpObserved                       func(httpheaders.ObservedRecord)
	httpGaps                           func(httpheaders.Counters)
	httpAccounting, httpLastAccounting httpheaders.SourceAccounting
	httpEntryAt                        time.Time
	httpFailure                        error
	httpClosed                         bool
	httpLost                           uint64
	mu                                 sync.Mutex
	live                               *nodeLiveCohort
	liveProgram                        []planning.BPFInstruction
	liveCounters                       *liveapp.BufferCounters
	ctx                                context.Context
	cancel                             context.CancelFunc
	ring                               *packets.Ring
	meter                              *collector.SourceMeter
	now                                func() time.Time
	timer                              *time.Timer
	timerAt                            time.Time
	stoppedUntil                       time.Time
	closed, engineExited, released     bool
	inputUnknown                       bool
	// records marks a syscall source: frames are fixed records, and drops
	// (rate, stale time, lost samples) are ring gaps that the saved window's
	// coverage reports, not a source stop or source-level InputUnknown, which
	// the hub would end and replace (ADR-273).
	records   bool
	maxEvents int64
	err       error
	done      chan struct{}
	release   func()
	budget    *collector.Budget
	budgetMu  *sync.Mutex
	lowering  collector.PolicyLimits
	// log reports why the source stopped (nil in tests).
	log func(string)
}

func newPacketSource(parent context.Context, permit collector.SourcePermit, lowering collector.PolicyLimits, limits packets.RingLimits, program []planning.BPFInstruction, syscallFilter *collector.SyscallFilter, engine observedPacketEngine, now func() time.Time, budget *collector.Budget, budgetMu *sync.Mutex, log func(string), ringDir string, httpConfigs ...*collector.HTTPProjection) (*packetSource, error) {
	if parent == nil || parent.Err() != nil || engine == nil || now == nil || budget == nil || budgetMu == nil || !permit.Startable(now()) {
		return nil, collector.ErrInvalid
	}
	if len(httpConfigs) > 1 {
		return nil, collector.ErrInvalid
	}
	var h *collector.HTTPProjection
	if len(httpConfigs) == 1 && httpConfigs[0] != nil {
		copy := *httpConfigs[0]
		h = &copy
		if syscallFilter != nil || len(program) == 0 || permit.Binding.ObservationGrantID == "" {
			return nil, collector.ErrInvalid
		}
	}
	if h == nil && permit.Binding.ObservationGrantID != "" {
		return nil, collector.ErrInvalid
	}
	var actual [32]byte
	if len(program) > 0 {
		actual = [32]byte(compiler.FilterProgramDigest(program))
	}
	if syscallFilter != nil {
		if len(program) > 0 || !syscallFilter.Valid() {
			return nil, collector.ErrInvalid
		}
		actual = deliveryapp.SyscallFilterDigest(*syscallFilter)
	}
	if actual != permit.Binding.ProgramDigest {
		return nil, collector.ErrInvalid
	}
	// One-second burst is the existing wire-token rule. Ring physical bytes
	// include all fixed segment framing and are reserved before allocation.
	// On the encrypted-disk medium only one segment and the headers are
	// resident (ADR-278); disk bytes are bounded by the ring volume.
	r := collector.SourceReservation{RingBytes: packets.MemoryRingBytes(limits, ringDir != ""), InputBytesPerSecond: permit.BytesPerSecond, InputBurstBytes: permit.BytesPerSecond}
	if limits.MaxSegments < 2 || limits.MaxSegments > 64 || limits.SegmentBytes <= 0 || limits.SegmentBytes > 64<<20 {
		return nil, collector.ErrInvalid
	}
	if h != nil {
		r.RingBytes += int64(h.MaxTotalBytes)
	}
	budgetMu.Lock()
	err := budget.ReserveSourceWithin(r, lowering)
	budgetMu.Unlock()
	if err != nil {
		return nil, err
	}
	release := func() { budgetMu.Lock(); defer budgetMu.Unlock(); _ = budget.ReleaseSource(r) }
	ctx, cancel := context.WithDeadline(parent, permit.HardUntil)
	ring, err := packets.NewRingOn(ctx, packets.RingBounds{StartedAt: permit.StartedAt, Until: permit.HardUntil}, limits, program, ringDir)
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
	s := &packetSource{ctx: ctx, cancel: cancel, ring: ring, meter: meter, now: now, done: make(chan struct{}), release: release, budget: budget, budgetMu: budgetMu, lowering: lowering, records: syscallFilter != nil, log: log, liveProgram: append([]planning.BPFInstruction(nil), program...)}
	if h != nil {
		s.httpConfig = h
		s.httpProjector, err = httpheaders.NewSourceProjector(httpheaders.Limits{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleTimeout: h.IdleTimeout}, permit.StartedAt, s.observeHTTPRecordLocked)
		if err != nil {
			cancel()
			_ = ring.Close()
			release()
			return nil, err
		}
	}
	if syscallFilter != nil {
		s.maxEvents = syscallFilter.MaxEvents
	}
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
		if s.log != nil && err != nil && !errors.Is(err, context.Canceled) {
			s.log(fmt.Sprintf("node collector: source %s stopped: %v", s.meter.Permit().Binding.SourceID, err))
		}
		s.cancel()
		if s.live != nil {
			s.live.Close()
		}
		clear(s.liveProgram)
		s.liveProgram = nil
		if s.timer != nil {
			s.timer.Stop()
		}
		closedAt := s.now()
		p := s.meter.Permit()
		if p.LeafUntil.Before(closedAt) {
			closedAt = p.LeafUntil
		}
		if p.HardUntil.Before(closedAt) {
			closedAt = p.HardUntil
		}
		if s.httpConfig != nil {
			s.closeHTTPLocked(closedAt)
		}
		_ = s.ring.CloseAt(closedAt)
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
	if s.records {
		s.addRecordLocked(f, now)
		return
	}
	if err := s.meter.Charge(int64(f.Wire), now); err != nil {
		s.stopLocked(err)
		return
	}
	if f.TimestampUnknown {
		s.inputUnknown = true
		_ = s.ring.Gap(now)
		s.stopLocked(ErrObservationClosed)
		return
	}
	if s.httpConfig != nil {
		s.addHTTPFrameLocked(f, now)
		s.scheduleLocked()
		return
	}
	if s.live != nil {
		s.live.append(f, now)
	}
	if err := s.ring.Add(f.Data, f.Wire, f.At, now); err != nil {
		s.inputUnknown = true
		s.stopLocked(err)
		return
	}
	s.scheduleLocked()
}
func (s *packetSource) notice(notice gadget.InputNotice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpConfig != nil {
		s.httpLost += notice.LostSamples
	}
	_ = s.ring.Gap(s.now())
	if s.live != nil {
		s.live.sensorLoss(max(uint64(1), notice.LostSamples))
	}
	if !s.records {
		s.inputUnknown = true
		s.stopLocked(ErrObservationClosed)
	}
}

// addRecordLocked retains one syscall record. Over-rate events and records
// outside the ring's time bounds are dropped as a visible ring gap; spent
// credit, an expired leaf or a closed ring still stop the source.
func (s *packetSource) addRecordLocked(f gadget.Frame, now time.Time) {
	err := s.meter.Charge(int64(f.Wire), now)
	if errors.Is(err, collector.ErrObservationRateExceeded) {
		_ = s.ring.Gap(now)
		return
	}
	if err != nil {
		s.stopLocked(err)
		return
	}
	if len(f.Data) == 0 {
		return // charged but not retained (result: errors)
	}
	if s.live != nil {
		s.live.append(f, now)
	}
	at := f.At
	if at.After(now) {
		at = now // boot-clock conversion can lead the wall clock slightly
	}
	if err := s.ring.AddRecord(f.Data, at, now); errors.Is(err, packets.ErrInvalid) {
		_ = s.ring.Gap(now)
	} else if err != nil {
		s.inputUnknown = true
		s.stopLocked(err)
		return
	}
	s.scheduleLocked()
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
		snaplen := packets.Snaplen
		if s.httpConfig != nil {
			snaplen = httpheaders.Snaplen
		}
		stats, err = engine(s.ctx, pod, snaplen, s.add, s.notice)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.engineExited = true
	if s.httpConfig != nil && stats.LostSamples > s.httpLost {
		s.httpLost = stats.LostSamples
	}
	if stats.LostSamples > 0 {
		_ = s.ring.Gap(s.now())
		if !s.records {
			s.inputUnknown = true
			err = errors.Join(err, ErrObservationClosed)
		}
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
	if s.httpConfig != nil {
		s.closeHTTPLocked(now)
		if s.httpFailure != nil {
			s.stopLocked(s.httpFailure)
			return
		}
	}
	if err = s.ring.Stop(now); err != nil {
		s.stopLocked(err)
		return
	}
	s.stoppedUntil = now.Add(packetSourceStopGrace)
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
	return &packetSourceSnapshot{copy: copy, release: release, records: s.records, maxEvents: s.maxEvents, httpConfig: s.httpConfig}, nil
}

type packetSourceSnapshot struct {
	httpConfig *collector.HTTPProjection
	records    bool  // syscall records, encoded as JSON Lines
	maxEvents  int64 // syscall events per saved window
	copy       *packets.WindowSnapshot
	once       sync.Once
	release    func()
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
func (s *packetSourceSnapshot) HistoryCoverage() packets.RingCoverage {
	return s.copy.HistoryCoverage()
}
