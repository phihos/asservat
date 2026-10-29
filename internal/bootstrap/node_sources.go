package bootstrap

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/collector"
)

// nodeSources belongs to the collector process, across poll/certificate
// reconnection. It never adopts another process/boot's source or grants itself
// collection authority. Initial replay tombstones survive their original start
// cutoff; a later renewal cannot construct a replacement engine.
type nodeSources struct {
	mu        sync.Mutex
	closed    bool
	sources   map[string]*packetSource
	plans     map[string]collector.SourceRingLimits
	stops     map[string]sourceStop
	engine    observedPacketEngine
	identity  func() collector.Identity
	now       func() time.Time
	budget    *collector.Budget
	budgetMu  *sync.Mutex
	available bool
}

type sourceStop struct {
	binding collector.SourceBinding
	until   time.Time
}

func (n *nodeSources) decide(parent context.Context, epoch string, w collector.Work) collector.Receipt {
	r := collector.Decide(w, n.now())
	if r.Reason == collector.ReasonWorkUnknown || r.Reason == collector.ReasonWorkExpired {
		return r
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || parent == nil || parent.Err() != nil || n.identity == nil {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	id := n.identity()
	b := w.StopSource
	if w.Source != nil {
		b = &w.Source.Permit.Binding
	}
	if b == nil || b.NodeUID != id.NodeUID || b.BootID != id.BootID || b.CollectorPodUID != id.PodUID || b.CollectorEpoch != id.Epoch || id.Epoch != epoch {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	if w.StopSource != nil {
		if s := n.sources[b.SourceID]; s != nil {
			s.mu.Lock()
			if s.meter.Permit().Binding != *b {
				s.mu.Unlock()
				r.Reason = collector.ReasonWorkUnknown
				return r
			}
			s.stopLocked(context.Canceled)
			s.mu.Unlock()
		}
		// Work.Sequence orders node enqueue, not a paused earlier SQL arm
		// commit. A terminal control can therefore arrive before that arm's
		// later enqueue. Retain the exact ID through the maximum original
		// five-second initial-start interval; no renewal can start an engine.
		if n.stops == nil {
			n.stops = make(map[string]sourceStop)
		}
		now := n.now()
		for id, stop := range n.stops {
			if !now.Before(stop.until) {
				delete(n.stops, id)
			}
		}
		if len(n.stops) >= int(collector.MaxActiveSources)+collector.MaxQueuedWork {
			r.Reason = collector.ReasonCaptureBusy
			return r
		}
		n.stops[b.SourceID] = sourceStop{binding: *b, until: now.Add(5 * time.Second)}
		r.Outcome, r.Reason = collector.OutcomeAccepted, ""
		return r
	}
	if !n.available || n.engine == nil {
		r.Reason = collector.ReasonEngineUnavailable
		return r
	}
	source := w.Source
	if deliveryapp.SourceResourcesDigest(source.Resources) != b.ResourceDigest {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	if stop, ok := n.stops[b.SourceID]; ok && n.now().Before(stop.until) {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	var actual [32]byte
	if len(source.Program) > 0 {
		actual = [32]byte(compiler.FilterProgramDigest(source.Program))
	}
	if actual != b.ProgramDigest || packets.CheckPrefixProgram(source.Program) != nil {
		r.Reason = collector.ReasonFilterUnsupported
		return r
	}
	if n.sources == nil {
		n.sources = make(map[string]*packetSource)
		n.plans = make(map[string]collector.SourceRingLimits)
	}
	if old := n.sources[b.SourceID]; old != nil {
		if n.plans[b.SourceID] != source.Ring || old.Renew(source.Permit) != nil {
			r.Reason = collector.ReasonWorkUnknown
			return r
		}
		r.Outcome, r.Reason = collector.OutcomeAccepted, ""
		return r
	}
	// Remove only joined, closed identities whose original start cutoff is
	// over. Keeping an unknown/closing engine still consumes its real budget.
	now := n.now()
	for key, s := range n.sources {
		s.mu.Lock()
		expired := s.released && !now.Before(s.meter.Permit().StartBy)
		s.mu.Unlock()
		if expired {
			delete(n.sources, key)
			delete(n.plans, key)
		}
	}
	if len(n.sources) >= int(collector.MaxActiveSources)+collector.MaxQueuedWork {
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	p := source.Ring
	limits := packets.RingLimits{MaxAge: p.MaxAge, MaxBytes: p.MaxBytes, SegmentBytes: p.SegmentBytes, MaxFrozenBytes: p.MaxFrozenBytes, MaxSegments: p.MaxSegments, MaxConcurrentSnapshots: p.MaxConcurrentSnapshots}
	s, err := newPacketSource(parent, source.Permit, source.Resources.Node, limits, source.Program, n.engine, n.now, n.budget, n.budgetMu)
	if err != nil {
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	n.sources[b.SourceID], n.plans[b.SourceID] = s, p
	r.Outcome, r.Reason = collector.OutcomeAccepted, ""
	return r
}

func (n *nodeSources) Close() {
	n.mu.Lock()
	n.closed = true
	owned := make([]*packetSource, 0, len(n.sources))
	for _, s := range n.sources {
		owned = append(owned, s)
		s.mu.Lock()
		s.stopLocked(context.Canceled)
		s.mu.Unlock()
	}
	n.mu.Unlock()
	for _, s := range owned {
		_ = s.Close()
	}
}

func (n *nodeSources) Status() ([]collector.SourceStatus, time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	asOf := n.now()
	out := make([]collector.SourceStatus, 0, len(n.sources))
	for _, s := range n.sources {
		s.mu.Lock()
		p := s.meter.Permit()
		out = append(out, collector.SourceStatus{SourceID: p.Binding.SourceID, Fence: p.Binding.Fence, IssuedAt: p.IssuedAt, LeafUntil: p.LeafUntil, Credit: p.Credit, ObservedBytes: s.meter.ObservedBytes(), Closed: s.closed || !n.now().Before(p.LeafUntil), Stopped: !s.stoppedUntil.IsZero(), InputUnknown: s.inputUnknown})
		s.mu.Unlock()
	}
	return out, asOf
}
