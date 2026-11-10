package bootstrap

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/syscalls"
	app "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/node"
)

// This holder belongs to the existing finite engine and ends at its original
// deadline/join. No engine, observation, ring or capture output is created by
// inspection. Accepted execution pins belong to the regional producer; the node
// independently matches only the original capture/work/runtime/permit facts.
type manualLiveHolder struct {
	ctx                                         context.Context
	active                                      atomic.Pointer[nodeLiveCohort]
	mu                                          sync.Mutex
	capture, work, pod                          string
	identity                                    collector.Identity
	started, until                              time.Time
	observationKind, session, fence, projection string
	program                                     []planning.BPFInstruction
	counters                                    *app.BufferCounters
	cohort                                      *nodeLiveCohort
	closed                                      bool
}

func (n *nodePackets) newManualLive(w collector.Work, p collector.PacketCapture, started time.Time, id collector.Identity) *manualLiveHolder {
	for _, x := range []string{w.ID, p.CaptureID, p.PodUID, id.NodeUID, id.BootID, id.PodUID, id.Epoch} {
		if !authorization.UUID(x) {
			return nil
		}
	}
	h := &manualLiveHolder{capture: p.CaptureID, work: w.ID, pod: p.PodUID, identity: id, started: started, until: started.Add(p.Duration), program: append([]planning.BPFInstruction(nil), p.Program...), counters: &app.BufferCounters{}, projection: v.Packet}
	if p.Syscalls != nil {
		h.projection = v.Syscall
	}
	if p.HTTP != nil {
		h.projection = v.HTTP
	}
	if o := p.Observation; o != nil {
		h.observationKind = "packet"
		h.session = o.Binding.SessionID
		h.fence = o.Binding.Fence
		h.until = minManualTime(h.until, o.LeaseUntil)
	}
	if a := p.Arguments; a != nil {
		h.observationKind = "arguments"
		h.session = a.Binding.SessionID
		h.fence = a.Binding.Fence
		h.until = minManualTime(h.until, a.LeaseUntil)
	}
	return h
}
func minManualTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
func (h *manualLiveHolder) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	h.active.Store(nil)
	if h.cohort != nil {
		h.cohort.Close()
		h.cohort = nil
	}
	clear(h.program)
	h.program = nil
}
func (h *manualLiveHolder) append(f gadget.Frame, now time.Time) {
	if h == nil {
		return
	}
	c := h.active.Load()
	if c == nil {
		return
	}
	if h.ctx == nil || h.ctx.Err() != nil || !now.Before(h.until) {
		return
	}
	c.append(f, now)
}
func (h *manualLiveHolder) notice(n uint64) {
	if h == nil {
		return
	}
	if c := h.active.Load(); c != nil {
		c.sensorLoss(max(uint64(1), n))
	}
}
func (h *manualLiveHolder) unsupported() {
	if h == nil {
		return
	}
	if c := h.active.Load(); c != nil {
		if !c.mu.TryLock() {
			c.buffer.Lose(1)
			return
		}
		defer c.mu.Unlock()
		if !c.closed {
			c.lose("protocol", 1)
		}
	}
}
func (h *manualLiveHolder) http(record httpheaders.ObservedRecord, now time.Time) {
	if h == nil {
		return
	}
	c := h.active.Load()
	if c == nil {
		return
	}
	if h.ctx == nil || h.ctx.Err() != nil || !now.Before(h.until) {
		return
	}
	c.appendHTTP(record, now)
}

// An inactive finite capture performs no argument metadata serialization.
// Expired cohorts are forgotten without blocking the engine on their cleanup.
func (h *manualLiveHolder) observing(now time.Time) bool {
	if h == nil {
		return false
	}
	c := h.active.Load()
	if c == nil {
		return false
	}
	if !c.mu.TryLock() {
		c.buffer.Lose(1)
		return false
	}
	stopped := c.closed || !now.Before(c.until)
	c.mu.Unlock()
	if stopped {
		h.active.CompareAndSwap(c, nil)
		return false
	}
	return true
}
func (h *manualLiveHolder) argument(call syscalls.ArgumentCall, now time.Time) {
	if !h.observing(now) {
		return
	}
	if call.Exit == nil {
		h.unsupported()
		return
	}
	exit := call.Exit.Event
	c := syscalls.Call{Number: exit.Number, Status: syscalls.Unmatched, PID: exit.PID, ExitedBoot: exit.Boot, Ret: exit.Ret}
	stamp := exit.Boot
	if call.Entry != nil {
		c.Status = syscalls.Returned
		c.EnteredBoot = call.Entry.Event.Boot
		stamp = c.EnteredBoot
	}
	// Only fixed metadata is projected. Argument values and user-memory bytes
	// remain exclusively in the already-authorized native argument recorder.
	raw := syscalls.MarshalRecord(c)
	h.append(gadget.Frame{Data: raw, RawTimestamp: stamp, Clock: "boottime", Wire: uint32(len(raw))}, now)
	clear(raw)
}
func (h *manualLiveHolder) matches(m collector.ManualLiveSource, id collector.Identity, projection string, now time.Time) bool {
	return !h.closed && h.ctx != nil && h.ctx.Err() == nil && now.Before(h.until) && projection == h.projection && h.identity == id && m.CaptureID == h.capture && m.WorkID == h.work && m.PodUID == h.pod && m.NodeUID == id.NodeUID && m.BootID == id.BootID && m.CollectorPodUID == id.PodUID && m.CollectorEpoch == id.Epoch && m.ObservationKind == h.observationKind && m.ObservationSessionID == h.session && m.ObservationFence == h.fence
}
func (n *nodePackets) readManualLive(ctx context.Context, w collector.Work, budget *nodeLiveBudget) (v.NodeReply, error) {
	if ctx == nil || ctx.Err() != nil || w.Live == nil || w.Live.Manual == nil || !w.Live.Valid() || !n.now().Before(w.NotAfter) || n.identity == nil {
		return v.NodeReply{}, v.ErrInvalid
	}
	r := w.Live
	m := *r.Manual
	n.budgetMu.Lock()
	running, ok := n.running[m.CaptureID]
	n.budgetMu.Unlock()
	if !ok || running.workID != m.WorkID || running.live == nil {
		return v.NodeReply{}, v.ErrUnavailable
	}
	h := running.live
	now := n.now()
	id := n.identity()
	h.mu.Lock()
	if !h.matches(m, id, r.Projection, now) {
		h.mu.Unlock()
		return v.NodeReply{}, v.ErrUnavailable
	}
	if !r.Inspect && (!m.StartedAt.Equal(h.started) || !m.HardUntil.Equal(h.until)) {
		h.mu.Unlock()
		return v.NodeReply{}, v.ErrDenied
	}
	m.StartedAt, m.HardUntil = h.started, h.until
	clock := "monotonic"
	if r.Projection == v.Syscall {
		clock = "boottime"
	}
	sample, e := sampleLiveClock(clock)
	now = n.now()
	if e != nil {
		h.mu.Unlock()
		return v.NodeReply{}, e
	}
	out := v.NodeReply{Manual: &m, WorkID: w.ID, SourceID: m.CaptureID, Fence: m.WorkID, BootID: m.BootID, Clock: clock, Rows: []v.StampedRow{}}
	if r.Head {
		out.Position = v.Position{Sequence: h.counters.Sequence.Load(), Lost: h.counters.Lost.Load(), ClockLost: h.counters.ClockLost.Load(), Unsupported: h.counters.Unsupported.Load(), SensorLost: h.counters.SensorLost.Load()}
		h.mu.Unlock()
	} else {
		until := minManualTime(w.NotAfter, minManualTime(m.HardUntil, r.PrivacyUntil))
		source := v.Source{Manual: &m, RootID: m.RootID, Target: authorization.Target{ClusterID: r.ClusterID, NamespaceUID: r.NamespaceUID, WorkloadUID: r.WorkloadUID, PodUID: m.PodUID}, OwnerKind: "manualSession", OwnerID: m.CaptureID, State: "Ready", SaveVia: "captureOutcome", Projections: []string{r.Projection}, LeaseUntil: m.HardUntil, HardUntil: m.HardUntil, PrivacyUntil: r.PrivacyUntil, Generation: r.Generation}
		c := h.cohort
		if c != nil {
			c.mu.Lock()
			usable := !c.closed && c.source.Same(source) && c.projection == r.Projection
			c.mu.Unlock()
			if !usable {
				c.Close()
				c = nil
				h.cohort = nil
				h.active.Store(nil)
			}
		}
		if c == nil {
			if !budget.reserve() {
				h.mu.Unlock()
				return v.NodeReply{}, v.ErrCapacity
			}
			buffer, err := app.NewBufferWithCounters(source, r.Projection, now, h.counters)
			if err != nil {
				budget.release()
				h.mu.Unlock()
				return v.NodeReply{}, err
			}
			filter, err := packets.NewFilter(h.program)
			if err != nil {
				buffer.Close()
				budget.release()
				h.mu.Unlock()
				return v.NodeReply{}, err
			}
			c = &nodeLiveCohort{source: source.Clone(), projection: r.Projection, clock: clock, buffer: buffer, budget: budget, filter: filter, projector: packets.NewLiveProjector()}
			h.cohort = c
		}
		e = c.activate(source, until, sample, now)
		if e == nil {
			budget.attach(c)
			h.active.Store(c)
		}
		h.mu.Unlock()
		if e != nil {
			c.Close()
			return v.NodeReply{}, e
		}
		readUntil := until.Add(-100 * time.Millisecond)
		if r.WaitMS > 0 {
			readUntil = minManualTime(readUntil, n.now().Add(time.Duration(r.WaitMS)*time.Millisecond))
		}
		if !n.now().Before(readUntil) {
			return v.NodeReply{}, v.ErrUnavailable
		}
		read, stop := context.WithDeadline(ctx, readUntil)
		out.Rows, out.Position, e = c.Read(read, v.Position{Sequence: r.AfterSequence, Lost: r.AfterLost, ClockLost: r.AfterClockLost, Unsupported: r.AfterUnsupported, SensorLost: r.AfterSensorLost}, r.Limit, n.now, r.WaitMS > 0)
		stop()
		if e != nil {
			return v.NodeReply{}, e
		}
	}
	h.mu.Lock()
	current := h.matches(m, n.identity(), r.Projection, n.now())
	h.mu.Unlock()
	if !current || ctx.Err() != nil || !n.now().Before(w.NotAfter) {
		clear(out.Rows)
		return v.NodeReply{}, v.ErrUnavailable
	}
	sample, e = sampleLiveClock(clock)
	if e != nil {
		clear(out.Rows)
		return v.NodeReply{}, e
	}
	out.Sample = sample.Nanos
	out.Examined = len(out.Rows)
	bounded, encoded, e := boundManualLiveReply(id.Epoch, *r, out)
	if e == nil {
		budget.deliver(n.now(), len(bounded.Rows), encoded, bounded.Dropped)
	}
	return bounded, e
}
func boundManualLiveReply(epoch string, r collector.LiveRead, out v.NodeReply) (v.NodeReply, int, error) {
	rows := out.Rows
	out.Rows = []v.StampedRow{}
	base, e := node.WireLiveReply(epoch, out)
	if e != nil {
		return v.NodeReply{}, 0, e
	}
	raw, e := json.Marshal(base)
	if e != nil {
		return v.NodeReply{}, 0, e
	}
	encoded := len(raw) + 64
	clear(raw)
	maximum := r.ReplyBytes
	if maximum == 0 {
		maximum = 24 << 10
	}
	if encoded > maximum {
		return v.NodeReply{}, 0, v.ErrCapacity
	}
	kept := 0
	for _, pending := range rows {
		row, e := json.Marshal(pending.Row)
		if e != nil {
			return v.NodeReply{}, 0, e
		}
		raw, e := json.Marshal(contracts.NodeLiveRow{Row: row, Nanos: pending.Nanos, Clock: pending.Clock})
		clear(row)
		if e != nil {
			return v.NodeReply{}, 0, e
		}
		cost := len(raw) + 1
		clear(raw)
		if cost > maximum-encoded {
			break
		}
		encoded += cost
		kept++
	}
	out.Dropped = len(rows) - kept
	clear(rows[kept:])
	out.Rows = rows[:kept]
	for _, row := range out.Rows {
		out.Bytes += int64(row.Row.Bytes())
	}
	return out, encoded, nil
}

func (h *manualLiveHolder) httpLoss(before, after httpheaders.Counters) {
	if h == nil || h.ctx == nil || h.ctx.Err() != nil {
		return
	}
	c := h.active.Load()
	if c == nil {
		return
	}
	delta, e := httpheaders.SourceAccountingDelta(httpheaders.SourceAccounting{Projection: before}, httpheaders.SourceAccounting{Projection: after})
	if e != nil {
		h.unsupported()
		return
	}
	c.httpLoss(delta.Projection, time.Now())
}
