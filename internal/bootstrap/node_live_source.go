package bootstrap

import (
	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/syscalls"
	app "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/transport/node"
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"sync"
	"time"
)

type liveClockSample struct {
	Nanos        int64
	At, Received time.Time
}

func sampleLiveClock(clock string) (liveClockSample, error) {
	id := int32(unix.CLOCK_MONOTONIC)
	if clock == "boottime" {
		id = unix.CLOCK_BOOTTIME
	} else if clock != "monotonic" {
		return liveClockSample{}, v.ErrInvalid
	}
	before := time.Now()
	var ts unix.Timespec
	if e := unix.ClockGettime(id, &ts); e != nil {
		return liveClockSample{}, e
	}
	return liveClockSample{ts.Nano(), before, time.Now()}, nil
}

// nodeLiveCohort holds approved fields only. It is activated independently of
// collection and can never access a ring or modify acquisition parameters.
type nodeLiveCohort struct {
	mu                sync.Mutex
	source            v.Source
	projection, clock string
	buffer            *app.Buffer
	budget            *nodeLiveBudget
	projector         *packets.LiveProjector
	filter            *packets.Filter
	sample            liveClockSample
	until             time.Time
	timer             *time.Timer
	closed            bool
}

func (s *packetSource) activateLive(source v.Source, projection string, until time.Time, budget *nodeLiveBudget, sample liveClockSample) (*nodeLiveCohort, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.meter.Permit()
	now := s.now()
	if source.Manual != nil || source.Binding != p.Binding || !source.HardUntil.Equal(p.HardUntil) || s.closed || s.engineExited || s.ctx.Err() != nil || !now.Before(p.LeafUntil) || !source.Valid(now) || !v.Projection(projection) || s.records != (projection == v.Syscall) || (s.httpConfig != nil) != (projection == v.HTTP) || until.After(p.LeafUntil) || until.After(source.PrivacyUntil) {
		return nil, v.ErrDenied
	}
	if s.live != nil {
		s.live.mu.Lock()
		usable := !s.live.closed && s.live.source.Same(source) && s.live.projection == projection
		s.live.mu.Unlock()
		if usable {
			if e := s.live.activate(source, until, sample, now); e != nil {
				return nil, e
			}
			return s.live, nil
		}
	}
	if !budget.reserve() {
		return nil, v.ErrCapacity
	}
	if s.liveCounters == nil {
		s.liveCounters = &app.BufferCounters{}
	}
	buffer, e := app.NewBufferWithCounters(source, projection, now, s.liveCounters)
	if e != nil {
		budget.release()
		return nil, e
	}
	filter, e := packets.NewFilter(s.liveProgram)
	if e != nil {
		budget.release()
		buffer.Close()
		return nil, e
	}
	clock := "monotonic"
	if s.records {
		clock = "boottime"
	}
	c := &nodeLiveCohort{source: source.Clone(), projection: projection, clock: clock, buffer: buffer, budget: budget, filter: filter, projector: packets.NewLiveProjector()}
	if e = c.activate(source, until, sample, now); e != nil {
		c.Close()
		return nil, e
	}
	s.live = c
	if projection == v.HTTP {
		s.httpObserved = func(record httpheaders.ObservedRecord) { c.appendHTTP(record, s.now()) }
		s.httpGaps = func(delta httpheaders.Counters) { c.httpLoss(delta, s.now()) }
	}
	return c, nil
}
func (c *nodeLiveCohort) activate(source v.Source, until time.Time, sample liveClockSample, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.source.Same(source) || sample.Nanos <= 0 || sample.At.IsZero() || sample.Received.Before(sample.At) || sample.Received.Sub(sample.At) > time.Second || sample.Received.After(now) || !now.Before(until) || until.After(now.Add(5*time.Second)) {
		return v.ErrDenied
	}
	if e := c.buffer.Activate(source, until, now); e != nil {
		return e
	}
	c.source = source.Clone()
	c.sample = sample
	c.until = until
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(max(time.Duration(0), until.Sub(now)), func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.until.Equal(until) {
			c.closeLocked()
		}
	})
	return nil
}
func (c *nodeLiveCohort) append(f gadget.Frame, now time.Time) {
	if !c.mu.TryLock() {
		c.buffer.Lose(1)
		return
	}
	defer c.mu.Unlock()
	if c.closed || !now.Before(c.until) {
		return
	}
	if !c.budget.take(now, len(f.Data)) {
		c.buffer.Lose(1)
		return
	}
	start := time.Now()
	defer func() { c.budget.finish(time.Since(start)) }()
	row, ok := c.pendingRow(f.RawTimestamp, f.Clock, now)
	if !ok {
		c.lose("clock", 1)
		return
	}
	if c.projection == v.Syscall {
		fields, valid := syscalls.LiveMetadata(f.Data)
		if !valid {
			c.buffer.Lose(1)
			return
		}
		row.Syscall = &fields
	} else {
		if !c.filter.Match(f.Data, int(f.Wire)) {
			return
		}
		fields, valid := c.projector.Metadata(f.Data, f.Wire, f.DirectionKnown, f.Ingress)
		if !valid {
			c.buffer.Lose(1)
			return
		}
		row.Packet = &fields
	}
	c.buffer.Append(row, int64(f.RawTimestamp), c.clock, now)
}
func (c *nodeLiveCohort) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}
func (c *nodeLiveCohort) closeLocked() {
	if !c.closed {
		c.closed = true
		if c.timer != nil {
			c.timer.Stop()
		}
		c.buffer.Close()
		c.source = v.Source{}
		c.filter = nil
		c.projector = nil
		c.budget.release()
	}
}
func (c *nodeLiveCohort) Read(ctx context.Context, after v.Position, limit int, now func() time.Time, wait ...bool) ([]app.PendingRow, v.Position, error) {
	rows, seq, _, e := c.buffer.Read(ctx, after.Sequence, limit, now, wait...)
	c.mu.Lock()
	position := c.buffer.LossPosition()
	c.mu.Unlock()
	position.Sequence = seq
	return rows, position, e
}

// readLive is invoked only by authenticated exact-purpose node work. Lookup
// never constructs an engine; no matching current source means unavailable.
func (n *nodeSources) readLive(ctx context.Context, w collector.Work) (v.NodeReply, error) {
	if ctx == nil || ctx.Err() != nil || w.Live == nil || collector.Decide(w, n.now()).Reason == collector.ReasonWorkUnknown || !n.now().Before(w.NotAfter) {
		return v.NodeReply{}, v.ErrInvalid
	}
	r := w.Live
	n.mu.Lock()
	s := n.sources[r.Binding.SourceID]
	closed := n.closed
	budget := n.liveBudget
	n.mu.Unlock()
	if s == nil || closed || budget == nil {
		return v.NodeReply{}, v.ErrUnavailable
	}
	s.mu.Lock()
	p := s.meter.Permit()
	records := s.records
	httpSource := s.httpConfig != nil
	s.mu.Unlock()
	if p.Binding != r.Binding || (r.Projection == v.Syscall) != records || httpSource != (r.Projection == v.HTTP) {
		return v.NodeReply{}, v.ErrDenied
	}
	source := v.Source{Binding: p.Binding, Target: authorization.Target{ClusterID: r.ClusterID, NamespaceUID: r.NamespaceUID, WorkloadUID: r.WorkloadUID, PodUID: r.Binding.PodUID}, OwnerKind: "policy", OwnerID: r.Binding.PolicyUID, State: "Ready", SaveVia: "recordingSave", Projections: []string{r.Projection}, LeaseUntil: p.LeafUntil, HardUntil: p.HardUntil, PrivacyUntil: r.PrivacyUntil, Generation: r.Generation}
	clock := "monotonic"
	if records {
		clock = "boottime"
	}
	sample, e := sampleLiveClock(clock)
	if e != nil {
		return v.NodeReply{}, e
	}

	out := v.NodeReply{WorkID: w.ID, SourceID: r.Binding.SourceID, Fence: r.Binding.Fence, BootID: r.Binding.BootID, Clock: clock, Rows: []v.StampedRow{}}
	if r.Head {
		// Passive discovery of the original source head never activates metadata
		// processing or allocates a cohort before a view is accounted.
		s.mu.Lock()
		if s.closed || s.engineExited || s.meter.Permit().Binding != r.Binding {
			s.mu.Unlock()
			return v.NodeReply{}, v.ErrUnavailable
		}
		if s.liveCounters != nil {
			out.Position = v.Position{Sequence: s.liveCounters.Sequence.Load(), Lost: s.liveCounters.Lost.Load(), ClockLost: s.liveCounters.ClockLost.Load(), Unsupported: s.liveCounters.Unsupported.Load(), SensorLost: s.liveCounters.SensorLost.Load()}
		}
		s.mu.Unlock()
	} else {
		c, e := s.activateLive(source, r.Projection, w.NotAfter, budget, sample)
		if e != nil {
			return v.NodeReply{}, e
		}
		readEnd := w.NotAfter.Add(-100 * time.Millisecond)
		if r.WaitMS > 0 {
			if candidate := n.now().Add(time.Duration(r.WaitMS) * time.Millisecond); candidate.Before(readEnd) {
				readEnd = candidate
			}
		}
		if !n.now().Before(readEnd) {
			return v.NodeReply{}, v.ErrUnavailable
		}
		read, done := context.WithDeadline(ctx, readEnd)
		out.Rows, out.Position, e = c.Read(read, v.Position{Sequence: r.AfterSequence, Lost: r.AfterLost, ClockLost: r.AfterClockLost, Unsupported: r.AfterUnsupported, SensorLost: r.AfterSensorLost}, r.Limit, n.now, r.WaitMS > 0)
		done()
		if e != nil {
			return v.NodeReply{}, e
		}
	}
	// An absolute short source leaf continues to bind the completion, even if a
	// later node source renewal exists. Sample after completed row selection.
	sample, e = sampleLiveClock(clock)
	if e != nil || ctx.Err() != nil || !n.now().Before(w.NotAfter) || !n.now().Before(p.LeafUntil) {
		return v.NodeReply{}, v.ErrUnavailable
	}
	out.Sample = sample.Nanos
	out.Examined = len(out.Rows)

	rows := out.Rows
	out.Rows = []v.StampedRow{}
	base, e := node.WireLiveReply(r.Binding.CollectorEpoch, out)
	if e != nil {
		return v.NodeReply{}, e
	}
	raw, e := json.Marshal(base)
	if e != nil {
		return v.NodeReply{}, e
	}
	maximum := r.ReplyBytes
	if maximum == 0 {
		maximum = 24 << 10
	}
	encoded := len(raw) + 64
	clear(raw)
	kept := 0
	for _, pending := range rows {
		row, e := json.Marshal(pending.Row)
		if e != nil {
			return v.NodeReply{}, e
		}
		raw, e := json.Marshal(contracts.NodeLiveRow{Row: row, Nanos: pending.Nanos, Clock: pending.Clock})
		clear(row)
		if e != nil {
			return v.NodeReply{}, e
		}
		cost := len(raw) + 1
		clear(raw)
		if cost > maximum-encoded {
			break
		}
		encoded += cost
		kept++
	}
	out.Rows = rows
	out.Dropped = len(out.Rows) - kept
	clear(out.Rows[kept:])
	out.Rows = out.Rows[:kept]

	for _, r := range out.Rows {
		out.Bytes += int64(r.Row.Bytes())
	}
	budget.deliver(n.now(), kept, encoded)
	return out, nil
}

func (p *nodeProcess) takeLiveUpload(reply v.NodeReply) bool {
	if p.budget == nil {
		return false
	}
	wire, e := node.WireLiveReply(p.epoch, reply)
	if e != nil {
		return false
	}
	defer func() {
		for _, row := range wire.Rows {
			clear(row.Row)
		}
	}()
	raw, e := json.Marshal(wire)
	if e != nil {
		return false
	}
	cost := int64(len(raw) + 4096)
	clear(raw)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.budget.TakeLiveUpload(p.now(), cost)
}

// pendingRow preserves the original native event stamp. It never infers an
// HTTP observation time from the sanitizer's wall timestamp.
func (c *nodeLiveCohort) pendingRow(stamp uint64, clock string, now time.Time) (v.Row, bool) {
	if stamp > 1<<63-1 || clock != c.clock {
		return v.Row{}, false
	}
	proof := v.ClockProof{SourceID: c.source.ID(), BootID: c.source.Boot(), Clock: c.clock, RemoteNanos: c.sample.Nanos, StartedAt: c.sample.At, ReceivedAt: c.sample.Received}
	// A sample precedes subsequent callbacks. Advance both ends by elapsed local
	// monotonic time; this is not a remote wall-clock placement or authority renewal.
	delta := time.Since(c.sample.Received)
	if delta < 0 || delta > 5*time.Second {
		return v.Row{}, false
	}
	proof.RemoteNanos += int64(delta + c.sample.Received.Sub(c.sample.At))
	proof.StartedAt = proof.StartedAt.Add(delta)
	proof.ReceivedAt = c.sample.Received.Add(delta)
	at, end, ms, ok := proof.Place(int64(stamp), c.source.ID(), c.source.Boot(), c.clock, c.source.PrivacyUntil, c.until, c.until)
	if !ok {
		return v.Row{}, false
	}
	return v.Row{ID: "pending", SourceID: c.source.ID(), Sequence: 1, ObservedAt: at, ReceivedAt: now, ExpiresAt: end, ClockUncertainty: ms, Generation: c.source.Generation, Projection: c.projection, PodUID: c.source.Pod()}, true
}
func (c *nodeLiveCohort) lose(reason string, n uint64) {
	if n == 0 {
		return
	}
	switch reason {
	case "clock":
		c.buffer.LoseClock(n)
	case "protocol":
		c.buffer.LoseProtocol(n)
	case "sensor":
		c.buffer.LoseSensor(n)
	}
	c.buffer.Lose(n)
}
func (c *nodeLiveCohort) appendHTTP(observed httpheaders.ObservedRecord, now time.Time) {
	if !c.mu.TryLock() {
		c.buffer.Lose(1)
		return
	}
	defer c.mu.Unlock()
	if c.closed || c.projection != v.HTTP || !now.Before(c.until) {
		return
	}
	record := observed.Record
	bytes := 128 + len(record.Method)
	for _, h := range record.Headers {
		bytes += len(h.Name) + len(h.Value)
	}
	if !c.budget.take(now, bytes) {
		c.buffer.Lose(1)
		return
	}
	started := time.Now()
	defer func() { c.budget.finish(time.Since(started)) }()
	row, ok := c.pendingRow(observed.Stamp.RawTimestamp, observed.Stamp.Clock, now)
	if !ok {
		c.lose("clock", 1)
		return
	}
	fields := &v.HTTPFields{Method: record.Method, Pairing: "request", Headers: []v.Header{}}
	if record.Status != 0 {
		status := record.Status
		fields.Status = &status
		fields.Pairing = "paired"
	}
	for _, h := range record.Headers {
		fields.Headers = append(fields.Headers, v.Header{Name: h.Name, Value: h.Value})
	}
	row.HTTP = fields
	c.buffer.Append(row, int64(observed.Stamp.RawTimestamp), observed.Stamp.Clock, now)
}
func (c *nodeLiveCohort) httpLoss(delta httpheaders.Counters, now time.Time) {
	if !c.mu.TryLock() {
		c.buffer.Lose(1)
		return
	}
	defer c.mu.Unlock()
	if c.closed || !now.Before(c.until) {
		return
	}
	if !c.budget.take(now, 128) {
		c.buffer.Lose(1)
		return
	}
	started := time.Now()
	defer func() { c.budget.finish(time.Since(started)) }()
	c.lose("protocol", delta.StoppedTLS+delta.StoppedHTTP2+delta.StoppedUpgrade+delta.StoppedConnect)
	c.buffer.Lose(delta.InvalidFrames + delta.FragmentFrames + delta.TruncatedFrames + delta.MidstreamFrames + delta.FlowLimitFrames + delta.RecordsDropped + delta.StoppedIncomplete + delta.StoppedGap + delta.StoppedBufferLimit + delta.StoppedMidstream + delta.StoppedMalformed + delta.StoppedHeaderLimit + delta.StoppedBudget + delta.StoppedPipeline + delta.StoppedUnpaired)
}

// sensorLoss is called by the already-running source's actual input notice.
// Viewer contention never blocks the source; lost reason detail degrades to
// the existing generic loss counter rather than claiming a complete view.
func (c *nodeLiveCohort) sensorLoss(n uint64) {
	if !c.mu.TryLock() {
		c.buffer.Lose(n)
		return
	}
	defer c.mu.Unlock()
	if !c.closed {
		c.lose("sensor", n)
	}
}
