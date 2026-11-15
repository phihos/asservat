// Package delivery owns peer work transport state (C-19). NodeChannel is the
// connector side of the private node work channel (ADR-246, I-02): one
// current stream per node, a bounded work queue pushed on that stream and the
// node's latest status in memory. It owns no SQL state; a connector restart
// forgets every node, whose collectors then reconnect.
package delivery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

var (
	ErrNodeInvalid         = errors.New("node channel: invalid request")
	ErrNodeDenied          = errors.New("node channel: authentication denied")
	ErrNodeUnauthenticated = errors.New("node channel: unknown or replaced node stream")
	ErrNodeConflict        = errors.New("node channel: stale node work")
	ErrNodeRateLimited     = errors.New("node channel: too many new streams")
	ErrNodeLimit           = errors.New("node channel: node or work limit reached")
	ErrNodeUnavailable     = errors.New("node channel: unavailable")
)

// MaxNodes bounds the in-memory registry: the Kubernetes scalability limit of
// 5,000 nodes per cluster.
const MaxNodes = 5000

// NodeAttester authenticates a collector's projected token once per
// connection. The returned identity has no Epoch.
type NodeAttester interface {
	AttestNode(ctx context.Context, token []byte) (collector.Identity, error)
}

// NodePeer is the authenticated collector Pod behind one connection.
type NodePeer struct {
	NodeUID string
	PodUID  string
}

// NodeView is one node's current view for the connector's own use. While the
// stream is open the latest report is current: the collector pushes changes,
// so ReportedAt and Report.ObservedAt read as now.
type NodeView struct {
	Identity   collector.Identity
	Connected  time.Time
	Report     *collector.Report
	ReportedAt time.Time
	Reports    uint64
	Current    bool
	Queued     int
}

type nodeEntry struct {
	id        collector.Identity
	kinds     []collector.WorkKind
	connected time.Time
	stream    uint64
	open      bool
	report    *collector.Report
	reports   uint64
	work      []collector.Work
	nextSeq   uint64
	wake      chan struct{}
	// captures are packetCapture items still awaiting their result, by work
	// ID; a receipt does not remove them, delivery or the deadline does.
	captures map[string]pendingCapture
	live     map[string]*pendingLive
}

// push queues one item for the node's stream and wakes it. A kind the
// collector did not announce in its Hello is refused.
func (e *nodeEntry) push(w collector.Work) error {
	if !slices.Contains(e.kinds, w.Kind) {
		return ErrNodeUnavailable
	}
	e.work = append(e.work, w)
	e.signal()
	return nil
}

func (e *nodeEntry) signal() {
	close(e.wake)
	e.wake = make(chan struct{})
}

type NodeChannel struct {
	now         func() time.Time
	mu          sync.Mutex
	nodes       map[string]*nodeEntry
	streams     uint64
	onChange    func(NodeView)
	sink        PacketSink
	profileSink ProfileSink
}

// NewNodeChannel composes the channel. onChange, when set, is called outside
// the lock after each new stream and each report whose assessment changed.
func NewNodeChannel(now func() time.Time, onChange func(NodeView)) (*NodeChannel, error) {
	if now == nil {
		return nil, ErrNodeInvalid
	}
	return &NodeChannel{now: now, nodes: map[string]*nodeEntry{}, onChange: onChange}, nil
}

// Connect makes this stream the node's current one. A stream from the same
// collector Pod keeps the node's queue, pending results and Epoch; a stream
// from another Pod replaces the entry, so the earlier Pod's queued work is
// dropped and its stream ends. id.Epoch names a new entry's generation.
func (c *NodeChannel) Connect(id collector.Identity, kinds []collector.WorkKind) (NodePeer, uint64, error) {
	if id.NodeUID == "" || id.PodUID == "" || id.NodeName == "" || id.Epoch == "" {
		return NodePeer{}, 0, ErrNodeInvalid
	}
	c.mu.Lock()
	now := c.now()
	e := c.nodes[id.NodeUID]
	if e == nil && len(c.nodes) >= MaxNodes {
		c.mu.Unlock()
		return NodePeer{}, 0, ErrNodeLimit
	}
	if e == nil || e.id.PodUID != id.PodUID {
		if e != nil {
			e.signal()
		}
		e = &nodeEntry{id: id, wake: make(chan struct{}), captures: map[string]pendingCapture{}}
		c.nodes[id.NodeUID] = e
	} else {
		e.id.BootID, e.id.Runtime = id.BootID, id.Runtime
		e.signal()
	}
	c.streams++
	e.stream, e.open, e.connected, e.kinds = c.streams, true, now, slices.Clone(kinds)
	view := c.view(e, now)
	c.mu.Unlock()
	if c.onChange != nil {
		c.onChange(view)
	}
	return NodePeer{NodeUID: id.NodeUID, PodUID: id.PodUID}, e.stream, nil
}

// Disconnect marks the node not current when stream is still its stream.
func (c *NodeChannel) Disconnect(p NodePeer, stream uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.nodes[p.NodeUID]; e != nil && e.stream == stream {
		e.open = false
	}
}

func (c *NodeChannel) current(p NodePeer) (*nodeEntry, error) {
	e := c.nodes[p.NodeUID]
	if e == nil || e.id.PodUID != p.PodUID {
		return nil, ErrNodeUnauthenticated
	}
	return e, nil
}

// Next returns queued work after the given sequence, waiting until there is
// some. A replaced stream ends with ErrNodeUnauthenticated.
func (c *NodeChannel) Next(ctx context.Context, p NodePeer, stream, after uint64) ([]collector.Work, error) {
	for {
		c.mu.Lock()
		e, err := c.current(p)
		if err == nil && e.stream != stream {
			err = ErrNodeUnauthenticated
		}
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		now := c.now()
		var out []collector.Work
		for _, w := range e.work {
			if w.Sequence > after && now.Before(w.NotAfter) {
				out = append(out, w)
			}
		}
		wake := e.wake
		c.mu.Unlock()
		if len(out) > 0 {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return nil, ErrNodeUnavailable
		case <-wake:
		}
	}
}

func sameAssessment(a, b []collector.Availability) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Mechanism != b[i].Mechanism || a[i].Adapter != b[i].Adapter || a[i].Prerequisites != b[i].Prerequisites || a[i].Hook != b[i].Hook || a[i].ProfileTLS != b[i].ProfileTLS || a[i].ProfileAuthorization != b[i].ProfileAuthorization || len(a[i].Reasons) != len(b[i].Reasons) {
			return false
		}
		for j := range a[i].Reasons {
			if a[i].Reasons[j] != b[i].Reasons[j] {
				return false
			}
		}
	}
	return true
}

// Report stores the status read from stream. A superseded stream cannot
// report. Receipts remove the work they answer from the queue.
func (c *NodeChannel) Report(p NodePeer, stream uint64, r collector.Report) error {
	if r.ObservedAt.IsZero() || len(r.Receipts) > collector.MaxReceipts || len(r.Mechanisms) > 8 || int64(len(r.Sources)) > collector.SourceStatusLimit {
		return ErrNodeInvalid
	}
	for _, rc := range r.Receipts {
		if (rc.Outcome != collector.OutcomeAccepted && rc.Outcome != collector.OutcomeRefused) || (rc.Reason != "" && !rc.Reason.Valid()) {
			return ErrNodeInvalid
		}
	}
	seenSources := make(map[string]bool, len(r.Sources))
	for _, source := range r.Sources {
		if !source.Valid(r.ObservedAt) || seenSources[source.SourceID] {
			return ErrNodeInvalid
		}
		seenSources[source.SourceID] = true
	}
	if r.Live != nil && !r.Live.Valid(r.ObservedAt) {
		return ErrNodeInvalid
	}
	c.mu.Lock()
	e, err := c.current(p)
	if err == nil && (e.stream != stream || !e.open) {
		err = ErrNodeUnauthenticated
	}
	if err != nil {
		c.mu.Unlock()
		return err
	}
	now := c.now()
	changed := e.report == nil || !sameAssessment(e.report.Mechanisms, r.Mechanisms)
	// A receipt answers exactly the item with its sequence and work ID. The
	// queue belongs to this collector Pod (current() matched it), so a
	// receipt from a replaced Pod can never reach it.
	type answer struct {
		seq uint64
		id  string
	}
	answered := map[answer]bool{}
	for _, rc := range r.Receipts {
		answered[answer{rc.Sequence, rc.WorkID}] = true
		if rc.Outcome == collector.OutcomeAccepted {
			for key, pending := range e.captures {
				if pending.cancelID == rc.WorkID && pending.cancelSeq == rc.Sequence {
					pending.cancelJoinedAt = now.UTC().Truncate(time.Microsecond)
					e.captures[key] = pending
				}
			}
		}

	}
	kept := e.work[:0]
	for _, w := range e.work {
		if !answered[answer{w.Sequence, w.ID}] && now.Before(w.NotAfter) {
			kept = append(kept, w)
		}
	}
	e.work = kept
	stored := r
	stored.Sources = append([]collector.SourceStatus(nil), r.Sources...)
	stored.Mechanisms = cloneNodeMechanisms(r.Mechanisms)
	stored.Live = cloneLiveStatus(r.Live)
	e.report = &stored
	e.reports++
	view := c.view(e, now)
	c.mu.Unlock()
	if changed && c.onChange != nil {
		c.onChange(view)
	}
	return nil
}

// Enqueue queues one work item without payload for the node's current
// stream. Packet captures use EnqueuePacket.
func (c *NodeChannel) Enqueue(nodeUID string, kind collector.WorkKind, notAfter time.Time) (collector.Work, error) {
	if !kind.Valid() || kind == collector.WorkLiveRead || kind == collector.WorkProfileCapture || kind == collector.WorkCancelProfileCapture || kind == collector.WorkPacketCapture || kind == collector.WorkSyscallCapture || kind == collector.WorkPacketSource || kind == collector.WorkStopPacketSource || kind == collector.WorkCancelPacketCapture {
		return collector.Work{}, ErrNodeInvalid
	}
	return c.enqueue(nodeUID, kind, notAfter, nil, nil, nil)
}

func (c *NodeChannel) enqueue(nodeUID string, kind collector.WorkKind, notAfter time.Time, packet *collector.PacketCapture, ctx context.Context, expected *targets.PacketSourceObservation) (collector.Work, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.nodes[nodeUID]
	now := c.now()
	if e == nil || !now.Before(notAfter) {
		return collector.Work{}, ErrNodeUnavailable
	}
	// This check and insertion share the same mutex: a replaced collector
	// cannot inherit work observed for an earlier Pod.
	if expected != nil {
		mechanism := collector.MechanismPacket
		if packet != nil && packet.Arguments != nil {
			mechanism = collector.MechanismSyscall
		}
		if ctx == nil || ctx.Err() != nil || !expected.Valid(now) || packet == nil ||
			packet.PodUID != expected.PodUID || e.id.NodeUID != expected.NodeUID ||
			e.id.BootID != expected.BootID || e.id.PodUID != expected.CollectorPodUID ||
			e.id.Epoch != expected.CollectorEpoch || !c.view(e, now).RecorderAvailable(mechanism) ||
			notAfter.After(now.Add(collector.PacketCaptureStartWithin)) {
			return collector.Work{}, ErrNodeUnavailable
		}
		if deadline, ok := ctx.Deadline(); ok && !now.Before(deadline) {
			return collector.Work{}, ErrNodeUnavailable
		}
		if a := packet.Arguments; a != nil {
			b := a.Binding
			if !a.ValidFinite(now) || !a.StartBy.Equal(notAfter) || a.Duration != packet.Duration || b.CaptureID != packet.CaptureID || b.PodUID != packet.PodUID || b.NodeUID != e.id.NodeUID || b.BootID != e.id.BootID || b.CollectorPodUID != e.id.PodUID || b.CollectorEpoch != e.id.Epoch {
				return collector.Work{}, ErrNodeUnavailable
			}
		}
		if permit := packet.Observation; permit != nil {
			b := permit.Binding
			if !permit.ValidFinite(now) || !permit.StartBy.Equal(notAfter) || permit.Duration != packet.Duration ||
				b.CaptureID != packet.CaptureID || b.PodUID != packet.PodUID || b.ProgramDigest != packet.ProgramDigest ||
				b.NodeUID != e.id.NodeUID || b.BootID != e.id.BootID || b.CollectorPodUID != e.id.PodUID || b.CollectorEpoch != e.id.Epoch {
				return collector.Work{}, ErrNodeUnavailable
			}
		}
	}
	for id, p := range e.captures {
		if !now.Before(p.until) {
			delete(e.captures, id)
		}
	}
	if len(e.work) >= collector.MaxQueuedWork || packet != nil && len(e.captures) >= collector.MaxQueuedWork {
		return collector.Work{}, ErrNodeLimit
	}
	e.nextSeq++
	h := hex.EncodeToString(raw[:])
	w := collector.Work{ID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Sequence: e.nextSeq, Kind: kind, NotAfter: notAfter, Packet: packet}
	if err := e.push(w); err != nil {
		return collector.Work{}, err
	}
	if packet != nil {
		e.captures[w.ID] = pendingCapture{captureID: packet.CaptureID, until: notAfter.Add(packet.Duration + PacketUploadMargin)}
	}
	return w, nil
}

func (c *NodeChannel) view(e *nodeEntry, now time.Time) NodeView {
	v := NodeView{Identity: e.id, Connected: e.connected, Reports: e.reports, Queued: len(e.work)}
	if e.report != nil {
		r := *e.report
		r.Sources = append([]collector.SourceStatus(nil), e.report.Sources...)
		r.Mechanisms = cloneNodeMechanisms(e.report.Mechanisms)
		r.Live = cloneLiveStatus(e.report.Live)
		v.Report, v.ReportedAt = &r, r.ObservedAt
		if e.open {
			v.Current, v.ReportedAt, r.ObservedAt = true, now, now
		}
	}
	return v
}

// Nodes returns every connected node, ordered by node name.
func (c *NodeChannel) Nodes() []NodeView {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	out := make([]NodeView, 0, len(c.nodes))
	for _, e := range c.nodes {
		out = append(out, c.view(e, now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity.NodeName < out[j].Identity.NodeName })
	return out
}

func cloneNodeMechanisms(in []collector.Availability) []collector.Availability {
	out := append([]collector.Availability(nil), in...)
	for n := range out {
		out[n].Reasons = append([]collector.Reason(nil), in[n].Reasons...)
		out[n].LiveProjections = append([]string(nil), in[n].LiveProjections...)
	}
	return out
}

func cloneLiveStatus(in *collector.LiveStatus) *collector.LiveStatus {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
