package delivery

import (
	"context"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-248: manual packet captures over the node channel. The connector queues
// one packetCapture item for the node that runs the target Pod; that node
// process (and no other) may deliver exactly one result for it before the
// capture's deadline. The result goes to the PacketSink, which encrypts and
// stores it; the channel itself never holds capture bytes.

// PacketUploadMargin is how long after a capture's end its upload may still
// arrive (node buffering, token bucket wait and transfer of at most 8 MiB).
const PacketUploadMargin = 30 * time.Second

// PacketSink receives one finished capture. pcapng yields exactly
// r.CapturedBytes; the sink must consume it before returning.
type PacketSink interface {
	DeliverPacket(ctx context.Context, node collector.Identity, r collector.PacketResult, pcapng io.Reader) error
}

type pendingCapture struct {
	captureID string
	until     time.Time
}

// SetPacketSink installs the receiver of capture results. It is set once
// during composition, before the listener serves.
func (c *NodeChannel) SetPacketSink(s PacketSink) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sink = s
}

// NodeByName returns the current view of the node with this Kubernetes name.
func (c *NodeChannel) NodeByName(name string) (NodeView, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for _, e := range c.nodes {
		if e.id.NodeName == name {
			return c.view(e, now), true
		}
	}
	return NodeView{}, false
}

// PacketRecorderAvailable reports whether the view's current report offers
// the packet recorder.
func (v NodeView) PacketRecorderAvailable() bool {
	if !v.Current || v.Report == nil {
		return false
	}
	for _, m := range v.Report.Mechanisms {
		if m.Mechanism == collector.MechanismPacket {
			return m.Adapter == collector.AdapterAvailable && m.Prerequisites
		}
	}
	return false
}

// EnqueuePacket queues one capture for the node's current process. startBy
// bounds when the node may still start it; the result is accepted until
// startBy plus the duration plus PacketUploadMargin.
func (c *NodeChannel) EnqueuePacket(nodeUID string, p collector.PacketCapture, startBy time.Time) (collector.Work, error) {
	if !p.Valid() {
		return collector.Work{}, ErrNodeInvalid
	}
	packet := p
	packet.Program = append(packet.Program[:0:0], p.Program...)
	w, err := c.enqueue(nodeUID, collector.WorkPacketCapture, startBy, &packet, nil, nil)
	if err != nil {
		return w, err
	}
	return w, nil
}

// EnqueuePacketExpected queues only for the exact observed whole-Pod source.
// Freshness applies at enqueue; already-issued work retains its original start
// bound. The observation itself supplies no grant or sensitive-input authority.
func (c *NodeChannel) EnqueuePacketExpected(ctx context.Context, expected targets.PacketSourceObservation, p collector.PacketCapture, startBy time.Time) (collector.Work, error) {
	if !p.Valid() {
		return collector.Work{}, ErrNodeInvalid
	}
	packet := p
	packet.Program = append(packet.Program[:0:0], p.Program...)
	return c.enqueue(expected.NodeUID, collector.WorkPacketCapture, startBy, &packet, ctx, &expected)
}

// DeliverPacket hands one node's result for a queued capture to the sink.
// Only the process the item was queued for may deliver, only once and only
// before the capture's deadline.
func (c *NodeChannel) DeliverPacket(ctx context.Context, p NodePeer, epoch string, r collector.PacketResult, body io.Reader) error {
	if ctx == nil || body == nil || !r.Valid() {
		return ErrNodeInvalid
	}
	c.mu.Lock()
	e, err := c.current(p, epoch)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	pending, ok := e.captures[r.WorkID]
	if !ok || pending.captureID != r.CaptureID || !c.now().Before(pending.until) || c.sink == nil {
		c.mu.Unlock()
		return ErrNodeConflict
	}
	delete(e.captures, r.WorkID)
	id, sink := e.id, c.sink
	c.mu.Unlock()
	if err := sink.DeliverPacket(ctx, id, r, io.LimitReader(body, r.CapturedBytes)); err != nil {
		return ErrNodeUnavailable
	}
	return nil
}
