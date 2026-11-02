package delivery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

// EnqueuePacketCancel queues a restrictive stop of one finite packetCapture
// item this channel queued for the node's current process (ADR-283). It only
// names that existing work: it creates no result slot and never extends the
// pending capture's upload deadline. The node reports the stopped capture as
// failed through the existing slot.
func (c *NodeChannel) EnqueuePacketCancel(ctx context.Context, nodeUID, captureID, workID string, until time.Time) (collector.Work, error) {
	cancel := collector.PacketCancel{CaptureID: captureID, WorkID: workID}
	if ctx == nil || ctx.Err() != nil || !cancel.Valid() {
		return collector.Work{}, ErrNodeInvalid
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e := c.nodes[nodeUID]
	if e == nil || ctx.Err() != nil || !now.Before(until) || until.After(now.Add(5*time.Second)) {
		return collector.Work{}, ErrNodeUnavailable
	}
	if end, ok := ctx.Deadline(); !ok || until.After(end) {
		return collector.Work{}, ErrNodeUnavailable
	}
	pending, ok := e.captures[workID]
	if !ok || pending.cancelOnly || pending.snapshot != nil || pending.captureID != captureID || !now.Before(pending.until) {
		return collector.Work{}, ErrNodeUnavailable
	}
	if len(e.work) >= collector.MaxQueuedWork || e.nextSeq == ^uint64(0) {
		return collector.Work{}, ErrNodeLimit
	}
	e.nextSeq++
	h := hex.EncodeToString(raw[:])
	work := collector.Work{ID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Sequence: e.nextSeq, Kind: collector.WorkCancelPacketCapture, NotAfter: until, CancelPacket: &cancel}
	e.work = append(e.work, work)
	close(e.wake)
	e.wake = make(chan struct{})
	return work, nil
}
