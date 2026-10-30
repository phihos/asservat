package delivery

import (
	"asservat.local/asservat/internal/domain/collector"
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// EnqueueSourceSnapshotCancel uses the existing node work and bounded result
// slots. It authorizes no new read and does not depend on source lease renewal.
func (c *NodeChannel) EnqueueSourceSnapshotCancel(ctx context.Context, x collector.SourceSnapshot, until time.Time) (collector.Work, error) {
	if ctx == nil || ctx.Err() != nil || !x.Valid() || SourceBindingDigest(x.Binding) != [32]byte(x.Request.SourceBindingDigest) {
		return collector.Work{}, ErrNodeInvalid
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e := c.nodes[x.Binding.NodeUID]
	if e == nil || ctx.Err() != nil || !now.Before(until) || until.After(now.Add(5*time.Second)) {
		return collector.Work{}, ErrNodeUnavailable
	}
	if end, ok := ctx.Deadline(); !ok || until.After(end) {
		return collector.Work{}, ErrNodeUnavailable
	}
	id, b := e.id, x.Binding
	if b.BootID != id.BootID || b.CollectorPodUID != id.PodUID || b.CollectorEpoch != id.Epoch {
		return collector.Work{}, ErrNodeUnavailable
	}
	key := ""
	for workID, pending := range e.captures {
		if !now.Before(pending.until) {
			delete(e.captures, workID)
			continue
		}
		if pending.snapshot != nil && pending.snapshot.Equal(x) {
			key = workID
		}
	}
	if len(e.work) >= collector.MaxQueuedWork || e.nextSeq == ^uint64(0) || key == "" && len(e.captures) >= collector.MaxQueuedWork {
		return collector.Work{}, ErrNodeLimit
	}
	e.nextSeq++
	h := hex.EncodeToString(raw[:])
	work := collector.Work{ID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Sequence: e.nextSeq, Kind: collector.WorkCancelSourceSnapshot, NotAfter: until, CancelSnapshot: &x}
	fresh := key == ""
	if fresh {
		key = work.ID
	}
	pending := e.captures[key]
	if fresh {
		pending.cancelOnly = true
	}
	owned := x
	pending.snapshot = &owned
	pending.captureID = x.CaptureID
	pending.cancelID = work.ID
	pending.cancelSeq = work.Sequence
	pending.cancelJoinedAt = time.Time{}
	// Only receipt metadata survives this margin; upload still checks the
	// immutable ProcessingUntil separately, so no writer authority is extended.
	expires := x.Request.ProcessingUntil
	if expires.Before(now) {
		expires = now
	}
	pending.until = expires.Add(PacketUploadMargin)
	e.captures[key] = pending
	e.work = append(e.work, work)
	close(e.wake)
	e.wake = make(chan struct{})
	return work, nil
}

func (c *NodeChannel) SourceSnapshotCancellation(x collector.SourceSnapshot, workID string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.nodes[x.Binding.NodeUID]
	if e == nil || e.id.BootID != x.Binding.BootID || e.id.PodUID != x.Binding.CollectorPodUID || e.id.Epoch != x.Binding.CollectorEpoch {
		return time.Time{}, false
	}
	for _, pending := range e.captures {
		if pending.snapshot != nil && pending.snapshot.Equal(x) && pending.cancelID == workID && c.now().Before(pending.until) && !pending.cancelJoinedAt.IsZero() {
			return pending.cancelJoinedAt, true
		}
	}
	return time.Time{}, false
}
