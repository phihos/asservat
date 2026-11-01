package bootstrap

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/collector"
	"context"
)

// Cancellation is restrictive and independent of the source's current leaf.
// Its accepted receipt is emitted only after owned copy/upload cleanup joins,
// or an exact no-start tombstone fences the original remaining start interval.
func (n *nodeSources) cancelSnapshot(parent context.Context, epoch string, w collector.Work, r collector.Receipt) collector.Receipt {
	n.mu.Lock()
	x := *w.CancelSnapshot
	if parent == nil || parent.Err() != nil || n.closed || n.identity == nil || !x.Valid() || deliveryapp.SourceBindingDigest(x.Binding) != [32]byte(x.Request.SourceBindingDigest) || !n.now().Before(w.NotAfter) {
		n.mu.Unlock()
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	id, b := n.identity(), x.Binding
	if b.NodeUID != id.NodeUID || b.BootID != id.BootID || b.CollectorPodUID != id.PodUID || b.CollectorEpoch != id.Epoch || id.Epoch != epoch {
		n.mu.Unlock()
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	if n.snapshots == nil {
		n.snapshots = make(map[string]*nodeSourceSnapshot)
	}
	owned := n.snapshots[x.Request.SnapshotID]
	if owned == nil {
		for key, s := range n.snapshots {
			if s.joined && !n.now().Before(s.work.Request.StartBy) {
				delete(n.snapshots, key)
			}
		}
		if n.now().Before(x.Request.StartBy) {
			if len(n.snapshots) >= collector.MaxQueuedWork {
				n.mu.Unlock()
				r.Reason = collector.ReasonCaptureBusy
				return r
			}
			done := make(chan struct{})
			close(done)
			n.snapshots[x.Request.SnapshotID] = &nodeSourceSnapshot{work: x, cancel: func() {}, done: done, joined: true, cancelled: true}
		}
		// After original StartBy absence cannot turn into a later local start.
		n.mu.Unlock()
		r.Outcome, r.Reason = collector.OutcomeAccepted, ""
		return r
	}
	if !owned.work.Equal(x) {
		n.mu.Unlock()
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	owned.cancelled = true
	owned.cancel()
	done := owned.done
	n.mu.Unlock()
	select {
	case <-done:
		r.Outcome, r.Reason = collector.OutcomeAccepted, ""
	case <-parent.Done():
		r.Reason = collector.ReasonWorkUnknown
	}
	return r
}
