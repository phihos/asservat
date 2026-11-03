package bootstrap

import (
	"context"
	"slices"
	"time"
)

type storeWaiter struct{ bytes int64 }

// waitStoreLocked claims capacity in arrival order. The caller already owns
// its one-use delivery and holds h.mu; this returns with h.mu held too. Waiting
// never reads a body, extends a deadline, or reserves the encoder working set.
// FIFO admission prevents overtaking; it is not byte-quantum workload fairness.
func (h *ConnectorRecordings) waitStoreLocked(ctx context.Context, until time.Time, bytes int64) bool {
	if bytes <= 0 || bytes > maxStoringBytes || len(h.storeWaiters) >= maxHeldRecordings {
		return false
	}
	waiter := &storeWaiter{bytes: bytes}
	h.storeWaiters = append(h.storeWaiters, waiter)
	defer func() {
		for i, w := range h.storeWaiters {
			if w == waiter {
				h.storeWaiters = slices.Delete(h.storeWaiters, i, i+1)
				break
			}
		}
		h.notifyStoreLocked() // the next head may fit even without a store release
	}()
	for {
		if ctx.Err() != nil || !h.now().Before(until) {
			return false
		}
		if h.storeWaiters[0] == waiter && h.storing+waiter.bytes <= maxStoringBytes {
			h.storing += waiter.bytes
			return true
		}
		if h.storeReleased == nil {
			h.storeReleased = make(chan struct{})
		}
		changed := h.storeReleased
		h.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		h.mu.Lock()
	}
}

func (h *ConnectorRecordings) notifyStoreLocked() {
	if h.storeReleased != nil {
		close(h.storeReleased)
		h.storeReleased = nil
	}
}
