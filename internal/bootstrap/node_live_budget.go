package bootstrap

import (
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"sync"
	"time"
)

// nodeLiveBudget is separate from source/ring/snapshot credit. Its limits are
// supplied from protected operator configuration after qualification; nil/zero
// is unavailable. It never waits behind a viewer while collection is running.
type nodeLiveBudget struct {
	mu                            sync.Mutex
	limits                        v.ProcessingLimits
	held                          int
	second                        time.Time
	windowEvents, windowBytes     int64
	windowSpent                   time.Duration
	events, bytes                 int64
	spent                         time.Duration
	deliveredRows, deliveredBytes int64
	refusedAdmissions             int64
	cohorts                       map[*nodeLiveCohort]struct{}
	lostEvents, droppedRows       int64
}

func (b *nodeLiveBudget) reserve() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.limits.Valid() || b.held >= b.limits.Subscriptions || int64(b.held+1)*v.MaxBufferBytes > b.limits.MemoryBytes {
		b.refusedAdmissions++
		return false
	}
	b.held++
	return true
}
func (b *nodeLiveBudget) release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.held > 0 {
		b.held--
	}
}
func (b *nodeLiveBudget) attach(c *nodeLiveCohort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cohorts == nil {
		b.cohorts = map[*nodeLiveCohort]struct{}{}
	}
	if _, ok := b.cohorts[c]; ok {
		return
	}
	c.lossBase = c.buffer.LossPosition().Lost
	b.cohorts[c] = struct{}{}
}
func (b *nodeLiveBudget) detach(c *nodeLiveCohort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.cohorts[c]; !ok {
		return
	}
	b.lostEvents += int64(c.buffer.LossPosition().Lost - c.lossBase)
	delete(b.cohorts, c)
}
func (b *nodeLiveBudget) reset(now time.Time) {
	if b.second.IsZero() || now.Sub(b.second) >= time.Second {
		b.second = now
		b.windowEvents = 0
		b.windowBytes = 0
		b.windowSpent = 0
	}
}
func (b *nodeLiveBudget) take(now time.Time, bytes int) bool {
	if b == nil || bytes < 0 || !b.mu.TryLock() {
		return false
	}
	defer b.mu.Unlock()
	if now.Before(b.second) {
		return false
	}
	b.reset(now)
	if b.windowEvents >= b.limits.EventsPerSecond || int64(bytes) > b.limits.BytesPerSecond-b.windowBytes || b.windowSpent >= b.limits.TimePerSecond {
		return false
	}
	b.windowEvents++
	b.windowBytes += int64(bytes)
	b.events++
	b.bytes += int64(bytes)
	return true
}
func (b *nodeLiveBudget) finish(elapsed time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if elapsed > 0 {
		b.windowSpent += elapsed
		b.spent += elapsed
	}
}
func (b *nodeLiveBudget) deliver(now time.Time, rows, bytes, dropped int) {
	if b == nil || rows < 0 || bytes < 0 || dropped < 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Before(b.second) {
		return
	}
	b.reset(now)
	b.deliveredRows += int64(rows)
	b.deliveredBytes += int64(bytes)
	b.droppedRows += int64(dropped)
}
func (b *nodeLiveBudget) status() collector.LiveStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	lost, pending := b.lostEvents, 0
	for c := range b.cohorts {
		lost += int64(c.buffer.LossPosition().Lost - c.lossBase)
		pending += c.buffer.Pending()
	}
	return collector.LiveStatus{WindowStartedAt: b.second, Cohorts: b.held, ScanEvents: b.events, ScanBytes: b.bytes, ScanCPUNanos: b.spent.Nanoseconds(), DeliveredRows: b.deliveredRows, DeliveredBytes: b.deliveredBytes, RefusedAdmissions: b.refusedAdmissions, LostEvents: lost, DroppedRows: b.droppedRows, PendingRows: pending}
}
