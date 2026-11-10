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
	events, bytes                 int64
	spent                         time.Duration
	deliveredRows, deliveredBytes int64
	refusedAdmissions             int64
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
func (b *nodeLiveBudget) reset(now time.Time) {
	if b.second.IsZero() || now.Sub(b.second) >= time.Second {
		b.second = now
		b.events = 0
		b.bytes = 0
		b.spent = 0
		b.deliveredRows = 0
		b.deliveredBytes = 0
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
	if b.events >= b.limits.EventsPerSecond || int64(bytes) > b.limits.BytesPerSecond-b.bytes || b.spent >= b.limits.TimePerSecond {
		return false
	}
	b.events++
	b.bytes += int64(bytes)
	return true
}
func (b *nodeLiveBudget) finish(elapsed time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if elapsed > 0 {
		b.spent += elapsed
	}
}
func (b *nodeLiveBudget) deliver(now time.Time, rows, bytes int) {
	if b == nil || rows < 0 || bytes < 0 {
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
}
func (b *nodeLiveBudget) status() collector.LiveStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return collector.LiveStatus{WindowStartedAt: b.second, Cohorts: b.held, ScanEvents: b.events, ScanBytes: b.bytes, ScanCPUNanos: b.spent.Nanoseconds(), DeliveredRows: b.deliveredRows, DeliveredBytes: b.deliveredBytes, RefusedAdmissions: b.refusedAdmissions}
}
