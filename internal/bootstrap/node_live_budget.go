package bootstrap

import (
	v "asservat.local/asservat/internal/domain/live"
	"sync"
	"time"
)

// nodeLiveBudget is separate from source/ring/snapshot credit. Its limits are
// supplied from protected operator configuration after qualification; nil/zero
// is unavailable. It never waits behind a viewer while collection is running.
type nodeLiveBudget struct {
	mu            sync.Mutex
	limits        v.ProcessingLimits
	held          int
	second        time.Time
	events, bytes int64
	spent         time.Duration
}

func (b *nodeLiveBudget) reserve() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.limits.Valid() || b.held >= b.limits.Subscriptions || int64(b.held+1)*v.MaxBufferBytes > b.limits.MemoryBytes {
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
func (b *nodeLiveBudget) take(now time.Time, bytes int) bool {
	if b == nil || bytes < 0 || !b.mu.TryLock() {
		return false
	}
	defer b.mu.Unlock()
	if now.Before(b.second) {
		return false
	}
	if b.second.IsZero() || now.Sub(b.second) >= time.Second {
		b.second = now
		b.events = 0
		b.bytes = 0
		b.spent = 0
	}
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
