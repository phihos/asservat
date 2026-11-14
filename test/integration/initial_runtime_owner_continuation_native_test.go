package integration

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Counts and original request-deadline minima are diagnostics only. This fixed
// six-client recorder sees neither paths, headers nor bodies, performs no I/O,
// and does not create a context or a limiter. At most four nested named phases
// are retained; memory does not grow with request count.
type nativeOwnerDeadlineTrace struct {
	mu      sync.Mutex
	enabled bool
	phases  [4]*nativeOwnerDeadlinePhase
}
type nativeOwnerDeadlinePhase struct {
	name                    string
	calls, missing, expired [6]int64
	before, after           [6]time.Duration
}

func (x *nativeOwnerDeadlineTrace) begin(name string) func(*testing.T) {
	x.mu.Lock()
	if !x.enabled {
		x.mu.Unlock()
		return func(*testing.T) {}
	}
	p := &nativeOwnerDeadlinePhase{name: name}
	slot := -1
	for i, old := range x.phases {
		if old == nil {
			slot = i
			break
		}
	}
	if slot < 0 {
		x.mu.Unlock()
		return func(t *testing.T) { t.Error("owner trace phase bound exceeded") }
	}
	x.phases[slot] = p
	x.mu.Unlock()
	return func(t *testing.T) {
		x.mu.Lock()
		copy := *p
		x.phases[slot] = nil
		x.mu.Unlock()
		t.Logf("native original-deadline phase=%s calls=%v missing=%v expired-at-return=%v minimum-before[C B H S W T]=%v minimum-after=%v; no deadline created or renewed", copy.name, copy.calls, copy.missing, copy.expired, copy.before, copy.after)
	}
}
func (x *nativeOwnerDeadlineTrace) request(client int, ctx context.Context) func() {
	x.mu.Lock()
	if !x.enabled {
		x.mu.Unlock()
		return func() {}
	}
	phases := x.phases
	deadline, ok := ctx.Deadline()
	remaining := time.Until(deadline)
	for _, p := range phases {
		if p == nil {
			continue
		}
		p.calls[client]++
		if !ok {
			p.missing[client]++
			continue
		}
		if p.calls[client] == 1 || remaining < p.before[client] {
			p.before[client] = remaining
		}
	}
	x.mu.Unlock()
	return func() {
		x.mu.Lock()
		defer x.mu.Unlock()
		remaining := time.Until(deadline)
		for _, p := range phases {
			if p == nil || !ok {
				continue
			}
			if p.after[client] == 0 || remaining < p.after[client] {
				p.after[client] = remaining
			}
			if remaining <= 0 || ctx.Err() != nil {
				p.expired[client]++
			}
		}
	}
}

func initialBootstrapFixtureDuration(owner bool) time.Duration {
	if owner {
		return 12 * time.Minute
	}
	return 8 * time.Minute
}
func TestInitialBootstrapAggregateDeadlineSelection(t *testing.T) {
	if initialBootstrapFixtureDuration(false) != 8*time.Minute || initialBootstrapFixtureDuration(true) != 12*time.Minute {
		t.Fatal("owner-only aggregate fixture budget changed legacy or product selection")
	}
}
