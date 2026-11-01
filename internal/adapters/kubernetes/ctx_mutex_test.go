package kubernetes

import (
	"context"
	"testing"
	"time"
)

// A waiter gives up at its own deadline while the lock is held.
func TestCtxMutexWaiterHonoursItsContext(t *testing.T) {
	var m ctxMutex
	if !m.lock(context.Background()) {
		t.Fatal("first lock refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if m.lock(ctx) {
		t.Fatal("second lock acquired while held")
	}
	m.unlock()
	if !m.lock(context.Background()) {
		t.Fatal("lock not released")
	}
}
