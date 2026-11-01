package bootstrap

import (
	"context"
	"sync"
)

// ctxMutex is a mutex whose waiters honour their own context: a reader
// sharing one slow observation read gives up at its own deadline instead of
// blocking behind the holder. The zero value is ready.
type ctxMutex struct {
	once sync.Once
	ch   chan struct{}
}

func (m *ctxMutex) lock(ctx context.Context) bool {
	m.once.Do(func() { m.ch = make(chan struct{}, 1) })
	select {
	case m.ch <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (m *ctxMutex) unlock() { <-m.ch }
