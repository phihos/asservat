package kubernetes

import (
	"context"
	"sync"
)

// The wrapper changes only cancellation callback joining, not authority values,
// deadlines or the native graph. Its first subscription is the driver's outer
// provider borrow; all inner operation subscriptions stop normally.
type ownerInstallationDelayedJoin struct {
	context.Context
	mu      sync.Mutex
	first   bool
	entered chan struct{}
	release chan struct{}
}

func (s *ownerInstallationDelayedJoin) Value(any) any { return nil }
func (s *ownerInstallationDelayedJoin) AfterFunc(f func()) func() bool {
	s.mu.Lock()
	first := !s.first
	s.first = true
	s.mu.Unlock()
	stop := context.AfterFunc(s.Context, f)
	return func() bool {
		if first {
			close(s.entered)
			<-s.release
		}
		return stop()
	}
}
