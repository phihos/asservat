package kubernetes

import (
	"context"
	"sync"
	"time"
)

type ownerIdentityOperationDeadlineBarrier struct {
	context.Context
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *ownerIdentityOperationDeadlineBarrier) Deadline() (time.Time, bool) {
	deadline, ok := s.Context.Deadline()
	s.once.Do(func() { close(s.entered); <-s.release })
	return deadline, ok
}
