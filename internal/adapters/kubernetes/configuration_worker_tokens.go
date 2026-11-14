package kubernetes

import (
	"context"
	"os"
	"sync"
	"time"
)

type configurationWorkerTokenTransport struct {
	files *os.Root
	file  string
}

// A context value is mechanical request ownership, never native authority.
// Only the concrete reader can mint one, over its two exact loaded clients.
type configurationWorkerTokenInterval struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	now     func() time.Time
	until   time.Time
	clients [2]*configurationWorkerTokenTransport
	tokens  [2][]byte
	active  int
	closed  bool
	failed  bool
	rotated bool
	changed chan struct{}
}
